"""Derive deterministic source/AST facts for compiled ecological contracts."""
from __future__ import annotations

import argparse
import ast
from collections import Counter
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GIT = ROOT / "experiments/p0-complete-git-source-round125-n1823"
COMPILATION_SOURCE_PLAN = ROOT / "experiments/p0-ecological-contract-compilation-round159-n2007/RUN_PLAN.json"
AGENT_DECORATORS = {"tool", "function_tool", "tool_plain", "input_guardrail", "output_guardrail", "output_validator"}
AGENT_CALLS = {"Agent", "LlmAgent", "create_agent", "Crew", "Task", "register_before_tool_call_hook", "register_after_model_call_hook"}
AGENT_KEYWORDS = {"tools", "input_guardrails", "output_guardrails", "tool_input_guardrails", "before_tool_callback", "after_tool_callback", "guardrail", "middleware"}


def read(path): return json.loads(Path(path).read_bytes())
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def frozen_source_text(contract, evidence, tasks):
    """Recover a source view authenticated by the frozen screening receipt."""
    for unit in contract["parent_sample_ids"]:
        task = tasks.get(unit)
        if not task or task["receipts"].get(evidence["path"], {}).get("sha256") != evidence["source_sha256"]:
            continue
        source = next((row for row in task["payload"]["sources"]
                       if row["path"] == evidence["path"]), None)
        if source is None:
            continue
        lines = []
        for raw in source["content"].splitlines():
            number, separator, text = raw.partition("|")
            if separator and number.isdigit():
                lines.append(text)
        if not lines:
            raise ValueError("frozen_source_view_unreadable")
        return "\n".join(lines)
    raise KeyError(evidence["path"])


def call_name(node):
    func = node.func if isinstance(node, ast.Call) else node
    parts = []
    while isinstance(func, ast.Attribute): parts.append(func.attr); func = func.value
    if isinstance(func, ast.Name): parts.append(func.id)
    return ".".join(reversed(parts))


def facts_for_source(content):
    try: tree = ast.parse(content)
    except (SyntaxError, ValueError): return {"parsed": False, "agent": [], "guard": [], "commit": [], "functions": []}
    facts = {"parsed": True, "agent": [], "guard": [], "commit": [], "functions": []}
    for node in ast.walk(tree):
        start, end = getattr(node, "lineno", None), getattr(node, "end_lineno", getattr(node, "lineno", None))
        if start is None: continue
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            facts["functions"].append((start, end, node.name))
            for decorator in node.decorator_list:
                name = call_name(decorator.func if isinstance(decorator, ast.Call) else decorator)
                if name.split(".")[-1] in AGENT_DECORATORS:
                    facts["agent"].append((decorator.lineno, getattr(decorator, "end_lineno", decorator.lineno), name))
        if isinstance(node, ast.Call):
            name = call_name(node)
            keywords = {item.arg for item in node.keywords if item.arg}
            if name.split(".")[-1] in AGENT_CALLS or keywords & AGENT_KEYWORDS:
                facts["agent"].append((start, end, name))
            facts["commit"].append((start, end, name))
        if isinstance(node, (ast.If, ast.Raise, ast.Assert, ast.Return)):
            facts["guard"].append((start, end, type(node).__name__))
        if isinstance(node, (ast.Await, ast.Assign, ast.AugAssign, ast.Delete, ast.Return, ast.Yield)):
            facts["commit"].append((start, end, type(node).__name__))
    return facts


def overlaps(items, start, end):
    return any(a <= end and start <= b for a, b, _name in items)


def enclosing(functions, line):
    values = [(b - a, name) for a, b, name in functions if a <= line <= b]
    return min(values)[1] if values else None


def analyze_contract(contract, sources):
    parsed = {path: facts_for_source(content) for path, content in sources.items()}
    by_role = {}
    for evidence in contract["admission_evidence"]:
        by_role.setdefault(evidence["role"], []).append(evidence)
    def role_fact(role, fact):
        return any(e["path"] in parsed and parsed[e["path"]]["parsed"] and
                   overlaps(parsed[e["path"]][fact], e["line_start"], e["line_end"])
                   for e in by_role.get(role, []))
    agent = role_fact("agent_entry_binding", "agent")
    guard = role_fact("guard_registration", "guard") or role_fact("guard_registration", "agent")
    condition = role_fact("forbidden_condition", "guard")
    operation = role_fact("protected_operation", "commit")
    commit = role_fact("commit_point", "commit")
    orderings = []
    for g in by_role.get("guard_registration", []) + by_role.get("forbidden_condition", []):
        for c in by_role.get("commit_point", []):
            if g["path"] != c["path"] or g["path"] not in parsed: continue
            gf = enclosing(parsed[g["path"]]["functions"], g["line_start"])
            cf = enclosing(parsed[c["path"]]["functions"], c["line_start"])
            if gf and gf == cf:
                orderings.append("before" if g["line_start"] < c["line_start"] else "after" if g["line_start"] > c["line_start"] else "same_line")
    eligibility = agent and guard and condition and operation and commit
    return {"contract_id": contract["contract_id"], "protocol_group": contract["protocol_group"],
            "source_identity_verified": True, "python_sources_parsed": sum(value["parsed"] for value in parsed.values()),
            "agent_entry_anchor": agent, "guard_syntax_anchor": guard, "condition_syntax_anchor": condition,
            "operation_syntax_anchor": operation, "commit_syntax_anchor": commit,
            "same_function_orderings": sorted(set(orderings)), "mechanically_eligible_for_path_analysis": eligibility,
            "DEC_label": None, "claim_boundary": "Syntactic/source facts only; no dominance, path completeness, behavior or DEC verdict."}


def verify(admission):
    values, errors = [], []
    compilation_tasks = read(COMPILATION_SOURCE_PLAN)["tasks"]
    for contract in admission["contracts"]:
        if contract["protocol_group"] != "compiled_agent_bound_v4":
            values.append({"contract_id": contract["contract_id"], "protocol_group": contract["protocol_group"],
                           "mechanically_eligible_for_path_analysis": False, "DEC_label": None,
                           "reason": "legacy_contract_requires_protocol_migration"})
            continue
        repo_key = hashlib.sha256(contract["repository"].encode()).hexdigest()[:24]
        inventory_path = GIT / "repositories" / repo_key / "RESULT.json"
        inventory = read(inventory_path); exported = {row["path"]: row for row in inventory["exported"]}
        sources = {}
        try:
            if inventory["commit"] != contract["source_commit"]: raise ValueError("commit")
            for evidence in contract["admission_evidence"]:
                row = exported.get(evidence["path"])
                if row is not None:
                    path = GIT / row["destination"]
                    if sha(path) != evidence["source_sha256"] or row["sha256"] != evidence["source_sha256"]:
                        raise ValueError("source_hash")
                    sources[evidence["path"]] = path.read_text(encoding="utf-8-sig", errors="replace")
                else:
                    sources[evidence["path"]] = frozen_source_text(contract, evidence, compilation_tasks)
            values.append(analyze_contract(contract, sources))
        except (OSError, ValueError, KeyError) as exc:
            errors.append({"contract_id": contract["contract_id"], "reason": type(exc).__name__ + ":" + str(exc)})
    counts = Counter("eligible" if row.get("mechanically_eligible_for_path_analysis") else "not_eligible" for row in values)
    return {"schema_version": "p0-ecological-contract-structural-verification-1", "rows": values, "errors": errors,
            "counts": dict(counts), "execution_health": "completed" if not errors else "partial",
            "behavior_ground_truth_established": False, "DEC_prevalence_available": False,
            "claim_boundary": "Deterministic source identity and AST-shape qualification only; labels remain unavailable."}


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--admission", type=Path, required=True); parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(); value = verify(read(args.admission)); value["inputs"] = {
        str(args.admission.resolve().relative_to(ROOT)): sha(args.admission),
        str(COMPILATION_SOURCE_PLAN.relative_to(ROOT)): sha(COMPILATION_SOURCE_PLAN),
        str(Path(__file__).resolve().relative_to(ROOT)): sha(Path(__file__))}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("x") as handle: json.dump(value, handle, indent=2, sort_keys=True); handle.write("\n")
    print(json.dumps({"counts": value["counts"], "errors": len(value["errors"])}))


if __name__ == "__main__": main()
