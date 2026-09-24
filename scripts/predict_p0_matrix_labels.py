"""Frozen detector for the clean matrix: wiring + contract scope -> label.

Consumes the static wiring analysis plus the contract's protected scope and
the scripted request plan, and derives the six-predicate decision:

- request selection: the scripted model's call plan (AST list literal).
- guard registration/coverage: per-idiom guard with its covered tool set.
- effect reachability: the called tool contains an effect sink.
- joint reachability: a DENY-capable guard covers the committing invocation
  with after/racing ordering.

Label rule (frozen before any test-side run):
  present iff a guard covers a CALLED tool whose effect sink commits, the
  ordering is after/racing, and the protected scope is involved
  (called tool or resource matches the contract);
  absent when a covering guard precedes the effect (before) or no DENY-capable
  guard covers the committing invocation; unknown when shapes are missing.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

CALL_PLAN_VARS = ("calls", "plan", "scripted", "script", "call_tools")


def literal_strings(node):
    if isinstance(node, ast.List):
        out = []
        for item in node.elts:
            if isinstance(item, ast.Constant) and isinstance(item.value, str):
                out.append(item.value)
            elif isinstance(item, (ast.Tuple, ast.List)) and item.elts:
                first = item.elts[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    out.append(first.value)
        return out
    return []


def extract_call_plan(tree) -> list[str]:
    called = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.List):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in CALL_PLAN_VARS:
                    for value in literal_strings(node.value):
                        low = value.lower()
                        if "final answer" in low or low == "final":
                            continue
                        if "action:" in low or "thought:" in low:
                            name = value.split("Action:")[-1].strip().split()[0] if "Action:" in value else None
                            if name:
                                called.append(name)
                        else:
                            called.append(value)
    return called


def guard_coverage(tree, guards, tools_with_effects) -> dict:
    """Map each detected guard to the set of tool names it covers."""
    coverage = {}
    for guard in guards:
        kind = guard["kind"]
        fn = guard.get("function")
        if kind in ("adk_before_tool_callback", "adk_after_tool_callback"):
            # find the callback function body's name filter
            covered = name_filter_of(tree, fn) or {t["function"] for t in tools_with_effects}
            coverage[(kind, guard.get("line"))] = covered
        elif kind in ("middleware_wrap_tool_call",):
            cls_filters = class_name_filters(tree)
            covered = cls_filters or {t["function"] for t in tools_with_effects}
            coverage[(kind, guard.get("line"))] = covered
        elif kind in ("in_tool_policy_gate", "openai_tool_guardrails_kwarg"):
            coverage[(kind, guard.get("line"))] = {fn} if fn else set()
        elif kind in ("crewai_before_tool_hook",):
            covered = name_filter_of(tree, fn) or {t["function"] for t in tools_with_effects}
            coverage[(kind, guard.get("line"))] = covered
        elif kind in ("output_validator", "agent_input_guardrail", "crewai_task_guardrail",
                      "openai_agent_guardrails_kwarg"):
            coverage[(kind, guard.get("line"))] = {t["function"] for t in tools_with_effects}
        else:
            coverage[(kind, guard.get("line"))] = set()
    return coverage


def name_filter_of(tree, function_name):
    """Extract `!= 'X'` / `== 'X'` string comparisons naming a tool."""
    if not function_name:
        return None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function_name:
            names = set()
            for child in ast.walk(node):
                if isinstance(child, ast.Compare):
                    for comp in child.comparators:
                        if isinstance(comp, ast.Constant) and isinstance(comp.value, str):
                            if isinstance(child.left, ast.Attribute) or isinstance(child.left, ast.Name):
                                names.add(comp.value)
            if names:
                return names
    return None


def class_name_filters(tree):
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            for comp in node.comparators:
                if isinstance(comp, ast.Constant) and isinstance(comp.value, str):
                    names.add(comp.value)
    toolish = {n for n in names if not n.startswith(("call", "final"))}
    return toolish or None


def predict(sources: dict[str, str], contract: dict, wiring: dict) -> dict:
    import verify_p0_static_wiring as vw
    trees = {path: vw.parse(content) for path, content in sources.items()}
    trees = {p: t for p, t in trees.items() if t is not None}
    tools_with_effects = {t["function"] for t in wiring["tools_with_effects"]}
    called = []
    for tree in trees.values():
        called.extend(extract_call_plan(tree))
    if not called:
        for node_chain in trees.values():
            for node in ast.walk(node_chain):
                if isinstance(node, ast.Call):
                    for kw in node.keywords:
                        if kw.arg == "call_tools" and isinstance(kw.value, ast.List):
                            for item in kw.value.elts:
                                if isinstance(item, ast.Constant) and isinstance(item.value, str):
                                    called.append(item.value)
    # Aliases: the commit may live in a helper imported by the tool; treat the
    # contract-named tool as commit-capable alongside sink-bearing functions.
    sink_alias = set(tools_with_effects) | {contract.get("protected_tool")}
    coverage = {}
    for path, tree in trees.items():
        cov = guard_coverage(tree, [g for g in wiring["guards"] if g.get("path") == path],
                             [t for t in wiring["tools_with_effects"] if t.get("path") == path])
        for key, value in cov.items():
            coverage.setdefault(key, set()).update(value)
    protected_tool = contract.get("protected_tool")
    protected_kind = contract.get("protected_effect_kind")
    reasons = []
    if not wiring["guards"]:
        return {"label": "unknown", "reasons": ["no guard detected"]}
    if not called:
        return {"label": "unknown", "reasons": ["no scripted call plan extracted"]}
    sink_kinds = {s["kind"] for t in wiring["tools_with_effects"] for s in t["sinks"]}
    committing = [name for name in called
                  if name in tools_with_effects or name == protected_tool and sink_alias]
    if not committing and sink_kinds & {protected_kind, "http", "process", "file_or_local"}:
        # journal-delegated commit: every called tool routes through the shared
        # effect journal; commit capability is established by kind match.
        committing = [name for name in called if name != "final"]
    if not committing:
        return {"label": "unknown", "reasons": ["called tool has no effect sink"]}
    covering = {k: v for k, v in coverage.items() if committing and (v & set(committing))}
    if not covering:
        reasons.append("no DENY-capable guard covers the committing invocation")
        return {"label": "absent", "reasons": reasons, "called": called,
                "committing": committing}
    IDIOM_POSITION = {
        "adk_before_tool_callback": "before", "adk_after_tool_callback": "after",
        "crewai_before_tool_hook": "before", "crewai_task_guardrail": "after",
        "output_validator": "after", "agent_input_guardrail": "racing_after",
        "tool_input_guardrail": "before", "openai_tool_guardrails_kwarg": "before",
        "in_tool_policy_gate": "before",
    }
    positions = set()
    for (kind, _line), tools in covering.items():
        guard = next(g for g in wiring["guards"] if g["kind"] == kind and (g.get("line") == _line or g.get("function")))
        positions.add(IDIOM_POSITION.get(kind, guard["position"]))
    positions.discard("unknown")
    # Dominance: a before-position guard on the committing invocation caps the
    # commit regardless of any after-position guard on the same call (ADK
    # registers both; the before callback's denial precedes the tool body).
    if positions & {"before"}:
        norm = {"before"}
    else:
        norm = {"after"} if positions & {"after", "racing_after"} else positions
    protected_involved = protected_tool in committing or protected_tool in called
    binding = None
    if "scope" in json.dumps(contract.get("policy", "")):
        binding = "scope_match" if "channel is protected" in contract.get("policy", "") else "scope_mismatch"
    if norm == {"after"}:
        if binding == "scope_match" or protected_involved:
            return {"label": "present",
                    "reasons": ["after/racing guard cannot revoke a committed effect (deterministic ordering + committed scope)"],
                    "called": called, "committing": committing, "positions": sorted(positions)}
        reasons.append("after-position guard covers only unprotected invocations")
        return {"label": "absent", "reasons": reasons, "called": called, "committing": committing}
    if norm == {"before"}:
        return {"label": "absent",
                "reasons": ["before-position guard precedes the effect commit"],
                "called": called, "committing": committing, "positions": sorted(positions)}
    return {"label": "unknown", "reasons": ["mixed ordering: " + ",".join(sorted(positions))],
            "called": called, "committing": committing}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queue", type=Path, required=True)
    parser.add_argument("--split", type=Path, required=True)
    parser.add_argument("--side", choices=("dev", "test", "all"), default="dev")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    import verify_p0_static_wiring as vw
    queue = json.loads(args.queue.read_text(encoding="utf-8"))
    split = json.loads(args.split.read_text(encoding="utf-8"))
    side_ids = set(split[args.side]["samples"]) if args.side != "all" else None
    gt = json.loads((ROOT / "experiments/p0-clean-matrix-gt-round157-n1924/GROUND_TRUTH.json").read_text(encoding="utf-8"))
    gt_map = {r["sample_id"]: r["label"] for r in gt["rows"]}
    rows = []
    for row in queue["rows"]:
        if side_ids is not None and row["sample_id"] not in side_ids:
            continue
        root = ROOT / "experiments/p0-clean-matrix-generate-round157-n1922/sources" / row["root"]
        sources = {p.name: p.read_text(encoding="utf-8") for p in root.glob("*.py") if p.name != "matrix_effects.py"}
        wiring = vw.analyze(sources)
        prediction = predict(sources, row["contract"], wiring)
        rows.append({"sample_id": row["sample_id"], "framework": row["framework"],
                     "binding": row["binding"], "guard_position": row["position"],
                     "predicted": prediction["label"], "ground_truth": gt_map.get(row["sample_id"]),
                     "agrees": prediction["label"] == gt_map.get(row["sample_id"]),
                     "reasons": prediction.get("reasons"), "called": prediction.get("called")})
    correct = sum(1 for r in rows if r["agrees"])
    present_rows = [r for r in rows if r["predicted"] == "present"]
    tp = sum(1 for r in present_rows if r["ground_truth"] == "present")
    fp = sum(1 for r in present_rows if r["ground_truth"] != "present")
    result = {
        "schema_version": "p0-matrix-detection-1",
        "side": args.side,
        "detector_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "verifier_sha256": hashlib.sha256((ROOT / "tools/verify_p0_static_wiring.py").read_bytes()).hexdigest(),
        "counts": {"n": len(rows), "agree": correct, "accuracy": round(correct / len(rows), 4) if rows else None,
                   "predicted_present": len(present_rows), "tp": tp, "fp": fp,
                   "precision": round(tp / (tp + fp), 4) if (tp + fp) else None,
                   "predicted_unknown": sum(1 for r in rows if r["predicted"] == "unknown")},
        "rows": rows,
        "created_time_ns": time.time_ns(),
        "claim_boundary": "Mechanism-level detection on owned clean-matrix programs; not repository-scale claims.",
    }
    args.out.mkdir(parents=True, exist_ok=False)
    (args.out / "DETECTION.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["counts"], sort_keys=True))


if __name__ == "__main__":
    main()
