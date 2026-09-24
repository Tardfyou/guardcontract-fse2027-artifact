"""Strict DEC v2: universal candidate proof over broad cited source spans."""
from __future__ import annotations

import argparse
import ast
from collections import Counter
import json
from pathlib import Path
import time

import verify_p0_ecological_dec_witness as v1

ROOT = v1.ROOT
PRIORITY = {
    "http": {"send": 4, "request": 4, "get": 3, "post": 3, "put": 3, "patch": 3, "delete": 3,
             "urlopen": 3, "urlretrieve": 3},
    "file": {"write": 4, "write_text": 4, "write_bytes": 4, "unlink": 4, "remove": 4,
             "rmtree": 4, "rename": 4, "replace": 4, "move": 4, "copy": 3, "mkdir": 3,
             "read": 2, "read_text": 2, "read_bytes": 2, "open": 1},
    "database": {"commit": 5, "execute": 4, "executemany": 4, "insert": 3, "insert_one": 3,
                 "update": 3, "update_one": 3, "update_many": 3, "delete": 3,
                 "delete_one": 3, "delete_many": 3, "add": 2, "save": 2},
    "process": {"create_subprocess_exec": 5, "create_subprocess_shell": 5, "Popen": 5,
                "run": 4, "call": 4, "check_call": 4, "check_output": 4, "system": 4, "popen": 4},
    "communication": {"send_message": 5, "sendmail": 5, "send_email": 5, "send_mail": 5,
                      "publish": 4, "send": 3},
    "state": {"commit": 5, "save": 4, "set": 3, "update": 3, "append": 3,
              "extend": 3, "pop": 3, "clear": 3},
    "tool_execution": {"dispatch": 5, "execute": 5, "invoke": 5, "ainvoke": 5,
                       "handler": 4, "run": 4, "call": 4},
    "other_external": {},
}


def _candidate_nodes(contract, sources):
    parsed = {}
    for path, source in sources.items():
        try:
            parsed[path] = ast.parse(source)
        except (SyntaxError, ValueError):
            parsed[path] = None
    conditions, commits, unresolved_conditions, unresolved_commits = {}, {}, [], []
    for evidence in contract["admission_evidence"]:
        tree = parsed.get(evidence["path"])
        if evidence["role"] == "forbidden_condition":
            if tree is None:
                unresolved_conditions.append([evidence["path"], evidence["line_start"], "not_python"])
                continue
            nodes = [node for node in ast.walk(tree) if isinstance(node, ast.If)
                     and v1._overlaps(node.test, evidence["line_start"], evidence["line_end"])]
            if not nodes:
                unresolved_conditions.append([evidence["path"], evidence["line_start"], "no_if_test"])
            for node in nodes:
                conditions[(evidence["path"], node.lineno, node.end_lineno)] = (evidence["path"], node)
        elif evidence["role"] == "commit_point":
            if tree is None:
                unresolved_commits.append([evidence["path"], evidence["line_start"], "not_python"])
                continue
            calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                     and v1._overlaps(node, evidence["line_start"], evidence["line_end"])]
            if contract["effect_stratum"] != "other_external":
                scores = PRIORITY[contract["effect_stratum"]]
                calls = [node for node in calls if v1._call_leaf(node) in scores]
                if calls:
                    maximum = max(scores[v1._call_leaf(node)] for node in calls)
                    calls = [node for node in calls if scores[v1._call_leaf(node)] == maximum]
            if not calls:
                unresolved_commits.append([evidence["path"], evidence["line_start"], "no_supported_call"])
            for node in calls:
                commits[(evidence["path"], node.lineno, node.end_lineno, v1._call_leaf(node))] = (evidence["path"], node)
    return parsed, list(conditions.values()), list(commits.values()), unresolved_conditions, unresolved_commits


def _pair_proof(contract, evidence, path, tree, condition, commit):
    condition_function, commit_function = v1._enclosing_function(tree, condition), v1._enclosing_function(tree, commit)
    if condition_function is None or condition_function is not commit_function:
        return {"status": "unknown", "reason": "cross_function_pair"}
    function = condition_function
    if any(isinstance(node, (ast.Try, ast.TryStar, ast.For, ast.AsyncFor, ast.While, ast.Match))
           for node in ast.walk(function)):
        return {"status": "unknown", "reason": "unsupported_control_flow"}
    local_evidence = [row for row in evidence if row["path"] == path]
    if not any(row["role"] == "agent_entry_binding" and
               function.lineno - 3 <= row["line_start"] <= function.end_lineno for row in local_evidence):
        return {"status": "unknown", "reason": "agent_entry_not_local"}
    if not any(row["role"] == "guard_registration" and
               function.lineno - 3 <= row["line_start"] <= function.end_lineno for row in local_evidence):
        return {"status": "unknown", "reason": "guard_not_local"}
    if not any(row["role"] == "protected_operation" and
               v1._overlaps(function, row["line_start"], row["line_end"]) for row in local_evidence):
        return {"status": "unknown", "reason": "operation_not_local"}
    deny = v1._terminating_deny(condition.body, contract["framework"])
    if deny is None:
        return {"status": "unknown", "reason": "branch_not_deny"}
    condition_statement = v1._direct_statement(function.body, condition)
    commit_statement = v1._direct_statement(function.body, commit)
    scope = {"path": path, "function": function.name, "condition_line": condition.lineno,
             "commit_line": commit.lineno, "deny_line": deny.lineno,
             "scope_kind": "single_cited_agent_operation"}
    if condition_statement is condition and commit_statement is not None:
        condition_index, commit_index = function.body.index(condition), function.body.index(commit_statement)
        if commit_index < condition_index:
            return {"status": "proved", "label": "VIOLATION-PRESENT",
                    "proof_kind": "commit_before_forbidden_branch_deny", "proof_scope": scope}
        if condition_index < commit_index and not v1._contains(condition, commit):
            return {"status": "proved", "label": "CONFORMANT-WITHIN-SCOPE",
                    "proof_kind": "forbidden_branch_deny_dominates_commit", "proof_scope": scope}
    if v1._contains(condition, commit):
        commit_statement = v1._direct_statement(condition.body, commit)
        if commit_statement is not None and condition.body.index(commit_statement) < condition.body.index(deny):
            return {"status": "proved", "label": "VIOLATION-PRESENT",
                    "proof_kind": "forbidden_branch_commits_before_deny", "proof_scope": scope}
    return {"status": "unknown", "reason": "pair_relation_unproved"}


def local_proof(contract, sources):
    parsed, conditions, commits, unresolved_conditions, unresolved_commits = _candidate_nodes(contract, sources)
    if not conditions or not commits:
        return {"status": "unknown", "reason": "condition_or_commit_candidates_absent",
                "unresolved_conditions": unresolved_conditions, "unresolved_commits": unresolved_commits}
    pairs = []
    for condition_path, condition in conditions:
        for commit_path, commit in commits:
            if condition_path != commit_path:
                pairs.append({"status": "unknown", "reason": "cross_file_pair",
                              "condition": [condition_path, condition.lineno],
                              "commit": [commit_path, commit.lineno]})
                continue
            proof = _pair_proof(contract, contract["admission_evidence"], condition_path,
                                parsed[condition_path], condition, commit)
            pairs.append({**proof, "condition": [condition_path, condition.lineno],
                          "commit": [commit_path, commit.lineno]})
    violations = [row for row in pairs if row.get("label") == "VIOLATION-PRESENT"]
    if violations:
        witness = violations[0]
        return {"status": "proved", "label": "VIOLATION-PRESENT",
                "proof_kind": witness["proof_kind"], "proof_scope": witness["proof_scope"],
                "candidate_pairs": len(pairs), "existential_witness": witness}
    conformant = [row for row in pairs if row.get("label") == "CONFORMANT-WITHIN-SCOPE"]
    if (not unresolved_conditions and not unresolved_commits and len(conformant) == len(pairs)):
        return {"status": "proved", "label": "CONFORMANT-WITHIN-SCOPE",
                "proof_kind": "all_cited_condition_commit_pairs_dominated",
                "proof_scope": {"scope_kind": "all_cited_pairs_in_single_agent_operation",
                                "pairs": [row["proof_scope"] for row in conformant]},
                "candidate_pairs": len(pairs)}
    reasons = Counter(row["reason"] for row in pairs if row["status"] != "proved")
    return {"status": "unknown", "reason": "candidate_proof_obligations_unresolved",
            "pair_reasons": dict(reasons), "candidate_pairs": len(pairs),
            "unresolved_conditions": unresolved_conditions, "unresolved_commits": unresolved_commits}


def verify(admission, structural):
    facts = {row["contract_id"]: row for row in structural["rows"]}
    if structural.get("execution_health") != "completed" or structural.get("errors"):
        raise ValueError("structural_input_incomplete")
    compilation_tasks = v1.read(v1.COMPILATION_SOURCE_PLAN)["tasks"]
    rows = []
    for contract in admission["contracts"]:
        base = {"contract_id": contract["contract_id"], "repository": contract["repository"],
                "framework": contract["framework"], "protocol_group": contract["protocol_group"],
                "parent_sample_ids": contract["parent_sample_ids"], "effect_stratum": contract.get("effect_stratum"),
                "agent_mediation": contract.get("agent_mediation"), "execution_health": "completed"}
        structural_row = facts.get(contract["contract_id"])
        if structural_row is None:
            raise ValueError("missing_structural_row:" + contract["contract_id"])
        if contract["protocol_group"] != "compiled_agent_bound_v4":
            rows.append({**base, "DEC_label": "EXCLUDED", "reason": "legacy_protocol_not_migrated_to_v4",
                         "mechanical_evidence": None})
        elif not structural_row.get("mechanically_eligible_for_path_analysis"):
            rows.append({**base, "DEC_label": "UNKNOWN", "reason": "structural_prerequisites_unproven",
                         "mechanical_evidence": None})
        else:
            try:
                proof = local_proof(contract, v1._source_inventory(contract, compilation_tasks))
                label = proof.get("label", "UNKNOWN")
                rows.append({**base, "DEC_label": label,
                             "reason": proof.get("proof_kind", proof.get("reason")),
                             "mechanical_evidence": proof})
            except (OSError, ValueError, KeyError) as exc:
                rows.append({**base, "DEC_label": "UNKNOWN", "reason": "mechanical_analysis_error:"
                             + type(exc).__name__ + ":" + str(exc), "mechanical_evidence": None,
                             "execution_health": "error"})
    counts, health = Counter(row["DEC_label"] for row in rows), Counter(row["execution_health"] for row in rows)
    return {"schema_version": "p0-ecological-witness-only-dec-2", "rows": rows,
            "counts": {"contracts": len(rows), **dict(counts)}, "execution_health": dict(health),
            "behavior_ground_truth_established": False,
            "claim_boundary": ("VP is released by an existential bounded source witness. CWS requires every "
                               "mechanically enumerated cited condition-commit pair to be dominated and no cited "
                               "condition or commit obligation unresolved. UNKNOWN is retained otherwise.")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--admission", type=Path, required=True)
    parser.add_argument("--structural", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    admission_path, structural_path, out = args.admission.resolve(), args.structural.resolve(), args.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT / "experiments"):
        parser.error("output must be new and under experiments")
    inputs = {str(path.relative_to(ROOT)): v1.sha(path) for path in
              (admission_path, structural_path, v1.COMPILATION_SOURCE_PLAN,
               Path(__file__).resolve(), ROOT / "tools/verify_p0_ecological_dec_witness.py")}
    admission = v1.read(admission_path)
    plan = {"schema_version": "p0-ecological-witness-only-dec-plan-2",
            "task_version": "ecological-dec-witness-2-1", "created_time_ns": time.time_ns(),
            "planned_contracts": len(admission["contracts"]), "inputs": inputs,
            "model_calls": 0, "network": "none", "sandbox": "read_only_frozen_sources",
            "label_authority": "existential_witness_or_universal_cited_pair_proof",
            "comparability_break_reason": "v1 could not enumerate broad evidence spans; v2 universally checks all mechanically located candidates",
            "claim_boundary": "No model consensus, raw line order, or negative run may grant VP/CWS."}
    out.mkdir(parents=True)
    v1.write_new(out / "RUN_PLAN.json", plan)
    result = verify(admission, v1.read(structural_path)); result["inputs"] = inputs
    v1.write_new(out / "RESULT.json", result)
    manifest = {"schema_version": "p0-ecological-witness-only-dec-manifest-2",
                "plan_sha256": v1.sha(out / "RUN_PLAN.json"), "result_sha256": v1.sha(out / "RESULT.json"),
                "execution_health": "completed" if result["execution_health"].get("error", 0) == 0 else "partial",
                "scientific_outcome": "strict_four_state_dispositions",
                "planned_contracts": plan["planned_contracts"], "completed_contracts": len(result["rows"]),
                "finished_time_ns": time.time_ns()}
    v1.write_new(out / "RUN_MANIFEST.json", manifest)
    print(json.dumps({"counts": result["counts"], "execution_health": result["execution_health"]}, sort_keys=True))


if __name__ == "__main__":
    main()
