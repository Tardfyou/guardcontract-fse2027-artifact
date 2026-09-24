"""Summarize strict DEC outcomes without mixing in broad risk candidates."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import math
from pathlib import Path
import time

ROOT = Path(__file__).resolve().parents[1]


def read(path): return json.loads(Path(path).read_bytes())
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def ratio(a, b): return a / b if b else None


def summarize(admission, structural, dec):
    contracts = {row["contract_id"]: row for row in admission["contracts"]}
    facts = {row["contract_id"]: row for row in structural["rows"]}
    rows = {row["contract_id"]: row for row in dec["rows"]}
    if set(contracts) != set(facts) or set(contracts) != set(rows):
        raise ValueError("strict_dec_inventory_mismatch")
    eligible_ids = {identifier for identifier, row in facts.items()
                    if row.get("mechanically_eligible_for_path_analysis")}
    eligible = [rows[identifier] for identifier in sorted(eligible_ids)]
    counts = Counter(row["DEC_label"] for row in eligible)
    v, c, u = (counts.get(label, 0) for label in
               ("VIOLATION-PRESENT", "CONFORMANT-WITHIN-SCOPE", "UNKNOWN"))
    denominator = v + c + u
    by_repo = defaultdict(list)
    for row in eligible:
        by_repo[row["repository"]].append(row["DEC_label"])
    repo_v = sum("VIOLATION-PRESENT" in labels for labels in by_repo.values())
    repo_possible = sum(any(label in {"VIOLATION-PRESENT", "UNKNOWN"} for label in labels)
                        for labels in by_repo.values())
    strata = {}
    for field in ("framework", "effect_stratum", "agent_mediation", "protocol_group"):
        table = defaultdict(Counter)
        for row in eligible:
            table[str(row.get(field))][row["DEC_label"]] += 1
        strata[field] = {key: dict(value) for key, value in sorted(table.items())}
    unknown_reasons = Counter(row["reason"] for row in eligible if row["DEC_label"] == "UNKNOWN")
    cells = []
    for framework, cell in strata["framework"].items():
        n = sum(cell.values()); decided = cell.get("VIOLATION-PRESENT", 0) + cell.get("CONFORMANT-WITHIN-SCOPE", 0)
        cells.append({"framework": framework, "n": n, "decision_coverage": ratio(decided, n)})
    eligible_cells = [row for row in cells if row["n"] >= 10]
    weakest = min(eligible_cells, key=lambda row: row["decision_coverage"]) if eligible_cells else None
    return {
        "schema_version": "p0-ecological-strict-dec-statistics-1",
        "main_estimand": "mechanically_eligible_compiled_v4_contracts",
        "counts": {"mechanically_eligible_contracts": denominator,
                   "VIOLATION-PRESENT": v, "CONFORMANT-WITHIN-SCOPE": c, "UNKNOWN": u,
                   "admission_contracts_total": len(contracts),
                   "structurally_not_eligible": len(contracts) - len(eligible_ids),
                   "legacy_excluded": sum(row["DEC_label"] == "EXCLUDED" for row in rows.values())},
        "contract_metrics": {
            "decision_coverage": ratio(v + c, denominator),
            "confirmed_lower_bound": ratio(v, denominator),
            "possible_positive_upper_bound": ratio(v + u, denominator),
            "decided_set_conditional_fraction": ratio(v, v + c),
            "undefined_metric_encoding": None,
        },
        "repository_metrics": {
            "eligible_repositories": len(by_repo),
            "repositories_with_VP": repo_v,
            "repositories_with_VP_or_UNKNOWN": repo_possible,
            "confirmed_lower_bound": ratio(repo_v, len(by_repo)),
            "possible_positive_upper_bound": ratio(repo_possible, len(by_repo)),
        },
        "strata": strata,
        "unknown_reasons": dict(unknown_reasons),
        "weakest_framework_cell": weakest,
        "uncertainty": {
            "repository_cluster_bootstrap": "not_estimable_without_any_decided_contract",
            "reason": "All mechanically eligible contracts remain UNKNOWN under the frozen witness-only proof gate."
        },
        "execution_health": dec["execution_health"],
        "claim_boundary": ("Strict Panel B only. Null decided-set metrics are not zero. Broad risk candidates "
                           "are reported separately and are not used as DEC labels or prevalence.")
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--admission", type=Path, required=True)
    parser.add_argument("--structural", type=Path, required=True)
    parser.add_argument("--dec", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    paths = [args.admission.resolve(), args.structural.resolve(), args.dec.resolve(), Path(__file__).resolve()]
    out = args.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT / "experiments"):
        parser.error("output must be new and under experiments")
    inputs = {str(path.relative_to(ROOT)): sha(path) for path in paths}
    out.mkdir(parents=True)
    plan = {"schema_version": "p0-ecological-strict-dec-statistics-plan-1",
            "task_version": "strict-dec-statistics-1-1", "created_time_ns": time.time_ns(),
            "inputs": inputs, "main_denominator": "mechanically_eligible_compiled_v4_contracts"}
    (out / "RUN_PLAN.json").write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n")
    result = summarize(read(paths[0]), read(paths[1]), read(paths[2])); result["inputs"] = inputs
    (out / "RESULT.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    manifest = {"schema_version": "p0-ecological-strict-dec-statistics-manifest-1",
                "plan_sha256": sha(out / "RUN_PLAN.json"), "result_sha256": sha(out / "RESULT.json"),
                "execution_health": "completed", "scientific_outcome": "strict_statistics_computed",
                "finished_time_ns": time.time_ns()}
    (out / "RUN_MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"counts": result["counts"], "metrics": result["contract_metrics"]}, sort_keys=True))


if __name__ == "__main__": main()
