"""Freeze prediction-blind bidirectional behavior confirmations on held-out matrix cells."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import time

ROOT = Path(__file__).resolve().parents[1]


def read(path): return json.loads(Path(path).read_bytes())
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def build(gt, split, dec):
    test_ids = set(split["test"]["samples"])
    rows = [row for row in gt["rows"] if row["sample_id"] in test_ids]
    if len(rows) != len(test_ids) or len({row["sample_id"] for row in rows}) != len(rows):
        raise ValueError("heldout_inventory")
    confirmed, ineligible = [], []
    for row in rows:
        allow, deny = row["cells"]["ALLOW"], row["cells"]["DENY"]
        reasons = []
        if allow["protected_commits"] < 1:
            reasons.append("allow_protected_operation_not_observed")
        if deny["protected_denials"] < 1:
            reasons.append("deny_on_protected_operation_not_observed")
        if row["verification_issues"]:
            reasons.append("behavior_verification_issue")
        if reasons:
            ineligible.append({"sample_id": row["sample_id"], "reasons": reasons,
                               "ground_truth": row["label"]})
            continue
        label = ("VIOLATION-PRESENT" if deny["protected_commits"] >= 1
                 else "CONFORMANT-WITHIN-SCOPE")
        expected = "VIOLATION-PRESENT" if row["label"] == "present" else "CONFORMANT-WITHIN-SCOPE"
        if label != expected:
            raise ValueError("behavior_label_mismatch:" + row["sample_id"])
        confirmed.append({"sample_id": row["sample_id"], "framework": row["framework"],
                          "family": row["family"], "binding": row["binding"],
                          "guard_position": row["guard_position"], "effect_kind": row["effect_kind"],
                          "variant": row["variant"], "DEC_behavior_label": label,
                          "deny_zero_effect": deny["protected_commits"] == 0,
                          "allow_non_vacuous": allow["protected_commits"] >= 1,
                          "deny_protected_commits": deny["protected_commits"],
                          "deny_protected_denials": deny["protected_denials"],
                          "allow_protected_commits": allow["protected_commits"],
                          "record_sha256": row["record_sha256"], "execution_health": "completed"})
    strict_real = [row for row in dec["rows"]
                   if row["protocol_group"] == "compiled_agent_bound_v4"
                   and row["DEC_label"] in {"VIOLATION-PRESENT", "CONFORMANT-WITHIN-SCOPE"}]
    counts = Counter(row["DEC_behavior_label"] for row in confirmed)
    return {"schema_version": "p0-bidirectional-confirmation-1",
            "heldout": {"planned": len(rows), "confirmed": len(confirmed),
                        "ineligible_for_bidirectional_confirmation": len(ineligible),
                        "counts": dict(counts), "rows": confirmed, "ineligible_rows": ineligible},
            "real_repository_queue": {"eligible_strict_contracts": len(strict_real),
                                      "status": "empty_no_strict_vp_or_cws" if not strict_real else "ready",
                                      "contract_ids": [row["contract_id"] for row in strict_real]},
            "prediction_content_read_for_behavior_labels": False,
            "test_feedback_used_for_tuning": False,
            "claim_boundary": ("Behavior confirmation for owned held-out programs only. The real-repository "
                               "queue is empty because strict source proof released no VP/CWS; controlled labels "
                               "must not be reported as real-repository prevalence.")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ground-truth", type=Path, required=True)
    parser.add_argument("--split", type=Path, required=True)
    parser.add_argument("--dec", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    paths = [args.ground_truth.resolve(), args.split.resolve(), args.dec.resolve(), Path(__file__).resolve()]
    out = args.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT / "experiments"):
        parser.error("output must be new and under experiments")
    inputs = {str(path.relative_to(ROOT)): sha(path) for path in paths}
    gt, split, dec = (read(path) for path in paths[:3])
    out.mkdir(parents=True)
    plan = {"schema_version": "p0-bidirectional-confirmation-plan-1",
            "task_version": "bidirectional-confirmation-1-1", "created_time_ns": time.time_ns(),
            "planned_heldout_samples": len(split["test"]["samples"]), "inputs": inputs,
            "oracle": "authenticated_marker_and_effect_records", "model_calls": 0}
    (out / "RUN_PLAN.json").write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n")
    result = build(gt, split, dec); result["inputs"] = inputs
    (out / "RESULT.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    manifest = {"schema_version": "p0-bidirectional-confirmation-manifest-1",
                "plan_sha256": sha(out / "RUN_PLAN.json"), "result_sha256": sha(out / "RESULT.json"),
                "execution_health": "completed", "scientific_outcome": "heldout_behavior_confirmed",
                "planned": plan["planned_heldout_samples"], "completed": len(split["test"]["samples"]),
                "finished_time_ns": time.time_ns()}
    (out / "RUN_MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"heldout": result["heldout"]["counts"],
                      "confirmed": result["heldout"]["confirmed"],
                      "ineligible": result["heldout"]["ineligible_for_bidirectional_confirmation"],
                      "real_queue": result["real_repository_queue"]["status"]}, sort_keys=True))


if __name__ == "__main__": main()
