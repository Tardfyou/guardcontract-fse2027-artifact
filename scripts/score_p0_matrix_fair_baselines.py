"""Score frozen held-out baselines and component ablations on one denominator."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import verify_p0_static_wiring as wiring_verifier


def read(path): return json.loads(Path(path).read_bytes())
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def ratio(a, b): return a / b if b else None


def metrics(rows):
    decided = [row for row in rows if row["prediction"] in {"present", "absent"}]
    positives = [row for row in rows if row["ground_truth"] == "present"]
    tp = sum(row["prediction"] == "present" and row["ground_truth"] == "present" for row in rows)
    fp = sum(row["prediction"] == "present" and row["ground_truth"] == "absent" for row in rows)
    fn = sum(row["prediction"] == "absent" and row["ground_truth"] == "present" for row in rows)
    tn = sum(row["prediction"] == "absent" and row["ground_truth"] == "absent" for row in rows)
    pa = sum(row["prediction"] == "unknown" and row["ground_truth"] == "present" for row in rows)
    errors = fp + fn
    return {"n": len(rows), "decided": len(decided), "unknown": len(rows) - len(decided),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn, "positive_abstention": pa,
            "precision": ratio(tp, tp + fp), "recall_all_positives": ratio(tp, len(positives)),
            "coverage": ratio(len(decided), len(rows)), "decided_accuracy": ratio(len(decided) - errors, len(decided)),
            "selective_risk": ratio(errors, len(decided))}


def clawaudit_style(queue_row):
    root = ROOT / "experiments/p0-clean-matrix-generate-round157-n1922/sources" / queue_row["root"]
    sources = {path.name: path.read_text(encoding="utf-8") for path in root.glob("*.py")
               if path.name != "matrix_effects.py"}
    wiring = wiring_verifier.analyze(sources)
    positions = {row["guard_position"] for row in wiring["orderings"] if row["same_file"]
                 and row["guard_position"] in {"before", "after", "racing_after"}}
    if positions == {"before"}: return "absent"
    if positions and positions <= {"after", "racing_after"}: return "present"
    return "unknown"


def score(queue, split, gt, static, llm, dec):
    ids = set(split["test"]["samples"])
    queue_rows = {row["sample_id"]: row for row in queue["rows"] if row["sample_id"] in ids}
    gold = {row["sample_id"]: row["label"] for row in gt["rows"] if row["sample_id"] in ids}
    static_rows = {row["sample_id"]: row["predicted"] for row in static["rows"]}
    llm_rows = {row["sample_id"]: row["answer"]["label"] for row in llm["rows"]
                if row.get("state") == "completed"}
    if not (set(queue_rows) == set(gold) == set(static_rows) == set(llm_rows) == ids):
        raise ValueError("heldout_baseline_inventory")
    if llm.get("prediction_blind") is not True or llm["counts"].get("errors"):
        raise ValueError("llm_baseline_incomplete_or_unblinded")
    arm_predictions = {name: {} for name in (
        "verdict_only", "static_only", "llm_only", "full_cross_validated",
        "ablation_no_probe", "ablation_no_binding", "ablation_no_ordering_dominance",
        "ablation_no_cross_review_abstention", "clawaudit_style_adapted")}
    for sid in sorted(ids):
        row, s, l = queue_rows[sid], static_rows[sid], llm_rows[sid]
        arm_predictions["verdict_only"][sid] = "absent"
        arm_predictions["static_only"][sid] = s
        arm_predictions["llm_only"][sid] = l
        arm_predictions["full_cross_validated"][sid] = s if s == l and s in {"present", "absent"} else "unknown"
        arm_predictions["ablation_no_probe"][sid] = l
        arm_predictions["ablation_no_cross_review_abstention"][sid] = l
        arm_predictions["ablation_no_binding"][sid] = "present" if row["position"] == "after" else "absent"
        arm_predictions["ablation_no_ordering_dominance"][sid] = (
            "present" if row["binding"] == "scope_match" else "absent")
        arm_predictions["clawaudit_style_adapted"][sid] = clawaudit_style(row)
    arms, all_rows = {}, []
    for arm, predictions in arm_predictions.items():
        rows = [{"sample_id": sid, "framework": queue_rows[sid]["framework"],
                 "binding": queue_rows[sid]["binding"], "guard_position": queue_rows[sid]["position"],
                 "prediction": predictions[sid], "ground_truth": gold[sid]} for sid in sorted(ids)]
        arms[arm] = metrics(rows); all_rows.extend({**row, "arm": arm} for row in rows)
    real_decided = [row for row in dec["rows"] if row["protocol_group"] == "compiled_agent_bound_v4"
                    and row["DEC_label"] in {"VIOLATION-PRESENT", "CONFORMANT-WITHIN-SCOPE"}]
    return {"schema_version": "p0-heldout-fair-baselines-and-ablations-1",
            "heldout_samples": len(ids), "arms": arms, "rows": all_rows,
            "llm_cost": llm["budget"],
            "real_contract_baseline": {"strict_labeled_contracts": len(real_decided),
                                       "status": "not_estimable_without_strict_labels" if not real_decided else "ready"},
            "arm_definitions": {
                "ablation_no_probe": "LLM hypothesis without deterministic static verification; equals LLM-only by construction.",
                "ablation_no_binding": "Uses declared guard position but ignores request/resource binding.",
                "ablation_no_ordering_dominance": "Uses binding only and ignores whether DENY dominates commit.",
                "ablation_no_cross_review_abstention": "Accepts the single LLM arm without cross-check or abstention; equals LLM-only.",
                "full_cross_validated": "Decides only when frozen static and LLM arms agree.",
                "clawaudit_style_adapted": "Same-file syntactic guard/effect ordering only; unknown otherwise."
            },
            "test_feedback_used_for_tuning": False,
            "claim_boundary": ("Held-out owned-program comparison on a shared denominator and evidence budget. "
                               "The unavailable real-contract comparison is reported as not estimable, not zero.")}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("queue","split","ground-truth","static","llm","dec","out"):
        parser.add_argument("--"+name,type=Path,required=True)
    args=parser.parse_args();out=args.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT/"experiments"):parser.error("output must be new under experiments")
    paths=[args.queue.resolve(),args.split.resolve(),args.ground_truth.resolve(),args.static.resolve(),
           args.llm.resolve(),args.dec.resolve(),Path(__file__).resolve(),ROOT/"tools/verify_p0_static_wiring.py"]
    inputs={str(path.relative_to(ROOT)):sha(path) for path in paths};out.mkdir(parents=True)
    plan={"schema_version":"p0-heldout-fair-baselines-plan-1","task_version":"fair-baselines-1-1",
          "created_time_ns":time.time_ns(),"inputs":inputs,"side":"test","test_feedback_for_tuning":False}
    (out/"RUN_PLAN.json").write_text(json.dumps(plan,indent=2,sort_keys=True)+"\n")
    result=score(*(read(path) for path in paths[:6]));result["inputs"]=inputs
    (out/"RESULT.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    manifest={"schema_version":"p0-heldout-fair-baselines-manifest-1","plan_sha256":sha(out/"RUN_PLAN.json"),
              "result_sha256":sha(out/"RESULT.json"),"execution_health":"completed",
              "scientific_outcome":"heldout_baselines_scored","planned":result["heldout_samples"],
              "completed":result["heldout_samples"],"finished_time_ns":time.time_ns()}
    (out/"RUN_MANIFEST.json").write_text(json.dumps(manifest,indent=2,sort_keys=True)+"\n")
    print(json.dumps(result["arms"],sort_keys=True))


if __name__=="__main__":main()
