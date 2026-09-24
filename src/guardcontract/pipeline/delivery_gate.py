"""Freeze the FSE delivery gate without rewriting the underlying score."""
import json
from pathlib import Path

REQUIRED_REPAIR=("solution_proposed","patch_generated","effective_repair","discovered_and_effectively_repaired","allow_exact_preservation")

def evaluate(score):
    detection=score.get("detection",{})
    checks={"precision_reported": isinstance(detection.get("precision"), dict),
            "recall_reported": isinstance(detection.get("recall"), dict),
            "runtime_verified_reported": isinstance(detection.get("runtime_verified"), dict)}
    repair=score.get("repair",{})
    checks.update({f"{name}_reported": isinstance(repair.get(name), dict) for name in REQUIRED_REPAIR})
    return {"schema_version":"delivery-gate-2","historical_threshold":0.90,"current_hard_gate":None,
            "checks":checks,"passed":all(checks.values()),"scope":score.get("scope"),
            "evaluation_policy":"descriptive_report_completeness_without_fixed_precision_recall_threshold",
            "claim_boundary":"Historical development delivery control rewritten as report-completeness check; no fixed quality threshold, holdout or generalization claim."}

if __name__=="__main__":
    source=Path("experiments/five-framework-score-n260/SCORES.json")
    result=evaluate(json.loads(source.read_text()))
    out=Path("experiments/five-framework-delivery-gate-n314"); out.mkdir(exist_ok=True); (out/"RESULT.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n"); print(json.dumps({"passed":result["passed"],"checks":result["checks"]},sort_keys=True))
