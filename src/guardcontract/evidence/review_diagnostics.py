"""Post-hoc shape/verdict diagnostics for rejected certificate reviews."""
from collections import Counter
import hashlib
import json
from pathlib import Path

from guardcontract.backends.base import _extract_response_text


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def diagnose(directory):
    directory = Path(directory)
    plan, evaluation, manifest = (json.loads((directory / name).read_bytes()) for name in
                                  ("RUN_PLAN.json", "EVALUATION_PLAN.json", "RUN_MANIFEST.json"))
    if sha(directory / "RUN_PLAN.json") != evaluation["run_plan_sha256"] or sha(directory / "RUN_PLAN.json") != manifest["run_plan_sha256"]:
        raise ValueError("review_diagnostic_plan_drift")
    if sha(directory / "RESULT.json") != manifest["result_sha256"]:
        raise ValueError("review_diagnostic_result_drift")
    for relative, expected in manifest["files"].items():
        if sha(directory / relative) != expected:
            raise ValueError("review_diagnostic_artifact_drift")
    expected = {row["sample_id"]: row["claim_expectations"] for row in evaluation["cells"]}
    rows, counts = [], Counter()
    for sample in expected:
        result = json.loads((directory / "runs" / (sample + "-analyst") / "RESULT.json").read_bytes())
        if not result["calls"]:
            continue
        outer = json.loads((directory / "runs" / (sample + "-analyst") / "calls/call-000/RESPONSE.raw").read_bytes())
        value = json.loads(_extract_response_text(outer, "chat_completions"))
        claims = value.get("claims") if isinstance(value, dict) else None
        valid_inventory = (isinstance(claims, list) and all(isinstance(row, dict) for row in claims)
                           and {row.get("claim_id") for row in claims} == set(expected[sample])
                           and len(claims) == len(expected[sample]))
        if not valid_inventory:
            rows.append({"sample_id": sample, "raw_claim_inventory_valid": False})
            continue
        claim_rows = []
        for claim in claims:
            target, prediction = expected[sample][claim["claim_id"]], claim.get("verdict")
            known = target != "unknown"
            sources = claim.get("sources") if isinstance(claim.get("sources"), list) else []
            patterns = []
            for source in sources:
                if source in {"app", "helper", "sdk-contract"}:
                    patterns.append("whole_alias")
                elif isinstance(source, str) and source.startswith("sdk-contract:"):
                    patterns.append("unregistered_sdk_range")
                elif isinstance(source, str) and ":" in source:
                    patterns.append("source_range")
                else:
                    patterns.append("other")
            counts.update(patterns)
            counts["known_claim_slots"] += known
            counts["known_verdict_matches"] += known and prediction == target
            counts["unknown_claim_slots"] += not known
            counts["assertions_on_unknown_claims"] += not known and prediction != "unknown"
            claim_rows.append({"claim_id": claim["claim_id"], "reference": target, "raw_verdict": prediction,
                               "known_reference": known, "verdict_matches": known and prediction == target,
                               "citation_patterns": patterns})
        counts["raw_claim_inventories_valid"] += 1
        rows.append({"sample_id": sample, "raw_claim_inventory_valid": True, "claims": claim_rows,
                     "original_execution_state": result["execution_state"], "original_error": result.get("error_code")})
    return {"schema_version": "certificate-review-diagnostic-1", "records": rows, "counts": dict(counts),
            "original_acceptance_changed": False, "main_score_created": False, "new_model_calls": 0,
            "claim_boundary": "Raw rejected analyst verdict and citation-pattern diagnosis only; no valid review, critic result, or issue metric."}


def main():
    from guardcontract.paths import project_root
    source = project_root() / "experiments/certificate-review-n215"
    output = project_root() / "experiments/certificate-review-diagnostic-n216/DIAGNOSTIC.json"
    output.parent.mkdir(parents=True, exist_ok=False)
    with output.open("x") as handle:
        json.dump(diagnose(source), handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps({"output": str(output.relative_to(project_root())), "new_model_calls": 0}))


if __name__ == "__main__":
    main()
