"""Finalize n225 reviews and independently score reviewed source certificates."""
import argparse
import hashlib
import json
from pathlib import Path

from guardcontract.paths import project_root
from guardcontract.pipeline.reviewed_certificates import finalize


ROOT = project_root()
DIRECTORY = ROOT / "experiments/reviewed-certificates-n226"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_bytes())


def write_new(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def prepare():
    if DIRECTORY.exists():
        raise ValueError("reviewed226_existing_plan")
    review = ROOT / "experiments/certificate-review-n225"
    inputs = {}
    for path in review.rglob("*"):
        if path.is_file() and path.name != "EVALUATION_PLAN.json" and path.name != "SCORES.json":
            inputs[str(path.relative_to(ROOT))] = sha(path)
    for path in (Path(__file__), ROOT / "src/guardcontract/pipeline/reviewed_certificates.py"):
        inputs[str(path.relative_to(ROOT))] = sha(path)
    reference = ROOT / "experiments/layered-oracle-n192-i3/EVALUATION_FRAME.json"
    DIRECTORY.mkdir()
    write_new(DIRECTORY / "RUN_PLAN.json", {"schema_version": "reviewed-certificate-plan-1",
        "review_plan": str((review / "RUN_PLAN.json").relative_to(ROOT)),
        "review_result": str((review / "RESULT.json").relative_to(ROOT)),
        "review_manifest": str((review / "RUN_MANIFEST.json").relative_to(ROOT)),
        "inputs_sha256": inputs, "runtime_reference_read": False, "new_model_calls": 0,
        "goal_completion_proven": False})
    write_new(DIRECTORY / "EVALUATION_PLAN.json", {"schema_version": "reviewed-certificate-eval-1",
        "run_plan_sha256": sha(DIRECTORY / "RUN_PLAN.json"), "reference_path": str(reference.relative_to(ROOT)),
        "reference_sha256": sha(reference), "scorer_sha256": sha(Path(__file__)), "samples": 2,
        "holdout_eligible": False, "goal_completion_proven": False})
    print(json.dumps({"samples": 2, "new_model_calls": 0, "runtime_reference_read": False}))


def run():
    plan = read(DIRECTORY / "RUN_PLAN.json")
    for relative, expected in plan["inputs_sha256"].items():
        if sha(ROOT / relative) != expected:
            raise ValueError("reviewed226_input_drift:" + relative)
    review_plan, review_result, review_manifest = (read(ROOT / plan[key]) for key in
                                                   ("review_plan", "review_result", "review_manifest"))
    if sha(ROOT / plan["review_plan"]) != review_manifest["run_plan_sha256"] or sha(ROOT / plan["review_result"]) != review_manifest["result_sha256"]:
        raise ValueError("reviewed226_review_run_drift")
    critic_inputs = {cell["sample_id"]: read(ROOT / "experiments/certificate-review-n225/runs" /
                     (cell["sample_id"] + "-critic/ACTUAL_INPUT.json")) for cell in review_plan["cells"]}
    result = finalize(review_plan, review_result, critic_inputs)
    result.update(runtime_reference_read=False, new_model_calls=0)
    write_new(DIRECTORY / "RESULT.json", result)
    write_new(DIRECTORY / "RUN_MANIFEST.json", {"schema_version": "reviewed-certificate-run-1",
        "execution_health": "completed", "scientific_outcome": "unscored",
        "run_plan_sha256": sha(DIRECTORY / "RUN_PLAN.json"), "result_sha256": sha(DIRECTORY / "RESULT.json"),
        "goal_completion_proven": False})
    print(json.dumps({"accepted": result["accepted"], "model_calls_inherited": result["model_calls"], "new_model_calls": 0}))


def score():
    evaluation, result = read(DIRECTORY / "EVALUATION_PLAN.json"), read(DIRECTORY / "RESULT.json")
    if sha(DIRECTORY / "RUN_PLAN.json") != evaluation["run_plan_sha256"] or sha(ROOT / evaluation["reference_path"]) != evaluation["reference_sha256"] or sha(Path(__file__)) != evaluation["scorer_sha256"]:
        raise ValueError("reviewed226_evaluation_drift")
    gold = {row["sample_id"]: row["issue_present"] for row in read(ROOT / evaluation["reference_path"])["samples"]}
    if set(gold) != {row["sample_id"] for row in result["records"]}:
        raise ValueError("reviewed226_sample_inventory")
    tp = fp = fn = tn = accepted = 0
    rows = []
    for row in result["records"]:
        expected, prediction = gold[row["sample_id"]], row["issue_prediction"]
        tp += expected and prediction is True; fp += not expected and prediction is True
        fn += expected and prediction is not True; tn += not expected and prediction is False
        accepted += row["status"] == "accepted"
        rows.append({"sample_id": row["sample_id"], "reference": expected, "prediction": prediction,
                     "review_status": row["status"], "correct": prediction is not None and prediction == expected})
    ratio = lambda n, d: {"numerator": n, "denominator": d, "value": n / d if d else None}
    output = {"schema_version": "reviewed-certificate-score-1", "rows": rows,
        "issue_precision": ratio(tp, tp + fp), "issue_recall": ratio(tp, tp + fn),
        "issue_accuracy": ratio(tp + tn, len(rows)), "reviewed_certificate_coverage": ratio(accepted, len(rows)),
        "model_calls": result["model_calls"], "model_tokens": result["model_tokens"],
        "independent_runtime_verified": 0, "runtime_assembly_ready": False, "holdout_eligible": False,
        "scope": "static_plus_real_analyst_critic_plus_deterministic_evidence_on_two_exposed_development_controls",
        "goal_completion_proven": False}
    write_new(DIRECTORY / "SCORES.json", output)
    print(json.dumps({k: output[k] for k in ("issue_precision", "issue_recall", "issue_accuracy", "reviewed_certificate_coverage", "model_calls", "model_tokens")}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "run", "score"))
    {"prepare": prepare, "run": run, "score": score}[parser.parse_args().mode]()


if __name__ == "__main__":
    main()
