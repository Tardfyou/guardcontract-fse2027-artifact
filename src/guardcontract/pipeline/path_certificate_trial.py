"""Freeze, run and score deterministic source path certificates on owned controls."""
import argparse
import hashlib
import json
from pathlib import Path

from guardcontract.analysis.langchain_paths import analyze
from guardcontract.evidence.langchain_sdk_contract import enroll
from guardcontract.paths import project_root


ROOT = project_root()
DIRECTORY = ROOT / "experiments/path-certificates-n218"
SAMPLES = ("s001", "s009")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_new(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def read(path):
    return json.loads(Path(path).read_bytes())


def registered_sources():
    manifest_path = ROOT / "experiments/registration-pipeline-n182/RUN_MANIFEST.json"
    manifest = read(manifest_path)
    rows = {row["path"]: row["sha256"] for row in manifest["files"] if row["role"] == "dataset"}
    return manifest_path, rows


def prepare():
    if DIRECTORY.exists():
        raise ValueError("path213_existing_plan")
    manifest_path, registered = registered_sources()
    sdk_dir = ROOT / "experiments/langchain-semantics-n197-i2"
    sdk = enroll(sdk_dir)
    cells, inputs = [], {str(manifest_path.relative_to(ROOT)): sha(manifest_path)}
    for sid in SAMPLES:
        source_dir = ROOT / "experiments/registration-pipeline-n182/repositories" / sid
        app, helper = source_dir / "app.py", source_dir / "deferred_effects.py"
        for path in (app, helper):
            relative = str(path.relative_to(ROOT))
            if registered.get(relative) != sha(path):
                raise ValueError("path213_source_not_authenticated:" + relative)
            inputs[relative] = sha(path)
        repository_id = f"controlled/{sid}@{sha(app)}"
        cells.append({"sample_id": sid, "repository_id": repository_id,
                      "app_path": str(app.relative_to(ROOT)), "helper_path": str(helper.relative_to(ROOT))})
    for path in sdk_dir.iterdir():
        if path.is_file():
            inputs[str(path.relative_to(ROOT))] = sha(path)
    for path in (Path(__file__), ROOT / "src/guardcontract/analysis/langchain_paths.py",
                 ROOT / "src/guardcontract/evidence/langchain_sdk_contract.py",
                 ROOT / "src/guardcontract/analysis/callable_bindings.py",
                 ROOT / "src/guardcontract/discovery/router.py"):
        inputs[str(path.relative_to(ROOT))] = sha(path)
    plan = {"schema_version": "path-certificate-plan-3", "cells": cells, "inputs_sha256": inputs,
            "sdk_contract": sdk, "model_calls": 0, "runtime_trace_read": False,
            "scope": "two_exposed_owned_langchain_controls_source_prediction", "goal_completion_proven": False}
    reference_path = ROOT / "experiments/layered-oracle-n192-i3/EVALUATION_FRAME.json"
    DIRECTORY.mkdir()
    write_new(DIRECTORY / "RUN_PLAN.json", plan)
    write_new(DIRECTORY / "EVALUATION_PLAN.json", {"schema_version": "path-certificate-eval-3",
        "run_plan_sha256": sha(DIRECTORY / "RUN_PLAN.json"), "reference_path": str(reference_path.relative_to(ROOT)),
        "reference_sha256": sha(reference_path), "scorer_code_sha256": sha(Path(__file__)),
        "planned_samples": 2, "planned_sites": 4, "known_memberships": 3, "unknown_memberships": 1,
        "known_path_booleans": 8, "holdout_eligible": False,
        "scope": "development_evaluation_only_not_model_input", "goal_completion_proven": False})
    print(json.dumps({"samples": 2, "model_calls": 0, "runtime_trace_read": False}))


def run():
    if (DIRECTORY / "RESULT.json").exists():
        raise ValueError("path213_existing_result")
    plan = read(DIRECTORY / "RUN_PLAN.json")
    for relative, expected in plan["inputs_sha256"].items():
        if sha(ROOT / relative) != expected:
            raise ValueError("path213_input_drift:" + relative)
    records = []
    for cell in plan["cells"]:
        result = analyze((ROOT / cell["app_path"]).read_text(), (ROOT / cell["helper_path"]).read_text(),
                         plan["sdk_contract"], repository_id=cell["repository_id"])
        records.append({"sample_id": cell["sample_id"], "repository_id": cell["repository_id"], "certificate": result})
    output = {"schema_version": "path-certificate-result-3", "records": records,
              "model_calls": 0, "runtime_trace_read": False, "assembly_invoked": False,
              "goal_completion_proven": False}
    write_new(DIRECTORY / "RESULT.json", output)
    write_new(DIRECTORY / "RUN_MANIFEST.json", {"schema_version": "path-certificate-run-3",
        "execution_health": "completed", "scientific_outcome": "unscored",
        "run_plan_sha256": sha(DIRECTORY / "RUN_PLAN.json"), "result_sha256": sha(DIRECTORY / "RESULT.json"),
        "model_calls": 0, "goal_completion_proven": False})
    print(json.dumps({"states": [r["certificate"]["status"] for r in records], "model_calls": 0}))


def ratio(n, d):
    return {"numerator": n, "denominator": d, "value": n / d if d else None}


def score():
    if (DIRECTORY / "SCORES.json").exists():
        raise ValueError("path213_existing_scores")
    evaluation, plan, result = (read(DIRECTORY / name) for name in ("EVALUATION_PLAN.json", "RUN_PLAN.json", "RESULT.json"))
    if (sha(DIRECTORY / "RUN_PLAN.json") != evaluation["run_plan_sha256"]
            or sha(ROOT / evaluation["reference_path"]) != evaluation["reference_sha256"]
            or sha(Path(__file__)) != evaluation["scorer_code_sha256"]):
        raise ValueError("path213_evaluation_drift")
    reference = read(ROOT / evaluation["reference_path"])
    gold = {row["sample_id"]: row for row in reference["samples"]}
    predictions = {row["sample_id"]: row for row in result["records"]}
    if set(gold) != set(predictions) or set(predictions) != set(SAMPLES):
        raise ValueError("path213_sample_inventory")
    sample_rows, site_rows = [], []
    tp = fp = fn = tn = known_sites = correct_sites = known_paths = correct_paths = asserted_unknown = 0
    for sid in SAMPLES:
        expected, record = gold[sid], predictions[sid]
        certificate = record["certificate"]
        if record["repository_id"] != next(c["repository_id"] for c in plan["cells"] if c["sample_id"] == sid):
            raise ValueError("path213_repository_identity")
        predicted_issue = certificate["issue_prediction"] if certificate["status"] == "supported" else None
        target = expected["issue_present"]
        tp += predicted_issue is True and target is True
        fp += predicted_issue is True and target is False
        fn += predicted_issue is not True and target is True
        tn += predicted_issue is False and target is False
        sample_rows.append({"sample_id": sid, "reference_issue": target, "prediction": predicted_issue,
                            "correct": predicted_issue is not None and predicted_issue == target,
                            "status": certificate["status"]})
        expected_sites = {row["sink_site"]: row for row in expected["realizations"]}
        predicted_sites = {row["sink_site"]: row for row in certificate.get("sites", [])}
        if set(expected_sites) != set(predicted_sites):
            raise ValueError("path213_site_inventory")
        for site_id, ref in expected_sites.items():
            pred = predicted_sites[site_id]
            relation_known = ref["resource_relation"] != "unknown"
            relation_correct = relation_known and pred["relation"] == ref["resource_relation"]
            known_sites += relation_known
            correct_sites += relation_correct
            asserted_unknown += not relation_known and pred["relation"] != "unknown"
            comparisons = {}
            for decision in ("allow", "deny"):
                key = decision + "_effect_occurs"
                expected_value, predicted_value = ref[key], pred[key]
                is_known = expected_value is not None
                is_correct = is_known and predicted_value == expected_value
                known_paths += is_known
                correct_paths += is_correct
                comparisons[decision] = {"reference": expected_value, "prediction": predicted_value,
                                         "known_reference": is_known, "correct": is_correct}
            site_rows.append({"sample_id": sid, "sink_site": site_id,
                "reference_relation": ref["resource_relation"], "prediction_relation": pred["relation"],
                "relation_correct": relation_correct, "paths": comparisons})
    output = {"schema_version": "path-certificate-score-3", "sample_rows": sample_rows, "site_rows": site_rows,
        "issue_precision": ratio(tp, tp + fp), "issue_recall": ratio(tp, tp + fn), "issue_accuracy": ratio(tp + tn, len(SAMPLES)),
        "known_membership_accuracy": ratio(correct_sites, known_sites), "known_path_boolean_accuracy": ratio(correct_paths, known_paths),
        "assertions_on_unknown_membership": asserted_unknown, "supported_certificate_coverage": ratio(sum(r["status"] == "supported" for r in sample_rows), len(SAMPLES)),
        "holdout_eligible": False, "model_calls": 0, "assembly_ready": False,
        "scope": "two_exposed_development_source_certificates_not_full_pipeline_or_holdout", "goal_completion_proven": False}
    write_new(DIRECTORY / "SCORES.json", output)
    print(json.dumps({k: output[k] for k in ("issue_precision", "issue_recall", "issue_accuracy", "known_membership_accuracy", "known_path_boolean_accuracy", "supported_certificate_coverage")}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "run", "score"))
    {"prepare": prepare, "run": run, "score": score}[parser.parse_args().mode]()


if __name__ == "__main__":
    main()
