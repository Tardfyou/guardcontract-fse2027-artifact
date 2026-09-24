"""Generate and score Google ADK source path certificates on owned controls."""
import argparse, hashlib, json
from pathlib import Path

from guardcontract.analysis.adk_paths import analyze
from guardcontract.evidence.adk_sdk_contract import enroll
from guardcontract.paths import project_root

ROOT = project_root(); DIRECTORY = ROOT / "experiments/adk-path-certificates-n233"
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path): return json.loads(Path(path).read_bytes())
def write_new(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as handle: json.dump(value, handle, indent=2, sort_keys=True); handle.write("\n")


def prepare():
    if DIRECTORY.exists(): raise ValueError("adk231_existing_plan")
    manifest_path = ROOT / "experiments/multiframework-control-n174-i2/CONSTRUCTION_MANIFEST.json"
    manifest = read(manifest_path); indexed = {row["sample_id"]: row for row in manifest["records"]}
    sdk_dir = ROOT / "experiments/google-adk-contract-n50-dev"
    cells, inputs = [], {str(manifest_path.relative_to(ROOT)): sha(manifest_path)}
    for sid in ("s005", "s008"):
        path = ROOT / indexed[sid]["path"]
        if sha(path) != indexed[sid]["sha256"]: raise ValueError("adk231_source_drift")
        inputs[str(path.relative_to(ROOT))] = sha(path)
        cells.append({"sample_id": sid, "repository_id": f"controlled/{sid}@{sha(path)}", "source_path": str(path.relative_to(ROOT))})
    for path in sdk_dir.iterdir():
        if path.is_file(): inputs[str(path.relative_to(ROOT))] = sha(path)
    for path in (Path(__file__), ROOT / "src/guardcontract/analysis/adk_paths.py", ROOT / "src/guardcontract/evidence/adk_sdk_contract.py"):
        inputs[str(path.relative_to(ROOT))] = sha(path)
    reference = ROOT / "experiments/control-oracle-calibration-n175/RESULT.json"
    DIRECTORY.mkdir(); write_new(DIRECTORY / "RUN_PLAN.json", {"schema_version": "adk-path-plan-2", "cells": cells,
        "inputs_sha256": inputs, "sdk_contract": enroll(sdk_dir), "runtime_reference_read": False, "model_calls": 0,
        "scope": "two_exposed_owned_google_adk_controls", "goal_completion_proven": False})
    write_new(DIRECTORY / "EVALUATION_PLAN.json", {"schema_version": "adk-path-eval-2",
        "run_plan_sha256": sha(DIRECTORY / "RUN_PLAN.json"), "reference_path": str(reference.relative_to(ROOT)),
        "reference_sha256": sha(reference), "scorer_sha256": sha(Path(__file__)), "samples": 2, "holdout_eligible": False})
    print(json.dumps({"samples": 2, "model_calls": 0, "runtime_reference_read": False}))


def run():
    plan = read(DIRECTORY / "RUN_PLAN.json")
    for relative, expected in plan["inputs_sha256"].items():
        if sha(ROOT / relative) != expected: raise ValueError("adk231_input_drift:" + relative)
    rows = [{"sample_id": cell["sample_id"], "certificate": analyze((ROOT / cell["source_path"]).read_text(),
             plan["sdk_contract"], repository_id=cell["repository_id"])} for cell in plan["cells"]]
    result = {"schema_version": "adk-path-result-2", "records": rows, "runtime_reference_read": False,
              "model_calls": 0, "goal_completion_proven": False}
    write_new(DIRECTORY / "RESULT.json", result)
    print(json.dumps({"states": [r["certificate"]["status"] for r in rows], "model_calls": 0}))


def score():
    evaluation, result = read(DIRECTORY / "EVALUATION_PLAN.json"), read(DIRECTORY / "RESULT.json")
    if sha(DIRECTORY / "RUN_PLAN.json") != evaluation["run_plan_sha256"] or sha(ROOT / evaluation["reference_path"]) != evaluation["reference_sha256"] or sha(Path(__file__)) != evaluation["scorer_sha256"]:
        raise ValueError("adk231_evaluation_drift")
    gold = {row["sample_id"]: row["oracle"]["issue_present"] for row in read(ROOT / evaluation["reference_path"])["records"]
            if row["sample_id"] in {"s005", "s008"}}
    tp=fp=fn=tn=0; rows=[]
    for record in result["records"]:
        target=gold[record["sample_id"]]; prediction=record["certificate"].get("issue_prediction")
        tp += target and prediction is True; fp += not target and prediction is True
        fn += target and prediction is not True; tn += not target and prediction is False
        rows.append({"sample_id":record["sample_id"],"reference":target,"prediction":prediction,"correct":prediction==target})
    ratio=lambda n,d:{"numerator":n,"denominator":d,"value":n/d if d else None}
    output={"schema_version":"adk-path-score-2","rows":rows,"issue_precision":ratio(tp,tp+fp),"issue_recall":ratio(tp,tp+fn),
        "issue_accuracy":ratio(tp+tn,len(rows)),"holdout_eligible":False,"model_calls":0,
        "scope":"two_exposed_google_adk_development_controls_not_full_pipeline","goal_completion_proven":False}
    write_new(DIRECTORY / "SCORES.json",output); print(json.dumps({k:output[k] for k in ("issue_precision","issue_recall","issue_accuracy")}))


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("mode",choices=("prepare","run","score"))
    {"prepare":prepare,"run":run,"score":score}[parser.parse_args().mode]()
if __name__=="__main__":main()
