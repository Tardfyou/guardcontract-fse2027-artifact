"""Sliced-evidence analyst/critic trial over n214 source certificates."""
import argparse
import hashlib
import json
from pathlib import Path
import tempfile

from guardcontract.backends.recorded import RecordedTransport
from guardcontract.backends.replay import RecordedReplay, verify_inventory
from guardcontract.paths import project_root
from guardcontract.pipeline.review_execution import execute, score, write_new
from guardcontract.protocols.certificate_review_atomic import SYSTEM, decode, task


ROOT = project_root()
DIRECTORY = ROOT / "experiments/certificate-review-n225"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_bytes())


def freeze_inputs(mapping):
    result = {}
    for relative, expected in mapping.items():
        raw = (ROOT / relative).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("review217_input_drift:" + relative)
        result[relative] = raw
    return result


def prepare():
    if DIRECTORY.exists():
        raise ValueError("review217_existing_plan")
    source = ROOT / "experiments/path-certificates-n218"
    manifest, path_plan, path_result = (read(source / name) for name in ("RUN_MANIFEST.json", "RUN_PLAN.json", "RESULT.json"))
    if sha(source / "RUN_PLAN.json") != manifest["run_plan_sha256"] or sha(source / "RESULT.json") != manifest["result_sha256"]:
        raise ValueError("review217_certificate_drift")
    records = {row["sample_id"]: row for row in path_result["records"]}
    inputs, cells, evaluation = {}, [], []
    for path in source.iterdir():
        if path.is_file():
            inputs[str(path.relative_to(ROOT))] = sha(path)
    for cell in path_plan["cells"]:
        sid, certificate = cell["sample_id"], records[cell["sample_id"]]["certificate"]
        app, helper = (ROOT / cell["app_path"]).read_text(), (ROOT / cell["helper_path"]).read_text()
        payload, spec = task(certificate, app, helper, path_plan["sdk_contract"], repository_id=cell["repository_id"])
        directory = DIRECTORY / "inputs" / sid
        directory.mkdir(parents=True)
        write_new(directory / "ANALYST_INPUT.json", payload); write_new(directory / "ANALYST_SPEC.json", spec)
        analyst_input = str((directory / "ANALYST_INPUT.json").relative_to(ROOT))
        analyst_spec = str((directory / "ANALYST_SPEC.json").relative_to(ROOT))
        for relative in (analyst_input, analyst_spec, cell["app_path"], cell["helper_path"]):
            inputs[relative] = sha(ROOT / relative)
        cells.append({"sample_id": sid, "repository_id": cell["repository_id"], "app_path": cell["app_path"],
                      "helper_path": cell["helper_path"], "analyst_input": analyst_input,
                      "analyst_spec": analyst_spec, "certificate": certificate})
        expectations = {claim["claim_id"]: "contradicted" if claim["claim_id"].startswith("control-opposite-") else "supported"
                        for claim in payload["claims"]}
        evaluation.append({"sample_id": sid, "claim_expectations": expectations,
                           "claim_count": len(expectations), "analyst_input_id": payload["input_id"],
                           "certificate_unknown_state_claims": sum(" relation unknown " in " " + claim["statement"] + " " for claim in payload["claims"])})
    for path in (Path(__file__), ROOT / "src/guardcontract/pipeline/review_execution.py",
                 ROOT / "src/guardcontract/protocols/certificate_review_atomic.py",
                 ROOT / "src/guardcontract/protocols/certificate_review_v2.py",
                 ROOT / "src/guardcontract/protocols/certificate_review.py",
                 ROOT / "src/guardcontract/backends/recorded.py", ROOT / "src/guardcontract/backends/replay.py"):
        inputs[str(path.relative_to(ROOT))] = sha(path)
    plan = {"schema_version": "certificate-review-plan-6", "result_schema_version": "certificate-review-result-6",
        "cells": cells, "inputs_sha256": inputs,
        "sdk_contract": path_plan["sdk_contract"], "model": "DeepSeek-V4-Pro-0813", "max_tokens": 4096,
        "timeout_seconds": 90, "max_calls": 4, "max_total_tokens_stop_before_next_call": 64000,
        "retries": 0, "cache": "none", "study_use": "sliced_evidence_development_review_not_holdout",
        "goal_completion_proven": False}
    DIRECTORY.mkdir(exist_ok=True)
    write_new(DIRECTORY / "RUN_PLAN.json", plan)
    write_new(DIRECTORY / "EVALUATION_PLAN.json", {"schema_version": "certificate-review-eval-6",
        "run_plan_sha256": sha(DIRECTORY / "RUN_PLAN.json"), "cells": evaluation,
        "known_claim_verdicts": sum(v != "unknown" for row in evaluation for v in row["claim_expectations"].values()),
        "certificate_unknown_state_claims": sum(row["certificate_unknown_state_claims"] for row in evaluation),
        "review_verdict_expectation": "supported_for_all_complete_certificate_claims_including_supported_unknown_state",
        "negative_control_claims": sum(claim.startswith("control-opposite-") for row in evaluation for claim in row["claim_expectations"]),
        "scorer_sha256": sha(Path(__file__)), "scope": "development_certificate_review_not_issue_holdout"})
    print(json.dumps({"samples": len(cells), "claims": sum(row["claim_count"] for row in evaluation), "planned_calls": 4}))


def run(replay=False):
    plan = read(DIRECTORY / "RUN_PLAN.json")
    frozen = freeze_inputs(plan["inputs_sha256"])
    if replay:
        evaluation = read(DIRECTORY / "EVALUATION_PLAN.json")
        if sha(DIRECTORY / "RUN_PLAN.json") != evaluation["run_plan_sha256"] or sha(Path(__file__)) != evaluation["scorer_sha256"]:
            raise ValueError("review217_evaluation_drift")
        replay_type = type("Review217Replay", (RecordedReplay,), {"source_root": DIRECTORY / "runs"})
        with tempfile.TemporaryDirectory(prefix="guardcontract-review217-") as temporary:
            rebuilt = execute(plan, frozen, Path(temporary), "offline", root=ROOT, task_builder=task,
                              decoder=decode, system=SYSTEM, transport_factory=replay_type)
            if rebuilt != read(DIRECTORY / "RESULT.json"):
                raise ValueError("review217_replay_result")
            verify_inventory(DIRECTORY / "runs", rebuilt["records"])
        scored = {"schema_version": "certificate-review-score-6", **score(evaluation, rebuilt),
            "scope": "two_exposed_sliced_evidence_reviews_not_issue_holdout", "replay_verified": True,
            "actual_calls": rebuilt["actual_calls"], "actual_total_tokens": rebuilt["actual_total_tokens"],
            "summed_call_seconds": sum(call["duration_seconds"] for row in rebuilt["records"] for call in row["calls"])}
        write_new(DIRECTORY / "SCORES.json", scored)
        print(json.dumps({k: v for k, v in scored.items() if k != "rows"}))
        return
    key = (Path.home() / ".config/guardcontract/paratera.key").read_text().strip()
    result = execute(plan, frozen, DIRECTORY, key, root=ROOT, task_builder=task, decoder=decode,
                     system=SYSTEM, transport_factory=RecordedTransport)
    write_new(DIRECTORY / "RUN_MANIFEST.json", {"schema_version": "certificate-review-run-6",
        "execution_health": "partial" if any(row["execution_state"] in {"error", "missing"} for row in result["records"]) else "completed",
        "run_plan_sha256": sha(DIRECTORY / "RUN_PLAN.json"), "result_sha256": sha(DIRECTORY / "RESULT.json"),
        "files": {str(path.relative_to(DIRECTORY)): sha(path) for path in DIRECTORY.glob("runs/**/*") if path.is_file()},
        "goal_completion_proven": False})
    print(json.dumps({"calls": result["actual_calls"], "tokens": result["actual_total_tokens"],
                      "states": [row["execution_state"] for row in result["records"]]}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "run", "replay"))
    mode = parser.parse_args().mode
    prepare() if mode == "prepare" else run(replay=mode == "replay")


if __name__ == "__main__":
    main()
