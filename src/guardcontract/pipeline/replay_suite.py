"""Verify configured typed-review runs through one offline execution path."""
import argparse
import hashlib
import importlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from guardcontract.backends.replay import RecordedReplay, verify_inventory
from guardcontract.paths import project_root
from guardcontract.pipeline.blind_typed_review import execute, score


def read(path):
    return json.loads(path.read_bytes())


def checked_files(root, inventory):
    result = {}
    for relative, expected in inventory.items():
        path = (root / relative).resolve()
        if not path.is_relative_to(root.resolve()):
            raise ValueError("replay_input_outside_root")
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("replay_input_drift:" + relative)
        result[relative] = raw
    return result


def verify(root, entry):
    directory = (root / entry["directory"]).resolve()
    if not directory.is_relative_to(root.resolve()):
        raise ValueError("replay_run_outside_root")
    adapter_name = entry["adapter"]
    if not adapter_name.startswith("guardcontract.pipeline."):
        raise ValueError("replay_adapter_namespace")
    adapter = importlib.import_module(adapter_name)
    plan = read(directory / "RUN_PLAN.json")
    evaluation = read(directory / "EVALUATION_PLAN.json")
    manifest = read(directory / "RUN_MANIFEST.json")
    expected = read(directory / "RESULT.json")
    saved_score = read(directory / "SCORES.json")
    plan_hash = hashlib.sha256((directory / "RUN_PLAN.json").read_bytes()).hexdigest()
    result_hash = hashlib.sha256((directory / "RESULT.json").read_bytes()).hexdigest()
    if plan_hash != evaluation["run_plan_sha256"] or plan_hash != manifest["run_plan_sha256"]:
        raise ValueError("replay_plan_identity")
    if result_hash != manifest["result_sha256"]:
        raise ValueError("replay_result_identity")
    if hashlib.sha256(Path(adapter.__file__).read_bytes()).hexdigest() != evaluation["scorer_sha256"]:
        raise ValueError("replay_scorer_identity")
    frozen = checked_files(root, plan["inputs_sha256"])
    checked_files(directory, manifest["files"])
    transport = type("SuiteReplay", (RecordedReplay,), {"source_root": directory / "runs"})
    with TemporaryDirectory(prefix="guardcontract-replay-suite-") as temporary:
        rebuilt = execute(plan, frozen, Path(temporary), "offline-no-credential",
                          system=adapter.SYSTEM, decoder=adapter.decode,
                          transport_factory=transport)
        if rebuilt != expected:
            raise ValueError("replay_result_mismatch")
    verify_inventory(directory / "runs", rebuilt["records"])
    scores = score(evaluation, rebuilt, adapter.invariants)
    if any(saved_score.get(key) != value for key, value in scores.items()):
        raise ValueError("replay_score_mismatch")
    return {"directory": entry["directory"], "result_equal": True, "scores_equal": True,
            "recorded_calls": rebuilt["actual_calls"], "new_model_calls": 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    root = project_root()
    config = read(args.config)
    if config.get("schema_version") != 1 or not config.get("runs"):
        raise ValueError("replay_suite_config")
    results = [verify(root, entry) for entry in config["runs"]]
    print(json.dumps({"runs": results, "new_model_calls": 0}, sort_keys=True))


if __name__ == "__main__":
    main()
