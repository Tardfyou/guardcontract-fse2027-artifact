"""Generate and independently execute a deferral repair for reviewed s001."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

from guardcontract.evidence.langchain_sdk_contract import enroll
from guardcontract.paths import project_root
from guardcontract.repair.langchain_deferral import propose
from guardcontract.repair.verification import compare


ROOT = project_root()
DIRECTORY = ROOT / "experiments/langchain-repair-n228"


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
        raise ValueError("repair228_existing_plan")
    runtime_dir = ROOT / "experiments/runtime-validated-certificates-n227"
    reviewed_dir = ROOT / "experiments/reviewed-certificates-n226"
    certificate_dir = ROOT / "experiments/path-certificates-n218"
    runtime = read(runtime_dir / "RESULT.json")
    reviewed = read(reviewed_dir / "RESULT.json")
    certificates = read(certificate_dir / "RESULT.json")
    selected = next(row for row in runtime["records"] if row["sample_id"] == "s001")
    reviewed_row = next(row for row in reviewed["records"] if row["sample_id"] == "s001")
    certificate = next(row for row in certificates["records"] if row["sample_id"] == "s001")["certificate"]
    if not selected["runtime_verified"] or not selected["assembly_ready"] or reviewed_row["status"] != "accepted" or certificate["issue_prediction"] is not True:
        raise ValueError("repair228_unverified_source_issue")
    source = ROOT / "experiments/registration-pipeline-n182/repositories/s001"
    app, helper = source / "app.py", source / "deferred_effects.py"
    sdk_dir = ROOT / "experiments/langchain-semantics-n197-i2"
    inputs = {str(path.relative_to(ROOT)): sha(path) for path in (
        runtime_dir / "RESULT.json", runtime_dir / "RUN_MANIFEST.json", reviewed_dir / "RESULT.json",
        reviewed_dir / "RUN_MANIFEST.json", certificate_dir / "RESULT.json", certificate_dir / "RUN_MANIFEST.json",
        app, helper, Path(__file__), ROOT / "src/guardcontract/repair/langchain_deferral.py",
        ROOT / "src/guardcontract/repair/verification.py", ROOT / "src/guardcontract/runtime/langchain_repair_runner.py")}
    for path in sdk_dir.iterdir():
        if path.is_file():
            inputs[str(path.relative_to(ROOT))] = sha(path)
    interpreter = ROOT / ".venv-langchain/bin/python"
    plan = {"schema_version": "langchain-repair-plan-1", "sample_id": "s001", "inputs_sha256": inputs,
        "app_path": str(app.relative_to(ROOT)), "helper_path": str(helper.relative_to(ROOT)),
        "certificate": certificate, "sdk_contract": enroll(sdk_dir),
        "interpreter": str(interpreter), "interpreter_sha256": sha(interpreter.resolve()),
        "strategy": "defer_selected_write_until_allow", "planned_solutions": 1, "planned_patches": 1,
        "verification_gates": ["original_issue_reproduced", "deny_zero_effect", "allow_observable_behavior_preserved",
            "allow_effect_preserved", "source_changed", "helper_unchanged", "network_enforced"],
        "allow_oracle": "exact equality of complete run_cell ALLOW return object",
        "deny_oracle": "effect_count=0, marker absent, expected DENY exception observed",
        "network": "kernel seccomp before SDK imports", "model_calls": 0,
        "scope": "one_owned_exposed_langchain_development_issue", "goal_completion_proven": False}
    DIRECTORY.mkdir()
    write_new(DIRECTORY / "RUN_PLAN.json", plan)
    print(json.dumps({"planned_solutions": 1, "planned_patches": 1, "model_calls": 0}))


def run():
    plan = read(DIRECTORY / "RUN_PLAN.json")
    for relative, expected in plan["inputs_sha256"].items():
        if sha(ROOT / relative) != expected:
            raise ValueError("repair228_input_drift:" + relative)
    if sha(Path(plan["interpreter"]).resolve()) != plan["interpreter_sha256"]:
        raise ValueError("repair228_interpreter_drift")
    app, helper = ROOT / plan["app_path"], ROOT / plan["helper_path"]
    proposal = propose(app.read_text(), helper.read_text(), plan["certificate"], plan["sdk_contract"])
    patched_dir = DIRECTORY / "patched"
    patched_dir.mkdir()
    (patched_dir / "app.py").write_text(proposal.pop("patched_source"))
    (patched_dir / "deferred_effects.py").write_bytes(helper.read_bytes())
    write_new(DIRECTORY / "PATCH.json", proposal)
    env = dict(os.environ, PYTHONPATH=str(ROOT / "src"), PYTHONDONTWRITEBYTECODE="1")
    commands = []
    started = time.monotonic()
    for label, app_path, helper_path in (("original", app, helper), ("patched", patched_dir / "app.py", patched_dir / "deferred_effects.py")):
        output = DIRECTORY / (label.upper() + "_RUNTIME.json")
        command = [plan["interpreter"], "-m", "guardcontract.runtime.langchain_repair_runner",
                   "--app", str(app_path), "--helper", str(helper_path), "--output", str(output)]
        completed = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, timeout=120)
        commands.append({"label": label, "argv": ["<INTERPRETER>", "-m", *command[3:]], "returncode": completed.returncode,
                         "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(),
                         "stderr_sha256": hashlib.sha256(completed.stderr).hexdigest()})
        if completed.returncode != 0 or not output.exists():
            raise ValueError("repair228_runtime_failure:" + label)
    verification = compare(read(DIRECTORY / "ORIGINAL_RUNTIME.json"), read(DIRECTORY / "PATCHED_RUNTIME.json"))
    result = {"schema_version": "langchain-repair-result-1", "sample_id": "s001",
        "proposed_solutions": 1, "generated_patches": 1, "effective_repairs": int(verification["gate_passed"]),
        "discovered_and_effectively_repaired": int(verification["gate_passed"]), "verification": verification,
        "commands": commands, "duration_seconds": round(time.monotonic() - started, 6), "model_calls": 0,
        "goal_completion_proven": False}
    write_new(DIRECTORY / "RESULT.json", result)
    write_new(DIRECTORY / "RUN_MANIFEST.json", {"schema_version": "langchain-repair-run-1",
        "execution_health": "completed", "scientific_outcome": "success" if verification["gate_passed"] else "failure",
        "run_plan_sha256": sha(DIRECTORY / "RUN_PLAN.json"), "result_sha256": sha(DIRECTORY / "RESULT.json"),
        "files": {str(path.relative_to(DIRECTORY)): sha(path) for path in DIRECTORY.rglob("*") if path.is_file()},
        "goal_completion_proven": False})
    print(json.dumps({"proposed_solutions": 1, "generated_patches": 1,
                      "effective_repairs": result["effective_repairs"], "gates": verification["gates"]}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "run"))
    {"prepare": prepare, "run": run}[parser.parse_args().mode]()


if __name__ == "__main__":
    main()
