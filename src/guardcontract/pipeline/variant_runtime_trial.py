"""Runtime validation of supported source variants and generated repairs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

from guardcontract.analysis.langchain_paths import analyze
from guardcontract.evidence.langchain_sdk_contract import enroll
from guardcontract.paths import project_root
from guardcontract.pipeline.source_variant_trial import mutate
from guardcontract.repair.langchain_deferral import propose
from guardcontract.repair.verification import compare


ROOT = project_root()
DIRECTORY = ROOT / "experiments/source-variant-runtime-n230"


def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path): return json.loads(Path(path).read_bytes())
def write_new(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as handle: json.dump(value, handle, indent=2, sort_keys=True); handle.write("\n")


def prepare():
    if DIRECTORY.exists(): raise ValueError("variant230_existing_plan")
    source = ROOT / "experiments/source-variants-n229"
    source_plan, source_result = read(source / "RUN_PLAN.json"), read(source / "RESULT.json")
    if not source_result["gate_passed"] or {r["case_id"] for r in source_result["rows"] if r["status"] == "supported"} != {
            c["case_id"] for c in source_plan["cells"] if c["expected_status"] == "supported"}:
        raise ValueError("variant230_source_matrix_not_ready")
    cells = [cell for cell in source_plan["cells"] if cell["expected_status"] == "supported"]
    inputs = {str(path.relative_to(ROOT)): sha(path) for path in (source / "RUN_PLAN.json", source / "RESULT.json",
        Path(__file__), ROOT / "src/guardcontract/pipeline/source_variant_trial.py", ROOT / "src/guardcontract/analysis/langchain_paths.py",
        ROOT / "src/guardcontract/repair/langchain_deferral.py", ROOT / "src/guardcontract/repair/verification.py",
        ROOT / "src/guardcontract/runtime/langchain_repair_runner.py")}
    for sid in {cell["base"] for cell in cells}:
        for name in ("app.py", "deferred_effects.py"):
            path = ROOT / "experiments/registration-pipeline-n182/repositories" / sid / name; inputs[str(path.relative_to(ROOT))] = sha(path)
    sdk = ROOT / "experiments/langchain-semantics-n197-i2"
    for path in sdk.iterdir():
        if path.is_file(): inputs[str(path.relative_to(ROOT))] = sha(path)
    interpreter = ROOT / ".venv-langchain/bin/python"
    DIRECTORY.mkdir()
    write_new(DIRECTORY / "RUN_PLAN.json", {"schema_version": "source-variant-runtime-plan-1", "cells": cells,
        "inputs_sha256": inputs, "sdk_contract": enroll(sdk), "interpreter": str(interpreter),
        "interpreter_sha256": sha(interpreter.resolve()), "planned_original_runs": len(cells),
        "planned_repair_runs": sum(cell["repair_expected"] for cell in cells),
        "allow_oracle": "exact full return-object equality before and after repair", "network": "kernel seccomp before SDK imports",
        "model_calls": 0, "goal_completion_proven": False})
    print(json.dumps({"supported_variants": len(cells), "repair_variants": sum(c["repair_expected"] for c in cells)}))


def runtime(plan, label, app, helper, helper_path, commands):
    output = DIRECTORY / "runtime" / (label + ".json")
    module = helper_path.removesuffix(".py").replace("/", ".")
    command = [plan["interpreter"], "-m", "guardcontract.runtime.langchain_repair_runner", "--app", str(app),
               "--helper", str(helper), "--helper-module", module, "--output", str(output)]
    completed = subprocess.run(command, cwd=ROOT, env=dict(os.environ, PYTHONPATH=str(ROOT / "src"), PYTHONDONTWRITEBYTECODE="1"),
                               capture_output=True, timeout=120)
    commands.append({"label": label, "returncode": completed.returncode,
                     "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(), "stderr_sha256": hashlib.sha256(completed.stderr).hexdigest()})
    if completed.returncode != 0 or not output.exists(): raise ValueError("variant230_runtime_failure:" + label)
    return read(output)


def run():
    plan = read(DIRECTORY / "RUN_PLAN.json")
    for relative, expected in plan["inputs_sha256"].items():
        if sha(ROOT / relative) != expected: raise ValueError("variant230_input_drift:" + relative)
    if sha(Path(plan["interpreter"]).resolve()) != plan["interpreter_sha256"]: raise ValueError("variant230_interpreter_drift")
    source = ROOT / "experiments/registration-pipeline-n182/repositories"
    rows, commands = [], []
    started = time.monotonic()
    for cell in plan["cells"]:
        app = (source / cell["base"] / "app.py").read_text(); helper = (source / cell["base"] / "deferred_effects.py").read_text()
        app, helper, helper_path = mutate(app, helper, cell["mutation"])
        case_dir = DIRECTORY / "cases" / cell["case_id"] / "original"
        app_path, helper_file = case_dir / "app.py", case_dir / helper_path
        app_path.parent.mkdir(parents=True); helper_file.parent.mkdir(parents=True, exist_ok=True)
        app_path.write_text(app); helper_file.write_text(helper)
        certificate = analyze(app, helper, plan["sdk_contract"], repository_id="variant/" + cell["case_id"], helper_path=helper_path)
        original = runtime(plan, cell["case_id"] + "-original", app_path, helper_file, helper_path, commands)
        observed_issue = original["cells"]["DENY"]["effect_count"] > 0 and original["cells"]["DENY"]["expected_exception_observed"]
        repair_result = None
        if cell["repair_expected"]:
            proposal = propose(app, helper, certificate, plan["sdk_contract"])
            patched = DIRECTORY / "cases" / cell["case_id"] / "patched"
            patched_app, patched_helper = patched / "app.py", patched / helper_path
            patched_app.parent.mkdir(parents=True); patched_helper.parent.mkdir(parents=True, exist_ok=True)
            patched_app.write_text(proposal["patched_source"]); patched_helper.write_text(helper)
            repaired = runtime(plan, cell["case_id"] + "-patched", patched_app, patched_helper, helper_path, commands)
            repair_result = compare(original, repaired)
        rows.append({"case_id": cell["case_id"], "expected_issue": cell["expected_issue"], "observed_issue": observed_issue,
            "detection_match": observed_issue == cell["expected_issue"], "repair_expected": cell["repair_expected"],
            "repair_verified": repair_result is not None and repair_result["gate_passed"],
            "allow_exact_match": repair_result["allow_exact_match"] if repair_result else None})
    gate = all(r["detection_match"] and r["repair_verified"] == r["repair_expected"] for r in rows)
    result = {"schema_version": "source-variant-runtime-result-1", "rows": rows, "gate_passed": gate,
        "detection_accuracy": {"numerator": sum(r["detection_match"] for r in rows), "denominator": len(rows)},
        "effective_repairs": {"numerator": sum(r["repair_verified"] for r in rows), "denominator": sum(r["repair_expected"] for r in rows)},
        "commands": commands, "duration_seconds": round(time.monotonic() - started, 6), "model_calls": 0,
        "goal_completion_proven": False}
    write_new(DIRECTORY / "RESULT.json", result)
    write_new(DIRECTORY / "RUN_MANIFEST.json", {"schema_version": "source-variant-runtime-run-1",
        "execution_health": "completed", "scientific_outcome": "success" if gate else "failure",
        "run_plan_sha256": sha(DIRECTORY / "RUN_PLAN.json"), "result_sha256": sha(DIRECTORY / "RESULT.json"),
        "goal_completion_proven": False})
    print(json.dumps({"gate_passed": gate, "detection_accuracy": result["detection_accuracy"],
                      "effective_repairs": result["effective_repairs"], "runtime_processes": len(commands)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("mode", choices=("prepare", "run"))
    {"prepare": prepare, "run": run}[parser.parse_args().mode]()


if __name__ == "__main__": main()
