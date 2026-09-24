"""Freeze and run independent runtime validation for n226 certificates."""
import hashlib
import json
from pathlib import Path

from guardcontract.evidence.runtime_validation import validate
from guardcontract.paths import project_root


ROOT = project_root()
DIRECTORY = ROOT / "experiments/runtime-validated-certificates-n227"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_bytes())


def write_new(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def main():
    if DIRECTORY.exists():
        raise ValueError("runtime227_existing_result")
    reviewed = ROOT / "experiments/reviewed-certificates-n226"
    reference_path = ROOT / "experiments/layered-oracle-n192-i3/EVALUATION_FRAME.json"
    reviewed_manifest, reference = read(reviewed / "RUN_MANIFEST.json"), read(reference_path)
    if sha(reviewed / "RUN_PLAN.json") != reviewed_manifest["run_plan_sha256"] or sha(reviewed / "RESULT.json") != reviewed_manifest["result_sha256"]:
        raise ValueError("runtime227_reviewed_drift")
    for relative, expected in reference["inputs_sha256"].items():
        if sha(ROOT / relative) != expected:
            raise ValueError("runtime227_reference_input_drift:" + relative)
    inputs = {str(path.relative_to(ROOT)): sha(path) for path in
        (reviewed / "RUN_PLAN.json", reviewed / "RESULT.json", reviewed / "RUN_MANIFEST.json", reference_path,
         Path(__file__), ROOT / "src/guardcontract/evidence/runtime_validation.py")}
    result = validate(read(reviewed / "RESULT.json"), reference)
    result.update(inputs_sha256=inputs, new_model_calls=0,
                  inherited_model_calls=read(reviewed / "RESULT.json")["model_calls"])
    DIRECTORY.mkdir()
    write_new(DIRECTORY / "RESULT.json", result)
    write_new(DIRECTORY / "RUN_MANIFEST.json", {"schema_version": "runtime-validation-run-1",
        "execution_health": "completed", "scientific_outcome": "success" if result["assembly_ready"] else "failure",
        "result_sha256": sha(DIRECTORY / "RESULT.json"), "inputs_sha256": inputs,
        "goal_completion_proven": False})
    print(json.dumps({"runtime_verified": result["runtime_verified"], "assembly_ready": result["assembly_ready"],
                      "new_model_calls": 0, "inherited_model_calls": result["inherited_model_calls"]}))


if __name__ == "__main__":
    main()
