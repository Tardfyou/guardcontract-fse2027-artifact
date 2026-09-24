"""Frozen source-variant stress matrix for path detection and repair proposal."""
import argparse
import hashlib
import json
from pathlib import Path

from guardcontract.analysis.langchain_paths import analyze
from guardcontract.evidence.langchain_sdk_contract import enroll
from guardcontract.paths import project_root
from guardcontract.repair.langchain_deferral import propose


ROOT = project_root()
DIRECTORY = ROOT / "experiments/source-variants-n229"
CASES = (
    ("direct-positive", "s001", "identity", "supported", True, True),
    ("deferred-negative", "s009", "identity", "supported", False, False),
    ("renamed-class-parameters", "s001", "rename", "supported", True, True),
    ("moved-helper", "s001", "move_helper", "supported", True, True),
    ("modified-request", "s001", "modify_request", "unknown", None, False),
    ("conditional-handler", "s001", "conditional_handler", "unknown", None, False),
    ("additional-write", "s001", "extra_write", "unknown", None, False),
    ("additional-ledger-operation", "s001", "extra_ledger", "unknown", None, False),
    ("multiple-middleware", "s001", "multiple_middleware", "unknown", None, False),
    ("changed-request-payload", "s001", "wrong_payload", "unknown", None, False),
    ("broken-abort", "s009", "broken_abort", "unknown", None, False),
    ("swapped-commit-abort", "s009", "swap_commit_abort", "unknown", None, False),
    ("exception-after-handler", "s001", "raise_after_handler", "unknown", None, False),
    ("multiple-tool-requests", "s001", "multiple_requests", "unknown", None, False),
)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def mutate(app, helper, name):
    helper_path = "deferred_effects.py"
    if name == "identity":
        pass
    elif name == "rename":
        app = app.replace("ContractMiddleware", "PolicyLayer").replace(
            "def wrap_tool_call(self, request: Any, handler: Any)", "def wrap_tool_call(self, req: Any, proceed: Any)").replace(
            "request.tool_call", "req.tool_call").replace("handler(request)", "proceed(req)")
    elif name == "move_helper":
        app = app.replace("from deferred_effects import", "from support.ledger import")
        helper_path = "support/ledger.py"
    elif name == "modify_request":
        app = app.replace("return handler(request)", "return handler(request.override(state={}))")
    elif name == "conditional_handler":
        app = app.replace("        return handler(request)\n", "        if self.verdict == 'ALLOW':\n            return handler(request)\n        return ToolMessage(content='skip', tool_call_id=request.tool_call['id'])\n")
    elif name == "extra_write":
        app = app.replace("        marker.write_text(payload, encoding='utf-8')\n", "        marker.write_text(payload, encoding='utf-8')\n        marker.write_text(payload, encoding='utf-8')\n")
    elif name == "extra_ledger":
        app = app.replace("    model = DeterministicToolModel()", "    ledger.commit()\n    model = DeterministicToolModel()")
    elif name == "multiple_middleware":
        app = app.replace("middleware=[middleware]", "middleware=[middleware, middleware]")
    elif name == "wrong_payload":
        app = app.replace("'args': {'payload': PAYLOAD}", "'args': {'other': PAYLOAD}")
    elif name == "broken_abort":
        helper = helper.replace("        transaction.pending_effects.clear()\n", "        pass\n")
    elif name == "swap_commit_abort":
        app = app.replace("self.ledger.commit()", "self.ledger.__TEMP__()").replace(
            "self.ledger.abort()", "self.ledger.commit()").replace("self.ledger.__TEMP__()", "self.ledger.abort()")
    elif name == "raise_after_handler":
        app = app.replace("        return handler(request)\n", "        result = handler(request)\n        raise RuntimeError('after handler')\n")
    elif name == "multiple_requests":
        original = "tool_calls=[{'name': TOOL_NAME, 'args': {'payload': PAYLOAD}, 'id': 'guardcontract-call-1', 'type': 'tool_call'}]"
        second = "{'name': TOOL_NAME, 'args': {'payload': PAYLOAD}, 'id': 'guardcontract-call-2', 'type': 'tool_call'}"
        app = app.replace(original, original[:-1] + ", " + second + "]")
    else:
        raise ValueError("variant229_unknown_mutation")
    return app, helper, helper_path


def read(path):
    return json.loads(Path(path).read_bytes())


def write_new(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def prepare():
    if DIRECTORY.exists():
        raise ValueError("variant229_existing_plan")
    source = ROOT / "experiments/registration-pipeline-n182/repositories"
    sdk_dir = ROOT / "experiments/langchain-semantics-n197-i2"
    inputs = {}
    for sid in ("s001", "s009"):
        for name in ("app.py", "deferred_effects.py"):
            path = source / sid / name; inputs[str(path.relative_to(ROOT))] = sha(path)
    for path in sdk_dir.iterdir():
        if path.is_file(): inputs[str(path.relative_to(ROOT))] = sha(path)
    for path in (Path(__file__), ROOT / "src/guardcontract/analysis/langchain_paths.py",
                 ROOT / "src/guardcontract/repair/langchain_deferral.py", ROOT / "src/guardcontract/evidence/langchain_sdk_contract.py"):
        inputs[str(path.relative_to(ROOT))] = sha(path)
    cells = [{"case_id": case, "base": base, "mutation": mutation, "expected_status": status,
              "expected_issue": issue, "repair_expected": repair} for case, base, mutation, status, issue, repair in CASES]
    DIRECTORY.mkdir()
    write_new(DIRECTORY / "RUN_PLAN.json", {"schema_version": "source-variant-plan-1", "cells": cells,
        "inputs_sha256": inputs, "sdk_contract": enroll(sdk_dir), "model_calls": 0,
        "gate": "all status/issue expectations and all three positive repair proposals match",
        "scope": "mechanism_stress_on_mutations_of_two_exposed_owned_sources", "goal_completion_proven": False})
    print(json.dumps({"cells": len(cells), "supported": sum(c["expected_status"] == "supported" for c in cells),
                      "unknown": sum(c["expected_status"] == "unknown" for c in cells), "repair_expected": sum(c["repair_expected"] for c in cells)}))


def run():
    plan = read(DIRECTORY / "RUN_PLAN.json")
    for relative, expected in plan["inputs_sha256"].items():
        if sha(ROOT / relative) != expected: raise ValueError("variant229_input_drift:" + relative)
    source = ROOT / "experiments/registration-pipeline-n182/repositories"
    rows = []
    for cell in plan["cells"]:
        app = (source / cell["base"] / "app.py").read_text(); helper = (source / cell["base"] / "deferred_effects.py").read_text()
        app, helper, helper_path = mutate(app, helper, cell["mutation"])
        certificate = analyze(app, helper, plan["sdk_contract"], repository_id="variant/" + cell["case_id"], helper_path=helper_path)
        repair = None
        if certificate.get("status") == "supported" and certificate.get("issue_prediction") is True:
            repair = propose(app, helper, certificate, plan["sdk_contract"])
        rows.append({"case_id": cell["case_id"], "status": certificate["status"], "issue_prediction": certificate.get("issue_prediction"),
                     "gaps": certificate.get("gaps"), "repair_generated": repair is not None,
                     "repair_static_effective": repair is not None and repair["static_postcondition"]["issue_prediction"] is False})
    passed = all(row["status"] == cell["expected_status"] and row["issue_prediction"] == cell["expected_issue"]
                 and row["repair_generated"] == cell["repair_expected"] and row["repair_static_effective"] == cell["repair_expected"]
                 for row, cell in zip(rows, plan["cells"], strict=True))
    result = {"schema_version": "source-variant-result-1", "rows": rows, "gate_passed": passed,
        "counts": {"planned": len(rows), "supported": sum(r["status"] == "supported" for r in rows),
                   "unknown": sum(r["status"] == "unknown" for r in rows),
                   "repair_generated": sum(r["repair_generated"] for r in rows),
                   "repair_static_effective": sum(r["repair_static_effective"] for r in rows)},
        "model_calls": 0, "runtime_verifications": 0, "goal_completion_proven": False}
    write_new(DIRECTORY / "RESULT.json", result)
    print(json.dumps({"gate_passed": passed, **result["counts"]}))


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("mode", choices=("prepare", "run"))
    {"prepare": prepare, "run": run}[parser.parse_args().mode]()


if __name__ == "__main__": main()
