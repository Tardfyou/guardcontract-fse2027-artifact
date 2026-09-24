"""Prepare, run, replay, and score analyst/critic certificate reviews."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import tempfile

from guardcontract.backends.provider_endpoint import CHAT_COMPLETIONS_ENDPOINT, REQUIRED_THINKING
from guardcontract.backends.base import BackendError, _extract_response_text
from guardcontract.backends.recorded import RecordedTransport
from guardcontract.backends.replay import RecordedReplay, verify_inventory
from guardcontract.paths import project_root
from guardcontract.protocols.certificate_review import SYSTEM, decode, task


ROOT = project_root()
DIRECTORY = ROOT / "experiments/certificate-review-n215"
MODEL = "DeepSeek-V4-Pro-0813"


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
        raise ValueError("review215_existing_plan")
    source = ROOT / "experiments/path-certificates-n214"
    source_manifest, path_result = read(source / "RUN_MANIFEST.json"), read(source / "RESULT.json")
    if sha(source / "RUN_PLAN.json") != source_manifest["run_plan_sha256"] or sha(source / "RESULT.json") != source_manifest["result_sha256"]:
        raise ValueError("review215_path_certificate_drift")
    path_plan = read(source / "RUN_PLAN.json")
    cells, inputs, evaluation = [], {}, []
    for path in (source / "RUN_PLAN.json", source / "RESULT.json", source / "RUN_MANIFEST.json", source / "SCORES.json"):
        inputs[str(path.relative_to(ROOT))] = sha(path)
    by_sample = {row["sample_id"]: row for row in path_result["records"]}
    for source_cell in path_plan["cells"]:
        sid = source_cell["sample_id"]
        app = (ROOT / source_cell["app_path"]).read_text()
        helper = (ROOT / source_cell["helper_path"]).read_text()
        certificate = by_sample[sid]["certificate"]
        payload, spec = task(certificate, app, helper, path_plan["sdk_contract"],
                             repository_id=source_cell["repository_id"])
        cell_dir = DIRECTORY / "inputs" / sid
        cells.append({"sample_id": sid, "repository_id": source_cell["repository_id"],
            "app_path": source_cell["app_path"], "helper_path": source_cell["helper_path"],
            "analyst_input": str((cell_dir / "ANALYST_INPUT.json").relative_to(ROOT)),
            "analyst_spec": str((cell_dir / "ANALYST_SPEC.json").relative_to(ROOT)),
            "certificate": certificate})
        expected = {claim["claim_id"]: "unknown" if claim["claim_id"].endswith("membership")
                    and " relation unknown " in (" " + claim["statement"] + " ") else "supported" for claim in payload["claims"]}
        evaluation.append({"sample_id": sid, "claim_expectations": expected,
                           "analyst_input_id": payload["input_id"], "claim_count": len(expected)})
        cell_dir.mkdir(parents=True, exist_ok=True)
        write_new(cell_dir / "ANALYST_INPUT.json", payload)
        write_new(cell_dir / "ANALYST_SPEC.json", spec)
        for path in (cell_dir / "ANALYST_INPUT.json", cell_dir / "ANALYST_SPEC.json", ROOT / source_cell["app_path"], ROOT / source_cell["helper_path"]):
            inputs[str(path.relative_to(ROOT))] = sha(path)
    for path in (Path(__file__), ROOT / "src/guardcontract/protocols/certificate_review.py",
                 ROOT / "src/guardcontract/backends/recorded.py", ROOT / "src/guardcontract/backends/replay.py",
                 ROOT / "src/guardcontract/evidence/source_references.py"):
        inputs[str(path.relative_to(ROOT))] = sha(path)
    plan = {"schema_version": "certificate-review-plan-1", "cells": cells, "inputs_sha256": inputs,
        "sdk_contract": path_plan["sdk_contract"], "model": MODEL, "max_tokens": 4096, "timeout_seconds": 90,
        "max_calls": 4, "max_total_tokens_stop_before_next_call": 64000, "retries": 0, "cache": "none",
        "schedule": "s001 analyst, s001 critic, s009 analyst, s009 critic",
        "study_use": "two_exposed_development_certificate_reviews_not_holdout", "goal_completion_proven": False}
    DIRECTORY.mkdir(exist_ok=True)
    write_new(DIRECTORY / "RUN_PLAN.json", plan)
    write_new(DIRECTORY / "EVALUATION_PLAN.json", {"schema_version": "certificate-review-eval-1",
        "run_plan_sha256": sha(DIRECTORY / "RUN_PLAN.json"), "cells": evaluation,
        "known_claim_verdicts": sum(v != "unknown" for row in evaluation for v in row["claim_expectations"].values()),
        "unknown_claim_verdicts": sum(v == "unknown" for row in evaluation for v in row["claim_expectations"].values()),
        "scorer_sha256": sha(Path(__file__)), "scope": "agreement_with_independently_scored_static_certificate_not_issue_holdout"})
    print(json.dumps({"samples": len(cells), "planned_calls": 4,
                      "claims": sum(row["claim_count"] for row in evaluation)}))


def snapshots(plan):
    result = {}
    for relative, expected in plan["inputs_sha256"].items():
        raw = (ROOT / relative).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("review215_input_drift:" + relative)
        result[relative] = raw
    return result


def call_model(payload, spec, role, directory, plan, key, transport_factory):
    transport = transport_factory(directory / "calls", model=plan["model"], max_calls=1,
                                  max_total_tokens=plan["max_total_tokens_stop_before_next_call"])
    request = {"model": plan["model"], "temperature": 0, "thinking": REQUIRED_THINKING,
        "max_tokens": plan["max_tokens"], "response_format": {"type": "json_object"},
        "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": json.dumps(payload, sort_keys=True)}]}
    row = {"cell_id": directory.name, "role": role, "execution_state": "error", "review": None, "calls": []}
    try:
        raw = transport(CHAT_COMPLETIONS_ENDPOINT,
            {"Content-Type": "application/json", "Authorization": "Bearer " + key},
            json.dumps(request, separators=(",", ":")).encode(), plan["timeout_seconds"])
        if len(raw) > 1048576:
            raise ValueError("review215_response_budget")
        row["review"] = decode(json.loads(_extract_response_text(json.loads(raw), "chat_completions")), spec)
        row["execution_state"] = "completed"
    except BackendError:
        call = transport.calls[-1] if transport.calls else {}
        row.update(execution_state="model_invalid" if call.get("status") == "model_invalid" else "error",
                   fault_domain="model_contract" if call.get("status") == "model_invalid" else call.get("fault_domain", "client"),
                   error_code="incomplete_generation" if call.get("status") == "model_invalid" else "transport_or_envelope_error")
    except (ValueError, KeyError, TypeError, IndexError) as exc:
        call = transport.calls[-1] if transport.calls else {}
        row.update(execution_state="model_invalid" if call.get("status") == "completed" else "error",
                   fault_domain="model_contract" if call.get("status") == "completed" else "provider",
                   error_code=type(exc).__name__ + ":" + str(exc))
    row["calls"] = transport.calls
    write_new(directory / "ACTUAL_INPUT.json", payload)
    write_new(directory / "ACTUAL_SPEC.json", spec)
    write_new(directory / "RESULT.json", row)
    return row, transport.total_tokens, transport.usage_known


def execute(plan, frozen, output, key, transport_factory=RecordedTransport):
    if (output / "runs").exists():
        raise ValueError("review215_existing_run")
    records, total, usage_known = [], 0, True
    for cell in plan["cells"]:
        payload, spec = json.loads(frozen[cell["analyst_input"]]), json.loads(frozen[cell["analyst_spec"]])
        analyst_dir = output / "runs" / (cell["sample_id"] + "-analyst")
        if not usage_known or total >= plan["max_total_tokens_stop_before_next_call"]:
            analyst = {"cell_id": analyst_dir.name, "role": "analyst", "execution_state": "missing", "review": None,
                       "calls": [], "fault_domain": "budget", "error_code": "unknown_usage_or_budget_stop"}
            analyst_dir.mkdir(parents=True)
            write_new(analyst_dir / "ACTUAL_INPUT.json", payload); write_new(analyst_dir / "ACTUAL_SPEC.json", spec); write_new(analyst_dir / "RESULT.json", analyst)
        else:
            analyst, used, known = call_model(payload, spec, "analyst", analyst_dir, plan, key, transport_factory)
            total += used; usage_known &= known
        records.append(analyst)
        critic_dir = output / "runs" / (cell["sample_id"] + "-critic")
        if analyst["execution_state"] != "completed":
            critic_dir.mkdir(parents=True)
            critic = {"cell_id": critic_dir.name, "role": "critic",
                "execution_state": "model_invalid" if analyst["execution_state"] == "model_invalid" else "missing",
                "review": None, "calls": [], "fault_domain": "prerequisite", "error_code": "prerequisite_" + analyst["execution_state"]}
            write_new(critic_dir / "ACTUAL_INPUT.json", payload); write_new(critic_dir / "ACTUAL_SPEC.json", spec); write_new(critic_dir / "RESULT.json", critic)
        elif not usage_known or total >= plan["max_total_tokens_stop_before_next_call"]:
            critic_dir.mkdir(parents=True)
            critic = {"cell_id": critic_dir.name, "role": "critic", "execution_state": "missing", "review": None,
                "calls": [], "fault_domain": "budget", "error_code": "unknown_usage_or_budget_stop"}
            write_new(critic_dir / "ACTUAL_INPUT.json", payload); write_new(critic_dir / "ACTUAL_SPEC.json", spec); write_new(critic_dir / "RESULT.json", critic)
        else:
            app, helper = (ROOT / cell["app_path"]).read_text(), (ROOT / cell["helper_path"]).read_text()
            critic_payload, critic_spec = task(cell["certificate"], app, helper, plan["sdk_contract"],
                repository_id=cell["repository_id"], role="critic", previous=analyst["review"])
            critic, used, known = call_model(critic_payload, critic_spec, "critic", critic_dir, plan, key, transport_factory)
            total += used; usage_known &= known
        records.append(critic)
    result = {"schema_version": "certificate-review-result-1", "records": records,
        "actual_calls": sum(len(row["calls"]) for row in records), "actual_total_tokens": total if usage_known else None,
        "known_accounted_tokens": total, "usage_known": usage_known, "goal_completion_proven": False}
    write_new(output / "RESULT.json", result)
    return result


def score(evaluation, result):
    expected = {row["sample_id"]: row["claim_expectations"] for row in evaluation["cells"]}
    known = correct = unknown = asserted_unknown = 0
    states, rows = Counter(), []
    by_sample_role = {}
    for record in result["records"]:
        states[record["execution_state"]] += 1
        sample, role = record["cell_id"].rsplit("-", 1)
        by_sample_role[(sample, role)] = record
        predicted = {row["claim_id"]: row["verdict"] for row in record["review"]["claims"]} if record["execution_state"] == "completed" else {}
        for claim_id, target in expected[sample].items():
            actual = predicted.get(claim_id)
            is_known = target != "unknown"
            known += is_known; correct += is_known and actual == target
            unknown += not is_known; asserted_unknown += not is_known and actual != "unknown" and actual is not None
            rows.append({"sample_id": sample, "role": role, "claim_id": claim_id, "reference": target,
                         "prediction": actual, "correct": is_known and actual == target})
    healthy = not (states["error"] or states["missing"])
    ratio = lambda n, d: {"numerator": n, "denominator": d, "value": n / d if healthy and d else None}
    complete_pairs = sum(all(by_sample_role[(sid, role)]["execution_state"] == "completed"
                         and all(row["verdict"] == expected[sid][row["claim_id"]] for row in by_sample_role[(sid, role)]["review"]["claims"])
                         for role in ("analyst", "critic")) for sid in expected)
    return {"schema_version": "certificate-review-score-1", "execution_states": dict(states), "rows": rows,
        "known_claim_accuracy": ratio(correct, known), "unknown_claim_slots": unknown,
        "assertions_on_unknown_claims": asserted_unknown, "complete_sample_pair_accuracy": ratio(complete_pairs, len(expected)),
        "scientific_status": "scored_certificate_review" if healthy else "undetermined_infrastructure_or_missing",
        "scope": "two_exposed_development_certificate_reviews_not_issue_holdout", "goal_completion_proven": False}


def run_mode(replay=False):
    plan, frozen = read(DIRECTORY / "RUN_PLAN.json"), snapshots(read(DIRECTORY / "RUN_PLAN.json"))
    if replay:
        evaluation = read(DIRECTORY / "EVALUATION_PLAN.json")
        if sha(DIRECTORY / "RUN_PLAN.json") != evaluation["run_plan_sha256"] or sha(Path(__file__)) != evaluation["scorer_sha256"]:
            raise ValueError("review215_evaluation_drift")
        replay_type = type("ReviewReplay", (RecordedReplay,), {"source_root": DIRECTORY / "runs"})
        with tempfile.TemporaryDirectory(prefix="guardcontract-review215-") as temp:
            rebuilt = execute(plan, frozen, Path(temp), "offline", replay_type)
            if rebuilt != read(DIRECTORY / "RESULT.json"):
                raise ValueError("review215_replay_result")
            verify_inventory(DIRECTORY / "runs", rebuilt["records"])
        scored = score(evaluation, rebuilt)
        scored.update(replay_verified=True, actual_calls=rebuilt["actual_calls"], actual_total_tokens=rebuilt["actual_total_tokens"],
                      summed_call_seconds=sum(call["duration_seconds"] for row in rebuilt["records"] for call in row["calls"]))
        write_new(DIRECTORY / "SCORES.json", scored)
        print(json.dumps({k: v for k, v in scored.items() if k != "rows"}))
        return
    key = (Path.home() / ".config/guardcontract/paratera.key").read_text().strip()
    result = execute(plan, frozen, DIRECTORY, key)
    write_new(DIRECTORY / "RUN_MANIFEST.json", {"schema_version": "certificate-review-run-1",
        "execution_health": "partial" if any(r["execution_state"] in {"error", "missing"} for r in result["records"]) else "completed",
        "result_sha256": sha(DIRECTORY / "RESULT.json"), "run_plan_sha256": sha(DIRECTORY / "RUN_PLAN.json"),
        "files": {str(p.relative_to(DIRECTORY)): sha(p) for p in DIRECTORY.glob("runs/**/*") if p.is_file()},
        "goal_completion_proven": False})
    print(json.dumps({"calls": result["actual_calls"], "tokens": result["actual_total_tokens"],
                      "states": [r["execution_state"] for r in result["records"]]}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "run", "replay"))
    mode = parser.parse_args().mode
    prepare() if mode == "prepare" else run_mode(replay=mode == "replay")


if __name__ == "__main__":
    main()
