"""Shared bounded analyst/critic execution and scoring for review protocols."""
from collections import Counter
import json

from guardcontract.backends.provider_endpoint import CHAT_COMPLETIONS_ENDPOINT, REQUIRED_THINKING
from guardcontract.backends.base import BackendError, _extract_response_text
from guardcontract.backends.recorded import RecordedTransport


class ProviderEnvelopeError(ValueError):
    pass


def response_value(raw):
    try:
        outer = json.loads(raw)
        content = _extract_response_text(outer, "chat_completions")
    except (ValueError, KeyError, TypeError, IndexError) as exc:
        raise ProviderEnvelopeError("missing_or_invalid_response_content") from exc
    try:
        return json.loads(content)
    except (ValueError, TypeError):
        pass
    # Coding-plan responses may append prose after the JSON object despite
    # response_format json_object. Extract the first complete JSON value
    # deterministically: parsing must succeed with no trailing garbage inside
    # the value itself, and the raw bytes stay recorded as evidence.
    stripped = content.lstrip()
    start = stripped.find("{")
    if start >= 0:
        try:
            value, end = json.JSONDecoder().raw_decode(stripped[start:])
            if isinstance(value, dict):
                return value
        except ValueError:
            pass
    raise ValueError("model_content_not_json")


def write_new(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def call_model(payload, spec, role, directory, plan, key, *, system, decoder, transport_factory=RecordedTransport,
               payload_ensure_ascii=True):
    transport = transport_factory(directory / "calls", model=plan["model"], max_calls=1,
                                  max_total_tokens=plan["max_total_tokens_stop_before_next_call"])
    request = {"model": plan["model"], "temperature": 0, "thinking": REQUIRED_THINKING,
        "max_tokens": plan["max_tokens"], "response_format": {"type": "json_object"},
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": json.dumps(payload, sort_keys=True, ensure_ascii=payload_ensure_ascii)}]}
    row = {"cell_id": directory.name, "role": role, "execution_state": "error", "review": None, "calls": []}
    try:
        raw = transport(CHAT_COMPLETIONS_ENDPOINT,
            {"Content-Type": "application/json", "Authorization": "Bearer " + key},
            json.dumps(request, separators=(",", ":")).encode(), plan["timeout_seconds"])
        if len(raw) > 1048576:
            raise ValueError("review_response_budget")
        row["review"] = decoder(response_value(raw), spec)
        row["execution_state"] = "completed"
    except ProviderEnvelopeError as exc:
        row.update(execution_state="error", fault_domain="provider", error_code=str(exc))
    except BackendError:
        call = transport.calls[-1] if transport.calls else {}
        model_fault = call.get("status") == "model_invalid"
        row.update(execution_state="model_invalid" if model_fault else "error",
                   fault_domain="model_contract" if model_fault else call.get("fault_domain", "client"),
                   error_code="incomplete_generation" if model_fault else "transport_or_envelope_error")
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


def execute(plan, frozen, output, key, *, root, task_builder, decoder, system, transport_factory=RecordedTransport):
    if (output / "runs").exists():
        raise ValueError("review_existing_run")
    records, total, usage_known = [], 0, True
    if type(plan.get("max_calls")) is not int or not 1 <= plan["max_calls"] <= 100 or type(plan.get("max_total_tokens_stop_before_next_call")) is not int or plan["max_total_tokens_stop_before_next_call"] < 1:
        raise ValueError("review_execution_budget")
    can_call = lambda: usage_known and total < plan["max_total_tokens_stop_before_next_call"] and sum(len(row["calls"]) for row in records) < plan["max_calls"]
    for cell in plan["cells"]:
        payload, spec = json.loads(frozen[cell["analyst_input"]]), json.loads(frozen[cell["analyst_spec"]])
        analyst_dir = output / "runs" / (cell["sample_id"] + "-analyst")
        if not can_call():
            analyst_dir.mkdir(parents=True)
            analyst = {"cell_id": analyst_dir.name, "role": "analyst", "execution_state": "missing", "review": None,
                       "calls": [], "fault_domain": "budget", "error_code": "unknown_usage_or_budget_stop"}
            write_new(analyst_dir / "ACTUAL_INPUT.json", payload); write_new(analyst_dir / "ACTUAL_SPEC.json", spec); write_new(analyst_dir / "RESULT.json", analyst)
        else:
            analyst, used, known = call_model(payload, spec, "analyst", analyst_dir, plan, key,
                system=system, decoder=decoder, transport_factory=transport_factory)
            total += used; usage_known &= known
        records.append(analyst)
        critic_dir = output / "runs" / (cell["sample_id"] + "-critic")
        if analyst["execution_state"] != "completed":
            critic_dir.mkdir(parents=True)
            critic = {"cell_id": critic_dir.name, "role": "critic",
                "execution_state": "model_invalid" if analyst["execution_state"] == "model_invalid" else "missing",
                "review": None, "calls": [], "fault_domain": "prerequisite", "error_code": "prerequisite_" + analyst["execution_state"]}
            write_new(critic_dir / "ACTUAL_INPUT.json", payload); write_new(critic_dir / "ACTUAL_SPEC.json", spec); write_new(critic_dir / "RESULT.json", critic)
        elif not can_call():
            critic_dir.mkdir(parents=True)
            critic = {"cell_id": critic_dir.name, "role": "critic", "execution_state": "missing", "review": None,
                "calls": [], "fault_domain": "budget", "error_code": "unknown_usage_or_budget_stop"}
            write_new(critic_dir / "ACTUAL_INPUT.json", payload); write_new(critic_dir / "ACTUAL_SPEC.json", spec); write_new(critic_dir / "RESULT.json", critic)
        else:
            app, helper = (root / cell["app_path"]).read_text(), (root / cell["helper_path"]).read_text()
            critic_payload, critic_spec = task_builder(cell["certificate"], app, helper, plan["sdk_contract"],
                repository_id=cell["repository_id"], role="critic", previous=analyst["review"])
            critic, used, known = call_model(critic_payload, critic_spec, "critic", critic_dir, plan, key,
                system=system, decoder=decoder, transport_factory=transport_factory)
            total += used; usage_known &= known
        records.append(critic)
    result = {"schema_version": plan["result_schema_version"], "records": records, "actual_calls": sum(len(row["calls"]) for row in records),
        "actual_total_tokens": total if usage_known else None, "known_accounted_tokens": total,
        "usage_known": usage_known, "goal_completion_proven": False}
    write_new(output / "RESULT.json", result)
    return result


def score(evaluation, result):
    expected = {row["sample_id"]: row["claim_expectations"] for row in evaluation["cells"]}
    known = correct = unknown = asserted_unknown = control_total = control_correct = substantive_total = substantive_correct = 0
    states, rows, by_sample_role = Counter(), [], {}
    for record in result["records"]:
        states[record["execution_state"]] += 1
        sample, role = record["cell_id"].rsplit("-", 1)
        by_sample_role[(sample, role)] = record
        predicted = {row["claim_id"]: row["verdict"] for row in record["review"]["claims"]} if record["execution_state"] == "completed" else {}
        for claim_id, target in expected[sample].items():
            actual = predicted.get(claim_id)
            is_known = target != "unknown"
            known += is_known; correct += is_known and actual == target
            control = claim_id.startswith("control-opposite-")
            control_total += control and is_known; control_correct += control and is_known and actual == target
            substantive_total += not control and is_known; substantive_correct += not control and is_known and actual == target
            unknown += not is_known; asserted_unknown += not is_known and actual not in {"unknown", None}
            rows.append({"sample_id": sample, "role": role, "claim_id": claim_id, "reference": target,
                         "prediction": actual, "correct": is_known and actual == target})
    if set(by_sample_role) != {(sid, role) for sid in expected for role in ("analyst", "critic")}:
        raise ValueError("review_score_inventory")
    healthy = not (states["error"] or states["missing"])
    ratio = lambda n, d: {"numerator": n, "denominator": d, "value": n / d if healthy and d else None}
    complete_pairs = sum(all(by_sample_role[(sid, role)]["execution_state"] == "completed"
                         and all(row["verdict"] == expected[sid][row["claim_id"]] for row in by_sample_role[(sid, role)]["review"]["claims"])
                         for role in ("analyst", "critic")) for sid in expected)
    return {"execution_states": dict(states), "rows": rows, "known_claim_accuracy": ratio(correct, known),
        "substantive_claim_accuracy": ratio(substantive_correct, substantive_total),
        "negative_control_accuracy": ratio(control_correct, control_total),
        "unknown_claim_slots": unknown, "assertions_on_unknown_claims": asserted_unknown,
        "complete_sample_pair_accuracy": ratio(complete_pairs, len(expected)),
        "scientific_status": "scored_certificate_review" if healthy else "undetermined_infrastructure_or_missing",
        "goal_completion_proven": False}
