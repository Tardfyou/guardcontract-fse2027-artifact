"""Validate user-owned behavior-fixture observations without producing labels."""


def validate_observations(plan, rows):
    if not isinstance(plan, dict) or plan.get("schema_version") != "guardcontract-behavior-fixture-plan-1":
        raise ValueError("behavior_fixture_plan")
    if not isinstance(rows, list) or len(rows) != 2 or {row.get("decision") for row in rows} != {"ALLOW", "DENY"}:
        raise ValueError("behavior_fixture_pair")
    output = []
    for row in rows:
        invocation_id = row.get("invocation_id")
        events = row.get("events")
        markers = row.get("markers")
        if not isinstance(invocation_id, str) or not invocation_id or not isinstance(events, list) or not isinstance(markers, list):
            raise ValueError("behavior_fixture_observation_shape")
        if any(not isinstance(event, dict) or event.get("invocation_id") != invocation_id for event in events):
            raise ValueError("behavior_fixture_invocation_correlation")
        kinds = [event.get("kind") for event in events]
        guard_events = [event for event in events if event.get("kind") == "guard_verdict"]
        if len(guard_events) != 1 or guard_events[0].get("verdict") != row["decision"]:
            raise ValueError("behavior_fixture_guard_verdict")
        required = {"invocation_start", "guard_verdict"}
        if row["decision"] == "ALLOW":
            required |= {"tool_selected", "effect_attempt", "effect_committed"}
            if len(markers) != 1:
                raise ValueError("behavior_fixture_allow_marker_count")
        elif markers:
            raise ValueError("behavior_fixture_deny_marker_count")
        if not required.issubset(kinds):
            raise ValueError("behavior_fixture_required_events")
        output.append({"decision": row["decision"], "invocation_id": invocation_id,
                       "guard_verdict": row["decision"], "event_count": len(events),
                       "marker_count": len(markers), "observation_status": "verified"})
    return {"schema_version": "behavior-fixture-observation-1", "records": output,
            "prediction_label": None, "holdout_admission_authorized": False,
            "claim_boundary": "Correlated observation validation only; no issue label or prediction release."}
