"""Shared fail-closed release gate for actionable contract findings."""


def assess_actionable(*, policy_scope_status, guard_effect_path_status,
                      effect_status, ordering_status):
    missing = []
    if policy_scope_status != "bound":
        missing.append("bound_policy_scope")
    if guard_effect_path_status != "supported":
        missing.append("supported_guard_effect_path")
    if effect_status != "confirmed":
        missing.append("confirmed_effect")
    if ordering_status != "confirmed_by_independent_witness":
        missing.append("independent_order_witness")
    ready = (policy_scope_status == "bound"
             and guard_effect_path_status == "supported"
             and effect_status == "confirmed"
             and ordering_status == "confirmed_by_independent_witness")
    return {"policy_scope_status": policy_scope_status,
            "guard_effect_path_status": guard_effect_path_status,
            "ready_for_actionable_detection": ready,
            "missing_evidence": missing,
            "reason": "requires_bound_policy_scope_source_path_and_independent_order_witness"}
