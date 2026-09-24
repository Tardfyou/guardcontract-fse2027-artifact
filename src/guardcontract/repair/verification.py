"""Independent behavioral gates for a generated deferral repair."""


def compare(original, patched, network_mode="kernel_seccomp"):
    for result in (original, patched):
        if result.get("execution_health") != "completed" or set(result.get("cells", {})) != {"ALLOW", "DENY"}:
            raise ValueError("repair_verification_execution")
    original_allow, patched_allow = original["cells"]["ALLOW"], patched["cells"]["ALLOW"]
    original_deny, patched_deny = original["cells"]["DENY"], patched["cells"]["DENY"]
    if network_mode == "kernel_seccomp":
        network_ok = original.get("network_enforcement", {}).get("socket_creation_probe") == "EPERM" and patched.get("network_enforcement", {}).get("socket_creation_probe") == "EPERM"
    elif network_mode == "python_socket_connect_patch":
        network_ok = all(row.get("network_enforcement", {}).get("mechanism") == network_mode and row["network_enforcement"].get("connect") and row["network_enforcement"].get("create_connection") for row in (original, patched))
    else:
        raise ValueError("repair_verification_network_mode")
    gates = {
        "original_issue_reproduced": original_deny.get("effect_count") == 1 and original_deny.get("marker_exists") is True,
        "deny_zero_effect": patched_deny.get("effect_count") == 0 and patched_deny.get("marker_exists") is False
                            and patched_deny.get("expected_exception_observed") is True,
        "allow_observable_behavior_preserved": patched_allow == original_allow,
        "allow_effect_preserved": patched_allow.get("effect_count") == original_allow.get("effect_count") == 1
                                  and patched_allow.get("marker_payload") == original_allow.get("marker_payload"),
        "source_changed": patched.get("app_sha256") != original.get("app_sha256"),
        "helper_unchanged": patched.get("helper_sha256") == original.get("helper_sha256"),
        "network_enforced": network_ok,
    }
    return {"schema_version": "repair-verification-1", "gates": gates, "gate_passed": all(gates.values()),
            "original_deny": original_deny, "patched_deny": patched_deny,
            "allow_exact_match": patched_allow == original_allow,
            "claim_boundary": "One owned synchronous LangChain fixture under normal local IO; not cross-framework repair generalization."}
