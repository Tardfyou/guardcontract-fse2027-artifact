import json
import pytest
from guardcontract.paths import project_root
import sys
sys.path.insert(0, str(project_root() / "tools"))
from compile_p0_ecological_contracts import SYSTEM, decode, digest


def fixture():
    payload = {"unit_id": "u", "repository": "r", "sources": [{"path": "a.py", "content": "10|guard()\n11|if denied: return\n12|effect()"}]}
    receipts = {"a.py": {"sha256": "a" * 64}}
    value = {"unit_id": "u", "missing_information": [], "contracts": [{
        "protection_obligation": "Denied calls must not commit", "forbidden_condition": "denied",
        "protected_operation": "effect", "protected_resource": "record", "declared_mechanism": "guard",
        "commit_point": "effect call", "effect_stratum": "state", "agent_mediation": "direct_tool", "scope_limits": ["one invocation"],
        "pending_binding_information": [], "evidence": [
            {"path": "a.py", "start_line": 10, "end_line": 10, "role": "guard_registration"},
            {"path": "a.py", "start_line": 11, "end_line": 11, "role": "forbidden_condition"},
            {"path": "a.py", "start_line": 12, "end_line": 12, "role": "protected_operation"},
            {"path": "a.py", "start_line": 12, "end_line": 12, "role": "commit_point"},
            {"path": "a.py", "start_line": 10, "end_line": 10, "role": "agent_entry_binding"}]}]}
    return value, payload, receipts


def test_decoder_assigns_stable_identity_and_source_hash():
    value, payload, receipts = fixture(); result = decode(value, payload, receipts); contract = result["contracts"][0]
    assert contract["verification_ready"] is True
    assert contract["evidence"][0]["source_sha256"] == "a" * 64
    assert contract["contract_id"] == decode(value, payload, receipts)["contracts"][0]["contract_id"]


def test_decoder_keeps_missing_roles_out_of_ready_set():
    value, payload, receipts = fixture(); value["contracts"][0]["evidence"] = value["contracts"][0]["evidence"][:1]
    contract = decode(value, payload, receipts)["contracts"][0]
    assert contract["verification_ready"] is False
    assert "commit_point" in contract["missing_evidence_roles"]


def test_decoder_rejects_descriptive_effect_stratum():
    value, payload, receipts = fixture(); value["contracts"][0]["effect_stratum"] = "HTTP middleware stratum"
    with pytest.raises(ValueError, match="effect_stratum"):
        decode(value, payload, receipts)


def test_not_established_agent_mediation_is_not_verification_ready():
    value, payload, receipts = fixture(); value["contracts"][0]["agent_mediation"] = "not_established"
    contract = decode(value, payload, receipts)["contracts"][0]
    assert contract["verification_ready"] is False


def test_effect_strata_distinguish_os_process_from_in_process_eval():
    assert "process (OS process or shell execution)" in SYSTEM
    assert "tool_execution (in-process interpreter/eval" in SYSTEM
