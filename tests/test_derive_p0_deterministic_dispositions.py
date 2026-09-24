import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "derive_p0_deterministic_dispositions",
    ROOT / "tools/derive_p0_deterministic_dispositions.py",
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


FACTS_PRESENT = {
    "same_contract_scope": "true",
    "forbidden_condition_reachable": "true",
    "protected_operation_reachable": "true",
    "forbidden_commit_joint_reachable": "true",
}


def reviews(facts):
    value = {"facts": facts, "trace": ["guard", "effect"]}
    return {"analyst": {"value": value}, "critic": {"value": value}}


def install_present_merge(monkeypatch):
    monkeypatch.setattr(MODULE, "merge", lambda _contract, _left, _right: {
        "contract_audit_prediction": "present",
        "reason": "same_scope_forbidden_commit_path_hypothesis",
        "facts": FACTS_PRESENT,
    })


def test_strict_witness_does_not_release_two_role_consensus(monkeypatch):
    install_present_merge(monkeypatch)
    result = MODULE.disposition_for(
        {"install_returncode": 0, "probes": []},
        reviews(FACTS_PRESENT),
        {},
        strict_witness=True,
    )
    assert result["disposition"] == "unknown"
    assert result["kind"] == "deterministic_layer_unknown"
    assert any("model agreement is not a mechanical witness" in line for line in result["derivation"])


def test_strict_witness_does_not_release_ordering_plus_model_facts(monkeypatch):
    install_present_merge(monkeypatch)
    result = MODULE.disposition_for(
        {"install_returncode": 0, "probes": []},
        reviews(FACTS_PRESENT),
        {},
        wiring_fact={"positions": ["after"], "guards": 1, "tools_with_effects": 1},
        strict_witness=True,
    )
    assert result["disposition"] == "unknown"
    assert any("no mechanical shared-path witness" in line for line in result["derivation"])


def test_strict_witness_keeps_probe_based_exclusion():
    result = MODULE.disposition_for(
        {"install_returncode": 1, "probes": []},
        reviews(FACTS_PRESENT),
        {},
        strict_witness=True,
    )
    assert result["disposition"] == "incompatibility_evidenced"
    assert result["kind"] == "environment_uninstallable"
