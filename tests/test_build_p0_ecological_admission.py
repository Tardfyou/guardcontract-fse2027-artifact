import json
from pathlib import Path
import sys
from guardcontract.paths import project_root
sys.path.insert(0, str(project_root() / "tools"))
from build_p0_ecological_admission import evidence_identity_basis, evidence_key


def test_evidence_identity_ignores_model_wording_but_not_agent_binding():
    base = {"effect_stratum": "http", "agent_mediation": "direct_tool", "evidence": [
        {"role": "agent_entry_binding", "path": "a.py", "line_start": 1, "line_end": 1, "source_sha256": "x"}]}
    assert evidence_key({**base, "protection_obligation": "one"}) == evidence_key({**base, "protection_obligation": "two"})
    changed = {**base, "agent_mediation": "not_established"}
    assert evidence_key(base) != evidence_key(changed)


def test_source_identity_can_use_frozen_screening_receipt_when_git_export_omits_non_code_file():
    evidence = {"path": "Dockerfile", "source_sha256": "a" * 64}
    assert evidence_identity_basis(evidence, {}, {"Dockerfile": {"sha256": "a" * 64}}) == \
        "frozen_screening_source_receipt"


def test_source_identity_still_fails_when_neither_authenticated_source_matches():
    evidence = {"path": "a.py", "source_sha256": "a" * 64}
    try:
        evidence_identity_basis(evidence, {"a.py": {"sha256": "b" * 64}},
                                {"a.py": {"sha256": "c" * 64}})
    except ValueError as exc:
        assert str(exc) == "compiled_source_identity"
    else:
        raise AssertionError("identity mismatch must fail closed")
