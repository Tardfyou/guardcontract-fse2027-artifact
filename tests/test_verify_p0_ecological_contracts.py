from guardcontract.paths import project_root
import sys
sys.path.insert(0, str(project_root() / "tools"))
from verify_p0_ecological_contracts import analyze_contract, frozen_source_text


def test_same_function_tool_guard_and_commit_is_mechanically_eligible():
    source = "from x import tool\n@tool\ndef write(x):\n    if not x:\n        raise ValueError()\n    commit(x)\n"
    contract = {"contract_id": "c", "protocol_group": "compiled_agent_bound_v4", "admission_evidence": [
        {"role": "agent_entry_binding", "path": "a.py", "line_start": 2, "line_end": 2},
        {"role": "guard_registration", "path": "a.py", "line_start": 3, "line_end": 5},
        {"role": "forbidden_condition", "path": "a.py", "line_start": 4, "line_end": 5},
        {"role": "protected_operation", "path": "a.py", "line_start": 6, "line_end": 6},
        {"role": "commit_point", "path": "a.py", "line_start": 6, "line_end": 6}]}
    row = analyze_contract(contract, {"a.py": source})
    assert row["mechanically_eligible_for_path_analysis"] is True
    assert row["same_function_orderings"] == ["before"]
    assert row["DEC_label"] is None


def test_cors_without_agent_entry_is_not_eligible():
    source = "app.add_middleware(CORSMiddleware)\n"
    contract = {"contract_id": "c", "protocol_group": "compiled_agent_bound_v4", "admission_evidence": [
        {"role": "guard_registration", "path": "a.py", "line_start": 1, "line_end": 1},
        {"role": "forbidden_condition", "path": "a.py", "line_start": 1, "line_end": 1},
        {"role": "protected_operation", "path": "a.py", "line_start": 1, "line_end": 1},
        {"role": "commit_point", "path": "a.py", "line_start": 1, "line_end": 1}]}
    assert analyze_contract(contract, {"a.py": source})["mechanically_eligible_for_path_analysis"] is False


def test_non_git_export_source_can_be_reconstructed_from_authenticated_numbered_view():
    contract = {"parent_sample_ids": ["u1"]}
    evidence = {"path": "Dockerfile", "source_sha256": "a" * 64}
    tasks = {"u1": {"receipts": {"Dockerfile": {"sha256": "a" * 64}},
                     "payload": {"sources": [{"path": "Dockerfile",
                                                "content": "1|FROM python\n2|RUN true"}]}}}
    assert frozen_source_text(contract, evidence, tasks) == "FROM python\nRUN true"
