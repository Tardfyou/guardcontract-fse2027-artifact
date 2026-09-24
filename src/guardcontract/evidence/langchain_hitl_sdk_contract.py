"""Enroll LangChain HITL ordering on top of the existing v1 SDK contract."""
import hashlib
import json
from pathlib import Path

from guardcontract.evidence.langchain_sdk_contract import enroll as enroll_v1


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def enroll(base_directory, hitl_result_path):
    base = enroll_v1(base_directory)
    path = Path(hitl_result_path)
    result = json.loads(path.read_text(encoding="utf-8"))
    if (result.get("schema_version") != "langchain-hitl-contract-fixture-1"
            or result.get("execution_health") != "completed"
            or result.get("scientific_outcome") != "success"
            or result.get("public_repository_code_executed") is not False
            or result.get("network_enforcement", {}).get("mechanism") != "kernel_seccomp"
            or result.get("network_enforcement", {}).get("socket_creation_probe") != "EPERM"):
        raise ValueError("langchain_hitl_contract_result")
    rows = {row.get("decision"): row for row in result.get("rows", [])}
    if set(rows) != {"reject", "approve"} or not all(row.get("matches_contract") for row in rows.values()):
        raise ValueError("langchain_hitl_contract_rows")
    reject, approve = rows["reject"], rows["approve"]
    if (reject.get("verdict") != "DENY" or reject.get("interrupt_count") != 1
            or reject.get("effect_count") != 0 or reject.get("marker_exists") is not False
            or approve.get("verdict") != "ALLOW" or approve.get("interrupt_count") != 1
            or approve.get("effect_count") != 1 or approve.get("marker_exists") is not True):
        raise ValueError("langchain_hitl_contract_ordering")
    expected_versions = {key: value for key, value in base["framework_versions"].items()
                         if key in {"langchain", "langgraph"}}
    if result.get("framework_versions") != expected_versions:
        raise ValueError("langchain_hitl_contract_versions")
    contract = {"schema_version": "langchain-sdk-contract-2",
                "framework_versions": base["framework_versions"],
                "facts": {**base["facts"],
                          "human_reject_removes_selected_tool_before_execution": True},
                "limits": [*base["limits"], "HumanInTheLoopMiddleware static interrupt_on",
                           "one deterministic tool call", "approve or reject decision"],
                "evidence": {"base_contract_sha256": base["contract_sha256"],
                             "hitl_result": _sha(path),
                             "hitl_runtime_source": result["runtime_source"]},
                "application_path_or_effect_verified": False}
    contract["contract_sha256"] = hashlib.sha256(json.dumps(
        contract, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return contract
