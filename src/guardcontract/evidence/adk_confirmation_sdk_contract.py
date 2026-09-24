"""Enroll ADK confirmation ordering over the frozen callback SDK contract."""
import hashlib
import json
from pathlib import Path

from guardcontract.evidence.adk_sdk_contract import enroll as enroll_v1


def _sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def enroll(base_directory, confirmation_result_path):
    base = enroll_v1(base_directory); path = Path(confirmation_result_path)
    result = json.loads(path.read_text(encoding="utf-8"))
    if (result.get("schema_version") != "google-adk-confirmation-contract-fixture-1"
            or result.get("execution_health") != "completed"
            or result.get("scientific_outcome") != "success"
            or result.get("public_repository_code_executed") is not False
            or result.get("network_enforcement", {}).get("mechanism") != "kernel_seccomp"
            or result.get("network_enforcement", {}).get("socket_creation_probe") != "EPERM"):
        raise ValueError("adk_confirmation_contract_result")
    rows = {row.get("state"): row for row in result.get("rows", [])}
    if set(rows) != {"pending", "reject", "approve"} or not all(
            row.get("matches_contract") for row in rows.values()):
        raise ValueError("adk_confirmation_contract_rows")
    if ([rows[state]["effect_count"] for state in ("pending", "reject", "approve")] != [0, 0, 1]
            or [rows[state]["confirmation_requests"] for state in ("pending", "reject", "approve")] != [1, 0, 0]):
        raise ValueError("adk_confirmation_contract_ordering")
    if result.get("framework_versions") != base["framework_versions"]:
        raise ValueError("adk_confirmation_contract_versions")
    contract = {"schema_version": "google-adk-sdk-contract-2",
                "framework_versions": base["framework_versions"],
                "facts": {**base["facts"],
                          "require_confirmation_reject_skips_function_invocation": True,
                          "require_confirmation_approve_invokes_function_once": True},
                "limits": [*base["limits"], "FunctionTool require_confirmation true",
                           "pending/reject/approve states", "direct run_async"],
                "evidence": {"base_contract_sha256": base["contract_sha256"],
                             "confirmation_result": _sha(path),
                             "confirmation_runtime_source": result["runtime_source"]},
                "application_path_or_effect_verified": False}
    contract["contract_sha256"] = hashlib.sha256(json.dumps(
        contract, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return contract
