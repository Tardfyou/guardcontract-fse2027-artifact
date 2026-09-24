"""Enroll a narrow synchronous LangChain callback contract from frozen probes."""
import hashlib
import json
from pathlib import Path


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def enroll(directory):
    directory = Path(directory)
    manifest = json.loads((directory / "RUN_MANIFEST.json").read_bytes())
    for name, expected in manifest["files"].items():
        if sha(directory / name) != expected:
            raise ValueError("sdk_contract_artifact_drift:" + name)
    result = json.loads((directory / "RESULT.json").read_bytes())
    plan = json.loads((directory / "RUN_PLAN.json").read_bytes())
    locations = json.loads((directory / "SOURCE_LOCATIONS.json").read_bytes())
    rows = {row["case"]: row for row in result["rows"]}
    required = {f"{kind}-{deny}" for kind in ("call", "skip", "twice", "raise_before", "raise_after")
                for deny in (False, True)}
    if set(rows) < required or any(not rows[name]["matches_contract"] for name in required):
        raise ValueError("sdk_contract_probe_coverage")
    call_allow = rows["call-False"]["observation"]
    call_deny = rows["call-True"]["observation"]
    if call_allow["events"] != ["model_1", "wrapper_enter", "write", "handler_return", "wrapper_return", "model_2", "after_agent"]:
        raise ValueError("sdk_contract_allow_order")
    if call_deny["events"] != [*call_allow["events"], "guard_deny"] or call_deny["writes"] != 1:
        raise ValueError("sdk_contract_deny_order")
    skip = rows["skip-True"]["observation"]
    if skip["writes"] != 0 or skip["events"] != ["model_1", "wrapper_enter", "wrapper_return", "model_2", "after_agent", "guard_deny"]:
        raise ValueError("sdk_contract_skip_order")
    definitions = {row["symbol"]: row for row in locations["definitions"]}
    expected_symbols = {"create_agent", "_make_model_to_tools_edge", "_make_tools_to_model_edge",
                        "ToolNode._execute_tool_sync", "ToolNode._run_one"}
    if set(definitions) != expected_symbols:
        raise ValueError("sdk_contract_definition_inventory")
    identity = json.loads((directory / "RUNTIME_IDENTITY.json").read_bytes())
    contract = {
        "schema_version": "langchain-sdk-contract-1",
        "framework_versions": plan.get("packages"),
        "runtime_identity_sha256": sha(directory / "RUNTIME_IDENTITY.json"),
        "source_locations_sha256": sha(directory / "SOURCE_LOCATIONS.json"),
        "facts": {
            "synchronous_single_middleware": True,
            "pending_tool_request_enters_wrapper": True,
            "calling_handler_once_executes_selected_registered_tool_once": True,
            "wrapper_return_routes_to_model_then_after_agent": True,
            "wrapper_return_without_handler_skips_selected_tool": True,
            "after_agent_deny_occurs_after_successful_handler_effect": True,
            "wrapper_exception_before_return_skips_after_agent": True,
        },
        "limits": ["sync agent.invoke", "one middleware", "one fixed tool request", "default error handling",
                   "no recovery or retry", "return_direct false", "normal successful local IO"],
        "evidence": {"run_manifest": sha(directory / "RUN_MANIFEST.json"),
                     "run_plan": sha(directory / "RUN_PLAN.json"),
                     "result": sha(directory / "RESULT.json"),
                     "definitions": definitions},
        "application_path_or_effect_verified": False,
    }
    if contract["framework_versions"] != {"langchain": "1.4.0", "langgraph": "1.2.11", "langgraph-prebuilt": "1.1.0"}:
        raise ValueError("sdk_contract_framework_versions")
    contract["contract_sha256"] = hashlib.sha256(json.dumps(contract, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return contract
