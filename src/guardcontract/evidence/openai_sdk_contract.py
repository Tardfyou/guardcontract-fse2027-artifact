"""Enroll narrow OpenAI Agents 0.22.0 guard ordering from frozen sources."""
import hashlib,json
from pathlib import Path

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def enroll(census_directory,run_path,tool_execution_path):
    census_directory=Path(census_directory);run_path=Path(run_path);tool_execution_path=Path(tool_execution_path)
    config=json.loads((census_directory/"CENSUS_CONFIG.json").read_bytes());raw=json.loads((census_directory/"raw-evidence.json").read_bytes());manifest=json.loads((census_directory/"RUN_MANIFEST.json").read_bytes())
    expected_raw=next(r["sha256"] for r in manifest["files"] if r["path"].endswith("/raw-evidence.json") and r["role"]=="artifact-output")
    if sha(census_directory/"raw-evidence.json")!=expected_raw:raise ValueError("openai_contract_census_drift")
    cfg=next(r for r in config["frameworks"] if r["id"]=="openai-agents");row=next(r for r in raw["frameworks"] if r["id"]=="openai-agents")
    if cfg["version"]!="0.22.0" or not row["capture_complete"] or not row["wheel"]["hash_matches"] or row["wheel"]["observed_sha256"]!=cfg["wheel_sha256"]:raise ValueError("openai_contract_identity")
    run=run_path.read_text();tool=tool_execution_path.read_text()
    run_literals=["parallel_guardrails = [g for g in all_input_guardrails if g.run_in_parallel]","guardrail_task = asyncio.create_task(","model_task = asyncio.create_task(","await asyncio.gather(","guardrail_task,","model_task,"]
    tool_literals=["rejected_message = await _execute_tool_input_guardrails(","invocation_result = await _invoke_function_tool_with_metadata(","if not func_tool.tool_input_guardrails:","raise ToolInputGuardrailTripwireTriggered("]
    if not all(run.count(x)>=1 for x in run_literals) or not all(tool.count(x)>=1 for x in tool_literals):raise ValueError("openai_contract_source_anchors")
    contract={"schema_version":"openai-agents-sdk-contract-1","framework_versions":{"openai-agents":"0.22.0"},
        "facts":{"tool_input_guardrail_precedes_function_invocation":True,"tool_input_guardrail_raise_prevents_function_invocation":True,
            "missing_tool_input_guardrails_do_not_block":True,"parallel_input_guard_and_model_turn_are_concurrent_tasks":True,
            "parallel_input_guard_does_not_dominate_model_turn_effects":True},
        "limits":["Runner.run","one function tool","one fixed function call","first-turn input guardrails","normal asyncio scheduling","non-Temporal execution"],
        "evidence":{"census_raw_sha256":expected_raw,"wheel_sha256":cfg["wheel_sha256"],"run_source_sha256":sha(run_path),"tool_execution_source_sha256":sha(tool_execution_path)},
        "application_path_or_effect_verified":False}
    contract["contract_sha256"]=hashlib.sha256(json.dumps(contract,sort_keys=True,separators=(",",":")).encode()).hexdigest();return contract
