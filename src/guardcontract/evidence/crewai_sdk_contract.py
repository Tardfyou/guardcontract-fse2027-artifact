"""Enroll CrewAI 1.15.18 task and before-tool guard ordering from source."""
import hashlib,json
from pathlib import Path
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def enroll(metadata_path,task_path,tool_utils_path,hooks_path):
    metadata_path,task_path,tool_utils_path,hooks_path=map(Path,(metadata_path,task_path,tool_utils_path,hooks_path));metadata=metadata_path.read_text()
    if "\nVersion: 1.15.18\n" not in "\n"+metadata:raise ValueError("crewai_contract_version")
    task=task_path.read_text();utils=tool_utils_path.read_text();hooks=hooks_path.read_text()
    if not all(x in task for x in ("result = agent.execute_task(","task_output = self._invoke_guardrail_function(")):raise ValueError("crewai_contract_task_order")
    if task.index("result = agent.execute_task(")>=task.index("task_output = self._invoke_guardrail_function("):raise ValueError("crewai_contract_task_order")
    if not all(x in utils for x in ("if run_before_tool_call_hooks(hook_context):","return ToolResult(","tool_result = await tool_usage.ause(")) or utils.index("if run_before_tool_call_hooks(hook_context):")>=utils.index("tool_result = await tool_usage.ause("):raise ValueError("crewai_contract_tool_order")
    if not all(x in hooks for x in ("if result is False:","raise HookAborted(","except HookAborted:","return True")):raise ValueError("crewai_contract_hook_block")
    contract={"schema_version":"crewai-sdk-contract-1","framework_versions":{"crewai":"1.15.18"},"facts":{"task_guardrail_runs_after_agent_execute_task":True,
        "before_tool_hook_runs_before_tool_invocation":True,"before_tool_false_blocks_tool_invocation":True,"unregistered_before_tool_hook_does_not_mediate":True},
        "limits":["Crew kickoff","Process.sequential","one Task","one Agent","one scripted tool request","global before-tool hook","normal local IO"],
        "evidence":{"metadata_sha256":sha(metadata_path),"task_source_sha256":sha(task_path),"tool_utils_source_sha256":sha(tool_utils_path),"hooks_source_sha256":sha(hooks_path)},"application_path_or_effect_verified":False}
    contract["contract_sha256"]=hashlib.sha256(json.dumps(contract,sort_keys=True,separators=(",",":")).encode()).hexdigest();return contract
