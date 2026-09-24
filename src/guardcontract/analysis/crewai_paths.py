"""Fail-closed path recovery for pinned CrewAI controls."""
import ast,hashlib
from guardcontract.analysis.langchain_paths import Unsupported,calls,dotted,function,provenance,unique
from guardcontract.discovery.router import stable_node_id
def decorator_name(node):return dotted(node.func) if isinstance(node,ast.Call) else dotted(node)
def analyze(source,sdk_contract,*,repository_id,path="app.py"):
    source_hash=hashlib.sha256(source.encode()).hexdigest();base={"schema_version":"crewai-path-certificate-1","source_sha256":source_hash,"sdk_contract_sha256":sdk_contract.get("contract_sha256"),"runtime_reference_read":False,"assembly_ready":False}
    required={"task_guardrail_runs_after_agent_execute_task","before_tool_hook_runs_before_tool_invocation","before_tool_false_blocks_tool_invocation","unregistered_before_tool_hook_does_not_mediate"}
    if not repository_id:return {**base,"status":"unknown","gaps":["repository_identity_required"],"paths":[]}
    if sdk_contract.get("schema_version")!="crewai-sdk-contract-1" or not all(sdk_contract.get("facts",{}).get(k) is True for k in required):return {**base,"status":"unknown","gaps":["sdk_contract_not_applicable"],"paths":[]}
    try:
        tree=ast.parse(source);run=function(tree,"run_cell");model=function(tree,"ScriptedLLM.call");tool=function(run,"write_canary");task_guard=function(run,"task_guardrail");before=function(run,"before_tool_hook")
        request=unique((r for r in ast.walk(model) if isinstance(r,ast.Return) and isinstance(r.value,ast.Constant) and isinstance(r.value.value,str) and "Action: write_canary\nAction Input: {}" in r.value.value),"crewai_fixed_request")
        decorator=unique((d for d in tool.decorator_list if decorator_name(d)=="tool"),"crewai_tool_decorator")
        if not isinstance(decorator,ast.Call) or len(decorator.args)!=1 or not isinstance(decorator.args[0],ast.Constant) or decorator.args[0].value!="write_canary":raise Unsupported("crewai_tool_name")
        sink=unique(calls(tool,"marker.write_text"),"crewai_selected_write");all_writes=[c for c in ast.walk(tree) if isinstance(c,ast.Call) and dotted(c.func) and dotted(c.func).endswith(".write_text")]
        if all_writes!=[sink]:raise Unsupported("crewai_additional_write")
        agent=unique(calls(run,"Agent"),"crewai_one_agent");akw={k.arg:k.value for k in agent.keywords if k.arg}
        if not isinstance(akw.get("tools"),ast.List) or [dotted(x) for x in akw["tools"].elts]!=[tool.name] or dotted(akw.get("llm"))!="llm":raise Unsupported("crewai_agent_registration")
        task=unique(calls(run,"Task"),"crewai_one_task");tkw={k.arg:k.value for k in task.keywords if k.arg};guard_value=tkw.get("guardrail")
        registered=len(calls(run,"register_before_tool_call_hook"))==1 and dotted(calls(run,"register_before_tool_call_hook")[0].args[0])==before.name
        unregistered=len(calls(run,"unregister_before_tool_call_hook"))==1 and dotted(calls(run,"unregister_before_tool_call_hook")[0].args[0])==before.name
        post=dotted(guard_value)==task_guard.name and not registered;pre=isinstance(guard_value,ast.Constant) and guard_value.value is None and registered and unregistered
        if not(post or pre) or not isinstance(tkw.get("guardrail_max_retries"),ast.Constant) or tkw["guardrail_max_retries"].value!=0:raise Unsupported("crewai_guard_configuration")
        if len(calls(task_guard,"events.append"))!=1 or not any(isinstance(r,ast.Return) and isinstance(r.value,ast.Tuple) for r in task_guard.body):raise Unsupported("crewai_task_guard_shape")
        if len(calls(before,"events.append"))!=1 or not any(isinstance(r,ast.Return) and isinstance(r.value,ast.IfExp) for r in before.body):raise Unsupported("crewai_before_hook_shape")
        kickoff=unique(calls(run,"Crew"),"crewai_one_crew");ckw={k.arg:k.value for k in kickoff.keywords if k.arg}
        if not isinstance(ckw.get("agents"),ast.List) or [dotted(x) for x in ckw["agents"].elts]!=["agent"] or not isinstance(ckw.get("tasks"),ast.List) or [dotted(x) for x in ckw["tasks"].elts]!=["task"] or dotted(ckw.get("process"))!="Process.sequential":raise Unsupported("crewai_crew_binding")
        kickoff_calls=[c for c in ast.walk(run) if isinstance(c,ast.Call) and isinstance(c.func,ast.Attribute) and c.func.attr=="kickoff" and c.func.value is kickoff]
        if len(kickoff_calls)!=1:raise Unsupported("crewai_kickoff_binding")
        mode="task_output_post_effect" if post else "before_tool_hook";deny_occurs=post
        request_event=provenance(path,source,request,"selected_tool_request");sink_event=provenance(path,source,sink,"selected_write");guard_node=task_guard if post else before;guard_event=provenance(path,source,guard_node,"applicable_policy_decision")
        allow_events=[request_event,sink_event,guard_event] if post else [request_event,guard_event,sink_event];deny_events=list(allow_events) if post else [request_event,guard_event]
        site={"sink_site":stable_node_id(repository_id,"effect",path,sink.lineno,"marker.write_text"),"path":path,"line":sink.lineno,"relation":"same_logical_effect","allow_effect_occurs":True,"deny_effect_occurs":deny_occurs,"identity_scope":"originating_request_resource_and_operation","source_evidence":sink_event}
        return {**base,"status":"supported","gaps":[],"mode":mode,"logical_identity":{"request":"fixed_selected_tool_call","resource":"run_cell.marker","operation":"successful_text_publication","binding_verified":True},"guard":guard_event,"sink":sink_event,"sites":[site],"paths":[{"decision":"ALLOW","events":allow_events,"selected_effect_occurs":True,"guard_reports_deny":False},{"decision":"DENY","events":deny_events,"selected_effect_occurs":deny_occurs,"guard_reports_deny":True}],"review_evidence":{"request_binding":[request_event,provenance(path,source,tool,"registered_tool"),provenance(path,source,agent,"agent_registration"),provenance(path,source,task,"task_registration"),provenance(path,source,kickoff,"crew_registration")],"closed_application_path":[provenance(path,source,run,"closed_run_cell")]},"issue_prediction":deny_occurs,"source_semantics_verified":True,"scope":"crewai_1_15_18_sequential_one_task_one_tool_normal_io"}
    except (SyntaxError,Unsupported,KeyError,AttributeError,IndexError) as exc:return {**base,"status":"unknown","gaps":[str(exc) if isinstance(exc,Unsupported) else "source_shape_error"],"paths":[]}
