"""Path recovery including synchronized OpenAI Agents race repairs."""
import ast,hashlib
from guardcontract.analysis.langchain_paths import Unsupported,calls,dotted,function,provenance,unique
from guardcontract.discovery.router import stable_node_id
def decorator_name(node):return dotted(node.func) if isinstance(node,ast.Call) else dotted(node)
def assigned(run,name):return unique((r.value for r in run.body if isinstance(r,ast.Assign) and len(r.targets)==1 and isinstance(r.targets[0],ast.Name) and r.targets[0].id==name),"assignment:"+name)
def analyze(source,sdk_contract,*,repository_id,path="app.py"):
    source_hash=hashlib.sha256(source.encode()).hexdigest();base={"schema_version":"openai-agents-path-certificate-2","source_sha256":source_hash,"sdk_contract_sha256":sdk_contract.get("contract_sha256"),"runtime_reference_read":False,"assembly_ready":False}
    required={"tool_input_guardrail_precedes_function_invocation","tool_input_guardrail_raise_prevents_function_invocation","missing_tool_input_guardrails_do_not_block","parallel_input_guard_and_model_turn_are_concurrent_tasks","parallel_input_guard_does_not_dominate_model_turn_effects"}
    if not repository_id:return {**base,"status":"unknown","gaps":["repository_identity_required"],"paths":[]}
    if sdk_contract.get("schema_version")!="openai-agents-sdk-contract-1" or not all(sdk_contract.get("facts",{}).get(k) is True for k in required):return {**base,"status":"unknown","gaps":["sdk_contract_not_applicable"],"paths":[]}
    try:
        tree=ast.parse(source);run=function(tree,"run_cell");model=function(tree,"CanaryModel.get_response");decide=function(run,"decide")
        request=unique(calls(model,"ResponseFunctionToolCall"),"openai_fixed_request");request_kw={k.arg:k.value for k in request.keywords if k.arg}
        if not isinstance(request_kw.get("name"),ast.Constant) or request_kw["name"].value!="write_canary" or not isinstance(request_kw.get("arguments"),ast.Constant) or request_kw["arguments"].value!="{}":raise Unsupported("openai_request_binding")
        tool=unique((r for r in run.body if isinstance(r,(ast.FunctionDef,ast.AsyncFunctionDef)) and any(decorator_name(d)=="function_tool" for d in r.decorator_list)),"openai_one_function_tool");guard=function(run,"effect_gate");parallel=function(run,"parallel_guard")
        if tool.name!="write_canary" or not any(decorator_name(d)=="tool_input_guardrail" for d in guard.decorator_list):raise Unsupported("openai_tool_guard_definition")
        pdecor=unique((d for d in parallel.decorator_list if decorator_name(d)=="input_guardrail"),"openai_parallel_guard_decorator");pkw={k.arg:k.value for k in pdecor.keywords if k.arg}
        if not isinstance(pkw.get("run_in_parallel"),ast.Constant) or pkw["run_in_parallel"].value is not True or len(calls(parallel,"asyncio.sleep"))!=1 or len(calls(parallel,"decide"))!=1:raise Unsupported("openai_parallel_guard_shape")
        sink=unique(calls(tool,"marker.write_text"),"openai_selected_write");all_writes=[c for c in ast.walk(tree) if isinstance(c,ast.Call) and dotted(c.func) and dotted(c.func).endswith(".write_text")]
        if all_writes!=[sink]:raise Unsupported("openai_additional_write")
        fdecor=unique((d for d in tool.decorator_list if decorator_name(d)=="function_tool"),"openai_function_tool_decorator");fkw={k.arg:k.value for k in fdecor.keywords if k.arg}
        if dotted(fkw.get("tool_input_guardrails"))!="tool_guardrails":raise Unsupported("openai_tool_guard_binding")
        tool_guardrails=assigned(run,"tool_guardrails");agent=unique(calls(run,"Agent"),"openai_one_agent");akw={k.arg:k.value for k in agent.keywords if k.arg}
        if not isinstance(akw.get("tools"),ast.List) or [dotted(x) for x in akw["tools"].elts]!=[tool.name]:raise Unsupported("openai_agent_tool_registration")
        input_guards=akw.get("input_guardrails");pre=isinstance(tool_guardrails,ast.List) and [dotted(x) for x in tool_guardrails.elts]==[guard.name] and isinstance(input_guards,ast.List) and not input_guards.elts
        parallel_config=isinstance(tool_guardrails,ast.Constant) and tool_guardrails.value is None and isinstance(input_guards,ast.List) and [dotted(x) for x in input_guards.elts]==[parallel.name]
        synchronized=(parallel_config and isinstance(tool,ast.AsyncFunctionDef) and len(calls(tool,"decision_ready.wait"))==1 and len(calls(tool,"asyncio.Future"))==1 and len(calls(decide,"decision_ready.set"))==1 and any(k.arg=="record_event" for c in calls(parallel,"decide") for k in c.keywords) and len(calls(tool,"events.append"))==2)
        race=parallel_config and not synchronized
        if not(pre or race or synchronized):raise Unsupported("openai_guard_configuration")
        if len(calls(guard,"decide"))!=1 or len(calls(guard,"ToolGuardrailFunctionOutput.raise_exception"))!=1 or len(calls(decide,"events.append"))!=1:raise Unsupported("openai_policy_decision")
        runner=unique(calls(run,"Runner.run"),"openai_one_runner");rkw={k.arg:k.value for k in runner.keywords if k.arg}
        if not runner.args or dotted(runner.args[0])!="agent" or not isinstance(rkw.get("max_turns"),ast.Constant) or rkw["max_turns"].value!=2:raise Unsupported("openai_runner_binding")
        mode="tool_input_pre_effect" if pre else "synchronized_parallel_guard" if synchronized else "parallel_input_race";deny_occurs=race
        request_event=provenance(path,source,request,"selected_tool_request");guard_event=provenance(path,source,guard if pre else parallel,"applicable_policy_guard");decision_event=provenance(path,source,decide,"applicable_policy_decision");sink_event=provenance(path,source,sink,"selected_write")
        if pre:allow_events=[request_event,guard_event,decision_event,sink_event];deny_events=[request_event,guard_event,decision_event]
        elif race:
            launch=provenance(path,source,agent,"parallel_guard_and_model_turn_registration");allow_events=[launch,request_event,sink_event,guard_event,decision_event];deny_events=list(allow_events)
        else:
            launch=provenance(path,source,agent,"parallel_guard_and_model_turn_registration");wait=provenance(path,source,unique(calls(tool,"decision_ready.wait"),"openai_decision_wait"),"wait_for_policy_decision");allow_events=[launch,request_event,guard_event,decision_event,wait,sink_event];deny_events=[launch,request_event,guard_event,decision_event,wait]
        site={"sink_site":stable_node_id(repository_id,"effect",path,sink.lineno,"marker.write_text"),"path":path,"line":sink.lineno,"relation":"same_logical_effect","allow_effect_occurs":True,"deny_effect_occurs":deny_occurs,"identity_scope":"originating_request_resource_and_operation","source_evidence":sink_event}
        return {**base,"status":"supported","gaps":[],"mode":mode,"logical_identity":{"request":"fixed_selected_tool_call","resource":"run_cell.marker","operation":"successful_text_publication","binding_verified":True},"guard":decision_event,"sink":sink_event,"sites":[site],"paths":[{"decision":"ALLOW","events":allow_events,"selected_effect_occurs":True,"guard_reports_deny":False},{"decision":"DENY","events":deny_events,"selected_effect_occurs":deny_occurs,"guard_reports_deny":True}],"review_evidence":{"request_binding":[request_event,provenance(path,source,tool,"registered_tool"),provenance(path,source,agent,"agent_registration"),provenance(path,source,runner,"closed_runner_call")],"closed_application_path":[provenance(path,source,run,"closed_run_cell")]},"issue_prediction":deny_occurs,"source_semantics_verified":True,"scope":"openai_agents_0_22_runner_one_function_tool_first_turn_normal_asyncio"}
    except (SyntaxError,Unsupported,KeyError,AttributeError,IndexError) as exc:return {**base,"status":"unknown","gaps":[str(exc) if isinstance(exc,Unsupported) else "source_shape_error"],"paths":[]}
