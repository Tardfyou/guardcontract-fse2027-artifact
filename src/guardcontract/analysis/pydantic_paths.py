"""Fail-closed source lowering for the frozen Pydantic AI contract."""
import ast,hashlib
from guardcontract.analysis.langchain_paths import Unsupported,calls,comparison,dotted,function,provenance,unique,verify_helper
from guardcontract.discovery.router import stable_node_id

def analyze(source,helper_source,sdk_contract,*,repository_id,path="app.py",helper_path="deferred_effects.py"):
    base={"schema_version":"pydantic-path-certificate-1","source_sha256":hashlib.sha256(source.encode()).hexdigest(),"helper_source_sha256":hashlib.sha256(helper_source.encode()).hexdigest(),
          "sdk_contract_sha256":sdk_contract.get("contract_sha256"),"runtime_reference_read":False,"assembly_ready":False}
    required={"registered_tool_executes_before_output_validator","output_validator_retry_occurs_after_tool","output_validator_allow_returns_final_output","one_fixed_tool_request"}
    if not repository_id:return {**base,"status":"unknown","gaps":["repository_identity_required"],"paths":[]}
    if sdk_contract.get("schema_version")!="pydantic-sdk-contract-1" or not all(sdk_contract.get("facts",{}).get(k) is True for k in required):return {**base,"status":"unknown","gaps":["sdk_contract_not_applicable"],"paths":[]}
    try:
        tree=ast.parse(source);run=function(tree,"run_cell")
        helper_module=helper_path.removesuffix(".py").replace("/",".")
        if len([r for r in tree.body if isinstance(r,ast.ImportFrom) and r.module==helper_module and any(a.name=="DeferredEffectLedger" for a in r.names)])!=1:raise Unsupported("helper_import_binding")
        tools=[r for r in run.body if isinstance(r,ast.FunctionDef) and any(isinstance(d,ast.Attribute) and dotted(d)=="agent.tool_plain" for d in r.decorator_list)]
        validators=[r for r in run.body if isinstance(r,ast.FunctionDef) and any(isinstance(d,ast.Attribute) and dotted(d)=="agent.output_validator" for d in r.decorator_list)]
        tool=unique(tools,"pydantic_one_tool");guard=unique(validators,"pydantic_one_output_validator")
        agent=unique(calls(run,"Agent"),"pydantic_one_agent");agent_kwargs={k.arg:k.value for k in agent.keywords if k.arg}
        if not isinstance(agent_kwargs.get("retries"),ast.Constant) or agent_kwargs["retries"].value!=0:raise Unsupported("pydantic_retry_policy")
        model_init=function(tree,"CountingTestModel.__init__");super_init=unique((r for r in ast.walk(model_init) if isinstance(r,ast.Call)
            and isinstance(r.func,ast.Attribute) and r.func.attr=="__init__" and isinstance(r.func.value,ast.Call)
            and isinstance(r.func.value.func,ast.Name) and r.func.value.func.id=="super"),"pydantic_test_model")
        if not any(k.arg=="call_tools" and isinstance(k.value,ast.List) and [dotted(e) for e in k.value.elts]==["TOOL_NAME"] for k in super_init.keywords):raise Unsupported("pydantic_fixed_tool_request")
        constant_nodes={r.targets[0].id:r for r in tree.body if isinstance(r,ast.Assign) and len(r.targets)==1 and isinstance(r.targets[0],ast.Name) and isinstance(r.value,ast.Constant)}
        constants={name:r.value.value for name,r in constant_nodes.items()}
        if constants.get("TOOL_NAME")!=tool.name:raise Unsupported("pydantic_tool_name")
        direct=calls(tool,"marker.write_text");stages=calls(tool,"ledger.stage_text_write")
        if bool(direct)==bool(stages) or len(direct)>1 or len(stages)>1:raise Unsupported("pydantic_tool_effect_shape")
        helper=verify_helper(helper_source,helper_path);mode="direct_write" if direct else "deferred_stage"
        deny=[r for r in guard.body if isinstance(r,ast.If) and isinstance(r.test,ast.Compare) and isinstance(r.test.left,ast.Name) and r.test.left.id=="verdict" and isinstance(r.test.comparators[0],ast.Constant) and r.test.comparators[0].value=="DENY"]
        deny=unique(deny,"pydantic_deny_branch")
        if not calls(deny,"ModelRetry"):raise Unsupported("pydantic_deny_retry")
        commits=calls(guard,"ledger.commit");aborts=calls(guard,"ledger.abort")
        if mode=="direct_write" and (commits or aborts):raise Unsupported("pydantic_unexpected_ledger")
        if mode=="deferred_stage" and (len(commits)!=1 or len(aborts)!=1):raise Unsupported("pydantic_commit_abort")
        all_writes=[r for r in ast.walk(tree) if isinstance(r,ast.Call) and dotted(r.func) and dotted(r.func).endswith(".write_text")]
        if len(all_writes)!=(1 if mode=="direct_write" else 0):raise Unsupported("pydantic_additional_write")
        sink_node=direct[0] if direct else helper["commit"];sink_kind="direct_selected_write" if direct else "successful_pending_write"
        request=provenance(path,source,model_init,"fixed_selected_tool_request");tool_event=provenance(path,source,tool,"registered_tool")
        guard_event=provenance(path,source,guard,"output_validator_deny");sink_event=provenance(path if direct else helper_path,source if direct else helper_source,sink_node if direct else function(ast.parse(helper_source),"DeferredEffectLedger._commit"),sink_kind) if direct else helper["commit"]
        if mode=="direct_write":allow_events=[request,tool_event,sink_event,guard_event];deny_events=list(allow_events);deny_occurs=True
        else:
            stage_event=provenance(path,source,stages[0],"stage_selected_request_resource_payload")
            allow_events=[request,tool_event,stage_event,provenance(path,source,commits[0],"allow_commit"),helper["commit"],guard_event]
            deny_events=[request,tool_event,stage_event,provenance(path,source,aborts[0],"deny_abort"),helper["abort"],guard_event];deny_occurs=False
        helper_site=stable_node_id(repository_id,"effect",helper_path,helper["commit"]["start_line"],"effect.path.write_text")
        sites=[]
        if mode=="direct_write":
            direct_site=stable_node_id(repository_id,"effect",path,all_writes[0].lineno,"marker.write_text")
            sites.append({"sink_site":direct_site,"path":path,"line":all_writes[0].lineno,"relation":"same_logical_effect","allow_effect_occurs":True,"deny_effect_occurs":True})
        sites.append({"sink_site":helper_site,"path":helper_path,"line":helper["commit"]["start_line"],"relation":"same_logical_effect" if mode=="deferred_stage" else "unknown","allow_effect_occurs":mode=="deferred_stage","deny_effect_occurs":False})
        return {**base,"status":"supported","gaps":[],"mode":mode,"helper_path":helper_path,"guard":guard_event,"sink":sink_event,"sites":sites,
            "paths":[{"decision":"ALLOW","events":allow_events,"selected_effect_occurs":True,"guard_reports_deny":False},{"decision":"DENY","events":deny_events,"selected_effect_occurs":deny_occurs,"guard_reports_deny":True}],
            "review_evidence":{"request_binding":[provenance(path,source,constant_nodes[name],"request_constant") for name in ("PAYLOAD","TOOL_NAME")]
                +[provenance(path,source,model_init,"model_request_source"),provenance(path,source,tool,"registered_tool"),provenance(path,source,agent,"agent_registration")],
                "closed_application_path":[provenance(path,source,run,"closed_run_cell")]},
            "issue_prediction":deny_occurs,"source_semantics_verified":True,"scope":"pydantic_ai_2_40_run_sync_single_tool_normal_io"}
    except (SyntaxError,Unsupported,KeyError,AttributeError,IndexError) as exc:return {**base,"status":"unknown","gaps":[str(exc) if isinstance(exc,Unsupported) else "source_shape_error"],"paths":[]}
