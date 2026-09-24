"""Fail-closed source lowering for the pinned synchronous LangChain contract."""
import ast
import hashlib

from guardcontract.analysis.callable_bindings import extract as callable_bindings
from guardcontract.discovery.router import stable_node_id


class Unsupported(ValueError):
    pass


def source_sha(source):
    return hashlib.sha256(source.encode()).hexdigest()


def dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return base + "." + node.attr if base else None
    return None


def unique(nodes, reason):
    rows = list(nodes)
    if len(rows) != 1:
        raise Unsupported(reason)
    return rows[0]


def function(tree, symbol):
    node = tree
    for name in symbol.split("."):
        node = unique((row for row in node.body if isinstance(row, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
                       and row.name == name), "definition:" + symbol)
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        raise Unsupported("not_function:" + symbol)
    return node


def calls(node, name):
    return [row for row in ast.walk(node) if isinstance(row, ast.Call) and dotted(row.func) == name]


def comparison(node, owner, attribute, value):
    return (isinstance(node, ast.Compare) and len(node.ops) == len(node.comparators) == 1
            and isinstance(node.ops[0], ast.Eq) and dotted(node.left) == owner + "." + attribute
            and isinstance(node.comparators[0], ast.Constant) and node.comparators[0].value == value)


def provenance(path, source, node, kind):
    return {"kind": kind, "path": path, "source_sha256": source_sha(source),
            "start_line": node.lineno, "end_line": node.end_lineno}


def verify_helper(source, path="deferred_effects.py"):
    tree = ast.parse(source)
    stage = function(tree, "DeferredEffectLedger.stage_text_write")
    commit = function(tree, "DeferredEffectLedger._commit")
    public_commit = function(tree, "DeferredEffectLedger.commit")
    abort = function(tree, "DeferredEffectLedger._abort")
    public_abort = function(tree, "DeferredEffectLedger.abort")
    append = unique((c for c in calls(stage, "transaction.pending_effects.append")
                     if c.args and isinstance(c.args[0], ast.Call) and dotted(c.args[0].func) == "PendingTextWrite"), "helper_stage_shape")
    pending = append.args[0]
    if len(pending.args) < 2 or dotted(pending.args[0].func) != "Path" or not isinstance(pending.args[0].args[0], ast.Name) or pending.args[0].args[0].id != "path" or not isinstance(pending.args[1], ast.Name) or pending.args[1].id != "data":
        raise Unsupported("helper_stage_resource_payload")
    write = unique(calls(commit, "effect.path.write_text"), "helper_commit_write")
    if not write.args or dotted(write.args[0]) != "effect.data":
        raise Unsupported("helper_commit_payload")
    if len(calls(public_commit, "self._commit")) != 1 or len(calls(public_abort, "self._abort")) != 1:
        raise Unsupported("helper_public_delegation")
    if len(calls(abort, "transaction.pending_effects.clear")) != 1:
        raise Unsupported("helper_abort_clear")
    return {"status": "supported", "stage": provenance(path, source, stage, "stage_request_resource_payload"),
            "commit": provenance(path, source, write, "successful_pending_write"),
            "abort": provenance(path, source, abort, "clear_pending_without_write"),
            "source_semantics": "bounded_pending_text_write_only"}


def analyze(app_source, helper_source, sdk_contract, *, repository_id=None, path="app.py", helper_path="deferred_effects.py"):
    base = {"schema_version": "langchain-path-certificate-1", "app_source_sha256": source_sha(app_source),
            "helper_source_sha256": source_sha(helper_source), "sdk_contract_sha256": sdk_contract.get("contract_sha256"),
            "runtime_trace_or_behavior_reference_read": False, "source_semantics_verified": False,
            "assembly_ready": False}
    required_facts = {"synchronous_single_middleware", "pending_tool_request_enters_wrapper",
        "calling_handler_once_executes_selected_registered_tool_once", "wrapper_return_routes_to_model_then_after_agent",
        "wrapper_return_without_handler_skips_selected_tool", "after_agent_deny_occurs_after_successful_handler_effect"}
    if not isinstance(repository_id, str) or not repository_id:
        return {**base, "status": "unknown", "gaps": ["repository_identity_required"], "paths": []}
    if sdk_contract.get("schema_version") != "langchain-sdk-contract-1" or not all(sdk_contract.get("facts", {}).get(k) is True for k in required_facts):
        return {**base, "status": "unknown", "gaps": ["sdk_contract_not_applicable"], "paths": []}
    try:
        app = ast.parse(app_source)
        helper_module = helper_path.removesuffix(".py").replace("/", ".")
        helper_imports = [row for row in app.body if isinstance(row, ast.ImportFrom) and row.level == 0
                          and row.module == helper_module and any(alias.name == "DeferredEffectLedger" for alias in row.names)]
        if len(helper_imports) != 1:
            raise Unsupported("helper_import_binding")
        run = function(app, "run_cell")
        creates = [(parent, call) for parent in ast.walk(run) for call in ([parent.value] if isinstance(parent, ast.Assign) and isinstance(parent.value, ast.Call) else [])
                   if dotted(call.func) == "create_agent"]
        assignment, create = unique(creates, "one_create_agent")
        if len(assignment.targets) != 1 or not isinstance(assignment.targets[0], ast.Name):
            raise Unsupported("agent_binding")
        agent_name = assignment.targets[0].id
        keywords = {row.arg: row.value for row in create.keywords if row.arg}
        if set(keywords) != {"model", "tools", "middleware"} or not isinstance(keywords["tools"], ast.List) or len(keywords["tools"].elts) != 1 or not isinstance(keywords["middleware"], ast.List) or len(keywords["middleware"].elts) != 1:
            raise Unsupported("create_agent_configuration")
        tool_name = dotted(keywords["tools"].elts[0])
        middleware_name = dotted(keywords["middleware"].elts[0])
        if not tool_name or not middleware_name:
            raise Unsupported("registered_binding_names")
        middleware_assign = unique((row for row in ast.walk(run) if isinstance(row, ast.Assign) and len(row.targets) == 1
                                    and isinstance(row.targets[0], ast.Name) and row.targets[0].id == middleware_name
                                    and isinstance(row.value, ast.Call)), "middleware_constructor")
        middleware_class = dotted(middleware_assign.value.func)
        model_name = dotted(keywords["model"])
        model_assign = unique((row for row in ast.walk(run) if isinstance(row, ast.Assign) and len(row.targets) == 1
                               and isinstance(row.targets[0], ast.Name) and row.targets[0].id == model_name
                               and isinstance(row.value, ast.Call)), "model_constructor")
        if dotted(model_assign.value.func) != "DeterministicToolModel":
            raise Unsupported("model_request_source")
        tool = function(run, tool_name)
        wrapper = function(app, middleware_class + ".wrap_tool_call")
        after = function(app, middleware_class + ".after_agent")
        invocation = unique((c for c in calls(run, agent_name + ".invoke")), "one_agent_invoke")
        # Bind the fixed model request to the selected registered tool.
        generate = function(app, "DeterministicToolModel._generate")
        tool_request = unique((c for c in ast.walk(generate) if isinstance(c, ast.Call) and dotted(c.func) == "AIMessage"
                              and any(k.arg == "tool_calls" for k in c.keywords)), "fixed_tool_request")
        tool_calls_node = next(k.value for k in tool_request.keywords if k.arg == "tool_calls")
        if not isinstance(tool_calls_node, ast.List) or len(tool_calls_node.elts) != 1 or not isinstance(tool_calls_node.elts[0], ast.Dict):
            raise Unsupported("fixed_tool_request_shape")
        request_dict = {k.value: v for k, v in zip(tool_calls_node.elts[0].keys, tool_calls_node.elts[0].values)
                        if isinstance(k, ast.Constant) and isinstance(k.value, str)}
        if dotted(request_dict.get("name")) != "TOOL_NAME" or not isinstance(tool.decorator_list[0], ast.Name) or tool.decorator_list[0].id != "tool":
            raise Unsupported("tool_request_registration_binding")
        constant_nodes = {row.targets[0].id: row for row in app.body if isinstance(row, ast.Assign) and len(row.targets) == 1
                          and isinstance(row.targets[0], ast.Name) and isinstance(row.value, ast.Constant)}
        constants = {name: row.value.value for name, row in constant_nodes.items()}
        if constants.get("TOOL_NAME") != tool.name:
            raise Unsupported("tool_name_mismatch")
        args_node = request_dict.get("args")
        if not isinstance(args_node, ast.Dict) or len(args_node.keys) != 1 or not isinstance(args_node.keys[0], ast.Constant) or args_node.keys[0].value != "payload" or dotted(args_node.values[0]) != "PAYLOAD":
            raise Unsupported("tool_request_payload_binding")
        if not tool.args.args or tool.args.args[0].arg != "payload":
            raise Unsupported("tool_payload_parameter")
        constructor_args = {row.arg: dotted(row.value) for row in middleware_assign.value.keywords if row.arg}
        if constructor_args.get("verdict") != "verdict" or constructor_args.get("marker") != "marker" or constructor_args.get("ledger") != "ledger":
            raise Unsupported("middleware_context_binding")
        marker_assign = unique((row for row in run.body if isinstance(row, ast.Assign) and len(row.targets) == 1
                                and isinstance(row.targets[0], ast.Name) and row.targets[0].id == "marker"), "marker_binding")
        direct_sink = calls(tool, "marker.write_text")
        if len(direct_sink) != 1 or not direct_sink[0].args or dotted(direct_sink[0].args[0]) != "payload":
            raise Unsupported("tool_sink_shape")
        all_app_writes = [row for row in ast.walk(app) if isinstance(row, ast.Call) and dotted(row.func) and dotted(row.func).endswith(".write_text")]
        if all_app_writes != direct_sink:
            raise Unsupported("additional_application_writes")
        if any(isinstance(row, ast.Name) and row.id == "deferred_effect_scope" for row in ast.walk(run)):
            raise Unsupported("active_deferred_scope_unknown")
        handler_facts = callable_bindings(app_source, middleware_class + ".wrap_tool_call", wrapper.lineno, wrapper.end_lineno)
        handler_calls = [row for row in handler_facts["bindings"] if row["name"] == wrapper.args.args[2].arg]
        stage_calls = calls(wrapper, "self.ledger.stage_text_write")
        if bool(handler_calls) == bool(stage_calls):
            raise Unsupported("wrapper_must_call_handler_xor_stage")
        mode = "direct_handler" if handler_calls else "deferred_stage"
        if mode == "direct_handler":
            if len(handler_calls) != 1 or handler_calls[0]["expression"] != f"{wrapper.args.args[2].arg}({wrapper.args.args[1].arg})" or handler_calls[0]["enclosing_controls"]:
                raise Unsupported("handler_request_binding")
        else:
            stage_call = unique(stage_calls, "one_stage_call")
            if len(stage_call.args) != 2 or dotted(stage_call.args[0]) != "self.marker" or dotted(stage_call.args[1]) != "payload":
                raise Unsupported("stage_request_resource_binding")
            parents = {child: parent for parent in ast.walk(wrapper) for child in ast.iter_child_nodes(parent)}
            cursor = stage_call
            while cursor in parents and parents[cursor] is not wrapper:
                cursor = parents[cursor]
                if isinstance(cursor, (ast.If, ast.Try, ast.For, ast.While, ast.Match, ast.With)):
                    raise Unsupported("conditional_stage_unknown")
        if not any(isinstance(row, ast.Return) for row in wrapper.body):
            raise Unsupported("wrapper_return")
        deny_ifs = [row for row in after.body if isinstance(row, ast.If) and comparison(row.test, "self", "verdict", "DENY")]
        deny_if = unique(deny_ifs, "deny_branch")
        if not any(isinstance(row, ast.Raise) for row in deny_if.body):
            raise Unsupported("deny_does_not_terminate")
        helper = verify_helper(helper_source, helper_path)
        commit_calls, abort_calls = calls(after, "self.ledger.commit"), calls(after, "self.ledger.abort")
        ledger_calls = lambda method: [row for row in ast.walk(app) if isinstance(row, ast.Call)
                                        and dotted(row.func) in {"self.ledger." + method, "ledger." + method}]
        all_stages = ledger_calls("stage_text_write")
        all_commits = ledger_calls("commit")
        all_aborts = ledger_calls("abort")
        if mode == "direct_handler" and (commit_calls or abort_calls):
            raise Unsupported("unexpected_ledger_path")
        if mode == "direct_handler" and (all_stages or all_commits or all_aborts):
            raise Unsupported("unexpected_application_ledger_operation")
        if mode == "deferred_stage":
            allow_if = unique((row for row in after.body if isinstance(row, ast.If) and comparison(row.test, "self", "verdict", "ALLOW")), "allow_commit_branch")
            if (len([c for row in allow_if.body for c in ast.walk(row) if isinstance(c, ast.Call) and dotted(c.func) == "self.ledger.commit"]) != 1
                    or len([c for row in allow_if.orelse for c in ast.walk(row) if isinstance(c, ast.Call) and dotted(c.func) == "self.ledger.abort"]) != 1
                    or calls(ast.Module(body=allow_if.body, type_ignores=[]), "self.ledger.abort")
                    or calls(ast.Module(body=allow_if.orelse, type_ignores=[]), "self.ledger.commit")):
                raise Unsupported("commit_abort_partition")
            if all_stages != stage_calls or all_commits != commit_calls or all_aborts != abort_calls:
                raise Unsupported("additional_application_ledger_operation")
        request = provenance(path, app_source, tool_request, "selected_tool_request")
        wrapper_event = provenance(path, app_source, wrapper, "wrapper")
        tool_effect = provenance(path, app_source, direct_sink[0], "direct_selected_write")
        guard = provenance(path, app_source, deny_if, "applicable_deny_and_termination")
        common = [request, wrapper_event]
        if mode == "direct_handler":
            common += [provenance(path, app_source, wrapper, "same_request_handler_call"), tool_effect]
            allow_events = [*common, provenance(path, app_source, after, "after_agent_allow")]
            deny_events = [*common, guard]
            allow_occurs = deny_occurs = True
            sink = tool_effect
            helper_relation = "unknown"
            site_states = ((tool_effect, "same_logical_effect", True, True),
                           (helper["commit"], helper_relation, False, False))
        else:
            stage_event = provenance(path, app_source, stage_call, "stage_selected_request_resource_payload")
            common += [stage_event]
            commit_event = provenance(path, app_source, commit_calls[0], "policy_allow_commit")
            abort_event = provenance(path, app_source, abort_calls[0], "policy_deny_abort")
            allow_events = [*common, commit_event, helper["commit"], provenance(path, app_source, after, "after_agent_allow")]
            deny_events = [*common, abort_event, helper["abort"], guard]
            allow_occurs, deny_occurs, sink = True, False, helper["commit"]
            site_states = ((tool_effect, "same_logical_effect", False, False),
                           (helper["commit"], "same_logical_effect", True, False))
        sites = []
        calls_by_kind = {"direct_selected_write": "marker.write_text", "successful_pending_write": "effect.path.write_text"}
        for physical, relation, allow_state, deny_state in site_states:
            site_id = stable_node_id(repository_id, "effect", physical["path"], physical["start_line"], calls_by_kind[physical["kind"]])
            sites.append({"sink_site": site_id, "path": physical["path"], "line": physical["start_line"],
                          "relation": relation, "allow_effect_occurs": allow_state, "deny_effect_occurs": deny_state,
                          "identity_scope": "originating_request_resource_and_operation",
                          "source_evidence": physical})
        return {**base, "status": "supported", "mode": mode, "gaps": [],
            "middleware_class": middleware_class,
            "helper_path": helper_path,
            "logical_identity": {"request": "fixed_selected_tool_call", "resource": "run_cell.marker",
                                 "operation": "successful_text_publication", "binding_verified": True},
            "guard": guard, "sink": sink, "paths": [
                {"decision": "ALLOW", "events": allow_events, "selected_effect_occurs": allow_occurs, "guard_reports_deny": False},
                {"decision": "DENY", "events": deny_events, "selected_effect_occurs": deny_occurs, "guard_reports_deny": True}],
            "sites": sites,
            "review_evidence": {
                "request_binding": [provenance(path, app_source, constant_nodes[name], "request_constant") for name in ("PAYLOAD", "TOOL_NAME")]
                    + [provenance(path, app_source, generate, "model_request_source"), provenance(path, app_source, tool, "registered_tool"),
                       provenance(path, app_source, create, "tool_registration"), provenance(path, app_source, invocation, "entrypoint_invocation")],
                "closed_application_path": [provenance(path, app_source, run, "closed_run_cell")],
            },
            "issue_prediction": deny_occurs, "sdk_facts_used": sorted(required_facts),
            "source_semantics_verified": True, "assembly_ready": False,
            "scope": "pinned_sync_langchain_single_request_normal_io_source_certificate"}
    except (SyntaxError, Unsupported, KeyError, IndexError, AttributeError) as exc:
        return {**base, "status": "unknown", "gaps": [str(exc) if isinstance(exc, Unsupported) else "source_shape_error"], "paths": []}
