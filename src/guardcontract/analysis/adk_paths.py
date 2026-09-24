"""Fail-closed source lowering for the frozen Google ADK callback contract."""
import ast
import hashlib

from guardcontract.analysis.langchain_paths import Unsupported, calls, comparison, dotted, function, provenance, unique
from guardcontract.discovery.router import stable_node_id


def analyze(source, sdk_contract, *, repository_id, path="app.py"):
    base = {"schema_version": "google-adk-path-certificate-1", "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
            "sdk_contract_sha256": sdk_contract.get("contract_sha256"), "runtime_reference_read": False,
            "assembly_ready": False}
    required = {"before_tool_non_none_skips_selected_tool", "before_tool_none_continues_to_selected_tool",
                "after_tool_callback_occurs_after_successful_tool", "one_fixed_request_completes_with_two_model_calls"}
    if not repository_id:
        return {**base, "status": "unknown", "gaps": ["repository_identity_required"], "paths": []}
    if sdk_contract.get("schema_version") != "google-adk-sdk-contract-1" or not all(sdk_contract.get("facts", {}).get(k) is True for k in required):
        return {**base, "status": "unknown", "gaps": ["sdk_contract_not_applicable"], "paths": []}
    try:
        tree = ast.parse(source)
        run = function(tree, "_run_cell")
        tool = function(run, "publish_canary")
        decide = function(run, "decide")
        before = function(run, "before_tool_callback")
        after = function(run, "after_tool_callback")
        model_generate = function(tree, "DeterministicAdkModel.generate_content_async")
        request = unique(calls(model_generate, "types.Part.from_function_call"), "adk_fixed_request")
        request_kwargs = {row.arg: row.value for row in request.keywords if row.arg}
        if dotted(request_kwargs.get("name")) != "TOOL_NAME" or not isinstance(request_kwargs.get("args"), ast.Dict):
            raise Unsupported("adk_request_binding")
        constant_nodes = {row.targets[0].id: row for row in tree.body if isinstance(row, ast.Assign) and len(row.targets) == 1
                          and isinstance(row.targets[0], ast.Name) and isinstance(row.value, ast.Constant)}
        constants = {name: row.value.value for name, row in constant_nodes.items()}
        if constants.get("TOOL_NAME") != tool.name:
            raise Unsupported("adk_tool_name")
        agent_call = unique(calls(run, "LlmAgent"), "adk_one_agent")
        keywords = {row.arg: row.value for row in agent_call.keywords if row.arg}
        if set(keywords) != {"name", "model", "tools", "before_tool_callback", "after_tool_callback"} or not isinstance(keywords["tools"], ast.List) or [dotted(x) for x in keywords["tools"].elts] != [tool.name]:
            raise Unsupported("adk_agent_configuration")
        if dotted(keywords["before_tool_callback"]) != before.name or dotted(keywords["after_tool_callback"]) != after.name:
            raise Unsupported("adk_callback_binding")
        sink = unique(calls(tool, "marker.write_text"), "adk_tool_sink")
        all_writes = [row for row in ast.walk(tree) if isinstance(row, ast.Call) and dotted(row.func) and dotted(row.func).endswith(".write_text")]
        if all_writes != [sink] or not sink.args or dotted(sink.args[0]) != "payload":
            raise Unsupported("adk_additional_or_changed_write")
        # Accept the local verdict comparison explicitly.
        local_deny = [row for row in ast.walk(decide) if isinstance(row, ast.Compare) and isinstance(row.left, ast.Name)
                      and row.left.id == "verdict" and len(row.comparators) == 1 and isinstance(row.comparators[0], ast.Constant)
                      and row.comparators[0].value == "DENY"]
        if len(local_deny) != 1 or len(calls(decide, "record")) != 1:
            raise Unsupported("adk_policy_decision")
        before_decide, after_decide = calls(before, "decide"), calls(after, "decide")
        def conditional_return(callback, verdict):
            rows = [row for row in callback.body if isinstance(row, ast.Return) and isinstance(row.value, ast.IfExp)
                    and isinstance(row.value.test, ast.Compare) and isinstance(row.value.test.left, ast.Name)
                    and row.value.test.left.id == "verdict" and len(row.value.test.comparators) == 1
                    and isinstance(row.value.test.comparators[0], ast.Constant) and row.value.test.comparators[0].value == verdict
                    and isinstance(row.value.body, ast.Call) and dotted(row.value.body.func) == "decide"
                    and isinstance(row.value.orelse, ast.Constant) and row.value.orelse.value is None]
            return len(rows) == 1
        split = len(before_decide) == len(after_decide) == 1 and conditional_return(before, "DENY") and conditional_return(after, "ALLOW")
        if not split and (bool(before_decide) == bool(after_decide) or len(before_decide) > 1 or len(after_decide) > 1):
            raise Unsupported("adk_decision_placement")
        mode = "split_guard" if split else "before_tool" if before_decide else "after_tool"
        request_event = provenance(path, source, request, "selected_tool_request")
        before_event = provenance(path, source, before, "before_tool_callback")
        tool_event = provenance(path, source, sink, "selected_write")
        decide_event = provenance(path, source, decide, "applicable_policy_decision")
        after_event = provenance(path, source, after, "after_tool_callback")
        if mode == "after_tool":
            allow_events = [request_event, before_event, tool_event, after_event, decide_event]
            deny_events = list(allow_events); deny_occurs = True
        else:
            allow_events = [request_event, before_event, decide_event, tool_event, after_event]
            deny_events = [request_event, before_event, decide_event]; deny_occurs = False
        site_id = stable_node_id(repository_id, "effect", path, sink.lineno, "marker.write_text")
        return {**base, "status": "supported", "gaps": [], "mode": mode,
            "logical_identity": {"request": "fixed_selected_tool_call", "resource": "run_cell.marker",
                                 "operation": "successful_text_publication", "binding_verified": True},
            "guard": decide_event, "sink": tool_event, "sites": [{"sink_site": site_id, "path": path, "line": sink.lineno,
                "relation": "same_logical_effect", "allow_effect_occurs": True, "deny_effect_occurs": deny_occurs,
                "identity_scope": "originating_request_resource_and_operation", "source_evidence": tool_event}],
            "paths": [{"decision": "ALLOW", "events": allow_events, "selected_effect_occurs": True, "guard_reports_deny": False},
                      {"decision": "DENY", "events": deny_events, "selected_effect_occurs": deny_occurs, "guard_reports_deny": True}],
            "review_evidence": {"request_binding": [provenance(path, source, constant_nodes[name], "request_constant") for name in ("PAYLOAD", "TOOL_NAME")]
                + [provenance(path, source, model_generate, "model_request_source"), provenance(path, source, tool, "registered_tool"),
                   provenance(path, source, agent_call, "agent_registration")],
                "closed_application_path": [provenance(path, source, run, "closed_run_cell")]},
            "issue_prediction": deny_occurs, "source_semantics_verified": True,
            "scope": "google_adk_2_7_inmemory_single_request_normal_io_source_certificate"}
    except (SyntaxError, Unsupported, KeyError, AttributeError, IndexError) as exc:
        return {**base, "status": "unknown", "gaps": [str(exc) if isinstance(exc, Unsupported) else "source_shape_error"], "paths": []}
