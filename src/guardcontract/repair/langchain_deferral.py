"""Minimal source-bound deferral repair for a verified direct-handler path."""
import ast
import hashlib

from guardcontract.analysis.langchain_paths import analyze, dotted, function, Unsupported


def source_sha(source):
    return hashlib.sha256(source.encode()).hexdigest()


def indentation(line):
    return line[:len(line) - len(line.lstrip())]


def replace_lines(lines, start, end, replacement):
    return [*lines[:start - 1], *replacement, *lines[end:]]


def propose(app_source, helper_source, certificate, sdk_contract):
    if certificate.get("status") != "supported" or certificate.get("mode") != "direct_handler" or certificate.get("issue_prediction") is not True:
        raise ValueError("repair_requires_verified_direct_handler_issue")
    if certificate.get("app_source_sha256") != source_sha(app_source) or certificate.get("helper_source_sha256") != source_sha(helper_source):
        raise ValueError("repair_source_identity")
    tree = ast.parse(app_source)
    middleware_class = certificate.get("middleware_class")
    if not isinstance(middleware_class, str) or not middleware_class:
        raise ValueError("repair_middleware_identity")
    init = function(tree, middleware_class + ".__init__")
    wrapper = function(tree, middleware_class + ".wrap_tool_call")
    after = function(tree, middleware_class + ".after_agent")
    final_output = [row for row in init.body if isinstance(row, ast.AnnAssign) and dotted(row.target) == "self.final_output"]
    handler_returns = [row for row in wrapper.body if isinstance(row, ast.Return) and isinstance(row.value, ast.Call)
                       and isinstance(row.value.func, ast.Name) and row.value.func.id == wrapper.args.args[2].arg]
    final_assign = [row for row in after.body if isinstance(row, ast.Assign) and len(row.targets) == 1 and dotted(row.targets[0]) == "self.final_output"]
    if len(final_output) != 1 or len(handler_returns) != 1 or len(final_assign) != 1:
        raise ValueError("repair_source_shape")
    tail = after.body[after.body.index(final_assign[0]) + 1:]
    if (len(tail) != 3 or not isinstance(tail[0], ast.Expr) or dotted(tail[0].value.func) != "self.record"
            or not isinstance(tail[1], ast.If) or not isinstance(tail[2], ast.Return)):
        raise ValueError("repair_after_agent_shape")
    lines = app_source.splitlines(keepends=True)
    init_indent = indentation(lines[final_output[0].lineno - 1])
    wrapper_indent = indentation(lines[handler_returns[0].lineno - 1])
    request_name = wrapper.args.args[1].arg
    after_indent = indentation(lines[tail[0].lineno - 1])
    edits = [
        {"kind": "track_staged_payload", "start_line": final_output[0].end_lineno + 1, "end_line": final_output[0].end_lineno,
         "replacement": [init_indent + "self.staged_payload: str | None = None\n"]},
        {"kind": "defer_handler_effect", "start_line": handler_returns[0].lineno, "end_line": handler_returns[0].end_lineno,
         "replacement": [wrapper_indent + "self.ledger.stage_text_write(self.marker, payload, encoding='utf-8')\n",
                         wrapper_indent + "self.staged_payload = payload\n",
                         wrapper_indent + f"return ToolMessage(content='publish-request-recorded', tool_call_id={request_name}.tool_call['id'], name=TOOL_NAME)\n"]},
        {"kind": "commit_or_abort_before_policy_return", "start_line": tail[0].lineno, "end_line": tail[-1].end_lineno,
         "replacement": [after_indent + "if self.verdict == 'ALLOW':\n",
                         after_indent + "    if self.ledger.commit() != 1:\n",
                         after_indent + "        raise RuntimeError('expected exactly one committed effect')\n",
                         after_indent + "    self.record('protected_effect', effect=EFFECT_ID, tool=TOOL_NAME, payload=self.staged_payload)\n",
                         after_indent + "else:\n",
                         after_indent + "    self.ledger.abort()\n",
                         after_indent + "self.record('guard_verdict', verdict=self.verdict, decision_inputs=['final_output'], output=self.final_output)\n",
                         after_indent + "if self.verdict == 'DENY':\n",
                         after_indent + "    raise GuardDenied('GuardContract deterministic DENY')\n",
                         after_indent + "return None\n"]},
    ]
    patched = lines
    for edit in sorted(edits, key=lambda row: row["start_line"], reverse=True):
        if edit["end_line"] < edit["start_line"]:
            patched = [*patched[:edit["start_line"] - 1], *edit["replacement"], *patched[edit["start_line"] - 1:]]
        else:
            patched = replace_lines(patched, edit["start_line"], edit["end_line"], edit["replacement"])
    patched_source = "".join(patched)
    ast.parse(patched_source)
    prediction = analyze(patched_source, helper_source, sdk_contract, repository_id="repair-candidate@" + source_sha(patched_source),
                         helper_path=certificate.get("helper_path", "deferred_effects.py"))
    if prediction.get("status") != "supported" or prediction.get("issue_prediction") is not False:
        raise ValueError("repair_static_validation_failed")
    return {"schema_version": "langchain-deferral-repair-1", "strategy": "defer_selected_write_until_allow",
        "original_sha256": source_sha(app_source), "patched_sha256": source_sha(patched_source),
        "edits": edits, "patched_source": patched_source, "static_postcondition": prediction,
        "source_files_changed": 1, "generated_patch": True, "runtime_verified": False,
        "scope": "verified_single_request_sync_langchain_direct_handler_fixture"}
