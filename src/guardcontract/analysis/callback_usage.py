"""Locate formal callback usage without asserting runtime activation or effects."""
import ast
import hashlib
import symtable


def extract(source, symbol, start_line, end_line):
    result = {"task_version": "198-2", "symbol": symbol, "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
              "scope": "formal_callback_references_only", "runtime_activation_proven": False,
              "effect_occurrence_proven": False, "control_flow_complete": False, "status": "unknown", "gaps": []}
    try:
        tree = ast.parse(source)
        table = symtable.symtable(source, "registered-source.py", "exec")
    except SyntaxError:
        return {**result, "gaps": ["source_syntax"]}
    current, scope = tree, table
    for name in symbol.split("."):
        candidates = [n for n in current.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.name == name]
        if len(candidates) != 1:
            return {**result, "gaps": ["ambiguous_definition"]}
        current = candidates[0]
        tables = [t for t in scope.get_children() if t.get_name() == name and t.get_lineno() == current.lineno]
        if len(tables) != 1:
            return {**result, "gaps": ["symbol_table_definition_mismatch"]}
        scope = tables[0]
    if not isinstance(current, ast.FunctionDef) or (current.lineno, current.end_lineno) != (start_line, end_line):
        return {**result, "gaps": ["registered_span_mismatch_or_async"]}
    args = current.args
    if len(args.args) != 3 or args.posonlyargs or args.kwonlyargs or args.vararg or args.kwarg or args.defaults or current.decorator_list:
        return {**result, "gaps": ["unresolved_wrapper_signature"]}
    request, callback = args.args[1].arg, args.args[2].arg
    result["formals"] = {"request": request, "callback": callback}
    for name in (request, callback):
        entry = scope.lookup(name)
        if entry.is_assigned() or entry.is_imported() or not entry.is_parameter():
            result["gaps"].append("formal_rebound:" + name)
    nodes = [n for statement in current.body for n in ast.walk(statement)]
    if any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda,
                         ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)) for n in nodes):
        result["gaps"].append("nested_scope_callback_analysis_required")
    parents = {child: node for node in nodes for child in ast.iter_child_nodes(node)}
    references = [n for n in nodes if isinstance(n, ast.Name) and n.id == callback and isinstance(n.ctx, ast.Load)]
    calls = []
    for reference in references:
        parent = parents.get(reference)
        if not isinstance(parent, ast.Call) or parent.func is not reference:
            result["gaps"].append("callback_escapes_or_indirect_use")
            continue
        direct_request = len(parent.args) == 1 and isinstance(parent.args[0], ast.Name) and parent.args[0].id == request and not parent.keywords
        if not direct_request:
            result["gaps"].append("callback_request_binding_changed")
        controls, cursor = [], parent
        while cursor in parents:
            cursor = parents[cursor]
            if isinstance(cursor, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With, ast.AsyncWith, ast.Match, ast.IfExp, ast.BoolOp)):
                controls.append({"kind": type(cursor).__name__, "line": cursor.lineno})
        calls.append({"line": parent.lineno, "end_line": parent.end_lineno,
                      "expression": ast.get_source_segment(source, parent), "direct_request_argument": direct_request,
                      "enclosing_controls": controls})
    result.update(direct_call_sites=calls, syntactic_reference_count=len(references),
                  request_contents_unchanged_proven=False,
                  usage="direct_calls" if references and len(calls) == len(references) else "no_explicit_reference" if not references else "indirect_or_escaped",
                  gaps=sorted(set(result["gaps"])))
    if not result["gaps"]:
        result["status"] = "resolved_formal_usage"
    return result
