"""Source-local calls to formal or closure-captured parameters, not execution proof."""
import ast
import hashlib
import symtable


def extract(source, symbol, start_line, end_line):
    result = {"schema_version": "212-1", "symbol": symbol, "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
              "bindings": [], "unresolved_calls": [], "status": "unknown", "gaps": [],
              "runtime_activation_proven": False, "effect_occurrence_proven": False,
              "policy_semantics_verified": False, "control_flow_complete": False}
    try:
        tree = ast.parse(source)
        table = symtable.symtable(source, "source.py", "exec")
    except SyntaxError:
        return {**result, "gaps": ["source_syntax"]}
    node, scopes = tree, []
    for name in symbol.split("."):
        matches = [n for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.name == name]
        if len(matches) != 1:
            return {**result, "gaps": ["ambiguous_or_indirect_definition"]}
        node = matches[0]
        matching_tables = [t for t in table.get_children() if t.get_name() == name and t.get_lineno() == node.lineno]
        if len(matching_tables) != 1:
            return {**result, "gaps": ["symbol_table_mismatch"]}
        table = matching_tables[0]
        scopes.append((node, table))
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or (node.lineno, node.end_lineno) != (start_line, end_line):
        return {**result, "gaps": ["target_span"]}
    parents = {child: parent for parent in ast.walk(node) for child in ast.iter_child_nodes(parent)}
    barriers = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda,
                ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)

    def rebound(owner_table, name):
        own = owner_table.lookup(name)
        if own.is_assigned() or own.is_imported():
            return True
        pending = list(owner_table.get_children())
        while pending:
            child = pending.pop()
            if name in child.get_identifiers():
                entry = child.lookup(name)
                if entry.is_nonlocal() and entry.is_assigned():
                    return True
            pending.extend(child.get_children())
        return False

    for call in ast.walk(node):
        if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name):
            continue
        cursor, controls, nested = call, [], False
        awaited = isinstance(parents.get(call), ast.Await)
        within_body = False
        while cursor in parents:
            previous, cursor = cursor, parents[cursor]
            if cursor is node:
                within_body = previous in node.body
                break
            if isinstance(cursor, barriers):
                nested = True
            if isinstance(cursor, (ast.If, ast.Try, ast.With, ast.AsyncWith, ast.For, ast.AsyncFor, ast.While, ast.IfExp, ast.BoolOp, ast.Match)):
                controls.append({"kind": type(cursor).__name__, "line": cursor.lineno})
        if not within_body:
            result["gaps"].append("definition_time_expression_outside_target_body")
            continue
        if nested:
            result["gaps"].append("nested_expression_or_child_body_not_lowered")
            continue
        name = call.func.id
        entry = table.lookup(name)
        origin = None
        if entry.is_parameter():
            origin = scopes[-1]
        elif entry.is_free():
            for outer_node, outer_table in reversed(scopes[:-1]):
                if outer_table.get_type() != "function" or name not in outer_table.get_identifiers():
                    continue
                candidate = outer_table.lookup(name)
                if candidate.is_parameter():
                    origin = (outer_node, outer_table)
                    break
                if candidate.is_local():
                    break
        reason = None
        if origin is None:
            reason = "not_resolved_to_a_formal_parameter"
        elif rebound(origin[1], name):
            reason = "parameter_or_closure_cell_rebound"
        if reason:
            result["unresolved_calls"].append({"line": call.lineno, "name": name, "reason": reason})
            continue
        result["bindings"].append({"line": call.lineno, "end_line": call.end_lineno,
            "expression": ast.get_source_segment(source, call), "name": name,
            "origin": "target_parameter" if origin[0] is node else "enclosing_function_parameter",
            "parameter_owner_line": origin[0].lineno, "parameter_owner_name": origin[0].name,
            "awaited": awaited, "enclosing_controls": controls,
            "lexical_binding_verified": True, "execution_callback_semantics_verified": False})
    result["gaps"] = sorted(set(result["gaps"]))
    result["status"] = "extracted_lexical_call_facts"
    result["scope"] = "syntactic_call_sites_and_static_parameter_binding_not_actual_calls_or_policy_roles"
    return result
