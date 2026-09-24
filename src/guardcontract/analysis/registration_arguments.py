"""Resolve registration argument expressions without assigning issue labels."""
import ast
import hashlib

from guardcontract.analysis.resource_binding import PythonBindingsV3


def inspect(source, line, keyword):
    index = PythonBindingsV3(source)
    matches = [node for node in ast.walk(index.tree) if isinstance(node, ast.Call)
               and node.lineno == line and any(k.arg == keyword for k in node.keywords)]
    base = {"source_sha256": hashlib.sha256(source.encode()).hexdigest(),
            "call_line": line, "keyword": keyword, "status": "unknown",
            "runtime_activation_verified": False}
    if len(matches) != 1:
        return {**base, "reason": "call_not_unique"}
    call = matches[0]
    constructor = index.resolve(call.func)
    if constructor is None or id(call) in index.dead_nodes:
        return {**base, "reason": "call_binding_unresolved"}
    if any(k.arg is None for k in call.keywords):
        return {**base, "reason": "dynamic_keyword_unpack"}
    value = next(k.value for k in call.keywords if k.arg == keyword)
    scope = index.scopes[id(value)]
    trace, seen = [], set()
    while isinstance(value, ast.Name):
        if value.id in index.named_expression_names | index.externally_declared_names:
            return {**base, "reason": "dynamic_name"}
        current = scope
        while current and value.id not in current.bindings and "*" not in current.bindings:
            current = current.parent
        definitions = current.bindings.get(value.id, []) if current else []
        key = (id(current), value.id)
        if (current is None or "*" in current.bindings or key in seen
                or len(definitions) != 1 or definitions[0] is None or definitions[0][0] != "expr"):
            return {**base, "reason": "argument_binding_unresolved"}
        seen.add(key)
        expression, defining_scope = definitions[0][1:]
        if expression is None or id(expression) in index.dead_nodes:
            return {**base, "reason": "argument_binding_unresolved"}
        if current is scope and (value.lineno, value.col_offset) < (expression.end_lineno, expression.end_col_offset):
            return {**base, "reason": "argument_precedes_assignment"}
        trace.append({"name": value.id, "assignment_value_line": expression.lineno})
        value, scope = expression, defining_scope
    if isinstance(value, ast.Constant) and value.value is None:
        return {**base, "status": "literal_none", "callee": constructor[0], "trace": trace}
    # A collection initializer is useful evidence, but may later be mutated or escape.
    if isinstance(value, (ast.List, ast.Tuple)):
        return {**base, "status": "collection_initializer", "callee": constructor[0],
                "trace": trace, "initializer": ast.unparse(value),
                "effective_collection_verified": False}
    return {**base, "reason": "nonliteral_argument"}
