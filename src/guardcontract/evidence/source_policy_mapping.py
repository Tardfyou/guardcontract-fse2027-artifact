"""Map declarative guard policy, tool registration, and effect nodes in source.

The mapper never imports or executes repository code.  It accepts only Python
AST constructs needed to preserve a policy predicate in an inert fixture; every
unsupported construct fails closed.
"""
from __future__ import annotations

import ast
import hashlib
import itertools
import json
import textwrap
from pathlib import Path
from types import SimpleNamespace

from guardcontract.discovery.framework_declarations import (
    LANGCHAIN_INJECTED_TOOL_PARAMETER_ANNOTATIONS,
)


def _leaf(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _leaf(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _contains_name(node, name):
    return any(isinstance(item, ast.Name) and item.id == name for item in ast.walk(node))


def _import_aliases(tree):
    aliases = {}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module:
            for item in node.names:
                aliases[item.asname or item.name] = f"{node.module}.{item.name}"
        elif isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name.split(".")[0]] = (
                    item.name if item.asname else item.name.split(".")[0])
    return aliases


def _canonical(node, aliases):
    name = _leaf(node)
    if not name:
        return None
    head, *tail = name.split(".")
    base = aliases.get(head, head)
    return ".".join([base, *tail])


def _span(node):
    return {"start_line": node.lineno, "end_line": getattr(node, "end_lineno", node.lineno),
            "start_col": node.col_offset, "end_col": getattr(node, "end_col_offset", None)}


def _source_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_inventory_sha256(paths):
    inventory = [{"path": str(Path(path)), "sha256": _source_hash(Path(path))}
                 for path in sorted({Path(path) for path in paths}, key=str)]
    if len(inventory) == 1:
        return inventory[0]["sha256"]
    return hashlib.sha256(json.dumps(inventory, sort_keys=True,
        separators=(",", ":")).encode()).hexdigest()


def _resolve_name(tree, node):
    if not isinstance(node, ast.Name):
        return node
    assignments = [item for item in ast.walk(tree) if isinstance(item, (ast.Assign, ast.AnnAssign))]
    for item in reversed(assignments):
        targets = item.targets if isinstance(item, ast.Assign) else [item.target]
        if any(isinstance(target, ast.Name) and target.id == node.id for target in targets):
            return item.value
    return node


def _dict_entry(node, key):
    if not isinstance(node, ast.Dict):
        return None
    for item_key, value in zip(node.keys, node.values):
        try:
            literal = ast.literal_eval(item_key)
        except (ValueError, TypeError):
            continue
        if literal == key:
            return value
    return None


def _keyword(call, name):
    return next((item.value for item in call.keywords if item.arg == name), None)


def _function(tree, name):
    return next((item for item in ast.walk(tree)
                 if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == name), None)


def _direct_calls(function):
    pending = list(function.body)
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(node, ast.Call):
            yield node
        pending.extend(ast.iter_child_nodes(node))


def _unique_local_call_path(tree, source_function, target_function, max_depth=8):
    functions = {node.name: node for node in tree.body
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    if len(functions) != len([node for node in tree.body
                              if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]):
        return None
    paths = []

    def visit(current, path, seen):
        if len(path) > max_depth:
            return
        if current == target_function.name:
            paths.append(path)
            return
        function = functions.get(current)
        if function is None:
            return
        for call in _direct_calls(function):
            name = _leaf(call.func)
            if name in functions and name not in seen:
                visit(name, [*path, {"caller": current, "callee": name,
                                    "line": call.lineno}], seen | {name})

    visit(source_function.name, [], {source_function.name})
    return paths[0] if len(paths) == 1 else None


def _tool_parameters(function):
    parameters = []
    positional = list(function.args.posonlyargs) + list(function.args.args)
    defaults = [None] * (len(positional) - len(function.args.defaults)) + list(function.args.defaults)
    for argument, default in zip(positional, defaults):
        if argument.arg in {"self", "cls"}:
            continue
        annotation = ast.unparse(argument.annotation) if argument.annotation else None
        lowered = (annotation or "").lower()
        if "dict" in lowered or "mapping" in lowered:
            kind = "mapping"
        elif "list" in lowered or "sequence" in lowered or "tuple" in lowered:
            kind = "sequence"
        elif "bool" in lowered:
            kind = "boolean"
        elif "int" in lowered or "float" in lowered:
            kind = "number"
        elif "datetime" in lowered or "date" in lowered:
            kind = "temporal"
        elif annotation in LANGCHAIN_INJECTED_TOOL_PARAMETER_ANNOTATIONS:
            kind = "injected"
        elif annotation is None or lowered in {"str", "string"}:
            kind = "string"
        else:
            kind = "unsupported"
        parameters.append({"name": argument.arg, "annotation": annotation, "kind": kind,
                           "required": default is None})
    return parameters


def _policy_config(tree, source, value):
    value = _resolve_name(tree, value)
    if isinstance(value, ast.Constant) and isinstance(value.value, bool):
        return {"mode": "always" if value.value else "never", "allowed_decisions": [],
                "when_name": None, "when_source": None, "policy_span": _span(value)}
    if not isinstance(value, ast.Dict):
        return None
    allowed_node = _dict_entry(value, "allowed_decisions")
    when_node = _dict_entry(value, "when")
    try:
        allowed = ast.literal_eval(allowed_node) if allowed_node is not None else ["approve", "edit", "reject"]
    except (ValueError, TypeError):
        return None
    if not isinstance(allowed, (list, tuple)) or not all(isinstance(item, str) for item in allowed):
        return None
    when_name = _leaf(when_node) if when_node is not None else None
    when_function = _function(tree, when_name) if when_name and "." not in when_name else None
    if when_node is not None and when_function is None:
        return None
    when_source = textwrap.dedent(ast.get_source_segment(source, when_function)) if when_function else None
    return {"mode": "conditional" if when_function else "always",
            "allowed_decisions": list(allowed), "when_name": when_name,
            "when_source": when_source, "policy_span": _span(value),
            "when_span": _span(when_function) if when_function else None}


def _registration_bound(tree, tool_name, middleware_call, aliases):
    middleware_names = set()
    for item in ast.walk(tree):
        if not isinstance(item, ast.Assign) or item.value is not middleware_call:
            continue
        middleware_names.update(target.id for target in item.targets if isinstance(target, ast.Name))
    for call in (item for item in ast.walk(tree) if isinstance(item, ast.Call) and
                 _canonical(item.func, aliases) == "langchain.agents.create_agent"):
        tools = _resolve_name(tree, _keyword(call, "tools"))
        middleware = _resolve_name(tree, _keyword(call, "middleware"))
        if tools is None or middleware is None or not _contains_name(tools, tool_name):
            continue
        direct = any(item is middleware_call for item in ast.walk(middleware))
        named = any(_contains_name(middleware, name) for name in middleware_names)
        if direct or named:
            return call
    return None


def map_langchain_policy(path, tool_name, effect_line, expected_effect_call=None,
                         effect_path=None):
    path = Path(path)
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    aliases = _import_aliases(tree)
    effect_path = Path(effect_path) if effect_path is not None else path
    effect_source = effect_path.read_text(encoding="utf-8")
    effect_tree = tree if effect_path == path else ast.parse(effect_source, filename=str(effect_path))
    tool = _function(effect_tree, tool_name)
    if tool is None:
        return {"status": "unknown", "reason": "tool_function_unresolved"}
    effect_matches = []
    for call in (item for item in ast.walk(effect_tree) if isinstance(item, ast.Call)):
        if call.lineno <= effect_line <= getattr(call, "end_lineno", call.lineno):
            rendered = ast.unparse(call.func)
            if expected_effect_call is None or rendered == expected_effect_call or rendered.endswith(expected_effect_call):
                effect_matches.append(call)
    if len(effect_matches) != 1:
        return {"status": "unknown", "reason": "effect_statement_not_unique"}
    parents = {child: parent for parent in ast.walk(effect_tree) for child in ast.iter_child_nodes(parent)}
    owner = effect_matches[0]
    while owner in parents and not isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef)):
        owner = parents[owner]
    if not isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return {"status": "unknown", "reason": "effect_owner_unresolved"}
    call_path = [] if owner is tool else _unique_local_call_path(effect_tree, tool, owner)
    if call_path is None:
        return {"status": "unknown", "reason": "effect_local_call_path_not_unique"}

    candidates = []
    for call in (item for item in ast.walk(tree) if isinstance(item, ast.Call) and
                 _canonical(item.func, aliases) ==
                 "langchain.agents.middleware.HumanInTheLoopMiddleware"):
        interrupt_on = _keyword(call, "interrupt_on")
        interrupt_on = _resolve_name(tree, interrupt_on)
        policy_value = _dict_entry(interrupt_on, tool_name)
        if policy_value is None:
            continue
        config = _policy_config(tree, source, policy_value)
        if config is None:
            continue
        registration = _registration_bound(tree, tool_name, call, aliases)
        candidates.append((call, config, registration))
    bound = [item for item in candidates if item[2] is not None]
    if len(bound) != 1:
        return {"status": "unknown", "reason": "policy_registration_not_unique"}
    policy_call, config, registration = bound[0]
    effect = effect_matches[0]
    return {
        "status": "bound",
        "source_path": str(path),
        "source_sha256": source_inventory_sha256([path, effect_path]),
        "source_inventory": [{"path": str(item), "sha256": _source_hash(item)}
                             for item in sorted({path, effect_path}, key=str)],
        "tool_name": tool_name,
        "tool_parameters": _tool_parameters(tool),
        "policy": config,
        "mapping": {
            "tool_definition": {**_span(tool), "path": str(effect_path),
                                "source": ast.unparse(tool.args)},
            "policy_registration": {**_span(policy_call), "source": ast.unparse(policy_call)},
            "agent_registration": {**_span(registration), "source": ast.unparse(registration)},
            "effect_statement": {**_span(effect), "path": str(effect_path),
                                 "source": ast.unparse(effect)},
            "effect_owner": {**_span(owner), "path": str(effect_path), "symbol": owner.name},
            "local_call_path": call_path,
        },
        "effect_replacement": "local_marker_write",
        "repository_code_executed": False,
    }


def _eval_expr(node, env):
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        if node.id in env:
            return env[node.id]
        raise ValueError("predicate_name")
    if isinstance(node, ast.Attribute):
        value = _eval_expr(node.value, env)
        if node.attr.startswith("_"):
            raise ValueError("predicate_attribute")
        if isinstance(value, dict):
            return value[node.attr]
        return getattr(value, node.attr)
    if isinstance(node, ast.Subscript):
        return _eval_expr(node.value, env)[_eval_expr(node.slice, env)]
    if isinstance(node, ast.BoolOp):
        values = [_eval_expr(item, env) for item in node.values]
        return all(values) if isinstance(node.op, ast.And) else any(values)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return not _eval_expr(node.operand, env)
    if isinstance(node, ast.Compare):
        left = _eval_expr(node.left, env)
        for operator, comparator in zip(node.ops, node.comparators):
            right = _eval_expr(comparator, env)
            if isinstance(operator, ast.Eq): result = left == right
            elif isinstance(operator, ast.NotEq): result = left != right
            elif isinstance(operator, ast.In): result = left in right
            elif isinstance(operator, ast.NotIn): result = left not in right
            else: raise ValueError("predicate_compare")
            if not result:
                return False
            left = right
        return True
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id in {"bool", "len"}:
            function = bool if node.func.id == "bool" else len
            return function(*[_eval_expr(arg, env) for arg in node.args])
        if isinstance(node.func, ast.Attribute) and node.func.attr in {"get", "strip"}:
            receiver = _eval_expr(node.func.value, env)
            args = [_eval_expr(arg, env) for arg in node.args]
            if node.func.attr == "get" and isinstance(receiver, dict):
                return receiver.get(*args)
            if node.func.attr == "strip" and isinstance(receiver, str):
                return receiver.strip(*args)
        raise ValueError("predicate_call")
    if isinstance(node, (ast.Dict, ast.List, ast.Tuple)):
        return ast.literal_eval(node)
    raise ValueError("predicate_expression")


def evaluate_when_source(source, request_args):
    if source is None:
        return True
    tree = ast.parse(textwrap.dedent(source))
    function = next((item for item in tree.body if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))), None)
    if function is None or isinstance(function, ast.AsyncFunctionDef) or len(function.args.args) != 1:
        raise ValueError("predicate_function")
    env = {function.args.args[0].arg: SimpleNamespace(tool_call={"args": request_args})}
    for statement in function.body:
        if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant):
            continue
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1 and isinstance(statement.targets[0], ast.Name):
            env[statement.targets[0].id] = _eval_expr(statement.value, env)
            continue
        if isinstance(statement, ast.Return):
            return bool(_eval_expr(statement.value, env))
        raise ValueError("predicate_statement")
    raise ValueError("predicate_return")


def choose_policy_arguments(mapping):
    values = {
        "string": ["guardcontract-canary", ""],
        "mapping": [{"guardcontract.txt": "canary"}, {}],
        "sequence": [["guardcontract-canary"], []],
        "boolean": [True, False],
        "number": [1, 0],
        "temporal": ["2026-01-02T03:04:05Z", "2026-01-02"],
    }
    parameters = [item for item in mapping.get("tool_parameters", [])
                  if item["kind"] != "injected"]
    candidates = [values[item["kind"]] for item in parameters]
    combinations = itertools.product(*candidates) if candidates else [()]
    trigger = bypass = None
    for combination in itertools.islice(combinations, 256):
        arguments = {item["name"]: value for item, value in zip(parameters, combination)}
        outcome = evaluate_when_source(mapping["policy"].get("when_source"), arguments)
        if outcome and trigger is None:
            trigger = arguments
        if not outcome and bypass is None:
            bypass = arguments
    if mapping["policy"]["mode"] == "never":
        trigger = None
    return {"trigger": trigger, "bypass": bypass}
