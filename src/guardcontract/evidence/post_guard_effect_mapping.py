"""Map effect-result predicates in post-effect guard functions without execution."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

from guardcontract.analysis.guard_effect_order import analyze_guard_effect_order


def _name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    if isinstance(node, ast.Call):
        return _name(node.func)
    return None


def _span(node):
    return {"start_line": node.lineno, "end_line": getattr(node, "end_lineno", node.lineno)}


def _contains_deny(node):
    return any(isinstance(item, ast.Raise) and
               (_name(item.exc) or "").rsplit(".", 1)[-1] == "ModelRetry"
               for item in ast.walk(node))


def _alternative(value):
    if type(value) is bool:
        return not value
    if isinstance(value, int):
        return value + 1
    if isinstance(value, str):
        return value + "_other"
    raise ValueError("post_guard_predicate_literal")


def _predicate(test, result_name):
    if not isinstance(test, ast.Compare) or len(test.ops) != 1 or len(test.comparators) != 1:
        return None
    left, right = test.left, test.comparators[0]
    if (isinstance(left, ast.Attribute) and isinstance(left.value, ast.Name)
            and left.value.id == result_name and isinstance(right, ast.Constant)):
        field, literal, operator = left.attr, right.value, test.ops[0]
    elif (isinstance(right, ast.Attribute) and isinstance(right.value, ast.Name)
          and right.value.id == result_name and isinstance(left, ast.Constant)):
        field, literal, operator = right.attr, left.value, test.ops[0]
    else:
        return None
    if isinstance(operator, ast.Eq):
        deny, allow, operation = literal, _alternative(literal), "eq"
    elif isinstance(operator, ast.NotEq):
        deny, allow, operation = _alternative(literal), literal, "not_eq"
    else:
        return None
    return {"result_name": result_name, "field": field, "operation": operation,
            "literal": literal, "deny_value": deny, "allow_value": allow,
            "source": ast.unparse(test), **_span(test)}


def map_post_guard_effect(path, guard_symbol, effect_line, effect_call):
    path = Path(path)
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    guards = [node for node in ast.walk(tree)
              if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
              and node.name == guard_symbol.rsplit(".", 1)[-1]]
    if len(guards) != 1:
        return {"status": "unknown", "reason": "guard_function_not_unique"}
    guard = guards[0]
    decorators = [decorator.func if isinstance(decorator, ast.Call) else decorator
                  for decorator in guard.decorator_list]
    roles = [node.attr for node in decorators if isinstance(node, ast.Attribute)
             and node.attr in {"output_validator", "result_validator"}]
    if len(roles) != 1:
        return {"status": "unknown", "reason": "post_guard_registration_unresolved"}
    calls = [node for node in ast.walk(guard) if isinstance(node, ast.Call)
             and node.lineno <= effect_line <= getattr(node, "end_lineno", node.lineno)
             and ((_name(node.func) or "") == effect_call
                  or (_name(node.func) or "").endswith("." + effect_call))]
    if len(calls) != 1:
        return {"status": "unknown", "reason": "effect_call_not_unique"}
    effect = calls[0]
    parents = {child: parent for parent in ast.walk(guard) for child in ast.iter_child_nodes(parent)}
    statement = effect
    while statement in parents and not isinstance(statement, (ast.Assign, ast.AnnAssign)):
        statement = parents[statement]
    target = statement.targets[0] if isinstance(statement, ast.Assign) and len(statement.targets) == 1 else (
        statement.target if isinstance(statement, ast.AnnAssign) else None)
    if not isinstance(target, ast.Name):
        return {"status": "unknown", "reason": "effect_result_binding_unresolved"}
    deny_ifs = [node for node in ast.walk(guard) if isinstance(node, ast.If)
                and _contains_deny(node)]
    mapped = [(node, _predicate(node.test, target.id)) for node in deny_ifs]
    mapped = [(node, predicate) for node, predicate in mapped if predicate is not None]
    if len(mapped) != 1:
        return {"status": "unknown", "reason": "effect_result_deny_predicate_unresolved"}
    deny_if, predicate = mapped[0]
    order = analyze_guard_effect_order(guard, effect_line, effect_call)
    if order["status"] != "effect_before_deny_candidate":
        return {"status": "unknown", "reason": "effect_before_deny_unproven"}
    return {"status": "bound", "source_path": str(path),
            "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "framework": "pydantic-ai", "guard_symbol": guard_symbol,
            "guard_role": "output_validator", "effect_call": effect_call,
            "effect_line": effect_line, "predicate": predicate,
            "mapping": {"guard": _span(guard), "effect_statement": _span(statement),
                        "deny_branch": _span(deny_if), "static_order": order["status"]},
            "effect_replacement": "local_marker_and_closed_result",
            "repository_code_executed": False}


def predicate_denies(mapping, value):
    predicate = mapping["predicate"]
    if predicate["operation"] == "eq":
        return value == predicate["literal"]
    if predicate["operation"] == "not_eq":
        return value != predicate["literal"]
    raise ValueError("post_guard_predicate_operation")
