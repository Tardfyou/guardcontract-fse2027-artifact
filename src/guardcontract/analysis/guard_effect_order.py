"""Framework-neutral control-order analysis for effects inside guard bodies."""
from __future__ import annotations

import ast


DENIAL_EXCEPTIONS = {
    "ModelRetry", "InputGuardrailTripwireTriggered", "OutputGuardrailTripwireTriggered",
    "GuardrailTripwireTriggered", "HookAborted",
}


def _leaf(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _leaf(node.func)
    return None


def _call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _contains_effect(node, effect_line, effect_call):
    return any(isinstance(item, ast.Call) and item.lineno <= effect_line <=
               getattr(item, "end_lineno", item.lineno) and
               (effect_call is None or _call_name(item.func) == effect_call or
                _call_name(item.func).endswith("." + effect_call)) for item in ast.walk(node))


def _walk_block(statements, paths, effect_line, effect_call, gaps):
    current = paths
    for statement in statements:
        next_paths = []
        for events, terminated in current:
            if terminated:
                next_paths.append((events, terminated))
                continue
            if isinstance(statement, ast.If):
                branches = [statement.body, statement.orelse or []]
                branch_paths = []
                prefix = [*events, *([{"kind": "effect", "line": effect_line}]
                                     if _contains_effect(statement.test, effect_line, effect_call) else [])]
                for branch in branches:
                    branch_paths.extend(_walk_block(branch, [(prefix, False)], effect_line, effect_call, gaps))
                next_paths.extend(branch_paths)
                continue
            if isinstance(statement, (ast.With, ast.AsyncWith)):
                prefix = [*events, *([{"kind": "effect", "line": effect_line}]
                                     if any(_contains_effect(item.context_expr, effect_line, effect_call)
                                            for item in statement.items) else [])]
                next_paths.extend(_walk_block(statement.body, [(prefix, False)], effect_line,
                                              effect_call, gaps))
                continue
            if isinstance(statement, (ast.Try, ast.TryStar, ast.For, ast.AsyncFor, ast.While,
                                      ast.Match)):
                gaps.add("unsupported_control:" + type(statement).__name__)
                next_paths.append((events, "unknown"))
                continue
            emitted = list(events)
            if _contains_effect(statement, effect_line, effect_call):
                emitted.append({"kind": "effect", "line": effect_line})
            if isinstance(statement, ast.Raise) and _leaf(statement.exc) in DENIAL_EXCEPTIONS:
                emitted.append({"kind": "deny", "line": statement.lineno})
                next_paths.append((emitted, "deny"))
            elif isinstance(statement, (ast.Return, ast.Raise)):
                next_paths.append((emitted, "return"))
            else:
                next_paths.append((emitted, False))
        current = next_paths
    return current


def analyze_guard_effect_order(function, effect_line, effect_call=None):
    """Classify source order without claiming runtime feasibility or commitment."""
    if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
        raise ValueError("guard_effect_function")
    effect_calls = [item for item in ast.walk(function) if isinstance(item, ast.Call)
                    and item.lineno <= effect_line <= getattr(item, "end_lineno", item.lineno)
                    and (effect_call is None or _call_name(item.func) == effect_call or
                         _call_name(item.func).endswith("." + effect_call))]
    if len(effect_calls) != 1:
        return {"status": "unknown", "reason": "effect_call_not_unique", "paths": []}
    gaps = set()
    paths = _walk_block(function.body, [([], False)], effect_line, effect_call, gaps)
    deny_paths = [events for events, termination in paths if termination == "deny"]
    if gaps or any(termination == "unknown" for _, termination in paths):
        status = "unknown"
    elif not deny_paths:
        status = "unknown"
        gaps.add("deny_path_missing")
    elif any(any(event["kind"] == "effect" for event in events) for events in deny_paths):
        status = "effect_before_deny_candidate"
    else:
        status = "deny_precedes_effect"
    return {"status": status, "reason": sorted(gaps)[0] if gaps else status,
            "paths": [{"termination": termination, "events": events}
                      for events, termination in paths],
            "runtime_feasibility_verified": False, "effect_commit_verified": False}
