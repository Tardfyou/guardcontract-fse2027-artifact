"""Recover decorator-mediated guard/tool identities without executing source.

This complements constructor bindings. It records object identity and source
roles; activation, policy meaning, effects, and behavior remain separate.
"""
from __future__ import annotations

import ast
import hashlib

from guardcontract.analysis.source_bindings_v5 import SourceBindings
from guardcontract.analysis.source_bindings_v1 import Binding


PYDANTIC_ROLES = {
    "tool": "tools",
    "tool_plain": "tools",
    "output_validator": "guards",
    "result_validator": "guards",
}
CREWAI_DECORATORS = {
    "crewai.project.annotations.agent": "agent_factory",
    "crewai.project.agent": "agent_factory",
    "crewai.project.annotations.task": "task_factory",
    "crewai.project.task": "task_factory",
    "crewai.hooks.before_tool_call": "guards",
}
CREWAI_TOOL_DECORATORS = {"crewai.tools.tool", "crewai.tool", "crewai.tools.base_tool.tool"}
OPENAI_FUNCTION_TOOL = {"agents.function_tool", "agents.tool.function_tool"}


def _function(path, source, node):
    return {
        "path": path,
        "symbol": node.name,
        "line": node.lineno,
        "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "async": isinstance(node, ast.AsyncFunctionDef),
    }


def _decorator_base(decorator):
    return decorator.func if isinstance(decorator, ast.Call) else decorator


def _agent_method(index, path, decorator):
    base = _decorator_base(decorator)
    if not isinstance(base, ast.Attribute) or base.attr not in PYDANTIC_ROLES:
        return None
    owner = _pydantic_owner(index, path, base.value)
    if owner.kind != "construction" or owner.value.get("api") != "pydantic_ai.Agent":
        return None
    return owner, base.attr


def _pydantic_owner(index, path, expression):
    owner = index.resolve_expr(path, expression)
    if owner.kind == "construction":
        return owner
    if not isinstance(expression, ast.Name) or expression.id in index.tainted[path]:
        return owner
    writes = index.writes[path].get(expression.id, [])
    if len(writes) != 1 or not isinstance(writes[0], ast.Call):
        return owner
    call = writes[0]
    callee = index.resolve_expr(path, call.func)
    if callee.kind != "external" or callee.value != "pydantic_ai.Agent" or len(call.args) > 1:
        return owner
    positionals = tuple(index.resolve_expr(path, arg) for arg in call.args)
    keywords = index.call_keywords(path, call)
    if any(value.kind == "unknown" for value in positionals) or None in keywords:
        return owner
    return Binding("construction", {
        "api": "pydantic_ai.Agent", "args": positionals,
        "kwargs": keywords,
        "site": {"path": path, "line": call.lineno,
                 "source_sha256": hashlib.sha256(index.sources[path].encode()).hexdigest()},
    })


def _external_decorator(index, path, decorator):
    base = _decorator_base(decorator)
    bound = index.resolve_expr(path, base)
    return bound.value if bound.kind == "external" else None


def inspect(sources, index=None):
    index = index or SourceBindings(sources)
    pydantic, crewai, crewai_tools, openai_tools, unknown = {}, [], [], [], []
    for path, tree in sorted(index.trees.items()):
        if tree is None:
            unknown.append({"path": path, "reason": "source_syntax"})
            continue
        for node in tree.body:
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                call = node.value
                callee = index.resolve_expr(path, call.func)
                if (callee.kind == "external"
                        and callee.value == "crewai.hooks.register_before_tool_call_hook"
                        and len(call.args) == 1 and not call.keywords):
                    callback = index.resolve_expr(path, call.args[0])
                    direct = (index.function(path, call.args[0].id)
                              if isinstance(call.args[0], ast.Name) else None)
                    function = (_function(path, sources[path], direct) if direct is not None
                                else callback.value if callback.kind == "function" else None)
                    if function is not None:
                        crewai.append({
                            "framework": "crewai", "role": "guards",
                            "decorator": callee.value,
                            "function": function,
                            "registration_kind": "module_hook_registration",
                            "runtime_activation_verified": False,
                            "effect_reachability_verified": False,
                        })
                continue
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for decorator in node.decorator_list:
                    matched = _agent_method(index, path, decorator)
                    if matched:
                        owner, method = matched
                        key = hashlib.sha256(repr(owner.as_dict()).encode()).hexdigest()
                        row = pydantic.setdefault(key, {
                            "framework": "pydantic_ai",
                            "agent": owner.as_dict(),
                            "tools": [], "guards": [],
                            "registration_kind": "instance_decorator",
                            "runtime_activation_verified": False,
                            "effect_reachability_verified": False,
                        })
                        row[PYDANTIC_ROLES[method]].append({
                            **_function(path, sources[path], node),
                            "decorator_method": method,
                        })
                        continue
                    external = _external_decorator(index, path, decorator)
                    if external in CREWAI_DECORATORS:
                        role = CREWAI_DECORATORS[external]
                        crewai.append({
                            "framework": "crewai",
                            "role": role,
                            "decorator": external,
                            "function": _function(path, sources[path], node),
                            "registration_kind": "framework_decorator",
                            "runtime_activation_verified": False,
                            "effect_reachability_verified": False,
                        })
                    elif external in CREWAI_TOOL_DECORATORS:
                        crewai_tools.append({**_function(path, sources[path], node),
                                             "decorator": external})
                    elif external in OPENAI_FUNCTION_TOOL:
                        call = decorator if isinstance(decorator, ast.Call) else None
                        keywords = index.call_keywords(path, call) if call else {}
                        guards = keywords.get("tool_input_guardrails")
                        openai_tools.append({
                            "tool": _function(path, sources[path], node),
                            "guards": _function_values_binding(guards),
                            "guard_binding_status": ("known" if guards and _function_values_binding(guards)
                                                     else "not_declared" if guards is None else "unknown"),
                            "decorator": external,
                        })
            elif isinstance(node, ast.ClassDef):
                for child in node.body:
                    if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        continue
                    for decorator in child.decorator_list:
                        external = _external_decorator(index, path, decorator)
                        if external in CREWAI_DECORATORS:
                            crewai.append({
                                "framework": "crewai",
                                "role": CREWAI_DECORATORS[external],
                                "decorator": external,
                                "function": {**_function(path, sources[path], child),
                                             "class": node.name},
                                "registration_kind": "class_method_decorator_template",
                                "runtime_activation_verified": False,
                                "effect_reachability_verified": False,
                            })
    records = list(pydantic.values())
    for row in records:
        row["tools"].sort(key=lambda value: (value["path"], value["line"]))
        row["guards"].sort(key=lambda value: (value["path"], value["line"]))
        row["same_agent_guard_and_tool"] = bool(row["tools"] and row["guards"])
    return {
        "schema_version": "decorated-registration-identities-1",
        "pydantic_agents": records,
        "crewai_decorators": crewai,
        "crewai_tools": crewai_tools,
        "openai_tools": openai_tools,
        "unknown": unknown,
        "runtime_activation_verified": False,
        "claim_boundary": "Decorator/object source identities only; no effect, policy, runtime activation, or issue claim.",
    }


def _function_values_binding(binding):
    if binding is None:
        return []
    if binding.kind == "function":
        return [binding.value]
    if binding.kind == "wrapper":
        return _function_values_binding(binding.value.get("callback"))
    if binding.kind == "sequence":
        return [row for value in binding.value for row in _function_values_binding(value)]
    return []
