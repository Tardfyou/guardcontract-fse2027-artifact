"""Recover a closed literal registration graph using construction-time identities.

This interpreter never executes source. Agent/as_tool/handoff references capture
objects, not variable names. Unsupported construction effects or escapes create
gaps; they cannot establish that every path crosses the root guard's join.
The result describes registered topology, not feasibility or SDK execution.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass


@dataclass(frozen=True)
class _Ref:
    kind: str
    identity: str


class _Unknown:
    pass


_UNKNOWN = _Unknown()
_AGENT_API = _Ref("api", "agents.Agent")
_HANDOFF_API = _Ref("api", "agents.handoff")
_DECORATORS = {"agents.function_tool", "agents.input_guardrail", "agents.output_guardrail"}


def recover(source, root_agent, target_tool, guard_symbol):
    """Resolve final root/target/guard bindings and their captured topology.

    Names identify their final module bindings. Unresolved target/guard aliases
    remain unknown. Object identities include source positions and are local to
    this source text; callers must separately authenticate its byte identity.
    """
    env, objects, functions, labels = {}, {}, {}, {}
    gaps = set()
    steps = 0

    def gap(reason):
        gaps.add(reason)
        return _UNKNOWN

    def identity(node, kind):
        return f"{kind}:{node.lineno}:{node.col_offset}"

    def ref_label(ref):
        return labels.get(ref.identity, ref.identity)

    def graph_value(value):
        if isinstance(value, _Ref):
            return value.kind in {"agent", "agent_tool", "handoff"}
        if isinstance(value, (list, tuple)):
            return any(graph_value(v) for v in value)
        if isinstance(value, dict):
            return any(graph_value(v) for v in value.values())
        return False

    def keyword_values(call):
        result = {}
        for kw in call.keywords:
            if kw.arg is None:
                expanded = value(kw.value)
                if not isinstance(expanded, dict) or any(type(k) is not str for k in expanded):
                    gap("dynamic_keyword_expansion")
                    continue
                pairs = expanded.items()
            else:
                pairs = [(kw.arg, value(kw.value))]
            for key, item in pairs:
                if key in result:
                    gap("duplicate_constructor_keyword:" + key)
                result[key] = item
        return result

    def refs(items, kinds, field):
        if not isinstance(items, (list, tuple)):
            gap("unresolved_registration:" + field)
            return []
        result = []
        for item in items:
            if not isinstance(item, _Ref) or item.kind not in kinds:
                gap("unresolved_registration_item:" + field)
            else:
                result.append(item)
        return result

    def value(node):
        nonlocal steps
        steps += 1
        if steps > 10000:
            return gap("construction_budget")
        if isinstance(node, ast.Name):
            return env.get(node.id, _UNKNOWN)
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, (ast.List, ast.Tuple)):
            if any(isinstance(n, ast.Starred) for n in node.elts):
                return gap("registration_sequence_expansion")
            items = [value(n) for n in node.elts]
            return tuple(items) if isinstance(node, ast.Tuple) else items
        if isinstance(node, ast.Dict):
            result = {}
            for key, val in zip(node.keys, node.values):
                if key is None:
                    expanded = value(val)
                    if not isinstance(expanded, dict):
                        return gap("dynamic_mapping_expansion")
                    result.update(expanded)
                else:
                    resolved_key = value(key)
                    if type(resolved_key) not in {str, int, float, bool, type(None)}:
                        return gap("unsupported_mapping_key")
                    result[resolved_key] = value(val)
            return result
        if isinstance(node, ast.Attribute):
            owner = value(node.value)
            if isinstance(owner, _Ref) and owner.kind == "module":
                return _Ref("api", owner.identity + "." + node.attr)
            return gap("unsupported_attribute_access")
        if isinstance(node, ast.Call):
            if any(isinstance(n, ast.Starred) for n in node.args):
                return gap("constructor_argument_expansion")
            # Evaluate the callee before arguments, as Python does.
            owner = None
            if isinstance(node.func, ast.Attribute) and node.func.attr == "as_tool":
                owner = value(node.func.value)
                callee = None
            else:
                callee = value(node.func)
            positional = [value(n) for n in node.args]
            kw = keyword_values(node)
            if isinstance(owner, _Ref) and owner.kind == "agent":
                if len(positional) > 2 or set(kw) - {"tool_name", "tool_description"}:
                    gap("unsupported_as_tool_options")
                if any(k in kw for k in ("tool_name", "tool_description")[:len(positional)]):
                    gap("duplicate_as_tool_argument")
                ref = _Ref("agent_tool", identity(node, "agent_tool"))
                objects[ref.identity] = {"ref": ref, "owner": owner, "line": node.lineno}
                return ref
            if callee == _AGENT_API:
                if positional:
                    gap("agent_positional_arguments")
                allowed = {"tools", "handoffs", "input_guardrails", "name", "instructions",
                           "model", "handoff_description", "output_type", "model_settings"}
                if set(kw) - allowed:
                    gap("unsupported_agent_options")
                for key, item in kw.items():
                    if key not in {"tools", "handoffs", "input_guardrails"} and graph_value(item):
                        gap("graph_escape_in_agent_metadata")
                ref = _Ref("agent", identity(node, "agent"))
                objects[ref.identity] = {
                    "ref": ref, "line": node.lineno,
                    "tools": refs(kw.get("tools", []), {"function", "agent_tool"}, "tools"),
                    "handoffs": refs(kw.get("handoffs", []), {"agent", "handoff"}, "handoffs"),
                    "input_guards": refs(kw.get("input_guardrails", []), {"function"}, "input_guardrails"),
                }
                return ref
            if callee == _HANDOFF_API:
                if len(positional) > 1 or set(kw) - {"agent", "tool_name_override", "tool_description_override"}:
                    gap("unsupported_handoff_options")
                if positional and "agent" in kw:
                    gap("duplicate_handoff_agent")
                target = positional[0] if positional else kw.get("agent", _UNKNOWN)
                if not isinstance(target, _Ref) or target.kind != "agent":
                    return gap("unresolved_handoff_agent")
                ref = _Ref("handoff", identity(node, "handoff"))
                objects[ref.identity] = {"ref": ref, "owner": target, "line": node.lineno}
                return ref
            return gap("opaque_call_or_graph_escape")
        return gap("unsupported_construction_expression:" + type(node).__name__)

    def assign(target, item):
        if not isinstance(target, ast.Name):
            gap("unsupported_mutation_target")
            return
        env[target.id] = item
        if isinstance(item, _Ref) and item.kind in {"agent", "agent_tool", "handoff", "function"}:
            labels.setdefault(item.identity, target.id)

    def definition(node):
        # Defaults and decorators execute at definition time, even when the body
        # never runs. Do not silently ignore an opaque call in either position.
        for default in node.args.defaults + [n for n in node.args.kw_defaults if n is not None]:
            if graph_value(value(default)):
                gap("graph_object_captured_by_callable_default")
        for decorator in node.decorator_list:
            ref = value(decorator)
            if not isinstance(ref, _Ref) or ref.identity not in _DECORATORS:
                gap("unsupported_definition_decorator")
        for annotation in [n.annotation for n in node.args.posonlyargs + node.args.args + node.args.kwonlyargs] + [node.returns]:
            if annotation is not None and any(isinstance(n, ast.Call) for n in ast.walk(annotation)):
                gap("executable_annotation")
        ref = _Ref("function", identity(node, "function"))
        functions[ref.identity] = node
        assign(ast.Name(id=node.name), ref)

    try:
        tree = ast.parse(source)
        for node in tree.body:
            if isinstance(node, ast.ImportFrom):
                for imported in node.names:
                    if imported.name == "*":
                        gap("wildcard_import")
                    else:
                        module = node.module or ""
                        kind = "api" if not node.level else "external"
                        env[imported.asname or imported.name] = _Ref(kind, module + "." + imported.name)
            elif isinstance(node, ast.Import):
                for imported in node.names:
                    env[imported.asname or imported.name.split(".")[0]] = _Ref(
                        "module", imported.name if imported.asname else imported.name.split(".")[0])
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                definition(node)
            elif isinstance(node, ast.Assign):
                item = value(node.value)
                for target in node.targets:
                    assign(target, item)
            elif isinstance(node, ast.AnnAssign):
                if node.annotation and any(isinstance(n, ast.Call) for n in ast.walk(node.annotation)):
                    gap("executable_annotation")
                if node.value is not None:
                    assign(node.target, value(node.value))
            elif isinstance(node, ast.Expr):
                value(node.value)
            elif isinstance(node, ast.Pass):
                pass
            else:
                gap("unsupported_construction_statement:" + type(node).__name__)
    except (SyntaxError, RecursionError, TypeError, ValueError) as exc:
        gap("source_parse_or_construction_error:" + type(exc).__name__)

    root, target, guard = (env.get(name, _UNKNOWN) for name in (root_agent, target_tool, guard_symbol))
    for name, ref, kind in [("root", root, "agent"), ("target", target, "function"), ("guard", guard, "function")]:
        if not isinstance(ref, _Ref) or ref.kind != kind:
            gap("unresolved_final_binding:" + name)
    paths, reachable_functions = [], set()
    traversals = 0

    def walk(agent, path, seen):
        nonlocal traversals
        traversals += 1
        if traversals > 10000 or len(paths) > 1000 or len(path) > 100:
            gap("graph_traversal_budget")
            return
        if agent.identity in seen:
            gap("agent_cycle")
            return
        record = objects[agent.identity]
        reachable_functions.update(record["input_guards"])
        seen = seen | {agent.identity}
        for tool in record["tools"]:
            edge = {"kind": "tool", "owner": ref_label(agent), "owner_id": agent.identity,
                    "target": ref_label(tool), "target_id": tool.identity}
            if tool == target:
                edges = path + [edge]
                paths.append({"edges": edges,
                              "handoff_joins": sum(e["kind"] == "handoff" for e in edges),
                              "root_guard_joins": sum(e["kind"] == "handoff" and e["owner_id"] == root.identity for e in edges)})
            elif tool.kind == "agent_tool":
                walk(objects[tool.identity]["owner"], path + [dict(edge, kind="agent_as_tool")], seen)
            else:
                reachable_functions.add(tool)
        for wrapped in record["handoffs"]:
            child = objects[wrapped.identity]["owner"] if wrapped.kind == "handoff" else wrapped
            edge = {"kind": "handoff", "owner": ref_label(agent), "owner_id": agent.identity,
                    "target": ref_label(child), "target_id": child.identity}
            walk(child, path + [edge], seen)

    if isinstance(root, _Ref) and root.kind == "agent":
        labels[root.identity] = root_agent
        try:
            walk(root, [], set())
        except RecursionError:
            gap("graph_traversal_budget")
        if guard not in objects[root.identity]["input_guards"]:
            gap("root_guard_not_registered")
    # A relevant callback/helper can otherwise hide another agent invocation or
    # mutate the graph at runtime. Do not pretend its body is a registered edge.
    inspected = set()
    while reachable_functions:
        ref = reachable_functions.pop()
        if ref in inspected:
            continue
        inspected.add(ref)
        function = functions[ref.identity]
        locals_ = {n.arg for n in ast.walk(function) if isinstance(n, ast.arg)}
        locals_.update(n.id for n in ast.walk(function) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store))
        for node in ast.walk(function):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id not in locals_:
                captured = env.get(node.id)
                if graph_value(captured):
                    gap("runtime_graph_reference_in_callable")
                elif isinstance(captured, _Ref) and captured.kind == "function":
                    if captured == target:
                        gap("target_reference_outside_registration")
                    else:
                        reachable_functions.add(captured)
            if isinstance(node, (ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal)):
                gap("runtime_binding_extension")
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec", "globals", "locals", "getattr", "setattr", "delattr", "__import__"}:
                gap("dynamic_runtime_binding")

    status = "unknown"
    if not gaps and paths:
        status = "requires_root_guard_join" if all(p["root_guard_joins"] for p in paths) else "reachable_before_root_guard_join"
    return {"schema_version": "agent-boundary-graph-3", "status": status, "paths": paths,
            "gaps": sorted(gaps), "root_object_id": root.identity if isinstance(root, _Ref) else None,
            "object_bindings": {name: ref.identity for name, ref in env.items() if isinstance(ref, _Ref) and ref.kind in {"agent", "agent_tool", "handoff", "function"}},
            "root_input_guards": [ref_label(g) for g in objects[root.identity]["input_guards"]] if isinstance(root, _Ref) and root.kind == "agent" else [],
            "guard_symbol": guard_symbol, "sdk_barrier_verified": False, "behavior_label": None,
            "claim_boundary": "Construction-time registration identities only. Unsupported mutations and escapes remain gaps; SDK scheduling, callable effect semantics and runtime feasibility are not proved."}
