"""Join structural guard/tool identities to source-reachable effect sites.

The result is a development coverage layer. It proves lexical source identity
and bounded call edges; it does not prove activation, policy applicability,
runtime feasibility, a DENY verdict, or an issue label.
"""
from __future__ import annotations

import ast
import hashlib
import symtable

from guardcontract.analysis.decorated_registrations_v1 import inspect as decorated
from guardcontract.analysis.source_bindings_v5 import SourceBindings
from guardcontract.discovery.scout import effect_sites_from_tree
from guardcontract.analysis.lifecycle_profiles_v1 import lifecycle as role_lifecycle


def _function_values(binding):
    if not isinstance(binding, dict):
        return []
    if binding.get("kind") == "function":
        return [binding["value"]]
    if binding.get("kind") == "wrapper":
        return _function_values(binding.get("value", {}).get("callback"))
    if binding.get("kind") == "sequence":
        return [row for value in binding.get("value", []) for row in _function_values(value)]
    if binding.get("kind") == "construction" and binding.get("value", {}).get("api") in {
            "google.adk.tools.FunctionTool", "google.adk.tools.function_tool.FunctionTool"}:
        return _function_values(binding["value"].get("kwargs", {}).get("func", {}))
    return []


def _role_functions(record, role):
    values = []
    for name, payload in record.get("roles", {}).items():
        if payload.get("role") == role:
            values.extend(_function_values(payload.get("binding")))
    return values


def _definitions(index):
    result = {}
    for path, tree in index.trees.items():
        if tree is None:
            continue
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                result[(path, node.name)] = node
            elif isinstance(node, ast.ClassDef):
                for child in node.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        result[(path, node.name + "." + child.name)] = child
    return result


def _root_name(node):
    if isinstance(node, ast.Call):
        return _root_name(node.func)
    while isinstance(node, ast.Attribute):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _effect_origin_known(index, path, call, locals_):
    root = _root_name(call.func)
    if root in locals_:
        return False
    if root == "open" and root not in index.writes[path]:
        return True
    if root is None:
        return False
    binding = index.resolve_global(path, root)
    if binding.kind != "external":
        return False
    allowed = {
        "requests": "requests", "httpx": "httpx", "aiohttp": "aiohttp",
        "urllib": "urllib", "subprocess": "subprocess", "os": "os",
        "shutil": "shutil", "io": "io", "Path": "pathlib.Path",
    }
    return root in allowed and (binding.value == allowed[root]
                                or binding.value.startswith(allowed[root] + "."))


def _external_effect(binding):
    if binding.kind != "external":
        return None
    value = binding.value
    leaf = value.rsplit(".", 1)[-1]
    if (value.startswith(("requests.", "httpx.", "aiohttp.", "urllib.request."))
            and leaf in {"get", "post", "put", "patch", "delete", "request",
                         "head", "options", "stream", "urlopen", "urlretrieve"}):
        return "network", value
    if value.startswith("subprocess.") or value in {"os.system", "os.popen"}:
        return "subprocess", value
    if leaf in {"sendmail", "send_message", "send_email", "send_mail", "publish_message"}:
        return "message", value
    if leaf in {"commit", "insert_one", "update_one", "update_many", "delete_one",
                "delete_many", "executemany"}:
        return "database", value
    return None


def _direct_calls(node):
    pending = list(node.body)
    while pending:
        child = pending.pop()
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(child, ast.Call):
            yield child
        pending.extend(ast.iter_child_nodes(child))


def _local_names(source, node):
    table = symtable.symtable(source, "<source>", "exec")
    pending = [table]
    matches = []
    while pending:
        current = pending.pop()
        if current.get_name() == node.name and current.get_lineno() == node.lineno:
            matches.append(current)
        pending.extend(current.get_children())
    if len(matches) != 1:
        return None
    return {entry.get_name() for entry in matches[0].get_symbols()
            if entry.is_local() or entry.is_parameter() or entry.is_free()}


def _reachable_effects(index, definitions, start):
    pending = [start]
    seen, effects, calls, gaps = set(), [], [], []
    while pending:
        key = pending.pop()
        if key in seen:
            continue
        seen.add(key)
        node = definitions.get(key)
        if node is None:
            gaps.append({"function": list(key), "reason": "definition_not_enrolled"})
            continue
        locals_ = _local_names(index.sources[key[0]], node)
        if locals_ is None:
            gaps.append({"function": list(key), "reason": "symbol_table_ambiguous"})
            continue
        direct_calls = list(_direct_calls(node))
        for site in effect_sites_from_tree(index.trees[key[0]], key[0], within=node):
            candidates = [call for call in direct_calls if call.lineno == site.line]
            if len(candidates) == 1 and _effect_origin_known(index, key[0], candidates[0], locals_):
                effects.append({"path": site.path, "line": site.line,
                                "family": site.family, "call": site.call,
                                "function": list(key)})
            else:
                gaps.append({"function": list(key), "line": site.line,
                             "reason": "effect_call_local_shadow_or_line_ambiguous"})
        represented = {(effect["line"], effect["call"]) for effect in effects
                       if effect["function"] == list(key)}
        for call in direct_calls:
            if _root_name(call.func) in locals_:
                continue
            bound = index.resolve_expr(key[0], call.func)
            effect = _external_effect(bound)
            if effect and (call.lineno, effect[1]) not in represented:
                effects.append({"path": key[0], "line": call.lineno,
                                "family": effect[0], "call": effect[1],
                                "function": list(key)})
        for call in direct_calls:
            root = _root_name(call.func)
            if root in locals_:
                calls.append({"path": key[0], "line": call.lineno,
                              "status": "dynamic_local_or_parameter"})
                continue
            bound = index.resolve_expr(key[0], call.func)
            if bound.kind == "function":
                target = (bound.value["path"], bound.value["symbol"])
                calls.append({"path": key[0], "line": call.lineno,
                              "status": "source_function", "target": list(target)})
                pending.append(target)
            elif bound.kind == "external":
                calls.append({"path": key[0], "line": call.lineno,
                              "status": "external", "target": bound.value})
            else:
                calls.append({"path": key[0], "line": call.lineno,
                              "status": "unknown", "reason": bound.value})
    distinct = {repr((row["path"], row["line"], row["family"], row["call"], row["function"])): row
                for row in effects}
    return list(distinct.values()), calls, gaps


def _possible_deny(index, function):
    key = (function["path"], function["symbol"])
    node = _definitions(index).get(key)
    if node is None:
        return "unknown"
    for part in ast.walk(node):
        if isinstance(part, ast.Raise):
            return "syntactic_possible"
        if isinstance(part, ast.Return) and part.value is not None:
            if isinstance(part.value, ast.Constant) and part.value.value is False:
                return "syntactic_possible"
            if isinstance(part.value, (ast.Dict, ast.Call)):
                return "syntactic_possible"
    return "not_observed_in_supported_syntax"


def analyze(sources, *, max_operations=75_000, include_binding_records=False):
    index = SourceBindings(sources, max_operations=max_operations)
    definitions = _definitions(index)
    records = []
    for kind, values in (("module_expression", index.registrations()),
                         ("deferred_template", index.deferred_registrations())):
        for value in values:
            records.append({**value, "registration_kind": kind})
    decorator_rows = decorated(sources, index)
    for row in decorator_rows["pydantic_agents"]:
        declaration = {
            "framework": "pydantic_ai", "api": "pydantic_ai.Agent+instance_decorators",
            "registration_kind": "instance_decorator",
            "site": row["agent"]["value"]["site"],
            "direct_tools": row["tools"], "direct_guards": row["guards"],
            "runtime_activation_verified": False,
        }
        existing = next((r for r in records if r["framework"] == "pydantic_ai" and
                         all(r["site"].get(k) == declaration["site"][k] for k in ("path", "line"))), None)
        if existing is not None:
            existing.update(declaration)
        else:
            records.append(declaration)
    crewai_guards = [row["function"] for row in decorator_rows["crewai_decorators"]
                     if row["role"] == "guards"]
    if crewai_guards and decorator_rows["crewai_tools"]:
        records.append({
            "framework": "crewai", "api": "crewai.global_before_tool_decorators",
            "registration_kind": "global_decorator_conditional_activation",
            "site": crewai_guards[0], "direct_tools": decorator_rows["crewai_tools"],
            "direct_guards": crewai_guards, "runtime_activation_verified": False,
            "direct_lifecycle": ["pre_tool"],
        })
    for row in decorator_rows["openai_tools"]:
        if row["guards"]:
            records.append({
                "framework": "openai_agents", "api": "agents.function_tool+tool_input_guardrails",
                "registration_kind": "tool_decorator", "site": row["tool"],
                "direct_tools": [row["tool"]], "direct_guards": row["guards"],
                "runtime_activation_verified": False, "direct_lifecycle": ["pre_tool"],
            })
    output = []
    for record in records:
        def joined(role):
            values = record.get("direct_" + role, []) + _role_functions(record, role)
            return list({(v["path"], v["symbol"], v["line"]): v for v in values}.values())
        tools, guards = joined("tools"), joined("guards")
        if record.get("api") == "crewai.Task":
            kwargs = record.get("binding", {}).get("value", {}).get("kwargs", {})
            agent = kwargs.get("agent", {})
            if agent.get("kind") == "construction" and agent.get("value", {}).get("api") == "crewai.Agent":
                tools = _function_values(agent["value"].get("kwargs", {}).get("tools", {}))
        tool_rows = []
        for tool in tools:
            effects, calls, gaps = _reachable_effects(
                index, definitions, (tool["path"], tool["symbol"]))
            tool_rows.append({"source": tool, "effects": effects,
                              "call_edges": calls, "gaps": gaps})
        guard_rows = [{"source": guard, "deny_capability": _possible_deny(index, guard)}
                      for guard in guards]
        lifecycle = list(record.get("direct_lifecycle", []))
        for role_name, payload in record.get("roles", {}).items():
            if payload.get("role") == "guards":
                lifecycle.append(role_lifecycle(record["framework"], role_name))
        if record["framework"] == "pydantic_ai" and guard_rows:
            lifecycle.append(role_lifecycle("pydantic_ai", "output_validator"))
        effects = [effect for tool in tool_rows for effect in tool["effects"]]
        paired = bool(guard_rows and tool_rows)
        output.append({
            "framework": record["framework"], "api": record.get("api"),
            "registration_kind": record["registration_kind"],
            "site": record.get("site"), "guards": guard_rows, "tools": tool_rows,
            "guard_tool_source_joined": paired,
            "effect_bound_to_registered_tool": bool(paired and effects),
            "lifecycle": sorted(set(lifecycle)),
            "joint_path_status": ("structural_effect_and_guard_identity" if paired and effects
                                  else "effect_not_bound" if paired else "guard_tool_identity_incomplete"),
            "runtime_activation_verified": False, "policy_applicability_verified": False,
            "issue_label": None,
        })
    result = {
        "schema_version": "source-effect-paths-1",
        "records": output,
        "parse_failures": sorted(path for path, tree in index.trees.items() if tree is None),
        "decorator_unknown": decorator_rows["unknown"],
        "analysis_operations": index.operations,
        "analysis_budget_exhausted": index.operation_budget_exhausted,
        "claim_boundary": "Static source identity, bounded helper-call and effect binding only. No activation, policy, DENY, behavior, prevalence, or issue claim.",
    }
    if include_binding_records:
        result["binding_records"] = records
    return result
