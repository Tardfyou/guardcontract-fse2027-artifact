"""Bound, closed-source slices for real SDK tool-approval replay.

Only explicitly registered functions are compiled. Repository imports and module
initializers never execute. The tool body remains unchanged; the HTTP boundary
is replaced by a byte-producing local endpoint. This is an oracle, not detector
logic. Run public slices only inside the documented networkless container.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import json
from pathlib import Path


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = dotted(node.value)
        return prefix + "." + node.attr if prefix else ""
    return ""


def extract(path, symbol, expected_sha):
    if sha(path) != expected_sha:
        raise ValueError("slice_source_hash_mismatch")
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == symbol]
    if len(nodes) != 1:
        raise ValueError("slice_function_not_unique")
    node = copy.deepcopy(nodes[0])
    if any(dotted(d) not in {"tool", "wrap_tool_call"} for d in node.decorator_list):
        raise ValueError("slice_decorator_unsupported")
    node.decorator_list = []
    return node


def audit(node, allowed_calls):
    for part in ast.walk(node):
        if isinstance(part, (ast.Import, ast.ImportFrom, ast.ClassDef, ast.Lambda,
                             ast.Global, ast.Nonlocal, ast.With, ast.AsyncWith)):
            raise ValueError("slice_statement_unsupported")
        if isinstance(part, ast.Attribute) and part.attr.startswith("_"):
            raise ValueError("slice_private_attribute")
        if isinstance(part, ast.Name) and part.id.startswith("__"):
            raise ValueError("slice_private_name")
        if isinstance(part, ast.Call) and dotted(part.func) not in allowed_calls:
            raise ValueError("slice_call_unsupported:" + dotted(part.func))
    # Annotation/default evaluation is executable too; accept literals/simple
    # builtin type names only. No constructor or arbitrary default expressions.
    for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
        if arg.annotation and not (isinstance(arg.annotation, ast.Name)
                                   and arg.annotation.id in {"str", "int", "bool", "float", "dict", "list"}):
            raise ValueError("slice_annotation_unsupported")
    if node.returns and not (isinstance(node.returns, ast.Name)
                            and node.returns.id in {"str", "int", "bool", "float", "dict", "list"}):
        raise ValueError("slice_annotation_unsupported")
    for default in node.args.defaults + [d for d in node.args.kw_defaults if d]:
        ast.literal_eval(default)


def registration_proof(path, expected_sha, line, guard_symbol, tool_symbol):
    if sha(path) != expected_sha:
        raise ValueError("registration_source_hash_mismatch")
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
             and dotted(n.func) == "create_agent" and n.lineno == line]
    if len(calls) != 1:
        raise ValueError("registration_not_unique")
    kw = {k.arg: k.value for k in calls[0].keywords}
    middleware, tools = kw.get("middleware"), kw.get("tools")
    if (not isinstance(middleware, ast.List) or len(middleware.elts) != 1
            or dotted(middleware.elts[0]) != guard_symbol):
        raise ValueError("registration_middleware_not_exact")
    if not isinstance(tools, ast.List) or any(not isinstance(n, ast.Name) for n in tools.elts):
        raise ValueError("registration_tools_not_literal")
    if tool_symbol not in [n.id for n in tools.elts]:
        raise ValueError("registration_tool_missing")
    # Establish imports and decorator ownership; a same-name local helper must
    # not be silently substituted for the SDK API.
    imports = {a.asname or a.name: (n.module, a.name) for n in tree.body
               if isinstance(n, ast.ImportFrom) for a in n.names}
    if imports.get("create_agent") != ("langchain.agents", "create_agent"):
        raise ValueError("registration_sdk_import_missing")
    if imports.get("wrap_tool_call") != ("langchain.agents.middleware", "wrap_tool_call"):
        raise ValueError("registration_sdk_middleware_import_missing")
    functions = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    guard = functions.get(guard_symbol)
    if guard is None or [dotted(d) for d in guard.decorator_list] != ["wrap_tool_call"]:
        raise ValueError("registration_guard_decorator_missing")
    return {"status": "bound", "line": line, "guard": guard_symbol,
            "tool": tool_symbol, "registered_tools": [n.id for n in tools.elts],
            "scope": "one prescribed tool call; other tool choices are not evaluated"}


def load_function(node, namespace):
    module = ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[]))
    exec(compile(module, "<authenticated-source-slice>", "exec"), namespace)
    return namespace[node.name]


def source_identity(item):
    return hashlib.sha256(json.dumps(item["inventory"], sort_keys=True,
                                    separators=(",", ":")).encode()).hexdigest()
