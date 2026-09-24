"""Registration candidates with local policy delegates and imported helper sinks."""
import ast
from collections import defaultdict
import hashlib
import os
import warnings
from pathlib import Path

from guardcontract.discovery.scout import effect_sites_from_tree
from guardcontract.analysis.guard_effect_order import analyze_guard_effect_order
from guardcontract.discovery.guard_semantics import classify as classify_guard_semantics
from guardcontract.discovery.framework_declarations import (
    DECLARATIVE_MIDDLEWARE_POLICIES,
    DECLARATIVE_TOOL_POLICIES,
    DECORATED_GLOBAL_HOOKS,
    EVENT_HOOK_DECORATORS,
    MIDDLEWARE_AGENT_CONSTRUCTORS,
    PLUGIN_BASES,
    PLUGIN_GUARD_METHODS,
    PYDANTIC_OUTPUT_VALIDATOR_DECORATORS,
    RUNTIME_PLUGIN_CONSTRUCTORS,
)
from guardcontract.evidence.slicing import EXCLUDED_PARTS

AGENTS = {"agents.Agent", "crewai.Agent", "pydantic_ai.Agent",
          "google.adk.agents.Agent", "google.adk.agents.LlmAgent",
          "google.adk.agents.llm_agent.Agent", "google.adk.agents.llm_agent.LlmAgent"}
AGENT_FRAMEWORKS = {"agents.Agent": "openai-agents", "crewai.Agent": "crewai",
                    "pydantic_ai.Agent": "pydantic-ai",
                    "google.adk.agents.Agent": "google-adk",
                    "google.adk.agents.LlmAgent": "google-adk",
                    "google.adk.agents.llm_agent.Agent": "google-adk",
                    "google.adk.agents.llm_agent.LlmAgent": "google-adk"}
HOOKS = {"crewai.hooks.register_before_tool_call_hook", "crewai.hooks.register_after_tool_call_hook"}
TOOL_DECORATORS = {"agents.function_tool"}
FUNCTION_WRAPPERS = {"google.adk.tools.FunctionTool", "google.adk.tools.function_tool.FunctionTool",
                     "langchain_core.tools.StructuredTool.from_function",
                     "langchain.tools.StructuredTool.from_function"}
AGENT_TOOL_WRAPPERS = {"google.adk.tools.agent_tool.AgentTool"}
GUARD_KEYS = {"input_guardrails", "output_guardrails", "tool_input_guardrails", "tool_output_guardrails", "before_tool_callback", "after_tool_callback", "guardrail", "guardrails"}


def immediate_nodes(statements):
    stack = list(reversed(statements))
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        stack.extend(reversed(list(ast.iter_child_nodes(node))))


def _declaration_tables(extra=None):
    tables = {
        "agent_constructors": dict(AGENT_FRAMEWORKS),
        "function_wrappers": {symbol: {"function_position": 0, "function_keyword": "func"}
                              for symbol in FUNCTION_WRAPPERS},
        "middleware_agent_constructors": dict(MIDDLEWARE_AGENT_CONSTRUCTORS),
        "middleware_policies": dict(DECLARATIVE_MIDDLEWARE_POLICIES),
        "tool_policies": dict(DECLARATIVE_TOOL_POLICIES),
        "tool_decorator_policies": {},
    }
    if extra is None:
        return tables
    if not isinstance(extra, dict) or set(extra) - set(tables):
        raise ValueError("framework_declaration_tables")
    for table, rows in extra.items():
        if not isinstance(rows, dict):
            raise ValueError("framework_declaration_table")
        for symbol, declaration in rows.items():
            if not isinstance(symbol, str) or not symbol:
                raise ValueError("framework_declaration_row")
            if table == "agent_constructors":
                if not isinstance(declaration, str) or not declaration:
                    raise ValueError("framework_agent_declaration")
                tables[table][symbol] = declaration
                continue
            if not isinstance(declaration, dict):
                raise ValueError("framework_declaration_row")
            if table == "function_wrappers":
                if (set(declaration) != {"function_position", "function_keyword"}
                        or type(declaration["function_position"]) is not int
                        or declaration["function_position"] < 0
                        or not isinstance(declaration["function_keyword"], str)
                        or not declaration["function_keyword"]):
                    raise ValueError("framework_function_wrapper")
                tables[table][symbol] = dict(declaration)
                continue
            framework = declaration.get("framework")
            if not isinstance(framework, str) or not framework:
                raise ValueError("framework_declaration_framework")
            if table in {"middleware_policies", "tool_policies"}:
                required = {"framework", "parameter", "policy_keyword", "symbol"}
                if set(declaration) != required or any(
                        not isinstance(declaration[key], str) or not declaration[key]
                        for key in required):
                    raise ValueError("framework_policy_declaration")
            elif table == "tool_decorator_policies":
                required = {"framework", "parameter", "policy_keyword", "symbol",
                            "guarded_values", "deny_modes"}
                if (set(declaration) != required
                        or any(not isinstance(declaration[key], str) or not declaration[key]
                               for key in ("framework", "parameter", "policy_keyword", "symbol"))
                        or not isinstance(declaration["guarded_values"], list)
                        or not declaration["guarded_values"]
                        or not all(isinstance(value, str) for value in declaration["guarded_values"])
                        or not isinstance(declaration["deny_modes"], list)
                        or not declaration["deny_modes"]
                        or not all(isinstance(value, str) for value in declaration["deny_modes"])):
                    raise ValueError("framework_tool_decorator_policy")
            elif set(declaration) != {"framework"}:
                raise ValueError("framework_constructor_declaration")
            tables[table][symbol] = dict(declaration)
    return tables


class RegistrationIndex:
    def __init__(self, tree, path, framework_declarations=None):
        self.path = path
        declarations = _declaration_tables(framework_declarations)
        self.agent_constructors = declarations["agent_constructors"]
        self.function_wrappers = declarations["function_wrappers"]
        self.middleware_agent_constructors = declarations["middleware_agent_constructors"]
        self.middleware_policies = declarations["middleware_policies"]
        self.tool_policies = declarations["tool_policies"]
        self.tool_decorator_policies = declarations["tool_decorator_policies"]
        self.scopes, self.parent, self.definitions = {}, {}, {}
        self.annotations = defaultdict(list)
        self.direct_binding_values = set()
        self.unresolved = []
        self._scope("", tree.body, None)
        self.assignment_locations = defaultdict(list)
        self.guard_attribute_values = defaultdict(list)
        for owner, (nodes, _) in self.scopes.items():
            for node in nodes:
                if isinstance(node, (ast.Assign, ast.AnnAssign)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for target in targets:
                        if (isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name)
                                and target.attr in GUARD_KEYS):
                            self.guard_attribute_values[(owner, target.value.id, target.attr)].append(node.value)
                    self.assignment_locations[(owner, id(node.value))].append(
                        {"path": self.path, "start_line": node.lineno, "end_line": node.end_lineno})

    def _scope(self, name, statements, parent, parameters=()):
        nodes = list(immediate_nodes(statements))
        bindings = defaultdict(list)
        for parameter in parameters:
            bindings[parameter].append(None)
        for node in nodes:
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if node.level:
                    package = self.path.split("/")[:-1]
                    module = ".".join([*package[:len(package) - node.level + 1], *([module] if module else [])]) if node.level <= len(package) else ""
                for alias in node.names:
                    bindings[alias.asname or alias.name].append(module + "." + alias.name if module else None)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    bindings[alias.asname or alias.name.split(".")[0]].append(alias.name if alias.asname else alias.name.split(".")[0])
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    for name_node in ast.walk(target):
                        if isinstance(name_node, ast.Name) and isinstance(name_node.ctx, ast.Store):
                            bindings[name_node.id].append(node.value if isinstance(target, ast.Name) else None)
                            if isinstance(target, ast.Name) and node in statements:
                                self.direct_binding_values.add(id(node.value))
                            if isinstance(node, ast.AnnAssign) and isinstance(target, ast.Name):
                                self.annotations[(name, name_node.id)].append(node.annotation)
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.NamedExpr, ast.AugAssign)):
                for target in ast.walk(node.target):
                    if isinstance(target, ast.Name) and isinstance(target.ctx, ast.Store):
                        bindings[target.id].append(None)
            elif isinstance(node, ast.Delete):
                for target in node.targets:
                    for deleted in ast.walk(target):
                        if isinstance(deleted, ast.Name) and isinstance(deleted.ctx, ast.Del):
                            bindings[deleted.id].append(None)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if item.optional_vars:
                        for target in ast.walk(item.optional_vars):
                            if isinstance(target, ast.Name) and isinstance(target.ctx, ast.Store):
                                bindings[target.id].append(item.context_expr)
            elif isinstance(node, ast.ExceptHandler) and node.name:
                bindings[node.name].append(None)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                bindings[node.name].append(node)
                qualified = name + "." + node.name if name else node.name
                self.definitions[id(node)] = (name, qualified, node)
        self.scopes[name] = (nodes, bindings)
        self.parent[name] = parent
        for node in nodes:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                qualified = self.definitions[id(node)][1]
                parameters = () if isinstance(node, ast.ClassDef) else [a.arg for a in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)]
                if not isinstance(node, ast.ClassDef):
                    parameters += [a.arg for a in (node.args.vararg, node.args.kwarg) if a is not None]
                self._scope(qualified, node.body, name, parameters)

    def guard_attribute_bindings(self, function_name, scope):
        values = []
        while scope is not None:
            for parameter in GUARD_KEYS:
                values.extend(self.guard_attribute_values.get((scope, function_name, parameter), []))
            scope = self.parent[scope]
        return values

    def tool_guard_attribute_data(self, tools, scope):
        values = []
        for tool in tools:
            if isinstance(tool, (ast.FunctionDef, ast.AsyncFunctionDef)):
                values.extend(self.guard_attribute_bindings(tool.name, scope))
        return values

    def binding(self, name, scope, use_line=None):
        while scope is not None:
            values = self.scopes[scope][1].get(name, [])
            if values:
                if len(values) == 1:
                    return scope, values[0]
                if use_line is not None and all(isinstance(value, ast.AST) and
                                                id(value) in self.direct_binding_values
                                                for value in values):
                    preceding = [value for value in values
                                 if getattr(value, "end_lineno", value.lineno) < use_line]
                    if preceding:
                        latest_line = max(getattr(value, "end_lineno", value.lineno)
                                          for value in preceding)
                        latest = [value for value in preceding
                                  if getattr(value, "end_lineno", value.lineno) == latest_line]
                        if len(latest) == 1:
                            return scope, latest[0]
                return scope, None
            scope = self.parent[scope]
        return None, None

    def scoped(self, expression, scope, seen=()):
        if isinstance(expression, ast.Name):
            defining_scope, value = self.binding(expression.id, scope,
                                                 getattr(expression, "lineno", None))
            key = (defining_scope, expression.id)
            if key in seen or value is None:
                return None, defining_scope
            if isinstance(value, str) or isinstance(value, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                return value, defining_scope
            return self.scoped(value, defining_scope, (*seen, key))
        if isinstance(expression, ast.Attribute):
            value, defining_scope = self.scoped(expression.value, scope, seen)
            return (value + "." + expression.attr if isinstance(value, str) else None), defining_scope
        if isinstance(expression, ast.Subscript):
            value, defining_scope = self.scoped(expression.value, scope, seen)
            if isinstance(value, str) and value in AGENT_FRAMEWORKS:
                return value, defining_scope
        return expression, scope

    def resolve(self, expression, scope):
        return self.scoped(expression, scope)[0]

    def origin(self, expression, scope):
        value, defining_scope = self.scoped(expression, scope)
        if isinstance(value, ast.Call):
            canonical = self.resolve(value.func, defining_scope)
            if canonical in AGENTS or not isinstance(expression, ast.Name):
                return canonical
            current = scope
            while current is not None:
                annotations = self.annotations.get((current, expression.id), [])
                if annotations:
                    if len(annotations) != 1:
                        return canonical
                    annotation = annotations[0]
                    base = annotation.value if isinstance(annotation, ast.Subscript) else annotation
                    annotated = self.resolve(base, current)
                    return annotated if annotated in AGENTS else canonical
                current = self.parent[current]
            return canonical
        return value

    def functions(self, expression, scope, seen=frozenset()):
        if isinstance(expression, ast.Attribute):
            bound = self.bound_method_functions(expression, scope)
            if bound:
                return bound
        value, defining_scope = self.scoped(expression, scope)
        if id(value) in seen:
            return []
        if isinstance(value, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return [value]
        if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
            return [f for element in value.elts for f in self.functions(element, defining_scope, seen | {id(value)})]
        return []

    def bound_method_functions(self, expression, scope):
        """Resolve a uniquely bound local instance method conservatively."""
        if not isinstance(expression, ast.Attribute) or not isinstance(expression.value, ast.Name):
            return []
        owner_scope, binding = self.binding(expression.value.id, scope)
        if not isinstance(binding, ast.AST):
            return []
        instance = binding
        if isinstance(binding, (ast.Assign, ast.AnnAssign)):
            instance = binding.value
        if not isinstance(instance, ast.Call):
            return []
        class_value, class_scope = self.scoped(instance.func, owner_scope)
        if not isinstance(class_value, ast.ClassDef):
            return []
        methods = [node for node in class_value.body
                   if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                   and node.name == expression.attr]
        return methods if len(methods) == 1 else []

    def callable_functions(self, expression, scope):
        value = self.resolve(expression, scope)
        return [value] if isinstance(value, (ast.FunctionDef, ast.AsyncFunctionDef)) else []

    def guard_resolution_gaps(self, expression, scope, parameter, seen=frozenset()):
        if isinstance(expression, ast.Attribute) and self.bound_method_functions(expression, scope):
            return []
        value, owner = self.scoped(expression, scope)
        if isinstance(value, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return []
        if isinstance(value, ast.Constant) and value.value is None:
            return []
        if id(value) not in seen and isinstance(value, (ast.List, ast.Tuple, ast.Set)):
            return [gap for item in value.elts for gap in
                    self.guard_resolution_gaps(item, owner, parameter, seen | {id(value)})]
        return [{"path": self.path, "line": expression.lineno, "parameter": parameter,
                 "reason": "cyclic_guard_collection" if id(value) in seen else "guard_callable_unresolved"}]

    def tool_functions(self, expression, scope, seen=frozenset()):
        value, owner = self.scoped(expression, scope)
        if id(value) in seen:
            return []
        if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
            return [f for item in value.elts for f in self.tool_functions(item, owner, seen | {id(value)})]
        if isinstance(value, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return [value]
        if not isinstance(value, ast.Call):
            return []
        canonical = self.resolve(value.func, owner)
        if canonical in AGENT_TOOL_WRAPPERS:
            targets = [k.value for k in value.keywords if k.arg == "agent"]
            if value.args:
                targets.append(value.args[0])
            if len(targets) != 1:
                return []
            return self.tools_for_agent(targets[0], owner)
        if not isinstance(canonical, str) or canonical not in self.function_wrappers:
            return []
        declaration = self.function_wrappers[canonical]
        if any(k.arg is None or k.arg == "coroutine" for k in value.keywords):
            return []
        targets = [k.value for k in value.keywords
                   if k.arg == declaration["function_keyword"]]
        position = declaration["function_position"]
        if len(value.args) > position:
            targets.append(value.args[position])
        if len(targets) != 1:
            return []
        return self.callable_functions(targets[0], owner)

    def declarative_tool_policies(self, expression, scope, seen=frozenset()):
        value, owner = self.scoped(expression, scope)
        if id(value) in seen:
            return [], []
        if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
            pairs = [self.declarative_tool_policies(item, owner, seen | {id(value)})
                     for item in value.elts]
            return ([guard for guards, _ in pairs for guard in guards],
                    [binding for _, bindings in pairs for binding in bindings])
        if not isinstance(value, ast.Call):
            return [], []
        canonical = self.resolve(value.func, owner)
        declaration = self.tool_policies.get(canonical)
        if declaration is None:
            return [], []
        policies = [keyword.value for keyword in value.keywords
                    if keyword.arg == declaration["policy_keyword"]]
        if len(policies) != 1:
            return [], []
        policy, _ = self.scoped(policies[0], owner)
        literal = policy.value if isinstance(policy, ast.Constant) and type(policy.value) is bool else None
        if literal is False:
            return [], []
        tools = self.tool_functions(value, owner)
        wrapper = self.function_wrappers.get(canonical)
        targets = []
        if wrapper is not None:
            targets.extend(keyword.value for keyword in value.keywords
                           if keyword.arg == wrapper["function_keyword"])
            if len(value.args) > wrapper["function_position"]:
                targets.append(value.args[wrapper["function_position"]])
        declared_origin = self.origin(targets[0], owner) if len(targets) == 1 else None
        tool_symbols = sorted(self.definitions[id(tool)][1] for tool in tools)
        guard = {"path": self.path, "start_line": value.lineno, "end_line": value.end_lineno,
                 "evidence_start_line": value.lineno, "symbol": declaration["symbol"],
                 "parameter": declaration["parameter"], "framework": declaration["framework"]}
        binding = {"parameter": declaration["parameter"],
                   "policy_keyword": declaration["policy_keyword"],
                   "status": "static_always" if literal is True else "dynamic",
                   "guarded_tool_names": tool_symbols,
                   "deny_modes": ["reject"] if literal is True else [],
                   "tool_policies": [{"tool": symbol,
                                      "status": "static_always" if literal is True else "dynamic",
                                      "deny_modes": ["reject"] if literal is True else []}
                                     for symbol in tool_symbols],
                   "source": {"path": self.path, "start_line": policies[0].lineno,
                              "end_line": policies[0].end_lineno},
                   **({"declared_tool_origin": declared_origin}
                      if isinstance(declared_origin, str) else {})}
        return [guard], [binding]

    def declarative_tool_decorator_policies(self, tools, scope):
        guards, bindings = [], []
        for tool in tools:
            if not isinstance(tool, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in tool.decorator_list:
                if not isinstance(decorator, ast.Call):
                    continue
                canonical = self.resolve(decorator.func, scope)
                declaration = self.tool_decorator_policies.get(canonical)
                if declaration is None:
                    continue
                values = [keyword.value for keyword in decorator.keywords
                          if keyword.arg == declaration["policy_keyword"]]
                if len(values) != 1 or not isinstance(values[0], ast.Constant):
                    continue
                value = values[0].value
                if value not in declaration["guarded_values"]:
                    continue
                guard = {"path": self.path, "start_line": decorator.lineno,
                         "end_line": decorator.end_lineno,
                         "evidence_start_line": decorator.lineno,
                         "symbol": declaration["symbol"],
                         "parameter": declaration["parameter"],
                         "framework": declaration["framework"]}
                binding = {"parameter": declaration["parameter"],
                           "policy_keyword": declaration["policy_keyword"],
                           "status": "static_explicit",
                           "guarded_tool_names": [self.definitions[id(tool)][1]],
                           "deny_modes": list(declaration["deny_modes"]),
                           "tool_policies": [{"tool": self.definitions[id(tool)][1],
                                              "status": "static_explicit",
                                              "deny_modes": list(declaration["deny_modes"])}],
                           "source": {"path": self.path, "start_line": values[0].lineno,
                                      "end_line": values[0].end_lineno}}
                guards.append(guard)
                bindings.append(binding)
        return guards, bindings

    def unresolved_tools(self, expression, scope, seen=frozenset()):
        if expression is None:
            return []
        value, defining_scope = self.scoped(expression, scope)
        if id(value) not in seen and isinstance(value, (ast.List, ast.Tuple, ast.Set)):
            return [gap for element in value.elts for gap in self.unresolved_tools(element, defining_scope, seen | {id(value)})]
        if self.tool_functions(expression, scope):
            return []
        if isinstance(value, ast.Call):
            wrapper = self.resolve(value.func, defining_scope)
            declaration = self.function_wrappers.get(wrapper)
            if declaration is not None:
                targets = [keyword.value for keyword in value.keywords
                           if keyword.arg == declaration["function_keyword"]]
                position = declaration["function_position"]
                if len(value.args) > position:
                    targets.append(value.args[position])
                if len(targets) == 1:
                    target_origin = self.origin(targets[0], defining_scope)
                    return [{"path": self.path, "start_line": expression.lineno,
                             "end_line": expression.end_lineno,
                             "expression": ast.unparse(expression),
                             "origin": target_origin if isinstance(target_origin, str) else None,
                             "wrapper": wrapper,
                             "reason": "wrapper_function_unresolved"}]
        origin = self.origin(expression, scope)
        reason = "agent_tool_child_unresolved" if origin in AGENT_TOOL_WRAPPERS else (
            "mcp_toolset_unresolved" if isinstance(origin, str) and origin.rsplit(".", 1)[-1] in {"McpToolset", "MCPToolset"} else (
            "cyclic_tool_collection" if id(value) in seen else "tool_dispatch_unresolved")
        )
        details = {}
        if reason == "mcp_toolset_unresolved" and isinstance(value, ast.Call):
            for keyword in value.keywords:
                if keyword.arg != "tool_filter":
                    continue
                try:
                    parsed = ast.literal_eval(keyword.value)
                except (ValueError, TypeError, SyntaxError):
                    details["tool_filter"] = "dynamic"
                else:
                    details["tool_filter"] = parsed if isinstance(parsed, list) and all(isinstance(item, str) for item in parsed) else "dynamic"
        return [{"path": self.path, "start_line": expression.lineno,
                 "end_line": expression.end_lineno,
                 "expression": ast.unparse(expression),
                 "origin": origin if isinstance(origin, str) else None,
                 "reason": reason, **({"details": details} if details else {})}]

    def tool_binding_spans(self, expression, scope, seen=()):
        if expression is None:
            return []
        if isinstance(expression, ast.Name):
            owner, value = self.binding(expression.id, scope)
            key = (owner, expression.id)
            if key in seen or not isinstance(value, ast.AST):
                return []
            spans = self.assignment_locations[(owner, id(value))]
            return spans + self.tool_binding_spans(value, owner, (*seen, key))
        if isinstance(expression, (ast.List, ast.Tuple, ast.Set)):
            return [span for item in expression.elts for span in self.tool_binding_spans(item, scope, seen)]
        if isinstance(expression, ast.Call):
            return [{"path": self.path, "start_line": expression.lineno, "end_line": expression.end_lineno}]
        return []

    def tools_for_agent(self, expression, scope):
        value, defining_scope = self.scoped(expression, scope)
        if not isinstance(value, ast.Call) or self.origin(expression, scope) not in AGENTS:
            return []
        return [f for k in value.keywords if k.arg == "tools" for f in self.tool_functions(k.value, defining_scope)]

    def groups(self):
        found = []
        calls_by_scope_line = defaultdict(list)
        for owner, (nodes, _) in self.scopes.items():
            for node in nodes:
                if isinstance(node, ast.Call):
                    calls_by_scope_line[(owner, node.lineno)].append(node)

        def append(kind, scope, line, guards, tools, related_modules=(), *, framework,
                   extra_tool_gaps=(), unresolved_guard_gaps=(), declarative_guards=(),
                   policy_bindings=()):
            call_nodes = calls_by_scope_line[(scope, line)]
            tool_gaps = [gap for n in call_nodes
                         for keyword in n.keywords if keyword.arg == "tools"
                         for gap in self.unresolved_tools(keyword.value, scope)]
            tool_gaps.extend(extra_tool_gaps)
            guard_owned_effects = [
                {"path": self.path, "line": site.line, "family": site.family,
                 "call": site.call, "association": "guard_body_effect_candidate",
                 "guard_symbol": self.definitions[id(guard)][1],
                 "static_order": analyze_guard_effect_order(guard, site.line, site.call)}
                for guard in guards
                for site in effect_sites_from_tree(
                    guard, self.path, within=guard,
                    origin_resolver=lambda expression, owner=self.definitions[id(guard)][1]:
                        self.origin(expression, owner))
            ]
            if ((guards or unresolved_guard_gaps or declarative_guards)
                    and (tools or tool_gaps or guard_owned_effects)):
                call_ends = [n.end_lineno for n in call_nodes]
                found.append({"kind": kind, "scope": scope, "line": line, "guards": guards, "tools": tools,
                              "unresolved_guards": list(unresolved_guard_gaps),
                              "declarative_guards": list(declarative_guards),
                              "policy_bindings": list(policy_bindings),
                              "unresolved_tools": tool_gaps,
                              "guard_parameters": [{"parameter": k.arg,
                                  "symbol": self.definitions[id(f)][1], "definition_line": f.lineno,
                                  "registration_line": n.lineno}
                                  for n in call_nodes
                                  for k in n.keywords if k.arg in GUARD_KEYS
                                  for f in self.functions(k.value, scope)],
                              "tool_binding_spans": [span for n in call_nodes
                                  for k in n.keywords if k.arg == "tools"
                                  for span in self.tool_binding_spans(k.value, scope)],
                              "guard_binding_spans": [span for n in call_nodes
                                  for k in n.keywords if k.arg in GUARD_KEYS or k.arg == "middleware"
                                  for span in self.tool_binding_spans(k.value, scope)],
                              "registration_binding_spans": [span for n in call_nodes
                                  for span in self.tool_binding_spans(n.func, scope)],
                              "framework": framework,
                              "guard_owned_effects": guard_owned_effects,
                              "registration_end_line": max(call_ends, default=line),
                              "related_modules": sorted(set(related_modules))})
                parameters = found[-1]["guard_parameters"]
                parameters.extend({"parameter": guard["parameter"], "symbol": guard["symbol"],
                                   "definition_line": guard["start_line"], "registration_line": line,
                                   "source": "declarative_framework_policy"}
                                  for guard in declarative_guards)
                if kind in {"agent_decorator_registration", "middleware_registration", "runtime_plugin_registration"}:
                    parameters.extend({"parameter": "output_validator" if kind == "agent_decorator_registration" else guard.name,
                                       "symbol": self.definitions[id(guard)][1],
                                       "definition_line": guard.lineno, "registration_line": line}
                                      for guard in guards)
                elif kind == "tool_guardrail_decorator":
                    for tool in tools:
                        for decorator in tool.decorator_list:
                            if not isinstance(decorator, ast.Call) or decorator.lineno != line:
                                continue
                            parameters.extend({"parameter": k.arg, "symbol": self.definitions[id(f)][1],
                                               "definition_line": f.lineno, "registration_line": line}
                                              for k in decorator.keywords if k.arg in GUARD_KEYS
                                              for f in self.functions(k.value, scope))
                elif kind == "same_scope_global_hook":
                    for call in self.scopes[scope][0]:
                        if isinstance(call, ast.Call) and call.lineno == line:
                            canonical = self.resolve(call.func, scope)
                            if isinstance(canonical, str) and canonical in HOOKS:
                                parameters.extend({"parameter": canonical, "symbol": self.definitions[id(f)][1],
                                                   "definition_line": f.lineno, "registration_line": line}
                                                  for f in guards)
                elif kind == "decorated_global_hook":
                    parameters.extend({"parameter": binding["parameter"],
                                       "symbol": self.definitions[id(guard)][1],
                                       "definition_line": guard.lineno,
                                       "registration_line": line}
                                      for guard in guards
                                      for binding in policy_bindings)

        for scope, (nodes, bindings) in self.scopes.items():
            decorated = defaultdict(lambda: {"guards": [], "tools": []})
            for node in nodes:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for decorator in node.decorator_list:
                        target = decorator.func if isinstance(decorator, ast.Call) else decorator
                        if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
                            receiver = target.value.id
                            if self.origin(target.value, scope) == "pydantic_ai.Agent":
                                receiver = id(self.resolve(target.value, scope))
                                if target.attr in {"tool", "tool_plain"}:
                                    decorated[receiver]["tools"].append(node)
                                elif target.attr in PYDANTIC_OUTPUT_VALIDATOR_DECORATORS:
                                    decorated[receiver]["guards"].append(node)
                            elif target.attr in {"tool", "tool_plain", *PYDANTIC_OUTPUT_VALIDATOR_DECORATORS}:
                                self.unresolved.append({"path": self.path, "line": target.lineno,
                                                        "reason": "decorator_receiver_unresolved_or_outside_framework"})
                        if isinstance(decorator, ast.Call) and self.resolve(decorator.func, scope) in TOOL_DECORATORS:
                            guard_gaps = [gap for k in decorator.keywords if k.arg in GUARD_KEYS
                                          for gap in self.guard_resolution_gaps(k.value, scope, k.arg)]
                            guard_gaps.extend(gap for value in self.guard_attribute_bindings(node.name, scope)
                                              for gap in self.guard_resolution_gaps(value, scope, "post_bound_guard"))
                            self.unresolved.extend(guard_gaps)
                            guards = [f for k in decorator.keywords if k.arg in GUARD_KEYS for f in self.functions(k.value, scope)]
                            guards.extend(f for value in self.guard_attribute_bindings(node.name, scope)
                                          for f in self.functions(value, scope))
                            append("tool_guardrail_decorator", scope, decorator.lineno, guards, [node],
                                   framework="openai-agents", unresolved_guard_gaps=guard_gaps)
                        hook_parameter = None
                        canonical_decorator = self.resolve(target, scope)
                        if canonical_decorator in DECORATED_GLOBAL_HOOKS:
                            hook_parameter = DECORATED_GLOBAL_HOOKS[canonical_decorator]["parameter"]
                        elif (isinstance(decorator, ast.Call)
                              and canonical_decorator in EVENT_HOOK_DECORATORS
                              and decorator.args):
                            event = self.resolve(decorator.args[0], scope)
                            hook_parameter = EVENT_HOOK_DECORATORS[canonical_decorator].get(event)
                        if hook_parameter:
                            local_tools = []
                            for name in bindings:
                                local_tools.extend(self.tools_for_agent(ast.Name(id=name, ctx=ast.Load()), scope))
                            dispatch_gaps = [] if local_tools else [{"path": self.path,
                                "start_line": decorator.lineno, "end_line": decorator.end_lineno,
                                "expression": ast.unparse(target), "origin": canonical_decorator,
                                "reason": "global_tool_dispatch_unresolved"}]
                            append("decorated_global_hook", scope, decorator.lineno, [node], local_tools,
                                   framework="crewai", extra_tool_gaps=dispatch_gaps,
                                   policy_bindings=[{"parameter": hook_parameter,
                                                     "status": "decorator_registration"}])
                if not isinstance(node, ast.Call):
                    continue
                canonical = self.resolve(node.func, scope)
                kwargs = {k.arg: k.value for k in node.keywords if k.arg}
                tools = self.tool_functions(kwargs.get("tools"), scope)
                guards = [f for name, value in kwargs.items() if name in GUARD_KEYS for f in self.functions(value, scope)]
                if isinstance(canonical, str) and canonical in self.agent_constructors:
                    agent_framework = self.agent_constructors[canonical]
                    guard_gaps = [gap for name, value in kwargs.items() if name in GUARD_KEYS
                                  for gap in self.guard_resolution_gaps(value, scope, name)]
                    tool_guard_values = self.tool_guard_attribute_data(tools, scope)
                    guard_gaps.extend(gap for value in tool_guard_values
                                      for gap in self.guard_resolution_gaps(value, scope, "post_bound_guard"))
                    guards.extend(f for value in tool_guard_values
                                  for f in self.functions(value, scope))
                    declarative_guards, policy_bindings = self.declarative_tool_policies(
                        kwargs.get("tools"), scope)
                    decorator_guards, decorator_bindings = self.declarative_tool_decorator_policies(
                        tools, scope)
                    declarative_guards.extend(decorator_guards)
                    policy_bindings.extend(decorator_bindings)
                    declarative_guards = [guard for guard in declarative_guards
                                          if guard["framework"] == agent_framework]
                    active_parameters = {guard["parameter"] for guard in declarative_guards}
                    policy_bindings = [binding for binding in policy_bindings
                                       if binding["parameter"] in active_parameters]
                    self.unresolved.extend(guard_gaps)
                    append("constructor_guard_and_tools", scope, node.lineno, guards, tools,
                           framework=agent_framework, unresolved_guard_gaps=guard_gaps,
                           declarative_guards=declarative_guards,
                           policy_bindings=policy_bindings if declarative_guards else [])
                if canonical == "crewai.Task":
                    guard_gaps = [gap for name, value in kwargs.items() if name in GUARD_KEYS
                                  for gap in self.guard_resolution_gaps(value, scope, name)]
                    self.unresolved.extend(guard_gaps)
                    task_tools = self.tools_for_agent(kwargs.get("agent"), scope)
                    task_tool_gaps = []
                    if not task_tools and kwargs.get("agent") is not None:
                        task_tool_gaps.extend(self.unresolved_tools(kwargs["agent"], scope))
                    if not task_tools and not task_tool_gaps and kwargs.get("config") is not None:
                        config = kwargs["config"]
                        task_tool_gaps.append({"path": self.path, "start_line": config.lineno,
                                               "end_line": config.end_lineno,
                                               "expression": ast.unparse(config), "origin": None,
                                               "reason": "task_config_agent_binding_pending"})
                    append("task_agent_reference", scope, node.lineno, guards, task_tools,
                           framework="crewai", extra_tool_gaps=task_tool_gaps,
                           unresolved_guard_gaps=guard_gaps)
                if canonical in HOOKS and node.args:
                    self.unresolved.extend(self.guard_resolution_gaps(node.args[0], scope, canonical))
                    hook_guards = self.functions(node.args[0], scope)
                    local_tools = []
                    for name in bindings:
                        local_tools.extend(self.tools_for_agent(ast.Name(id=name, ctx=ast.Load()), scope))
                    dispatch_gaps = [] if local_tools else [{
                        "path": self.path,
                        "start_line": node.lineno,
                        "end_line": node.end_lineno,
                        "expression": ast.unparse(node.func),
                        "origin": canonical,
                        "reason": "global_tool_dispatch_unresolved",
                    }]
                    append("same_scope_global_hook", scope, node.lineno, hook_guards, local_tools,
                           framework="crewai", extra_tool_gaps=dispatch_gaps)
                if canonical in self.middleware_agent_constructors:
                    middleware_framework = self.middleware_agent_constructors[canonical]["framework"]
                    middleware, middleware_scope = self.scoped(kwargs.get("middleware"), scope)
                    if isinstance(middleware, (ast.List, ast.Tuple)):
                        methods = []
                        declarative_guards = []
                        policy_bindings = []
                        related_modules = set()
                        for item in middleware.elts:
                            cls = self.origin(item, middleware_scope)
                            instance, instance_scope = self.scoped(item, middleware_scope)
                            if isinstance(instance, ast.Call):
                                for argument in [*instance.args, *(k.value for k in instance.keywords)]:
                                    origin = self.origin(argument, instance_scope)
                                    if isinstance(origin, str) and "." in origin:
                                        related_modules.add(origin.rsplit(".", 1)[0])
                            if isinstance(cls, ast.ClassDef):
                                class_scope = self.definitions[id(cls)][0]
                                if any(self.resolve(base, class_scope) == "langchain.agents.middleware.AgentMiddleware" for base in cls.bases):
                                    methods.extend(n for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in {"before_agent", "after_agent", "before_model", "after_model", "wrap_tool_call", "awrap_tool_call"})
                            elif isinstance(cls, (ast.FunctionDef, ast.AsyncFunctionDef)):
                                # LangChain also accepts a function decorated with
                                # @wrap_tool_call directly in create_agent middleware.
                                wrapped = any(
                                    self.resolve(d.func if isinstance(d, ast.Call) else d, middleware_scope)
                                    == "langchain.agents.middleware.wrap_tool_call"
                                    for d in cls.decorator_list
                                )
                                if wrapped:
                                    methods.append(cls)
                            elif (isinstance(cls, str) and cls in self.middleware_policies
                                  and isinstance(instance, ast.Call)):
                                declaration = self.middleware_policies[cls]
                                if declaration["framework"] != middleware_framework:
                                    continue
                                values = [k.value for k in instance.keywords
                                          if k.arg == declaration["policy_keyword"]]
                                if len(values) != 1:
                                    continue
                                policy, policy_scope = self.scoped(values[0], instance_scope)
                                guarded_names = []
                                policy_status = "unknown"
                                if isinstance(policy, ast.Dict):
                                    policy_status = "static"
                                    enabled = False
                                    tool_policies = []
                                    deny_modes = set()
                                    for key, value in zip(policy.keys, policy.values):
                                        name = key.value if isinstance(key, ast.Constant) and isinstance(key.value, str) else None
                                        literal = value.value if isinstance(value, ast.Constant) and type(value.value) is bool else None
                                        if literal is not False:
                                            enabled = True
                                            if name is not None:
                                                guarded_names.append(name)
                                            modes = []
                                            item_status = "static_default" if literal is True else "dynamic"
                                            if literal is True:
                                                modes = ["reject", "respond"]
                                            elif isinstance(value, ast.Dict):
                                                allowed = next((v for k, v in zip(value.keys, value.values)
                                                    if isinstance(k, ast.Constant) and k.value == "allowed_decisions"), None)
                                                if isinstance(allowed, (ast.List, ast.Tuple)) and all(
                                                        isinstance(item, ast.Constant) and isinstance(item.value, str)
                                                        for item in allowed.elts):
                                                    item_status = "static_explicit"
                                                    modes = sorted({item.value for item in allowed.elts
                                                                   if item.value in {"reject", "respond"}})
                                            deny_modes.update(modes)
                                            tool_policies.append({"tool": name, "status": item_status,
                                                                  "deny_modes": modes})
                                    if not enabled:
                                        continue
                                else:
                                    tool_policies = []
                                    deny_modes = set()
                                declarative_guards.append({"path": self.path,
                                    "start_line": instance.lineno, "end_line": instance.end_lineno,
                                    "evidence_start_line": instance.lineno,
                                    "symbol": declaration["symbol"], "parameter": declaration["parameter"]})
                                policy_bindings.append({"parameter": declaration["parameter"],
                                    "policy_keyword": declaration["policy_keyword"],
                                    "status": policy_status, "guarded_tool_names": sorted(set(guarded_names)),
                                    "deny_modes": sorted(deny_modes), "tool_policies": tool_policies,
                                    "source": {"path": self.path, "start_line": values[0].lineno,
                                               "end_line": values[0].end_lineno}})
                        append("middleware_registration", scope, node.lineno, methods, tools, related_modules,
                               framework=middleware_framework, declarative_guards=declarative_guards,
                               policy_bindings=policy_bindings)
                if canonical in RUNTIME_PLUGIN_CONSTRUCTORS:
                    declaration = RUNTIME_PLUGIN_CONSTRUCTORS[canonical]
                    plugins, plugins_scope = self.scoped(kwargs.get("plugins"), scope)
                    plugin_items = plugins.elts if isinstance(plugins, (ast.List, ast.Tuple, ast.Set)) else []
                    methods = []
                    unresolved_plugins = []
                    for item in plugin_items:
                        plugin = self.origin(item, plugins_scope)
                        if isinstance(plugin, ast.ClassDef):
                            class_scope = self.definitions[id(plugin)][0]
                            if any(self.resolve(base, class_scope) in PLUGIN_BASES for base in plugin.bases):
                                methods.extend(child for child in plugin.body
                                               if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                                               and child.name in PLUGIN_GUARD_METHODS)
                        elif plugin is not None:
                            unresolved_plugins.append({"path": self.path, "line": item.lineno,
                                "parameter": "plugins", "reason": "plugin_class_unresolved",
                                "origin": plugin if isinstance(plugin, str) else None})
                    runtime_tools = []
                    runtime_tool_gaps = []
                    for keyword in declaration["agent_keywords"]:
                        if kwargs.get(keyword) is None:
                            continue
                        runtime_tools.extend(self.tools_for_agent(kwargs[keyword], scope))
                        if not runtime_tools:
                            runtime_tool_gaps.extend(self.unresolved_tools(kwargs[keyword], scope))
                    append("runtime_plugin_registration", scope, node.lineno, methods, runtime_tools,
                           framework=declaration["framework"], extra_tool_gaps=runtime_tool_gaps,
                           unresolved_guard_gaps=unresolved_plugins)
            for receiver, group in decorated.items():
                if group["guards"]:
                    append("agent_decorator_registration", scope, group["guards"][0].lineno, group["guards"], group["tools"], framework="pydantic-ai")
        return found


def _enrich_dependency_effects(root, files, groups):
    """Reuse the repository dependency index over already parsed source trees."""
    from guardcontract.discovery.dependencies import analyze_guard_repositories_i3 as dependency_core
    from guardcontract.discovery.dependencies import analyze_guard_repositories_i6 as dependency

    modules = []
    for path, tree in files.items():
        module = dependency_core.ModuleRecord(
            path=path, raw=b"", tree=tree, module=dependency_core.primary_module(path)
        )
        module._index()
        modules.append(module)
    for group in groups:
        recovered = []
        resolved_tools = []
        if group.get("framework") == "crewai" and group.get("kind") == "task_agent_reference":
            task = dependency.recover_task_evidence(
                Path(root), modules, {"path": group["path"], "line": group["registration_line"]}
            )
            recovered.extend(task.get("explicit_effects", []))
            resolved_tools.extend(task.get("resolved_tools", []))
            if task.get("hybrid_binding"):
                group["dependency_binding"] = task["hybrid_binding"]
            elif any(key in task for key in ("agent_factory", "task_config")):
                group["dependency_binding"] = {key: task[key] for key in ("agent_factory", "agent_factory_resolution", "task_config") if key in task}
        effects = {(item["path"], item["line"], item["call"]): item
                   for item in group.get("effects", [])}
        added = 0
        for item in recovered:
            key = (item["path"], item["line"], item["call"])
            if key not in effects:
                effects[key] = {**item, "association": "repository_dependency_candidate"}
                added += 1
        group["effects"] = sorted(effects.values(), key=lambda item: (item["path"], item["line"], item["call"]))
        _bind_unique_policy_tool(
            group, {item.get("tool_symbol") for item in group["effects"]},
            "unique_dependency_effect_tool_recovery")
        group["dependency_enrichment"] = {
            "resolved_tools": resolved_tools,
            "added_effect_candidates": added,
            "path_verified": False,
        }


def _recover_imported_tools(files, indexes, groups):
    """Resolve uniquely imported tool functions across the current repository.

    This is a repository-wide symbol-index operation.  Ambiguous, dynamic, or
    missing imports stay in ``unresolved_tools`` and therefore cannot become an
    actionable path by accident.
    """
    candidates = defaultdict(list)
    for path, index in indexes.items():
        module = path.removesuffix(".py").replace("/", ".")
        if module.endswith(".__init__"):
            module = module.removesuffix(".__init__")
        for _, qualified, node in index.definitions.values():
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                candidates[f"{module}.{node.name}"].append((path, index, node, qualified))
    for group in groups:
        recovered = []
        recovered_by_origin = defaultdict(set)
        remaining = []
        for unresolved in group.get("unresolved_tools", []):
            origin = unresolved.get("origin")
            matches = candidates.get(origin, []) if isinstance(origin, str) else []
            if len(matches) != 1:
                remaining.append(unresolved)
                continue
            path, index, function, qualified = matches[0]
            recovered.append({"path": path, "start_line": function.lineno,
                              "end_line": function.end_lineno, "evidence_start_line": min(
                                  [function.lineno, *(d.lineno for d in function.decorator_list)]),
                              "symbol": qualified})
            recovered_by_origin[origin].add(qualified)
            group.setdefault("effects", []).extend(
                {"path": site.path, "line": site.line, "family": site.family, "call": site.call,
                 "association": "imported_tool_definition_candidate", "tool_symbol": qualified}
                for site in effect_sites_from_tree(files[path], path, within=function)
            )
        if recovered:
            group["tools"].extend(recovered)
            for binding in group.get("policy_bindings", []):
                origin = binding.get("declared_tool_origin")
                symbols = recovered_by_origin.get(origin, set())
                if not binding.get("tool_policies") and len(symbols) == 1:
                    symbol = next(iter(symbols))
                    binding["guarded_tool_names"] = [symbol]
                    binding["tool_policies"] = [{"tool": symbol,
                        "status": binding.get("status", "unknown"),
                        "deny_modes": list(binding.get("deny_modes", []))}]
                    binding["cross_file_tool_binding"] = "declared_wrapper_target_recovery"
            _bind_unique_policy_tool(
                group, {item["symbol"] for item in recovered}, "unique_import_recovery")
        group["unresolved_tools"] = remaining
        group["effects"] = sorted(group.get("effects", []), key=lambda item: (item.get("path", ""), item.get("line", 0), item.get("call", ""), item.get("association", "")))


def _bind_unique_policy_tool(group, symbols, provenance):
    symbols = sorted(symbol for symbol in symbols if isinstance(symbol, str) and symbol)
    empty_policies = [binding for binding in group.get("policy_bindings", [])
                      if not binding.get("tool_policies")]
    if len(empty_policies) != 1 or len(symbols) != 1:
        return False
    binding = empty_policies[0]
    binding["guarded_tool_names"] = symbols
    binding["tool_policies"] = [
        {"tool": symbols[0], "status": binding.get("status", "unknown"),
         "deny_modes": list(binding.get("deny_modes", []))}]
    binding["cross_file_tool_binding"] = provenance
    return True


def _recover_imported_bound_guards(files, indexes, groups):
    """Recover uniquely imported class methods used as guard callbacks."""
    candidates = defaultdict(list)
    for path, index in indexes.items():
        parts = path.removesuffix(".py").replace("/", ".").split(".")
        modules = [".".join(parts[start:]) for start in range(len(parts))]
        for _, qualified, node in index.definitions.values():
            if not isinstance(node, ast.ClassDef):
                continue
            for method in node.body:
                if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for module in modules:
                        candidates[f"{module}.{node.name}.{method.name}"].append((path, index, method, f"{qualified}.{method.name}"))
    for group in groups:
        if not group.get("unresolved_guards"):
            continue
        index = indexes.get(group.get("path"))
        tree = files.get(group.get("path"))
        if index is None or tree is None:
            continue
        calls = [node for node in ast.walk(tree)
                 if isinstance(node, ast.Call) and node.lineno == group.get("registration_line")]
        recovered = []
        for call in calls:
            for keyword in call.keywords:
                if keyword.arg not in GUARD_KEYS or not isinstance(keyword.value, ast.Attribute):
                    continue
                if not isinstance(keyword.value.value, ast.Name):
                    continue
                owner, binding = index.binding(keyword.value.value.id, group.get("scope", ""))
                if not isinstance(binding, ast.Call):
                    continue
                class_ref = index.resolve(binding.func, owner)
                if not isinstance(class_ref, str):
                    continue
                matches = candidates.get(f"{class_ref}.{keyword.value.attr}", [])
                if len(matches) != 1:
                    continue
                path, target_index, method, qualified = matches[0]
                location = {"path": path, "start_line": method.lineno, "end_line": method.end_lineno,
                            "evidence_start_line": min([method.lineno, *(d.lineno for d in method.decorator_list)]),
                            "symbol": qualified}
                if location not in group.get("guards", []):
                    group.setdefault("guards", []).append(location)
                    group.setdefault("guard_parameters", []).append({"parameter": keyword.arg, "symbol": qualified,
                                                                        "definition_line": method.lineno,
                                                                        "registration_line": call.lineno})
                recovered.append((keyword.arg, call.lineno))
        if recovered:
            recovered_parameters = {parameter for parameter, _line in recovered}
            group["unresolved_guards"] = [gap for gap in group["unresolved_guards"]
                                           if gap.get("parameter") not in recovered_parameters]


def _recover_imported_plugin_guards(indexes, groups):
    """Resolve unique imported BasePlugin classes with pre/post tool hooks."""
    classes = defaultdict(list)
    for path, index in indexes.items():
        parts = path.removesuffix(".py").replace("/", ".").split(".")
        modules = [".".join(parts[start:]) for start in range(len(parts))]
        for scope, qualified, node in index.definitions.values():
            if not isinstance(node, ast.ClassDef):
                continue
            if not any(index.resolve(base, scope) in PLUGIN_BASES for base in node.bases):
                continue
            methods = [method for method in node.body
                       if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
                       and method.name in PLUGIN_GUARD_METHODS]
            if methods:
                for module in modules:
                    classes[f"{module}.{node.name}"].append((path, index, methods, qualified))
    for group in groups:
        if group.get("kind") != "runtime_plugin_registration":
            continue
        remaining = []
        for gap in group.get("unresolved_guards", []):
            if gap.get("reason") != "plugin_class_unresolved" or not gap.get("origin"):
                remaining.append(gap)
                continue
            matches = classes.get(gap["origin"], [])
            if len(matches) != 1:
                remaining.append(gap)
                continue
            path, index, methods, qualified = matches[0]
            for method in methods:
                symbol = f"{qualified}.{method.name}"
                location = {"path": path, "start_line": method.lineno,
                            "end_line": method.end_lineno,
                            "evidence_start_line": min([method.lineno,
                                *(decorator.lineno for decorator in method.decorator_list)]),
                            "symbol": symbol}
                if location not in group["guards"]:
                    group["guards"].append(location)
                    group["guard_parameters"].append({"parameter": method.name,
                        "symbol": symbol, "definition_line": method.lineno,
                        "registration_line": group["registration_line"],
                        "source": "unique_imported_plugin_class"})
                    group["guard_semantics"].append({"symbol": symbol,
                        "parameter": method.name,
                        **classify_guard_semantics([method], framework=group["framework"],
                                                   parameter=method.name)})
        group["unresolved_guards"] = remaining


def discover_registrations(root, max_files=2000, max_file_bytes=512000, max_groups=40, *,
                           index_class=RegistrationIndex, dependency_enrichment=True,
                           shared_call_recovery=True, module_roots=(".",), layout_mode="packaging",
                           framework_declarations=None):
    from guardcontract.discovery.repository_calls import validate_module_roots
    module_roots = validate_module_roots(module_roots)
    if layout_mode not in {"packaging", "explicit"}:
        raise ValueError("unknown_project_layout_mode")
    if any(type(v) is not int or v < 1 for v in (max_files, max_file_bytes, max_groups)):
        raise ValueError("positive_registration_budgets_required")
    _declaration_tables(framework_declarations)
    root = Path(root).resolve()
    files, indexes, ledger = {}, {}, []
    enumeration_complete = True
    def enumeration_error(exc):
        nonlocal enumeration_complete
        enumeration_complete = False
        failed = Path(exc.filename) if exc.filename else root
        ledger.append({"path": failed.relative_to(root).as_posix(),
                       "status": "unavailable", "error_kind": type(exc).__name__,
                       "stage": "source_enumeration"})
    def source_paths():
        for directory, dirs, names in os.walk(root, followlinks=False, onerror=enumeration_error):
            dirs[:] = sorted(d for d in dirs if d not in EXCLUDED_PARTS and not d.startswith(".venv") and not (Path(directory) / d).is_symlink())
            for name in sorted(names):
                if name.endswith(".py"):
                    yield Path(directory) / name
    candidates = source_paths()
    for number, path in enumerate(candidates):
        relative = path.relative_to(root).as_posix()
        status = {"path": relative}
        if number >= max_files:
            ledger.append({**status, "status": "file_budget_deferred"})
            enumeration_complete = False
            break
        try:
            if path.is_symlink() or not path.resolve().is_relative_to(root):
                raise ValueError("unsafe_source_path")
            with path.open("rb") as handle:
                raw = handle.read(max_file_bytes + 1)
            if len(raw) > max_file_bytes:
                raise ValueError("source_byte_budget")
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SyntaxWarning)
                tree = ast.parse(raw.decode("utf-8-sig"))
            indexes[relative] = index_class(
                tree, relative, framework_declarations=framework_declarations)
            files[relative] = tree
            status["status"] = "parsed"
            status["source_sha256"] = hashlib.sha256(raw).hexdigest()
            status["bytes"] = len(raw)
        except (OSError, UnicodeError, SyntaxError, ValueError) as exc:
            status.update(status="unavailable", error_kind=type(exc).__name__)
        ledger.append(status)
    groups, deferred = [], 0
    for path, index in indexes.items():
        for group in index.groups():
            if len(groups) >= max_groups:
                deferred += 1
                continue
            def location(node):
                return {"path": path, "start_line": node.lineno, "end_line": node.end_lineno,
                        "evidence_start_line": min([node.lineno, *(d.lineno for d in getattr(node, "decorator_list", []))]),
                        "symbol": index.definitions[id(node)][1]}
            effects = list(group.get("guard_owned_effects", []))
            helper_locations = []
            guard_semantics = []
            for guard in group["guards"]:
                symbol = index.definitions[id(guard)][1]
                parameters = [row["parameter"] for row in group["guard_parameters"]
                              if row.get("symbol") == symbol]
                guard_nodes = [guard]
                seen_guard_nodes = {id(guard)}
                pending_guard_nodes = [guard]
                while pending_guard_nodes:
                    current = pending_guard_nodes.pop()
                    current_scope = index.definitions[id(current)][1]
                    for call in ast.walk(current):
                        if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name):
                            continue
                        for helper in index.callable_functions(call.func, current_scope):
                            if id(helper) not in seen_guard_nodes:
                                seen_guard_nodes.add(id(helper))
                                guard_nodes.append(helper)
                                pending_guard_nodes.append(helper)
                for parameter in parameters or ["unknown"]:
                    guard_semantics.append({"symbol": symbol, "parameter": parameter,
                                            **classify_guard_semantics(
                                                guard_nodes, framework=group["framework"],
                                                parameter=parameter)})
            for guard in group.get("declarative_guards", []):
                policies = [row for row in group.get("policy_bindings", [])
                            if row.get("parameter") == guard["parameter"]]
                statically_complete = bool(policies) and all(
                    row.get("status") in {"static", "static_always"}
                    and all(item.get("status", "").startswith("static")
                            for item in row.get("tool_policies", []))
                    for row in policies)
                capability = ("present" if any(row.get("deny_modes") for row in policies)
                              else "absent" if statically_complete else "unknown")
                guard_semantics.append({"symbol": guard["symbol"], "parameter": guard["parameter"],
                                        "deny_capability": capability,
                                        "analysis_complete": capability in {"present", "absent"},
                                        "evidence": [{"kind": "external_runtime_decision",
                                                      "deny_modes": sorted({mode for row in policies
                                                                           for mode in row.get("deny_modes", [])})}]})
            for function in group["tools"]:
                tool_symbol = index.definitions[id(function)][1]
                effects.extend({"path": s.path, "line": s.line, "family": s.family, "call": s.call,
                                "association": "tool_body_syntax_not_execution", "tool_symbol": tool_symbol}
                               for s in effect_sites_from_tree(
                                   files[path], path, within=function,
                                   origin_resolver=lambda expression, owner=index.definitions[id(function)][1]:
                                       index.origin(expression, owner)))
            # Follow unique local function names, preserving their lexical scope.
            # These are possible delegates, not a proof that every call executes.
            roots = group["guards"] + group["tools"]
            local_call_edges = []
            visited = {id(node) for node in roots}
            todo = list(roots)
            import_modules = set(group["related_modules"])
            while todo:
                function = todo.pop()
                function_scope = index.definitions[id(function)][1]
                for node in immediate_nodes(function.body):
                    if isinstance(node, (ast.Name, ast.Attribute)) and isinstance(node.ctx, ast.Load):
                        origin = index.origin(node, function_scope)
                        if isinstance(origin, str) and "." in origin:
                            import_modules.add(origin.rsplit(".", 1)[0])
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                        for delegate in index.callable_functions(node.func, function_scope):
                            local_call_edges.append({"caller": location(function), "callee": location(delegate),
                                                     "path": path, "line": node.lineno,
                                                     "status": "lexically_resolved_call_candidate"})
                            if id(delegate) not in visited:
                                visited.add(id(delegate))
                                todo.append(delegate)
                                helper_locations.append({**location(delegate), "association": "local_call_candidate"})
            # Keep tool delegate effects separate from policy-only helper calls.
            tool_seen = {id(node) for node in group["tools"]}
            tool_todo = [(node, [], index.definitions[id(node)][1]) for node in group["tools"]]
            while tool_todo:
                caller, chain, root_tool_symbol = tool_todo.pop()
                caller_scope = index.definitions[id(caller)][1]
                for call in immediate_nodes(caller.body):
                    if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name):
                        continue
                    for delegate in index.callable_functions(call.func, caller_scope):
                        if id(delegate) in tool_seen:
                            continue
                        tool_seen.add(id(delegate))
                        delegate_chain = [*chain, {"path": path, "line": call.lineno,
                                                   "caller": caller_scope,
                                                   "callee": index.definitions[id(delegate)][1]}]
                        tool_todo.append((delegate, delegate_chain, root_tool_symbol))
                        effects.extend({"path": s.path, "line": s.line, "family": s.family,
                                        "call": s.call, "association": "local_tool_call_candidate",
                                        "call_chain": delegate_chain, "tool_symbol": root_tool_symbol}
                                       for s in effect_sites_from_tree(
                                           files[path], path, within=delegate,
                                           origin_resolver=lambda expression, owner=index.definitions[id(delegate)][1]:
                                               index.origin(expression, owner)))
            for helper, tree in files.items():
                module = helper.removesuffix(".py").replace("/", ".")
                if module.endswith(".__init__"):
                    module = module.removesuffix(".__init__")
                if module in import_modules:
                    helper_index = indexes[helper]
                    effects.extend({"path": s.path, "line": s.line, "family": s.family, "call": s.call,
                                    "association": "imported_helper_candidate_path_unresolved"} for s in effect_sites_from_tree(tree, helper))
                    helper_locations.extend({"path": helper, "start_line": node.lineno, "end_line": node.end_lineno,
                                             "symbol": qualified, "association": "imported_helper_definition_candidate"}
                                            for _, qualified, node in helper_index.definitions.values()
                                            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)))
            groups.append({"kind": group["kind"], "path": path, "scope": group["scope"], "registration_line": group["line"],
                           "framework": group["framework"],
                           "unresolved_tools": group["unresolved_tools"],
                           "tool_binding_spans": group["tool_binding_spans"],
                           "guard_binding_spans": group["guard_binding_spans"],
                           "registration_binding_spans": group["registration_binding_spans"],
                           "guard_parameters": group["guard_parameters"],
                           "guard_semantics": guard_semantics,
                           "registration_end_line": group["registration_end_line"],
                           "guards": [location(n) for n in group["guards"]] + group.get("declarative_guards", []),
                           "policy_bindings": group.get("policy_bindings", []),
                           "tools": [location(n) for n in group["tools"]],
                           "unresolved_guards": group.get("unresolved_guards", []),
                           "helpers": helper_locations,
                           "local_call_edges": local_call_edges,
                           "effects": effects, "guard_effect_path_verified": False, "runtime_activation_verified": False})
    project_layout = {"files": [], "declarations": [], "gaps": [], "complete": True}
    if layout_mode == "packaging":
        from guardcontract.discovery.project_layout import read_project_layout
        project_layout = read_project_layout(root, files)
        module_roots = tuple(dict.fromkeys([*module_roots, *(d["root"] for d in project_layout["declarations"])]))
    if shared_call_recovery:
        from guardcontract.discovery.repository_calls import enrich_call_candidates
        enrich_call_candidates(files, indexes, groups, module_roots=module_roots)
    _recover_imported_tools(files, indexes, groups)
    _recover_imported_bound_guards(files, indexes, groups)
    _recover_imported_plugin_guards(indexes, groups)
    if dependency_enrichment:
        _enrich_dependency_effects(root, files, groups)
    return {"task_version": "registration-project-layout-3", "module_roots": list(module_roots),
            "project_layout": project_layout, "layout_mode": layout_mode,
            "groups": groups, "files": ledger, "groups_budget_deferred": deferred,
            "source_enumeration_complete": enumeration_complete,
            "unresolved_registrations": [r for index in indexes.values() for r in index.unresolved],
            "execution_health": "completed" if all(x["status"] == "parsed" for x in ledger) and not deferred and project_layout["complete"] else "partial",
            "claim_boundary": "Source registration candidates only. Hooks, middleware and imported helper sinks require downstream path and behavior validation."}
