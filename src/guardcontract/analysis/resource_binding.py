"""Conservative Python lexical binding, never a runtime reachability proof.

Version 159-2: indexed queries, conservative per-name mutation masks, alias coordinates.
Scopes with multiple or conditional definitions stay unresolved. Inputs are
untrusted source text; this module parses but never imports/executes that text.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field


def dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return base + "." + node.attr if base else None
    return None


@dataclass
class Scope:
    parent: object = None
    kind: str = "module"
    bindings: dict = field(default_factory=dict)

    def bind(self, name, value):
        self.bindings.setdefault(name, []).append(value)


class PythonBindingsV3(ast.NodeVisitor):
    def __init__(self, source):
        self.tree = ast.parse(source)
        self.named_expression_names = {node.target.id for node in ast.walk(self.tree) if isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name)}
        self.externally_declared_names = {name for node in ast.walk(self.tree) if isinstance(node, (ast.Global, ast.Nonlocal)) for name in node.names}
        self.scope = Scope()
        self.scopes = {}
        self.conditional = False
        self.dead = False
        self.dead_nodes = set()
        self.visit(self.tree)
        self.node_index = NodeIndex(list(ast.walk(self.tree)))
        self.query_count = 0
        self.candidate_count = 0

    def visit(self, node):
        self.scopes[id(node)] = self.scope
        if self.dead:
            self.dead_nodes.add(id(node))
        return super().visit(node)

    def _bind(self, name, value):
        if self.dead:
            # Python determines function-local names at compile time, even for
            # assignments/imports in statically dead branches.
            if self.scope.kind == "function":
                self.scope.bind(name, None)
        else:
            self.scope.bind(name, None if self.conditional else value)

    def visit_Import(self, node):
        for alias in node.names:
                self._bind(alias.asname or alias.name.split(".")[0],
                       ("import", alias.name if alias.asname else alias.name.split(".")[0], node.lineno, node.col_offset))

    def visit_ImportFrom(self, node):
        for alias in node.names:
            if alias.name == "*":
                self._bind("*", None)
            else:
                self._bind(alias.asname or alias.name,
                           ("import", node.module + "." + alias.name, node.lineno, node.col_offset)
                           if node.module and node.level == 0 else None)

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self._bind(node.id, None)

    def visit_Attribute(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            name = dotted(node)
            if name:
                self._bind(name.split(".")[0], None)
        self.generic_visit(node)

    def visit_Assign(self, node):
        self.visit(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._bind(target.id, ("expr", node.value, self.scope))
            else:
                self.visit(target)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self.visit(node.value)
        if isinstance(node.target, ast.Name):
            self._bind(node.target.id, ("expr", node.value, self.scope) if node.value else None)
        else:
            self.visit(node.target)

    def visit_ExceptHandler(self, node):
        if node.name:
            self._bind(node.name, None)
        self.generic_visit(node)

    def visit_Global(self, node):
        for name in node.names:
            self._bind(name, None)

    visit_Nonlocal = visit_Global

    def visit_MatchAs(self, node):
        if node.name:
            self._bind(node.name, None)
        self.generic_visit(node)

    visit_MatchStar = visit_MatchAs

    def visit_MatchMapping(self, node):
        if node.rest:
            self._bind(node.rest, None)
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        self._bind(node.name, None)
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in node.args.defaults + [v for v in node.args.kw_defaults if v is not None]:
            self.visit(default)
        for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs + [a for a in (node.args.vararg, node.args.kwarg) if a]:
            if arg.annotation:
                self.visit(arg.annotation)
        if node.returns:
            self.visit(node.returns)
        outer = self.scope
        # A class namespace is not an enclosing lexical scope for a method.
        parent = outer.parent if outer.kind == "class" else outer
        self.scope = Scope(parent=parent, kind="function")
        for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
            self.scope.bind(arg.arg, None)
        for arg in (node.args.vararg, node.args.kwarg):
            if arg:
                self.scope.bind(arg.arg, None)
        for child in node.body:
            self.visit(child)
        self.scope = outer

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self._bind(node.name, None)
        for item in node.bases + node.decorator_list:
            self.visit(item)
        outer = self.scope
        parent = outer
        while parent and parent.kind == "class":
            parent = parent.parent
        for keyword in node.keywords:
            self.visit(keyword)
        self.scope = Scope(parent=parent, kind="class")
        for child in node.body:
            self.visit(child)
        self.scope = outer

    def visit_Lambda(self, node):
        outer = self.scope
        for default in node.args.defaults + [v for v in node.args.kw_defaults if v is not None]:
            self.visit(default)
        self.scope = Scope(parent=outer.parent if outer.kind == "class" else outer, kind="function")
        for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
            self.scope.bind(arg.arg, None)
        for arg in (node.args.vararg, node.args.kwarg):
            if arg:
                self.scope.bind(arg.arg, None)
        self.visit(node.body)
        self.scope = outer

    def visit_If(self, node):
        self.visit(node.test)
        prior_cond, prior_dead = self.conditional, self.dead
        fixed = node.test.value if isinstance(node.test, ast.Constant) and type(node.test.value) is bool else None
        for branch, selected in ((node.body, fixed), (node.orelse, None if fixed is None else not fixed)):
            self.conditional = prior_cond or fixed is None
            self.dead = prior_dead or selected is False
            for child in branch:
                self.visit(child)
        self.conditional, self.dead = prior_cond, prior_dead

    def _conditional_visit(self, node):
        old = self.conditional
        self.conditional = True
        self.generic_visit(node)
        self.conditional = old

    visit_Try = _conditional_visit
    visit_TryStar = _conditional_visit
    visit_For = _conditional_visit
    visit_AsyncFor = _conditional_visit
    visit_While = _conditional_visit
    visit_Match = _conditional_visit
    visit_With = _conditional_visit
    visit_AsyncWith = _conditional_visit
    def _comprehension(self, node):
        # v1 deliberately does not prove names inside comprehension scopes.
        # Their stores must not contaminate the enclosing namespace.
        outer = self.scope
        for item in ast.walk(node):
            if isinstance(item, ast.NamedExpr) and isinstance(item.target, ast.Name):
                self._bind(item.target.id, None)
        self.scope = Scope(parent=outer.parent if outer.kind == "class" else outer, kind="function")
        self.scope.bind("*", None)
        self.generic_visit(node)
        self.scope = outer

    visit_ListComp = _comprehension
    visit_SetComp = _comprehension
    visit_DictComp = _comprehension
    visit_GeneratorExp = _comprehension

    def resolve(self, node, scope=None, visited=frozenset()):
        scope = scope or self.scopes.get(id(node))
        if scope is None or id(node) in self.dead_nodes:
            return None
        if isinstance(node, ast.Attribute):
            base = self.resolve(node.value, scope, visited)
            return (base[0] + "." + node.attr, base[1], base[2]) if base else None
        if isinstance(node, ast.Call):
            resolved = self.resolve(node.func, scope, visited)
            return (resolved[0], resolved[1], "constructor_result") if resolved else None
        if not isinstance(node, ast.Name):
            return None
        # Global/nonlocal and annotation scopes need deeper dataflow. Until then,
        # a walrus-assigned spelling is conservatively unresolved everywhere,
        # while unrelated imported names remain analyzable.
        if node.id in self.named_expression_names or node.id in self.externally_declared_names:
            return None
        current = scope
        while current:
            if "*" in current.bindings:
                return None
            if node.id in current.bindings:
                values = current.bindings[node.id]
                key = (id(current), node.id)
                if key in visited or len(values) != 1 or values[0] is None:
                    return None
                value = values[0]
                if value[0] == "import":
                    # Do not bind a same-scope use preceding its import.
                    if current is scope and (getattr(node, "lineno", 0), getattr(node, "col_offset", 0)) < (value[2], value[3]):
                        return None
                    return value[1], value[2], "import"
                expr = value[1]
                if current is scope and (getattr(node, "lineno", 0), getattr(node, "col_offset", 0)) < (getattr(expr, "end_lineno", 0), getattr(expr, "end_col_offset", 0)):
                    return None
                return self.resolve(expr, value[2], visited | {key})
            current = current.parent
        return None

    def check(self, observation, contract):
        line = observation["line"]
        marker = observation.get("marker") or observation.get("guard")
        roots = contract["import_roots"]
        def target(resolved):
            return resolved and any(resolved[0] == root or resolved[0].startswith(root + ".") for root in roots)
        def spans(node):
            return getattr(node, "lineno", -1) <= line <= getattr(node, "end_lineno", -1)
        def proof(kind, node, resolved, **extra):
            return {"status": "supported", "reason": "lexical_framework_binding", "use_kind": kind,
                    "symbol": resolved[0], "import_line": resolved[1], "binding_kind": resolved[2],
                    "node_start_line": node.lineno, "node_end_line": node.end_lineno,
                    "reachability": "unknown", "registration": "unknown", "external_package_identity": "unverified", **extra}
        lifecycle_keyword = {
            "openai-input": "input_guardrails", "openai-output": "output_guardrails",
            "openai-tool-input": "tool_input_guardrails", "openai-tool-output": "tool_output_guardrails",
            "crewai-task-output": "guardrail",
        }.get(observation.get("lifecycle"))
        canonical = (marker or "").lstrip("@").rstrip("(")
        nodes = self.node_index.query(line)
        self.query_count += 1
        self.candidate_count += len(nodes)
        for node in nodes:
            if id(node) in self.dead_nodes:
                continue
            if isinstance(node, ast.Call):
                resolved = self.resolve(node.func)
                if target(resolved) and spans(node.func) and resolved[2] == "import":
                    if resolved[0].endswith("." + canonical) or dotted(node.func) == canonical:
                        return proof("imported_call", node.func, resolved)
                for kw in node.keywords:
                    name = lifecycle_keyword or canonical
                    if kw.arg != name:
                        continue
                    if lifecycle_keyword:
                        matches_guard = any(dotted(item) == marker for item in ast.walk(kw.value))
                        located = node.lineno == line and matches_guard
                    else:
                        located = kw.lineno == line
                    if not located or not target(resolved) or resolved[2] != "import":
                        continue
                    disabled = (isinstance(kw.value, ast.Constant) and (kw.value.value is None or kw.value.value is False)) or (
                        isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)) and not kw.value.elts)
                    if disabled:
                        return {"status": "refuted", "reason": "literal_disabled_control", "reachability": "unknown"}
                    # Keyword ownership is stronger than same-file co-occurrence,
                    # but framework runtime semantics are deliberately not inferred.
                    return proof("framework_call_keyword", kw, resolved, keyword=kw.arg)
            elif isinstance(node, (ast.Name, ast.Attribute)) and isinstance(node.ctx, ast.Load) and spans(node):
                resolved = self.resolve(node)
                if target(resolved) and resolved[2] == "import" and (resolved[0].endswith("." + canonical) or dotted(node) == canonical):
                    return proof("imported_symbol_reference", node, resolved)
        # Only syntactically non-executable matches are negative evidence here.
        executable = [n for n in nodes if isinstance(n, (ast.Name, ast.Attribute, ast.keyword)) and spans(n)]
        string_matches = [n for n in nodes if isinstance(n, ast.Constant) and isinstance(n.value, str) and spans(n) and canonical in n.value]
        if string_matches and not executable:
            return {"status": "refuted", "reason": "string_or_docstring_only", "reachability": "unknown"}
        return {"status": "unknown", "reason": "unresolved_symbol_or_registration", "reachability": "unknown"}


class NodeIndex:
    """Static interval tree; query order preserves the original AST breadth order."""
    def __init__(self, nodes):
        relevant = (ast.Call, ast.Name, ast.Attribute, ast.keyword)
        entries = [(node.lineno, node.end_lineno, i, node) for i, node in enumerate(nodes)
                   if hasattr(node, "lineno") and (isinstance(node, relevant) or
                      isinstance(node, ast.Constant) and isinstance(node.value, str))]
        self.root = self._build(entries)

    def _build(self, entries):
        if not entries:
            return None
        center = sorted((start + end) // 2 for start, end, _, _ in entries)[len(entries) // 2]
        left, right, overlap = [], [], []
        for entry in entries:
            if entry[1] < center:
                left.append(entry)
            elif entry[0] > center:
                right.append(entry)
            else:
                overlap.append(entry)
        return (center, sorted(overlap, key=lambda e: e[0]), sorted(overlap, key=lambda e: -e[1]),
                self._build(left), self._build(right))

    def query(self, line):
        found, branch = [], self.root
        while branch:
            center, starts, ends, left, right = branch
            if line < center:
                for entry in starts:
                    if entry[0] > line:
                        break
                    found.append(entry)
                branch = left
            elif line > center:
                for entry in ends:
                    if entry[1] < line:
                        break
                    found.append(entry)
                branch = right
            else:
                found.extend(starts)
                break
        return [entry[3] for entry in sorted(found, key=lambda e: e[2])]
