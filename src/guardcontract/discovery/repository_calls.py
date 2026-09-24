"""Framework-independent lexical call candidates over the parsed source inventory.

Uses the existing scope index, never simple-name or path-suffix matching.
These edges identify source call targets, not feasible executions or policy scope.
"""
import ast
from collections import defaultdict, deque
from pathlib import PurePosixPath


def validate_module_roots(roots):
    if not isinstance(roots, (list, tuple)) or not roots:
        raise ValueError("module_roots_list_required")
    for root in roots:
        if not isinstance(root, str) or not root or "\\" in root or "\x00" in root:
            raise ValueError("invalid_module_root")
        path = PurePosixPath(root)
        if path.is_absolute() or ".." in path.parts or path.as_posix() != root:
            raise ValueError("invalid_module_root")
    return tuple(dict.fromkeys(roots))


def location(index, node):
    return {"path": index.path, "start_line": node.lineno, "end_line": node.end_lineno,
            "evidence_start_line": min([node.lineno, *(d.lineno for d in node.decorator_list)]),
            "symbol": index.definitions[id(node)][1]}


def identity(entry):
    return entry["path"], entry["symbol"], entry["start_line"]


class RepositoryCalls:
    def __init__(self, indexes, *, module_roots=(".",)):
        self.indexes = indexes
        self.module_roots = validate_module_roots(module_roots)
        self.modules = defaultdict(set)
        self.functions = {}
        for path, index in indexes.items():
            # Full inventory names retain relative-import identities. Additional
            # import roots are explicit inputs, never inferred from suffix matches.
            names = {path}
            for root in self.module_roots:
                if root != "." and path.startswith(root + "/"):
                    names.add(path[len(root) + 1:])
            for name in names:
                module = name.removesuffix(".py").replace("/", ".")
                if module.endswith(".__init__"):
                    module = module.removesuffix(".__init__")
                self.modules[module].add(path)
            for _, _, node in index.definitions.values():
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.functions[identity(location(index, node))] = (index, node)

    def binding_spans(self, index, expression, scope, seen=()):
        """Keep imports and distant aliases in the eventual evidence slice."""
        if isinstance(expression, ast.Attribute):
            return self.binding_spans(index, expression.value, scope, seen)
        if not isinstance(expression, ast.Name):
            return []
        owner, value = index.binding(expression.id, scope)
        key = (owner, expression.id)
        if key in seen or value is None:
            return []
        spans = []
        if isinstance(value, str):
            for node in index.scopes[owner][0]:
                if isinstance(node, (ast.Import, ast.ImportFrom)) and any(
                    (alias.asname or (alias.name.split(".")[0] if isinstance(node, ast.Import)
                                      else alias.name)) == expression.id for alias in node.names
                ):
                    spans.append({"path": index.path, "start_line": node.lineno, "end_line": node.end_lineno})
        elif isinstance(value, ast.AST):
            spans.extend(index.assignment_locations.get((owner, id(value)), []))
            spans.extend(self.binding_spans(index, value, owner, (*seen, key)))
        return spans

    def resolve(self, index, expression, scope):
        spans, seen = [], set()
        # Re-exports may cycle; the bound also avoids recursion on hostile input.
        for _ in range(64):
            spans.extend(self.binding_spans(index, expression, scope))
            value, _ = index.scoped(expression, scope)
            if isinstance(value, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return (index, value), spans, None
            if not isinstance(value, str) or "." not in value:
                return None, spans, "call_target_unresolved"
            if value in seen:
                return None, spans, "import_alias_cycle"
            seen.add(value)
            module, _, name = value.rpartition(".")
            paths = self.modules.get(module, [])
            if len(paths) != 1:
                return None, spans, "module_ambiguous" if paths else "module_not_in_inventory"
            index = self.indexes[next(iter(paths))]
            expression, scope = ast.Name(id=name, ctx=ast.Load()), ""
        return None, spans, "import_resolution_budget"

    def recover(self, roots, *, max_functions=512, max_edges=4096):
        from guardcontract.discovery.registration import immediate_nodes

        if type(max_functions) is not int or max_functions < 1:
            raise ValueError("positive_repository_call_function_budget_required")
        if type(max_edges) is not int or max_edges < 1:
            raise ValueError("positive_repository_call_edge_budget_required")

        pending = deque(identity(root) for root in roots)
        visited, nodes, edges, gaps, spans = set(), [], [], [], []
        truncated = False
        while pending:
            key = pending.popleft()
            if key in visited:
                continue
            if len(visited) >= max_functions:
                truncated = True
                break
            visited.add(key)
            pair = self.functions.get(key)
            if pair is None:
                gaps.append({"path": key[0], "line": key[2], "reason": "root_not_in_inventory"})
                continue
            index, function = pair
            caller = location(index, function)
            nodes.append(caller)
            for call in immediate_nodes(function.body):
                if not isinstance(call, ast.Call):
                    continue
                if len(edges) + len(gaps) >= max_edges:
                    truncated = True
                    break
                target, bindings, reason = self.resolve(index, call.func, caller["symbol"])
                if target is None:
                    gaps.append({"path": index.path, "line": call.lineno, "reason": reason})
                    continue
                target_index, target_node = target
                callee = location(target_index, target_node)
                edges.append({"caller": caller, "callee": callee, "path": index.path,
                              "line": call.lineno, "status": "lexically_resolved_call_candidate"})
                spans.extend(bindings)
                pending.append(identity(callee))
            if truncated:
                break
        unique_spans = {(s["path"], s["start_line"], s["end_line"]): s for s in spans}
        return {"nodes": nodes, "edges": edges, "gaps": gaps,
                "module_roots": list(self.module_roots),
                "binding_spans": [unique_spans[key] for key in sorted(unique_spans)],
                "truncated": truncated, "path_verified": False}


def enrich_call_candidates(files, indexes, groups, *, module_roots=(".",)):
    from guardcontract.discovery.scout import effect_sites_from_tree

    repository = RepositoryCalls(indexes, module_roots=module_roots)
    for group in groups:
        graph = repository.recover(group["tools"])
        group["shared_tool_calls"] = graph
        group["call_binding_spans"] = graph["binding_spans"]
        roots = {identity(row) for row in [*group["tools"], *group["guards"]]}
        helpers = {identity(row): row for row in group["helpers"]}
        effects = {(row["path"], row["line"], row["call"]): row for row in group["effects"]}
        edges = {(identity(row["caller"]), identity(row["callee"]), row["line"]): row
                 for row in group["local_call_edges"]}
        for edge in graph["edges"]:
            edges[(identity(edge["caller"]), identity(edge["callee"]), edge["line"])] = edge
        for entry in graph["nodes"]:
            key = identity(entry)
            if key in roots:
                continue
            helpers[key] = {**entry, "association": "lexical_tool_delegate_candidate"}
            index, function = repository.functions[key]
            for site in effect_sites_from_tree(files[index.path], index.path, within=function):
                effect_key = (site.path, site.line, site.call)
                effect = effects.setdefault(effect_key, {
                    "path": site.path, "line": site.line, "family": site.family, "call": site.call,
                    "association": "cross_file_tool_call_candidate"})
                effect["lexical_tool_delegate"] = entry
        group["effects"] = [effects[key] for key in sorted(effects)]
        group["helpers"] = [helpers[key] for key in sorted(helpers)]
        group["local_call_edges"] = list(edges.values())
