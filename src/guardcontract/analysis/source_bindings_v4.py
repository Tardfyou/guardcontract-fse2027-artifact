"""Cycle-safe structural bindings for repository-scale analysis."""
from __future__ import annotations

from guardcontract.analysis.source_bindings_v3 import SourceBindings as BindingsV3
from guardcontract.analysis.source_bindings_v1 import Binding, unknown


class SourceBindings(BindingsV3):
    def __init__(self, sources, *, max_operations=250_000):
        if type(max_operations) is not int or max_operations < 1_000:
            raise ValueError("binding_operation_budget")
        self.max_operations = max_operations
        self.operations = 0
        self.operation_budget_exhausted = False
        self._symbol_lookup = {}
        super().__init__(sources)

    def _symbol_table(self, path, node):
        if path not in self._symbol_lookup:
            root = self.symbol_tables.get(path)
            if root is None and path not in self.symbol_tables:
                import symtable
                try:
                    root = symtable.symtable(self.sources[path], path, "exec")
                except SyntaxError:
                    root = None
                self.symbol_tables[path] = root
            lookup = {}
            pending = list(root.get_children()) if root is not None else []
            while pending:
                table = pending.pop()
                key = (table.get_name(), table.get_lineno())
                lookup[key] = table if key not in lookup else None
                pending.extend(table.get_children())
            self._symbol_lookup[path] = lookup
        return self._symbol_lookup[path].get((node.name, node.lineno))

    def _use_operation(self):
        self.operations += 1
        if self.operations > self.max_operations:
            self.operation_budget_exhausted = True
            return False
        return True

    def _expr(self, path, node, seen, local):
        if not self._use_operation():
            return unknown("binding_operation_budget_exhausted")
        return super()._expr(path, node, seen, local)

    def _factory(self, *args, **kwargs):
        if not self._use_operation():
            return unknown("binding_operation_budget_exhausted")
        return super()._factory(*args, **kwargs)

    def _invalidate(self, local, names, reason):
        affected = {id(local[name]) for name in names if name in local}
        memo = {}
        visiting = set()
        visits = 0

        def contains(value):
            nonlocal visits
            identity = id(value)
            if identity in affected:
                return True
            if identity in memo:
                return memo[identity]
            if identity in visiting:
                return False
            visits += 1
            if visits > 10_000:
                self.operation_budget_exhausted = True
                return True
            visiting.add(identity)
            if isinstance(value, Binding):
                result = contains(value.value)
            elif isinstance(value, dict):
                result = any(contains(item) for item in value.values())
            elif isinstance(value, (tuple, list)):
                result = any(contains(item) for item in value)
            else:
                result = False
            visiting.remove(identity)
            memo[identity] = result
            return result

        for name, value in list(local.items()):
            if name in names or contains(value):
                local[name] = unknown(reason)
