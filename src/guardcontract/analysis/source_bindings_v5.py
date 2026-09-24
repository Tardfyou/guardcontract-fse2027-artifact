"""Repository-scale deferred binding scans only API-relevant lexical scopes."""
from __future__ import annotations

import ast
import json

from guardcontract.analysis.source_bindings_v4 import SourceBindings as BindingsV4
from guardcontract.analysis.source_bindings_v2 import APIS


class SourceBindings(BindingsV4):
    def _api_aliases(self, path):
        aliases = set()
        for name in self.writes.get(path, {}):
            value = self.resolve_global(path, name)
            if value.kind == "external" and value.value in APIS:
                aliases.add(name)
        return aliases

    def _api_relevant(self, path, node, aliases):
        if any(isinstance(part, ast.Name) and isinstance(part.ctx, ast.Load)
               and part.id in aliases for part in ast.walk(node)):
            return True
        for call in (part for part in ast.walk(node) if isinstance(part, ast.Call)):
            value = self.resolve_expr(path, call.func)
            if value.kind == "external" and value.value in APIS:
                return True
        return False

    def deferred_registrations(self):
        result = []
        for path, tree in self.trees.items():
            if tree is None:
                continue
            aliases = self._api_aliases(path)
            for statement in tree.body:
                if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                if not self._api_relevant(path, statement, aliases):
                    continue
                if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    local = self._local_env(statement, path=path)
                    self._statements(path, statement.body, local, statement.name,
                                     (("factory", path, statement.name),), (), result)
                else:
                    self._statements(path, [statement], {}, "", (), (), result)
        distinct = {json.dumps(row, sort_keys=True): row for row in result}
        return list(distinct.values())
