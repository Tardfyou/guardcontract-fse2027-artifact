"""Closed AST-only source object bindings; no activation or effect claims.

Sources are supplied by the caller. No import, eval, exec, or filesystem lookup of
an analyzed module occurs. Ambiguity is retained, including writes after a use.
"""
import ast
from dataclasses import dataclass
import hashlib
import symtable
from pathlib import PurePosixPath


# API identity is the only framework-specific input to the resolver.
API_ADAPTERS = {
    'langchain': {'langchain.agents.create_agent': {'tools': 'tools', 'middleware': 'guards'}},
    'openai_agents': {'agents.Agent': {'tools': 'tools', 'input_guardrails': 'guards', 'output_guardrails': 'guards', 'handoffs': 'delegates'}},
    'crewai': {'crewai.Agent': {'tools': 'tools'}, 'crewai.Task': {'guardrail': 'guards', 'guardrails': 'guards'}},
    'pydantic_ai': {'pydantic_ai.Agent': {'tools': 'tools'}},
    'google_adk': {'google.adk.agents.Agent': {'tools': 'tools', 'before_tool_callback': 'guards', 'after_tool_callback': 'guards', 'before_model_callback': 'guards', 'after_model_callback': 'guards'}},
}
APIS = {api: (framework, roles) for framework, rows in API_ADAPTERS.items() for api, roles in rows.items()}


@dataclass(frozen=True)
class Binding:
    kind: str
    value: object
    provenance: tuple = ()

    def as_dict(self):
        def encode(value):
            if isinstance(value, Binding):
                return value.as_dict()
            if isinstance(value, dict):
                return {k: encode(v) for k, v in value.items()}
            if isinstance(value, (tuple, list)):
                return [encode(v) for v in value]
            return value
        return {'kind': self.kind, 'value': encode(self.value), 'provenance': list(self.provenance)}


def unknown(reason):
    return Binding('unknown', {'reason': reason})


class SourceBindings:
    def __init__(self, sources):
        self.sources = dict(sources)
        self.trees, self.defs, self.writes, self.tainted, self.positions = {}, {}, {}, {}, {}
        self.modules = {}
        for path, source in sorted(self.sources.items()):
            if PurePosixPath(path).is_absolute() or '..' in PurePosixPath(path).parts or not path.endswith('.py'):
                raise ValueError('sources require relative Python paths')
            module = path[:-3].replace('/', '.')
            if module.endswith('.__init__'):
                module = module[:-9]
            if module in self.modules:
                self.modules[module] = None
            else:
                self.modules[module] = path
            try:
                self.trees[path] = ast.parse(source)
            except SyntaxError:
                self.trees[path] = None
        for path, tree in self.trees.items():
            self.defs[path], self.writes[path], self.tainted[path], self.positions[path] = {}, {}, set(), {}
            if tree is None:
                continue
            for node in tree.body:
                self._index(path, node, direct=True)
        # Reject global writes from helper bodies, even if their activation is
        # unknown. They invalidate the closed immutable-global profile.
        for path, tree in self.trees.items():
            if tree is None:
                continue
            for function in ast.walk(tree):
                if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    declared = {name for n in ast.walk(function) if isinstance(n, ast.Global) for name in n.names}
                    stored = {n.id for n in ast.walk(function) if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del))}
                    self.tainted[path].update(declared & stored)

        # Build alias/capture edges across the provided source inventory.
        edges = []
        for path, tree in self.trees.items():
            if tree is None:
                continue
            for stmt in tree.body:
                if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                    targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                    names = {t.id for t in targets if isinstance(t, ast.Name)}
                    if isinstance(stmt.value, (ast.Name, ast.List, ast.Tuple, ast.Dict)):
                        names.update(n.id for n in ast.walk(stmt.value) if isinstance(n, ast.Name))
                        edges.append({(path, name) for name in names})
                if isinstance(stmt, ast.ImportFrom):
                    module = self._import_module(path, stmt)
                    target = self.modules.get(module)
                    if target:
                        for alias in stmt.names:
                            edges.append({(path, alias.asname or alias.name), (target, alias.name)})
            # Unknown calls can mutate values even when their result is assigned.
            def immediate(node):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                    return
                yield node
                for child in ast.iter_child_nodes(node):
                    yield from immediate(child)
            for call in (n for n in immediate(tree) if isinstance(n, ast.Call)):
                callee = self._expr(path, call.func, (), {})
                pure = callee.kind == 'external' and callee.value in APIS
                if callee.kind == 'function':
                    pure = self._factory(callee, path, call, (), {}).kind != 'unknown'
                if not pure:
                    values = list(call.args) + [kw.value for kw in call.keywords]
                    for item in values:
                        self.tainted[path].update(n.id for n in ast.walk(item) if isinstance(n, ast.Name))
        changed = True
        while changed:
            before = sum(map(len, self.tainted.values()))
            for edge in edges:
                if any(name in self.tainted[path] for path, name in edge):
                    for path, name in edge:
                        self.tainted[path].add(name)
            # A mutated imported module may have any export changed.
            for path, names in self.writes.items():
                for name, rows in names.items():
                    if name not in self.tainted[path] or len(rows) != 1:
                        continue
                    row = rows[0]
                    if isinstance(row, tuple) and row[0] == 'import':
                        target = self.modules.get(row[1])
                        if target:
                            self.tainted[target].update(self.writes[target])
            changed = sum(map(len, self.tainted.values())) != before

    def _index(self, path, node, direct=False):
        writes = self.writes[path]
        def add(name, value):
            writes.setdefault(name, []).append(value)
            self.positions[path].setdefault(name, []).append(node.lineno)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            add(node.name, node if direct else None)
            if direct and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.defs[path][node.name] = node
            return
        if isinstance(node, ast.Import):
            for alias in node.names:
                add(alias.asname or alias.name.split('.')[0], ('import', alias.name if alias.asname else alias.name.split('.')[0]) if direct else None)
            return
        if isinstance(node, ast.ImportFrom):
            module = self._import_module(path, node)
            for alias in node.names:
                add(alias.asname or alias.name, ('from', module, alias.name) if direct else None)
            return
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    add(target.id, node.value if direct else None)
                else:
                    self.tainted[path].update(n.id for n in ast.walk(target) if isinstance(n, ast.Name))
            return
        if isinstance(node, (ast.AugAssign, ast.Delete)):
            targets = node.targets if isinstance(node, ast.Delete) else [node.target]
            for target in targets:
                self.tainted[path].update(n.id for n in ast.walk(target) if isinstance(n, ast.Name))
            return
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            call = node.value
            # Ignored call results may mutate all directly supplied bindings.
            values = [call.func.value] if isinstance(call.func, ast.Attribute) else []
            values += list(call.args) + [kw.value for kw in call.keywords]
            for value in values:
                self.tainted[path].update(n.id for n in ast.walk(value) if isinstance(n, ast.Name))
            return
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.stmt):
                self._index(path, child, direct=False)
        for child in ast.walk(node):
            if isinstance(child, ast.NamedExpr):
                self.tainted[path].update(n.id for n in ast.walk(child.target) if isinstance(n, ast.Name))

    def _import_module(self, path, node):
        if not node.level:
            return node.module or ''
        parts = path[:-3].split('/')
        package = parts[:-1]
        if node.level > len(package):
            return None
        return '.'.join(package[:len(package) - node.level + 1] + ([node.module] if node.module else []))

    def _receipt(self, path, node):
        return {'path': path, 'line': node.lineno, 'source_sha256': hashlib.sha256(self.sources[path].encode()).hexdigest()}

    def function(self, path, symbol):
        node = self.defs.get(path, {}).get(symbol)
        return node if node is not None and len(self.writes[path].get(symbol, [])) == 1 else None

    def resolve_global(self, path, name):
        return self._name(path, name, (), {})

    def _name(self, path, name, seen, local):
        if name in local:
            return local[name]
        key = (path, name)
        if key in seen:
            return unknown('binding_cycle')
        if path not in self.trees or self.trees[path] is None:
            return unknown('source_unavailable_or_syntax')
        if name in self.tainted[path] or '*' in self.writes[path]:
            return unknown('binding_mutated_or_escaped')
        rows = self.writes[path].get(name, [])
        if len(rows) != 1 or rows[0] is None:
            return unknown('binding_absent_or_rebound')
        node = rows[0]
        if isinstance(node, tuple):
            if node[0] == 'import':
                return self._module(node[1])
            _, module, symbol = node
            if module is None:
                return unknown('invalid_relative_import')
            if module in self.modules:
                target = self.modules[module]
                if target is None:
                    return unknown('ambiguous_module')
                if symbol in self.writes[target]:
                    return self._name(target, symbol, (*seen, key), {})
                if module + '.' + symbol in self.modules:
                    return self._module(module + '.' + symbol)
                return unknown('local_export_absent')
            if module + '.' + symbol in self.modules:
                return self._module(module + '.' + symbol)
            if any(m == module or m.startswith(module + '.') or module.startswith(m + '.')
                   for m in self.modules):
                return unknown('local_dependency_or_export_unavailable')
            return Binding('external', module + '.' + symbol)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return Binding('function', {**self._receipt(path, node), 'symbol': node.name,
                           'decorators': [ast.unparse(d) for d in node.decorator_list]}, (self._receipt(path, node),))
        if isinstance(node, ast.ClassDef):
            return unknown('class_binding_unsupported')
        return self._expr(path, node, (*seen, key), local)

    def _module(self, name):
        if name in self.modules:
            return Binding('module', name) if self.modules[name] is not None else unknown('ambiguous_module')
        if any(m.startswith(name + '.') for m in self.modules):
            return Binding('module', name)
        return Binding('external', name)

    def resolve_expr(self, path, node):
        return self._expr(path, node, (), {})

    def _expr(self, path, node, seen, local):
        if node is None:
            return unknown('value_absent')
        if isinstance(node, ast.Name):
            # Module aliases are evaluated at their assignment, unlike names in
            # an invoked factory body. Later definitions cannot repair NameError.
            lines = self.positions.get(path, {}).get(node.id, [])
            in_factory = any(key[0] == 'factory' for key in seen)
            if node.id not in local and not in_factory and len(lines) == 1 and lines[0] > node.lineno:
                return unknown('binding_used_before_definition')
            return self._name(path, node.id, seen, local)
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, int, float, bool, type(None))):
            return Binding('constant', node.value)
        if isinstance(node, ast.Attribute):
            base = self._expr(path, node.value, seen, local)
            if base.kind == 'external':
                return Binding('external', base.value + '.' + node.attr)
            if base.kind == 'module':
                module = base.value
                target = self.modules.get(module)
                if target and node.attr in self.writes[target]:
                    return self._name(target, node.attr, seen, {})
                if module + '.' + node.attr in self.modules:
                    return self._module(module + '.' + node.attr)
            return unknown('attribute_binding_unsupported')
        if isinstance(node, (ast.List, ast.Tuple)):
            items = []
            for child in node.elts:
                item = self._expr(path, child.value if isinstance(child, ast.Starred) else child, seen, local)
                if isinstance(child, ast.Starred):
                    if item.kind != 'sequence':
                        return unknown('dynamic_sequence_unpack')
                    items.extend(item.value)
                else:
                    items.append(item)
            return Binding('sequence', tuple(items))
        if isinstance(node, ast.Dict):
            result = {}
            for key, value in zip(node.keys, node.values):
                bound = self._expr(path, value, seen, local)
                if key is None:
                    if bound.kind != 'mapping':
                        return unknown('dynamic_mapping_unpack')
                    result.update(bound.value)
                elif isinstance(key, ast.Constant) and isinstance(key.value, str):
                    result[key.value] = bound
                else:
                    return unknown('non_string_mapping_key')
            return Binding('mapping', result)
        if isinstance(node, ast.Subscript):
            base, index = self._expr(path, node.value, seen, local), self._expr(path, node.slice, seen, local)
            if index.kind == 'constant' and base.kind in ('mapping', 'sequence'):
                try:
                    return base.value[index.value]
                except (KeyError, IndexError, TypeError):
                    pass
            return unknown('subscript_unresolved')
        if isinstance(node, ast.Call):
            callee = self._expr(path, node.func, seen, local)
            if callee.kind == 'function':
                return self._factory(callee, path, node, seen, local)
            if callee.kind == 'external' and callee.value in APIS:
                kwargs = self._keywords(path, node, seen, local)
                if None in kwargs or node.args:
                    return unknown('constructor_argument_unsupported')
                return Binding('construction', {'api': callee.value, 'kwargs': kwargs,
                                'site': self._receipt(path, node)})
            return unknown('dynamic_call')
        return unknown('expression_unsupported:' + type(node).__name__)

    def _keywords(self, path, call, seen, local):
        result = {}
        for kw in call.keywords:
            value = self._expr(path, kw.value, seen, local)
            additions = value.value if kw.arg is None and value.kind == 'mapping' else {kw.arg: value}
            if kw.arg is None and value.kind != 'mapping':
                return {None: unknown('dynamic_keyword_unpack')}
            if set(result).intersection(additions):
                return {None: unknown('duplicate_keyword')}
            result.update(additions)
        return result

    def call_keywords(self, path, call):
        return self._keywords(path, call, (), {})

    def _factory(self, binding, caller_path, call, seen, caller_local):
        target = binding.value
        path, symbol = target['path'], target['symbol']
        key = ('factory', path, symbol)
        if key in seen:
            return unknown('factory_cycle')
        node = self.function(path, symbol)
        if node is None or node.decorator_list or isinstance(node, ast.AsyncFunctionDef):
            return unknown('factory_decorated_async_or_rebound')
        args = node.args
        if args.posonlyargs or args.vararg or args.kwarg or any(isinstance(a, ast.Starred) for a in call.args):
            return unknown('factory_signature_unsupported')
        names = [arg.arg for arg in args.args]
        kwargs = self._keywords(caller_path, call, seen, caller_local)
        if None in kwargs or len(call.args) > len(names):
            return unknown('factory_argument_mismatch')
        local = dict(zip(names, [self._expr(caller_path, a, seen, caller_local) for a in call.args]))
        if set(local).intersection(kwargs):
            return unknown('factory_duplicate_argument')
        local.update(kwargs)
        defaults = dict(zip(names[len(names) - len(args.defaults):], args.defaults)) if args.defaults else {}
        defaults.update({arg.arg: value for arg, value in zip(args.kwonlyargs, args.kw_defaults) if value is not None})
        valid = set(names) | {arg.arg for arg in args.kwonlyargs}
        if set(local) - valid:
            return unknown('factory_extra_argument')
        for name in valid - local.keys():
            if name not in defaults:
                return unknown('factory_missing_argument')
            local[name] = self._expr(path, defaults[name], seen, {})
        table = symtable.symtable(ast.unparse(node), '<factory>', 'exec').get_children()[0]
        if any(s.is_declared_global() or s.is_nonlocal() for s in table.get_symbols()):
            return unknown('factory_external_binding_write')
        for entry in table.get_symbols():
            if entry.is_local() and entry.get_name() not in local:
                local[entry.get_name()] = unknown('unbound_factory_local')
        # Python determines local names for the whole body, including later writes.
        for stmt in node.body:
            if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                for target_node in targets:
                    if isinstance(target_node, ast.Name) and target_node.id not in local:
                        local[target_node.id] = unknown('unbound_factory_local')
        for stmt in node.body:
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str):
                continue
            if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                if any(not isinstance(t, ast.Name) for t in targets):
                    return unknown('factory_mutation')
                value = self._expr(path, stmt.value, (*seen, key), local)
                for target_node in targets:
                    local[target_node.id] = value
                continue
            if isinstance(stmt, ast.Return):
                return self._expr(path, stmt.value, (*seen, key), local)
            return unknown('factory_body_unsupported:' + type(stmt).__name__)
        return unknown('factory_return_absent')

    def registrations(self):
        result = []
        for path, tree in self.trees.items():
            if tree is None:
                continue
            # Only module statements: function-local calls need instantiated scope.
            for statement in tree.body:
                call = statement.value if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.Expr)) else None
                if not isinstance(call, ast.Call):
                    continue
                binding = self.resolve_expr(path, call)
                if binding.kind != 'construction':
                    continue
                api = binding.value['api']
                framework, roles = APIS[api]
                result.append({'framework': framework, 'api': api, 'site': self._receipt(path, call),
                               'roles': {name: {'role': roles[name], 'binding': value.as_dict()}
                                         for name, value in binding.value['kwargs'].items() if name in roles},
                               'binding': binding.as_dict(), 'runtime_activation_verified': False})
        return result
