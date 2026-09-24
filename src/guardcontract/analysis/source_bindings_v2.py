"""Deferred lexical registration templates, separate from instantiated bindings.

A template states how a constructor's source arguments bind if its lexical path
is evaluated. It does not establish object activation, branch reachability,
effective guard semantics, effect reachability, or a security issue label.
"""
import ast
import symtable
from pathlib import PurePosixPath
from .source_bindings_v1 import SourceBindings as BaseBindings, Binding, unknown, APIS as BASE_APIS


APIS = dict(BASE_APIS)
_ADK_ROLES = BASE_APIS['google.adk.agents.Agent'][1]
for _api in ('google.adk.agents.LlmAgent', 'google.adk.agents.llm_agent.LlmAgent', 'google.adk.agents.llm_agent.Agent'):
    APIS[_api] = ('google_adk', dict(_ADK_ROLES))
for _api in ('google.adk.tools.FunctionTool', 'google.adk.tools.function_tool.FunctionTool'):
    APIS[_api] = ('google_adk', {'func': 'tools', 'require_confirmation': 'declarative_policy'})
for _api in ('langchain.agents.middleware.HumanInTheLoopMiddleware',
             'langchain.agents.middleware.human_in_the_loop.HumanInTheLoopMiddleware'):
    APIS[_api] = ('langchain', {'interrupt_on': 'declarative_policy'})
# Names/order checked against the installed 1.4.0 / 2.40.0 / 2.7.0 SDK
# signatures. Argument binding is shared; adapters declare API slots only.
POSITIONAL_FIELDS = {
    'langchain.agents.create_agent': ('model', 'tools'),
    'pydantic_ai.Agent': ('model',),
    'google.adk.tools.FunctionTool': ('func',),
    'google.adk.tools.function_tool.FunctionTool': ('func',),
}
WRAPPERS = {
    'agents.InputGuardrail': 'guardrail_function',
    'agents.OutputGuardrail': 'guardrail_function',
    'agents.guardrail.InputGuardrail': 'guardrail_function',
    'agents.guardrail.OutputGuardrail': 'guardrail_function',
}


def source_identity_known(binding):
    if binding.kind == 'function':
        return True
    if binding.kind == 'wrapper':
        return source_identity_known(binding.value['callback'])
    if binding.kind == 'sequence':
        return bool(binding.value) and all(source_identity_known(value) for value in binding.value)
    return False


def explicitly_empty(binding):
    return (binding.kind == 'sequence' and not binding.value) or (binding.kind == 'constant' and binding.value is None)


class SourceBindings(BaseBindings):
    def __init__(self, sources):
        self.lexical_functions = {}
        self.symbol_tables = {}
        for path, source in sources.items():
            try:
                self._index_functions(path, ast.parse(source).body, '')
            except SyntaxError:
                pass
        self._initialize_sources(sources)
        for path, tree in self.trees.items():
            if tree is not None:
                self._index_functions(path, tree.body, '')

    def _initialize_sources(self, sources):
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
                pure = callee.kind == 'external' and (callee.value in APIS or callee.value in WRAPPERS)
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

    def _index_functions(self, path, statements, prefix):
        for node in statements:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                symbol = prefix + node.name
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.lexical_functions[(path, symbol)] = node
                self._index_functions(path, node.body, symbol + '.')

    def function(self, path, symbol):
        if '.' in symbol:
            return self.lexical_functions.get((path, symbol))
        return super().function(path, symbol)

    def _expr(self, path, node, seen, local):
        if isinstance(node, ast.IfExp):
            truth = self._truth(path, node.test, seen, local)
            return self._expr(path, node.body if truth else node.orelse, seen, local) if truth is not None else unknown('conditional_expression')
        if isinstance(node, ast.Subscript):
            base = self._expr(path, node.value, seen, local)
            # Generic Agent[T] preserves the constructor source API identity;
            # no assertion about runtime type arguments or SDK validation.
            if base.kind == 'external' and base.value in APIS:
                return base
        if isinstance(node, ast.Call):
            target = self._expr(path, node.func, seen, local)
            if target.kind == 'external' and target.value in APIS:
                kwargs = self._keywords(path, node, seen, local)
                positional = POSITIONAL_FIELDS.get(target.value, ())
                if None in kwargs or len(node.args) > len(positional) or any(isinstance(arg, ast.Starred) for arg in node.args):
                    return unknown('constructor_argument_unsupported')
                names = positional[:len(node.args)]
                if set(names) & set(kwargs):
                    return unknown('constructor_duplicate_argument')
                kwargs.update({name: self._expr(path, arg, seen, local) for name, arg in zip(names, node.args)})
                return Binding('construction', {'api': target.value, 'kwargs': kwargs, 'site': self._receipt(path, node)})
            if target.kind == 'external' and target.value in WRAPPERS:
                kwargs = self._keywords(path, node, seen, local)
                key = WRAPPERS[target.value]
                if None in kwargs or len(node.args) > 1 or (node.args and key in kwargs):
                    return unknown('wrapper_argument_unsupported')
                callback = self._expr(path, node.args[0], seen, local) if node.args else kwargs.get(key, unknown('wrapper_callback_absent'))
                return Binding('wrapper', {'api': target.value, 'callback': callback, 'site': self._receipt(path, node), 'effective_guard_semantics_verified': False})
        return super()._expr(path, node, seen, local)

    def _truth(self, path, node, seen, local):
        if isinstance(node, ast.Constant) and isinstance(node.value, (bool, type(None), int, str)):
            return bool(node.value)
        return None

    def _symbol_table(self, path, node):
        if path not in self.symbol_tables:
            try:
                self.symbol_tables[path] = symtable.symtable(self.sources[path], path, 'exec')
            except SyntaxError:
                self.symbol_tables[path] = None
        root = self.symbol_tables[path]
        if root is None:
            return None
        pending = list(root.get_children())
        while pending:
            table = pending.pop()
            if table.get_name() == node.name and table.get_lineno() == node.lineno:
                return table
            pending.extend(table.get_children())
        return None

    def _local_env(self, node, enclosing=None, path=None):
        local = dict(enclosing or {})
        table = self._symbol_table(path, node)
        if table is None:
            return {n.id: unknown('symbol_table_unavailable') for n in ast.walk(node) if isinstance(n, ast.Name)}
        for symbol in table.get_symbols():
            if symbol.is_local():
                local[symbol.get_name()] = unknown('parameter_uninstantiated' if symbol.is_parameter() else 'unbound_local')
            if symbol.is_declared_global():
                local.pop(symbol.get_name(), None)
            if symbol.is_nonlocal():
                local[symbol.get_name()] = unknown('nonlocal_cell_unsupported')
        return local

    @staticmethod
    def _writes(statements):
        result = set()
        for statement in statements:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                result.add(statement.name)
                continue
            for node in ast.walk(statement):
                if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                    result.add(node.id)
                if isinstance(node, ast.Import):
                    result.update(alias.asname or alias.name.split('.')[0] for alias in node.names)
                if isinstance(node, ast.ImportFrom):
                    result.update(alias.asname or alias.name for alias in node.names)
        return result

    def _function_binding(self, path, node, symbol, local, future):
        captured = dict(local)
        for name in self._writes(future):
            if name in captured:
                captured[name] = unknown('closure_cell_written_after_definition')
        return Binding('function', {**self._receipt(path, node), 'symbol': symbol,
                       'decorators': [ast.unparse(d) for d in node.decorator_list],
                       'lexical_environment': captured}, (self._receipt(path, node),))

    def _factory(self, binding, caller_path, call, seen, caller_local):
        # Keep the v1 factory path for module functions until nested definitions
        # require lexical closures. Both paths reject arbitrary execution.
        target = binding.value
        node = self.function(target['path'], target['symbol'])
        if node is None or node.lineno != target['line'] or node.decorator_list or isinstance(node, ast.AsyncFunctionDef):
            return unknown('factory_decorated_async_or_rebound')
        key = ('factory', target['path'], target['symbol'])
        if key in seen:
            return unknown('factory_cycle')
        args = node.args
        if args.posonlyargs or args.vararg or args.kwarg or any(isinstance(a, ast.Starred) for a in call.args):
            return unknown('factory_signature_unsupported')
        names = [a.arg for a in args.args]
        kwargs = self._keywords(caller_path, call, seen, caller_local)
        if None in kwargs or len(call.args) > len(names):
            return unknown('factory_argument_mismatch')
        bound = dict(zip(names, [self._expr(caller_path, a, seen, caller_local) for a in call.args]))
        if set(bound) & set(kwargs):
            return unknown('factory_duplicate_argument')
        bound.update(kwargs)
        defaults = dict(zip(names[len(names)-len(args.defaults):], args.defaults)) if args.defaults else {}
        defaults.update({a.arg: default for a, default in zip(args.kwonlyargs, args.kw_defaults) if default is not None})
        valid = set(names) | {a.arg for a in args.kwonlyargs}
        if set(bound) - valid:
            return unknown('factory_extra_argument')
        for name in valid - bound.keys():
            if name not in defaults:
                return unknown('factory_missing_argument')
            bound[name] = self._expr(target['path'], defaults[name], seen, target.get('lexical_environment', {}))
        table = self._symbol_table(target['path'], node)
        if table is None:
            return unknown('symbol_table_unavailable')
        if any(s.is_declared_global() or s.is_nonlocal() for s in table.get_symbols()):
            return unknown('factory_external_binding_write')
        local = self._local_env(node, target.get('lexical_environment'), target['path'])
        local.update(bound)
        _, returned, stopped = self._statements(target['path'], node.body, local, target['symbol'], (*seen, key), (), None, pure=True)
        return returned if stopped and returned is not None else unknown('factory_return_unsupported')

    def _invalidate(self, local, names, reason):
        affected = {id(local[name]) for name in names if name in local}
        def contains(value):
            if isinstance(value, Binding):
                return id(value) in affected or contains(value.value)
            if isinstance(value, dict):
                return any(contains(v) for v in value.values())
            if isinstance(value, (tuple, list)):
                return any(contains(v) for v in value)
            return False
        for name, value in list(local.items()):
            if contains(value):
                local[name] = unknown(reason)

    def _expression_escape(self, path, expression, local, seen):
        if expression is None:
            return
        for node in ast.walk(expression):
            if not isinstance(node, ast.Call):
                continue
            target = self._expr(path, node.func, seen, local)
            safe = target.kind == 'external' and (target.value in APIS or target.value in WRAPPERS)
            if target.kind == 'function':
                safe = self._factory(target, path, node, seen, local).kind != 'unknown'
            if not safe:
                args = [*node.args, *(k.value for k in node.keywords)]
                if isinstance(node.func, ast.Attribute):
                    args.append(node.func.value)
                names = {n.id for part in args for n in ast.walk(part) if isinstance(n, ast.Name)}
                if target.kind == 'function':
                    captures = target.value.get('lexical_environment', {}).values()
                    names.update(name for name, value in local.items() if any(value is capture for capture in captures))
                self._invalidate(local, names, 'local_value_mutated_or_escaped')

    def _record_calls(self, path, expression, local, symbol, seen, controls, records):
        if expression is None:
            return
        self._expression_escape(path, expression, local, seen)
        if records is None:
            return
        def children(node):
            if isinstance(node, (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                return
            yield node
            for child in ast.iter_child_nodes(node):
                yield from children(child)
        for call in (n for n in children(expression) if isinstance(n, ast.Call)):
            binding = self._expr(path, call, seen, local)
            if binding.kind == 'construction':
                records.append(self._record(path, call, binding, 'deferred_template', symbol, controls))

    def _record(self, path, call, binding, kind, symbol='', controls=()):
        api = binding.value['api']
        framework, role_names = APIS[api]
        roles = {name: {'role': role_names[name], 'binding': value.as_dict(),
                        'source_identity_status': 'known' if source_identity_known(value) else 'known_empty' if explicitly_empty(value) else 'unknown'}
                 for name, value in binding.value['kwargs'].items() if name in role_names}
        return {'framework': framework, 'api': api, 'site': self._receipt(path, call),
                'registration_kind': kind, 'lexical_symbol': symbol,
                'path_conditions': list(controls), 'roles': roles, 'binding': binding.as_dict(),
                'role_status': {role: ('known' if any(v['role'] == role and v['source_identity_status'] == 'known' for v in roles.values()) and
                                           all(v['source_identity_status'] in ('known', 'known_empty') for v in roles.values() if v['role'] == role)
                                      else 'known_empty' if any(v['role'] == role for v in roles.values()) and all(v['source_identity_status'] == 'known_empty' for v in roles.values() if v['role'] == role)
                                      else 'unknown' if any(v['role'] == role for v in roles.values()) else 'not_declared')
                                for role in ('guards', 'tools', 'delegates')},
                'runtime_activation_verified': False, 'effect_reachability_verified': False,
                'issue_label': None}

    def _statements(self, path, statements, local, symbol, seen, controls, records, pure=False):
        local = dict(local)
        for offset, stmt in enumerate(statements):
            future = statements[offset+1:]
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                child_symbol = symbol + '.' + stmt.name if symbol else stmt.name
                binding = self._function_binding(path, stmt, child_symbol, local, future)
                local[stmt.name] = binding
                if records is not None:
                    env = self._local_env(stmt, binding.value['lexical_environment'], path)
                    self._statements(path, stmt.body, env, child_symbol, (*seen, ('factory', path, child_symbol)), controls, records)
                continue
            if isinstance(stmt, ast.ClassDef):
                if pure:
                    return local, unknown('factory_class_definition'), True
                # A method does not close over its class namespace. Instance and
                # inherited attributes remain unknown; no constructor guessing.
                for method in stmt.body:
                    if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        child_symbol = symbol + '.' + stmt.name + '.' + method.name if symbol else stmt.name + '.' + method.name
                        env = self._local_env(method, local if symbol else {}, path)
                        self._statements(path, method.body, env, child_symbol, (*seen, ('factory', path, child_symbol)), controls, records)
                local[stmt.name] = unknown('class_object_unsupported')
                continue
            if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                self._record_calls(path, stmt.value, local, symbol, seen, controls, records)
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                if any(not isinstance(t, ast.Name) for t in targets):
                    names = {n.id for target in targets for n in ast.walk(target) if isinstance(n, ast.Name)}
                    self._invalidate(local, names, 'attribute_or_container_mutation')
                    if pure:
                        return local, unknown('factory_mutation'), True
                    continue
                value = self._expr(path, stmt.value, seen, local)
                for target in targets:
                    local[target.id] = value
                continue
            if isinstance(stmt, ast.Return):
                self._record_calls(path, stmt.value, local, symbol, seen, controls, records)
                return local, self._expr(path, stmt.value, seen, local), True
            if isinstance(stmt, ast.If):
                self._record_calls(path, stmt.test, local, symbol, seen, controls, records)
                truth = self._truth(path, stmt.test, seen, local)
                if truth is not None:
                    local, result, stopped = self._statements(path, stmt.body if truth else stmt.orelse, local, symbol, seen, controls, records, pure)
                    if stopped:
                        return local, result, True
                else:
                    if pure:
                        return local, unknown('factory_dynamic_branch'), True
                    terminations = []
                    branch_changes = set()
                    for branch, polarity in ((stmt.body, True), (stmt.orelse, False)):
                        branch_env, _, stopped = self._statements(path, branch, local, symbol, seen, (*controls, {'line': stmt.lineno, 'condition': ast.unparse(stmt.test), 'value': polarity}), records)
                        terminations.append(stopped)
                        branch_changes.update(name for name, value in branch_env.items() if local.get(name) != value)
                    if all(terminations):
                        return local, unknown('conditional_returns'), True
                    touched = self._writes(stmt.body + stmt.orelse) | branch_changes
                    self._invalidate(local, touched, 'conditional_binding_join')
                    for name in touched:
                        local[name] = unknown('conditional_binding_join')
                continue
            if isinstance(stmt, (ast.Import, ast.ImportFrom)):
                if isinstance(stmt, ast.Import):
                    for alias in stmt.names:
                        local[alias.asname or alias.name.split('.')[0]] = self._module(alias.name if alias.asname else alias.name.split('.')[0])
                else:
                    module = self._import_module(path, stmt)
                    for alias in stmt.names:
                        if alias.name == '*':
                            for name in local:
                                local[name] = unknown('star_import')
                        elif module in self.modules and self.modules[module]:
                            local[alias.asname or alias.name] = self._name(self.modules[module], alias.name, seen, {})
                        elif module:
                            local[alias.asname or alias.name] = Binding('external', module + '.' + alias.name)
                continue
            if isinstance(stmt, ast.Expr):
                self._record_calls(path, stmt.value, local, symbol, seen, controls, records)
                if isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str):
                    continue
                if pure:
                    return local, unknown('factory_side_effect_statement'), True
                if isinstance(stmt.value, ast.Call):
                    call = stmt.value
                    names = {n.id for part in [call.func, *call.args, *(k.value for k in call.keywords)] for n in ast.walk(part) if isinstance(n, ast.Name)}
                    self._invalidate(local, names, 'local_value_mutated_or_escaped')
                continue
            if isinstance(stmt, (ast.Pass, ast.Global, ast.Nonlocal)):
                continue
            if pure:
                return local, unknown('factory_statement_unsupported:' + type(stmt).__name__), True
            # Loops/try/with are only potential lexical templates. Invalidate
            # names they may write before entering and after leaving each block.
            touched = self._writes([stmt])
            uncertain = dict(local)
            for name in touched:
                uncertain[name] = unknown('dynamic_control_binding')
            for _, field in ast.iter_fields(stmt):
                if isinstance(field, list):
                    block = [n for n in field if isinstance(n, ast.stmt)]
                    if block:
                        block_env, _, _ = self._statements(path, block, uncertain, symbol, seen, (*controls, {'line': stmt.lineno, 'kind': type(stmt).__name__, 'reachability': 'unknown'}), records)
                        changed = {name for name, value in block_env.items() if uncertain.get(name) != value}
                        self._invalidate(uncertain, changed, 'dynamic_control_binding')
                        for name in changed:
                            uncertain[name] = unknown('dynamic_control_binding')
            local = uncertain
        return local, None, False

    def registrations(self):
        result = []
        for path, tree in self.trees.items():
            if tree is None:
                continue
            for stmt in tree.body:
                call = stmt.value if isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.Expr)) else None
                if isinstance(call, ast.Call):
                    binding = self.resolve_expr(path, call)
                    if binding.kind == 'construction':
                        result.append(self._record(path, call, binding, 'module_expression'))
        return result

    def deferred_registrations(self):
        result = []
        for path, tree in self.trees.items():
            if tree is None:
                continue
            for stmt in tree.body:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    local = self._local_env(stmt, path=path)
                    self._statements(path, stmt.body, local, stmt.name, (('factory', path, stmt.name),), (), result)
                elif isinstance(stmt, ast.ClassDef):
                    self._statements(path, [stmt], {}, '', (), (), result)
        # The same constructor AST may be encountered via nested expression
        # traversal. Deduplicate only identical scoped/path-conditioned records.
        import json
        distinct = {json.dumps(row, sort_keys=True): row for row in result}
        return list(distinct.values())
