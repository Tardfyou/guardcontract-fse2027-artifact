"""Resolve static definitions and re-exports without importing analyzed code.

Receipts locate source definitions; they do not assert successful construction,
post-decorator object identity, execution reachability, or contract correctness.
"""
import ast
from collections import defaultdict
import hashlib
from pathlib import PurePosixPath


class SourceSymbolIndex:
    def __init__(self, sources):
        self.sources = dict(sources)
        self.modules = defaultdict(list)
        self.parsed = {}
        for path in sources:
            p = PurePosixPath(path)
            if p.is_absolute() or '..' in p.parts or not path.endswith('.py'):
                raise ValueError('symbol_index_source_path')
            module = path[:-3].replace('/', '.')
            if module.endswith('.__init__'):
                module = module[:-9]
            self.modules[module].append(path)

    def _parse(self, module):
        paths = self.modules.get(module, [])
        if len(paths) != 1:
            raise ValueError('symbol_module_ambiguous_or_missing')
        path = paths[0]
        if module in self.parsed:
            return self.parsed[module]
        tree = ast.parse(self.sources[path])
        bindings = defaultdict(list)
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                bindings[node.name].append(('definition', node))
            elif isinstance(node, ast.ImportFrom):
                base = node.module or ''
                if node.level:
                    package = module.split('.') if path.endswith('/__init__.py') else module.split('.')[:-1]
                    if node.level > len(package):
                        raise ValueError('symbol_relative_import')
                    base = '.'.join(package[:len(package) - node.level + 1] + ([base] if base else []))
                for alias in node.names:
                    bindings[alias.asname or alias.name].append(('reference', base + '.' + alias.name))
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    bindings[alias.asname or alias.name.split('.')[0]].append(('reference', alias.name if alias.asname else alias.name.split('.')[0]))
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        bindings[target.id].append(('alias', node.value))
            else:
                # Conditional imports/rebindings cannot be resolved from the
                # apparent unconditional definition while ignoring the branch.
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Name) and isinstance(sub.ctx, (ast.Store, ast.Del)):
                        bindings[sub.id].append(('dynamic', sub))
                    elif isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        bindings[sub.name].append(('dynamic', sub))
                    elif isinstance(sub, (ast.Import, ast.ImportFrom)):
                        for alias in sub.names:
                            bindings[alias.asname or alias.name.split('.')[0]].append(('dynamic', sub))
        self.parsed[module] = (path, bindings)
        return path, bindings

    def _reference(self, module, node):
        if isinstance(node, ast.Subscript):
            node = node.value
        if isinstance(node, ast.Name):
            return module + '.' + node.id
        if isinstance(node, ast.Attribute):
            return self._reference(module, node.value) + '.' + node.attr
        raise ValueError('symbol_dynamic_expression')

    def _overload(self, module, node):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return False
        _, bindings = self._parse(module)
        for decorator in node.decorator_list:
            parts = ast.unparse(decorator).split('.')
            values = bindings.get(parts[0], [])
            if len(values) == 1 and values[0][0] == 'reference':
                target = '.'.join([values[0][1], *parts[1:]])
                if target in {'typing.overload', 'typing_extensions.overload'}:
                    return True
        return False

    def _implementation(self, module, nodes):
        if len(nodes) > 1 and all(self._overload(module, n) for n in nodes[:-1]) and not self._overload(module, nodes[-1]):
            return nodes[-1]
        if len(nodes) == 1 and not self._overload(module, nodes[0]):
            return nodes[0]
        raise ValueError('symbol_overloads_without_unique_implementation')

    def _resolve(self, symbol, seen):
        if symbol in seen or len(seen) >= 64:
            raise ValueError('symbol_resolution_cycle')
        seen = (*seen, symbol)
        parts = symbol.split('.')
        for i in range(len(parts) - 1, 0, -1):
            module = '.'.join(parts[:i])
            if module in self.modules:
                rest = parts[i:]
                break
        else:
            raise ValueError('symbol_module_not_in_inventory')
        path, bindings = self._parse(module)
        if '*' in bindings:
            raise ValueError('symbol_star_import_not_resolved')
        values = bindings.get(rest[0], [])
        if len(values) > 1 and all(kind == 'definition' for kind, _ in values):
            values = [('definition', self._implementation(module, [node for _, node in values]))]
        if len(values) != 1:
            raise ValueError('symbol_absent_or_rebound')
        kind, value = values[0]
        suffix = '.' + '.'.join(rest[1:]) if len(rest) > 1 else ''
        if kind == 'reference':
            return self._resolve(value + suffix, seen)
        if kind == 'alias':
            return self._resolve(self._reference(module, value) + suffix, seen)
        if kind != 'definition':
            raise ValueError('symbol_conditional_binding')
        node = value
        if self._overload(module, node):
            raise ValueError('symbol_overload_stub_only')
        if len(rest) > 1:
            if not isinstance(node, ast.ClassDef) or len(rest) != 2:
                raise ValueError('symbol_attribute_not_statically_resolved')
            declarations = []
            for member in node.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and member.name == rest[1]:
                    declarations.append(member)
                elif isinstance(member, (ast.Assign, ast.AnnAssign)):
                    targets = member.targets if isinstance(member, ast.Assign) else [member.target]
                    if any(isinstance(t, ast.Name) and t.id == rest[1] for t in targets):
                        declarations.append(None)
                else:
                    for child in ast.walk(member):
                        if ((isinstance(child, ast.Name) and isinstance(child.ctx, (ast.Store, ast.Del)) and child.id == rest[1])
                                or (isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and child.name == rest[1])):
                            declarations.append(None)
            if declarations and all(n is not None for n in declarations):
                node = self._implementation(module, declarations)
            elif declarations:
                raise ValueError('symbol_class_member_rebound')
            elif len(node.bases) == 1:
                return self._resolve(self._reference(module, node.bases[0]) + '.' + rest[1], seen)
            else:
                raise ValueError('symbol_inheritance_requires_explicit_mro')
        first = min([node.lineno] + [d.lineno for d in getattr(node, 'decorator_list', [])])
        return {'status': 'located', 'resolved_symbol': symbol, 'path': path,
                'start_line': first, 'end_line': node.end_lineno,
                'kind': type(node).__name__, 'resolution_chain': list(seen),
                'decorators': [ast.unparse(d) for d in getattr(node, 'decorator_list', [])],
                'source_sha256': hashlib.sha256(self.sources[path].encode()).hexdigest(),
                'definition_node_sha256': hashlib.sha256(ast.dump(node, include_attributes=True).encode()).hexdigest(),
                'runtime_identity_verified': False, 'contract_prediction': None}

    def resolve(self, symbol):
        if not isinstance(symbol, str) or not symbol or any(not p.isidentifier() for p in symbol.split('.')):
            raise ValueError('symbol_query_shape')
        try:
            result = self._resolve(symbol, ())
        except (ValueError, SyntaxError) as exc:
            result = {'status': 'unresolved', 'reason': str(exc), 'contract_prediction': None}
        return {**result, 'requested_symbol': symbol}

    def excerpt(self, receipt):
        if receipt.get('status') != 'located':
            raise ValueError('symbol_excerpt_not_located')
        source = self.sources[receipt['path']]
        if hashlib.sha256(source.encode()).hexdigest() != receipt['source_sha256']:
            raise ValueError('symbol_excerpt_source_drift')
        lines = source.splitlines()
        return '\n'.join(f'{n}|{lines[n-1]}' for n in range(receipt['start_line'], receipt['end_line'] + 1))
