"""Development-only binding of a declared wrapper to its exact source callable.

SDK knowledge is supplied as a wrapper contract; this shared resolver does not
infer that a wrapper protects every tool registered beside it.
"""
import ast
from pathlib import Path


def bind_wrapper(root, registration_path, wrapper_line, effect_path, effect_symbol, contract):
    root = Path(root).resolve()
    reg = root / registration_path
    effect = root / effect_path
    if any(p.is_symlink() or not p.resolve().is_relative_to(root) for p in (reg, effect)):
        raise ValueError("wrapper_source_escape")
    tree = ast.parse(reg.read_text())
    effect_tree = ast.parse(effect.read_text())
    if sum(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == effect_symbol
           for n in effect_tree.body) != 1:
        return {"status": "unknown", "reason": "effect_definition_not_unique"}
    bindings = {}
    uncertain = set()
    for stmt in tree.body:
        if stmt.lineno >= wrapper_line:
            break
        if isinstance(stmt, ast.ImportFrom):
            if any(a.name == "*" for a in stmt.names):
                return {"status": "unknown", "reason": "wildcard_import"}
            prefix = Path(registration_path).parent
            if stmt.level:
                for _ in range(stmt.level-1):
                    prefix = prefix.parent
                module_path = prefix / Path(*(stmt.module or '').split('.'))
            else:
                module_path = Path(*(stmt.module or '').split('.'))
            for a in stmt.names:
                symbol = (stmt.module + '.' if stmt.module else '') + a.name
                bindings[a.asname or a.name] = (symbol, str(module_path.with_suffix('.py')), a.name)
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            bindings[stmt.name] = (None, registration_path, stmt.name)
        elif isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    bindings[target.id] = bindings.get(stmt.value.id) if isinstance(stmt.value, ast.Name) else None
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            bindings[stmt.target.id] = bindings.get(stmt.value.id) if isinstance(stmt.value, ast.Name) else None
        elif isinstance(stmt, ast.Import):
            for a in stmt.names:
                bindings[a.asname or a.name.split('.')[0]] = (a.name if a.asname else a.name.split('.')[0], None, None)
        elif not isinstance(stmt, ast.Expr):
            for n in ast.walk(stmt):
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                    uncertain.add(n.id)

    def origin(node):
        if isinstance(node, ast.Name):
            return None if node.id in uncertain else bindings.get(node.id)
        if isinstance(node, ast.Attribute):
            parent = origin(node.value)
            return (parent[0]+'.'+node.attr, None, None) if parent and parent[0] else None
        return None

    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and n.lineno == wrapper_line]
    wrappers = [n for n in calls if origin(n.func) and origin(n.func)[0] == contract['qualified_api']]
    if len(wrappers) != 1:
        return {"status": "unknown", "reason": "wrapper_api_not_unique"}
    call = wrappers[0]
    if any(kw.arg is None for kw in call.keywords):
        return {"status": "unknown", "reason": "wrapper_keyword_expansion"}
    if any(isinstance(a, ast.Starred) for a in call.args):
        return {"status": "unknown", "reason": "wrapper_argument_expansion"}
    values = [kw.value for kw in call.keywords if kw.arg in contract['callable_keywords']]
    position = contract['callable_position']
    if len(call.args) > position:
        values.append(call.args[position])
    if len(values) != 1:
        return {"status": "unknown", "reason": "wrapped_callable_ambiguous"}
    bound = origin(values[0])
    if not bound or not bound[1] or not bound[2]:
        return {"status": "unknown", "reason": "wrapped_callable_unresolved"}
    target = root / bound[1]
    if not target.is_file() or target.is_symlink() or not target.resolve().is_relative_to(root):
        return {"status": "unknown", "reason": "wrapped_source_unavailable"}
    target_tree = ast.parse(target.read_text())
    definitions = [n for n in target_tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == bound[2]]
    if len(definitions) != 1:
        return {"status": "unknown", "reason": "wrapped_definition_not_unique"}
    # A later top-level rebinding makes the imported object's identity uncertain.
    for n in target_tree.body:
        if n.lineno > definitions[0].lineno and any(isinstance(x, ast.Name) and isinstance(x.ctx, ast.Store)
            and x.id == bound[2] for x in ast.walk(n)):
            return {"status": "unknown", "reason": "wrapped_definition_rebound"}
    same = target.resolve() == effect.resolve() and bound[2] == effect_symbol
    return {"status": "bound" if same else "guard_effect_binding_mismatch",
            "wrapped_callable": {"path": bound[1], "symbol": bound[2]},
            "effect_callable": {"path": effect_path, "symbol": effect_symbol},
            "issue_label": None, "development_only": True,
            "claim_boundary": "Wrapper attachment identity only; callbacks at agent scope and runtime policy applicability remain separate."}
