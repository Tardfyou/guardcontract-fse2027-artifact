"""Conservative framework-independent guard/effect co-domain candidates."""
import ast
import hashlib
from collections import defaultdict
from pathlib import Path
from guardcontract.discovery.generic_guard_catalog import MARKERS
from guardcontract.discovery.scout import effect_sites_from_tree
from guardcontract.evidence.slicing import EXCLUDED_PARTS


def _body_nodes(function):
    pending = list(reversed(function.body))
    while pending:
        node = pending.pop()
        yield node
        if node is not function and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        pending.extend(reversed(list(ast.iter_child_nodes(node))))


def co_domain_candidates(root, *, max_files=2000, max_pairs=5000):
    root=Path(root).resolve(); rows=[]; errors=[]; scanned=0
    if type(max_files) is not int or max_files<1 or type(max_pairs) is not int or max_pairs<1:
        raise ValueError('generic_relationship_budget')
    def result(truncated):
        return {'schema_version':'generic-relationship-2','candidates':rows,'errors':errors,
                'scanned_files':scanned,'truncated':truncated,
                'execution_health':'partial' if errors or truncated else 'completed',
                'claim_boundary':'Same-function and local-helper co-domain candidates only; no binding, order, policy, runtime or issue claim.'}
    for path in sorted(root.rglob('*.py')):
        if scanned>=max_files:break
        relative=path.relative_to(root)
        if (path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root)
                or any(part in EXCLUDED_PARTS or part.lower().startswith('.env') for part in relative.parts)):
            continue
        scanned+=1
        try: tree=ast.parse(path.read_text(encoding='utf-8-sig'),filename=str(path))
        except (OSError,UnicodeError,SyntaxError) as exc:
            errors.append({'path':relative.as_posix(),'error_kind':type(exc).__name__})
            continue
        relative=relative.as_posix()
        source_sha256=hashlib.sha256(path.read_bytes()).hexdigest()
        for fn in (n for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))):
            names=[]
            for n in ast.walk(fn):
                if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)) and n is not fn:continue
                if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
                    names.extend(marker for marker in MARKERS if marker in n.name.lower())
            guards=sorted(set(names)); effects=effect_sites_from_tree(tree,relative,within=fn)
            if not guards:continue
            for guard in guards:
                for effect in effects:
                    if len(rows)>=max_pairs:return result(True)
                    rows.append({'path':relative,'function':fn.name,'function_line':fn.lineno,'guard_marker':guard,
                                 'effect':{'line':effect.line,'family':effect.family,'call':effect.call},
                                 'binding_status':'co_domain_only','path_status':'unknown',
                                 'source_sha256':source_sha256,
                                 'evaluation_relevance':'non_production' if any(p in {'tests','test','examples','example','demo'} for p in Path(relative).parts) else 'production_candidate'})
            # Follow uniquely named local helpers from a guard function. This is
            # a shared lexical edge, not runtime reachability.
            local = defaultdict(list)
            for candidate in ast.walk(tree):
                if isinstance(candidate, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    local[candidate.name].append(candidate)
            for call in (n for n in _body_nodes(fn) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name)):
                helpers = [candidate for candidate in local.get(call.func.id, []) if candidate is not fn]
                if len(helpers) != 1: continue
                helper = helpers[0]
                helper_effects = effect_sites_from_tree(tree, relative, within=helper)
                for effect in helper_effects:
                    if len(rows)>=max_pairs:
                        return result(True)
                    rows.append({'path':relative,'function':fn.name,'function_line':fn.lineno,'guard_marker':guard,
                                 'helper':helper.name,'helper_line':helper.lineno,
                                 'effect':{'line':effect.line,'family':effect.family,'call':effect.call},
                                 'binding_status':'cross_function_co_domain','path_status':'unknown',
                                 'source_sha256':source_sha256,
                                 'evaluation_relevance':'non_production' if any(p in {'tests','test','examples','example','demo'} for p in Path(relative).parts) else 'production_candidate'})
    return result(False)
