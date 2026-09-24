"""Development-only control-path proof for callbacks with a continuation.

The caller must authenticate continuation identity and denial-return semantics.
This module knows no SDK names, repositories, messages, or effect types. A path
containing a continuation is a candidate, never proof that an effect committed.
Unsupported operations keep the result unknown. Frozen v24 does not use this.
"""
import ast


def analyze(function, *, continuation_parameter, denial_return_lines, pure_calls=()):
    params = [a.arg for a in function.args.posonlyargs + function.args.args]
    if continuation_parameter not in params:
        raise ValueError("continuation_parameter_missing")
    denied = set(denial_return_lines)
    actual_returns = {n.lineno for n in ast.walk(function) if isinstance(n, ast.Return)}
    if not denied or not denied <= actual_returns:
        return {"status": "unknown", "reason": "denial_return_identity_missing", "paths": []}
    gaps = set()
    pure_calls = set(pure_calls)

    def name(n):
        if isinstance(n, ast.Name):
            return n.id
        if isinstance(n, ast.Attribute):
            return name(n.value) + "." + n.attr
        return ""

    def expression(expr, events):
        if expr is None:
            return list(events)
        out = list(events)
        if any(isinstance(n, (ast.Lambda, ast.Await, ast.Yield, ast.YieldFrom,
                              ast.NamedExpr, ast.ListComp, ast.SetComp, ast.DictComp,
                              ast.GeneratorExp, ast.BoolOp, ast.IfExp)) for n in ast.walk(expr)):
            gaps.add("unsupported_expression_control")
        for call in [n for n in ast.walk(expr) if isinstance(n, ast.Call)]:
            callee = name(call.func)
            if callee == continuation_parameter:
                out.append({"kind": "continuation", "line": call.lineno})
                if any(isinstance(n, ast.Call) for arg in call.args for n in ast.walk(arg)):
                    gaps.add("nested_continuation_arguments")
            elif callee not in pure_calls:
                gaps.add("unresolved_call:" + callee)
        # Passing/storing the continuation is an escape, not a pure value.
        parents = {id(child): parent for parent in ast.walk(expr) for child in ast.iter_child_nodes(parent)}
        for n in ast.walk(expr):
            if isinstance(n, ast.Name) and n.id == continuation_parameter:
                parent = parents.get(id(n))
                if not isinstance(parent, ast.Call) or parent.func is not n:
                    gaps.add("continuation_escape")
        return out

    def block(statements, paths):
        current = paths
        for statement in statements:
            updated = []
            for events, terminal in current:
                if terminal:
                    updated.append((events, terminal))
                    continue
                if isinstance(statement, ast.If):
                    prefix = expression(statement.test, events)
                    if isinstance(statement.test, ast.Constant):
                        branches = [statement.body if statement.test.value else statement.orelse]
                    else:
                        branches = [statement.body, statement.orelse]
                    for branch in branches:
                        updated.extend(block(branch, [(prefix, None)]))
                elif isinstance(statement, ast.Return):
                    prefix = expression(statement.value, events)
                    term = "deny" if statement.lineno in denied else "return"
                    updated.append((prefix, term))
                elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
                    targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                    if any(isinstance(n, ast.Name) and n.id == continuation_parameter
                           for target in targets for n in ast.walk(target)):
                        gaps.add("continuation_rebound")
                    for target in targets:
                        expression(target, [])
                    updated.append((expression(statement.value, events), None))
                elif isinstance(statement, ast.Expr):
                    updated.append((expression(statement.value, events), None))
                elif isinstance(statement, ast.Pass):
                    updated.append((events, None))
                else:
                    gaps.add("unsupported_statement:" + type(statement).__name__)
                    updated.append((events, "unknown"))
            current = updated
        return current

    paths = block(function.body, [([], None)])
    deny_paths = [events for events, terminal in paths if terminal == "deny"]
    if gaps or not deny_paths:
        status = "unknown"
        reason = sorted(gaps)[0] if gaps else "no_reachable_denial_path"
    elif any(events for events in deny_paths):
        status, reason = "continuation_before_deny_candidate", "syntactic_path_requires_feasibility_and_effect_binding"
    else:
        status, reason = "deny_does_not_delegate", "all_supported_denial_paths_skip_continuation"
    return {"status": status, "reason": reason, "gaps": sorted(gaps),
            "paths": [{"events": events, "termination": terminal} for events, terminal in paths],
            "proof_scope": "callback control flow under caller-authenticated continuation and pure-call contracts",
            "runtime_effect_commit_verified": False, "issue_label": None,
            "detector_version": "v25-development-only"}
