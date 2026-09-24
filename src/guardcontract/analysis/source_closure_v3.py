"""Bind the exact module call node before enrolling its runtime source closure."""
import ast
from guardcontract.analysis.source_bindings_v3 import RuntimeSourceBindings as SourceBindings
from guardcontract.analysis.source_closure_v1 import enroll as enroll_closure


def enroll(sources,item):
    registration=item['registration'];source=sources.get(registration['path'])
    if source is None:raise ValueError('closure_registration_source_missing')
    tree=ast.parse(source);candidates=[]
    for statement in tree.body:
        if isinstance(statement,(ast.Assign,ast.AnnAssign,ast.Expr)):
            value=statement.value
            if isinstance(value,ast.Call) and value.lineno==registration['line']:candidates.append(value)
    if len(candidates)!=1:raise ValueError('closure_registration_is_deferred_or_not_module_expression')
    exact=SourceBindings(sources).resolve_expr(registration['path'],candidates[0])
    if exact.kind!='construction':raise ValueError('closure_exact_module_call_not_bound_construction')
    closure=enroll_closure(sources,item)
    if closure.registration!=exact.as_dict():raise ValueError('closure_registration_exact_node_mismatch')
    return closure
