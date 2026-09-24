"""Only instantiated module expressions may enter the runtime source profile."""
import ast
from guardcontract.analysis.source_closure_v1 import enroll as enroll_closure


def enroll(sources,item):
    registration=item['registration'];source=sources.get(registration['path'])
    if source is None:raise ValueError('closure_registration_source_missing')
    tree=ast.parse(source)
    candidates=[]
    for statement in tree.body:
        if isinstance(statement,(ast.Assign,ast.AnnAssign,ast.Expr)):
            value=statement.value
            if isinstance(value,ast.Call) and value.lineno==registration['line']:candidates.append(value)
    if len(candidates)!=1:
        raise ValueError('closure_registration_is_deferred_or_not_module_expression')
    # The shared resolver can instantiate a simple factory called here. A raw
    # constructor inside the factory is never resolved without its call binding.
    return enroll_closure(sources,item)
