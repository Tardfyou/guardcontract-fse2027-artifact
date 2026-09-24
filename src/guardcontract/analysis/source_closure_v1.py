"""Authenticated, name-independent function closures for bounded SDK slices.

Source imports are resolved as data. Runtime compilation uses only these audited
function bodies and explicit inert capabilities; module initializers never run.
"""
import ast
import copy
import hashlib
import symtable
from dataclasses import dataclass
from guardcontract.analysis.source_bindings_v1 import SourceBindings


BUILTINS={'str','int','bool','float','dict','list','tuple','print','input'}
EXTERNALS={'requests','requests.get','requests.post','os','os.getenv','pathlib','pathlib.Path',
    'streamlit','langchain_core','langchain_core.messages','langchain_core.messages.ToolMessage'}
DECORATORS={'langchain.tools.tool','langchain_core.tools.tool','langchain.agents.middleware.wrap_tool_call'}
ATTRIBUTES={'tool_call','session_state','get','post','json','status_code','getenv','lower','Path','write_text'}


def digest(value):return hashlib.sha256(value.encode()).hexdigest()


def audit_function(node,*,tool=False,approved_attributes=frozenset()):
    if not isinstance(node,ast.FunctionDef) or node.args.vararg or node.args.kwarg or node.args.posonlyargs:
        raise ValueError('closure_function_shape')
    forbidden=(ast.Import,ast.ImportFrom,ast.ClassDef,ast.Lambda,ast.Global,ast.Nonlocal,ast.With,ast.AsyncWith,
               ast.Await,ast.Yield,ast.YieldFrom,ast.For,ast.AsyncFor,ast.While,ast.ListComp,ast.SetComp,ast.DictComp,ast.GeneratorExp)
    for n in ast.walk(node):
        if n is not node and isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)):raise ValueError('nested_function_requires_closure_cell_profile')
        if isinstance(n,forbidden):raise ValueError('closure_statement_unsupported:'+type(n).__name__)
        if isinstance(n,ast.Name) and n.id.startswith('__'):raise ValueError('closure_private_name')
        if isinstance(n,ast.Attribute) and (n.attr.startswith('_') or (n.attr not in ATTRIBUTES and (n.lineno,n.col_offset,n.attr) not in approved_attributes) or not isinstance(n.ctx,ast.Load)):
            raise ValueError('closure_attribute_unsupported:'+n.attr)
        if isinstance(n,ast.Call) and (not isinstance(n.func,(ast.Name,ast.Attribute)) or any(k.arg is None for k in n.keywords) or any(isinstance(a,ast.Starred) for a in n.args)):
            raise ValueError('closure_dynamic_call_shape')
    for d in node.args.defaults+[d for d in node.args.kw_defaults if d is not None]:ast.literal_eval(d)
    if tool:
        for a in node.args.args+node.args.kwonlyargs:
            if a.annotation is not None and not (isinstance(a.annotation,ast.Name) and a.annotation.id in BUILTINS-{'print','input'}):
                raise ValueError('closure_tool_annotation_profile')
        if node.returns is not None and not (isinstance(node.returns,ast.Name) and node.returns.id in BUILTINS-{'print','input'}):
            raise ValueError('closure_tool_return_profile')
    else:
        # Function annotations are unobserved in this profile and not executed.
        for a in node.args.args+node.args.kwonlyargs:a.annotation=None
        node.returns=None
    return node


@dataclass
class Closure:
    resolver: object
    functions: dict
    globals: dict
    guard: tuple
    tool: tuple
    effect: dict
    registration: dict

    def receipt(self):
        return {'schema_version':'source-function-closure-1',
            'sources':{p:digest(s) for p,s in self.resolver.sources.items()},
            'functions':[{'path':p,'symbol':s,'line':n.lineno,'body_sha256':digest(ast.dump(n,include_attributes=False))} for (p,s),n in sorted(self.functions.items())],
            'guard':list(self.guard),'tool':list(self.tool),'effect':self.effect,'registration':self.registration,
            'module_initializers_executed':False,'scope':'enrolled synchronous source function closure only'}


def enroll(sources,item):
    resolver=SourceBindings(sources);functions={};bindings={};visiting=set()
    guard=(item['guard']['path'],item['guard']['symbol']);tool=(item['tool']['path'],item['tool']['symbol'])
    def add_binding(binding):
        if binding.kind=='function':add((binding.value['path'],binding.value['symbol']))
        elif binding.kind=='external':
            if binding.value not in EXTERNALS:raise ValueError('closure_external_capability_unsupported:'+binding.value)
        elif binding.kind in ('constant',):pass
        elif binding.kind in ('sequence','mapping'):
            for child in (binding.value.values() if binding.kind=='mapping' else binding.value):add_binding(child)
        elif binding.kind=='module':
            # Module members are enrolled from the exact attribute references,
            # not from importing or exposing the whole repository module.
            pass
        else:raise ValueError('closure_global_binding_unknown:'+str(binding.value))
    def add(key):
        if key in visiting:raise ValueError('closure_recursive_call_graph')
        if key in functions:return
        node=resolver.function(*key)
        ref=resolver.resolve_global(*key)
        if node is None or ref.kind!='function':raise ValueError('closure_function_binding_not_unique')
        decorators=[]
        for decorator in node.decorator_list:
            bound=resolver.resolve_expr(key[0],decorator)
            if bound.kind!='external' or bound.value not in DECORATORS:raise ValueError('closure_decorator_identity')
            decorators.append(bound.value)
        if key==guard and decorators!=['langchain.agents.middleware.wrap_tool_call']:
            raise ValueError('closure_guard_decorator_profile')
        if key==tool and (len(decorators)>1 or any(d not in {'langchain.tools.tool','langchain_core.tools.tool'} for d in decorators)):
            raise ValueError('closure_tool_decorator_profile')
        if key not in {guard,tool} and decorators:
            raise ValueError('closure_decorated_helper_requires_object_call_profile')
        visiting.add(key)
        clean=copy.deepcopy(node);clean.decorator_list=[]
        if key==tool:
            def annotation_identity(annotation):
                if annotation is None:return None
                primitive=None
                if isinstance(annotation,ast.Name) and annotation.id in BUILTINS-{'print','input'} and annotation.id not in resolver.writes[key[0]]:
                    primitive=annotation.id
                else:
                    actual=resolver.resolve_expr(key[0],annotation)
                    if actual.kind=='external' and actual.value.startswith('builtins.'):
                        candidate=actual.value.removeprefix('builtins.')
                        if candidate in BUILTINS-{'print','input'}:primitive=candidate
                if primitive is None:raise ValueError('closure_tool_annotation_binding')
                return ast.copy_location(ast.Name(id=primitive,ctx=ast.Load()),annotation)
            for parameter in clean.args.args+clean.args.kwonlyargs:parameter.annotation=annotation_identity(parameter.annotation)
            clean.returns=annotation_identity(clean.returns)
        table=symtable.symtable(ast.unparse(clean),'<closure>','exec').get_children()[0]
        approved=set()
        for part in ast.walk(clean):
            if isinstance(part,ast.Attribute):
                root=part
                while isinstance(root,ast.Attribute):root=root.value
                if not isinstance(root,ast.Name) or root.id not in table.get_identifiers() or not table.lookup(root.id).is_global():continue
                bound=resolver.resolve_expr(key[0],part)
                if bound.kind in ('function','module') or bound.kind=='external' and bound.value in EXTERNALS:
                    approved.add((part.lineno,part.col_offset,part.attr))
        audit_function(clean,tool=key==tool,approved_attributes=approved)
        table=symtable.symtable(ast.unparse(clean),'<closure>','exec').get_children()[0]
        loaded={n.id for n in ast.walk(clean) if isinstance(n,ast.Name) and isinstance(n.ctx,ast.Load)}
        global_names={s.get_name() for s in table.get_symbols() if s.is_global() and s.get_name() in loaded}
        namespace={}
        for name in sorted(global_names):
            # A module-level rebinding of a builtin remains authoritative.
            if name in BUILTINS and name not in resolver.writes[key[0]]:continue
            bound=resolver.resolve_global(key[0],name);add_binding(bound);namespace[name]=bound
        for expr in ast.walk(clean):
            if not isinstance(expr,ast.Attribute):continue
            root=expr
            while isinstance(root,ast.Attribute):root=root.value
            if not isinstance(root,ast.Name) or root.id not in namespace or namespace[root.id].kind!='module':continue
            bound=resolver.resolve_expr(key[0],expr)
            if bound.kind=='function':add_binding(bound)
        functions[key]=clean;bindings[key]=namespace;visiting.remove(key)
    add(guard);add(tool)
    effect=item['effect']
    if effect['kind'] not in ('http_get','http_post','file_write'):raise ValueError('closure_effect_kind')
    matches=[n for (p,_),node in functions.items() if p==effect['path'] for n in ast.walk(node)
        if isinstance(n,ast.Call) and n.lineno==effect['line']
        and ('column' not in effect or n.col_offset==effect['column'])
        and ('end_column' not in effect or n.end_col_offset==effect['end_column'])]
    if len(matches)!=1:raise ValueError('closure_effect_site_not_unique')
    expected_member={'http_get':'get','http_post':'post','file_write':'write_text'}[effect['kind']]
    site=matches[0]
    if isinstance(site.func,ast.Attribute):
        if site.func.attr!=expected_member:raise ValueError('closure_effect_kind_site_mismatch')
    elif isinstance(site.func,ast.Name):
        ref=resolver.resolve_global(effect['path'],site.func.id)
        if ref.kind!='external' or ref.value!='requests.'+expected_member:raise ValueError('closure_effect_alias_unbound')
    registration=item['registration'];tree=resolver.trees.get(registration['path'])
    calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and n.lineno==registration['line']] if tree else []
    # Construction-time expressions are shared with the generic resolver.
    possible=[]
    for call in calls:
        value=resolver.resolve_expr(registration['path'],call)
        if value.kind=='construction':possible.append(value)
    if len(possible)!=1:raise ValueError('closure_registration_unresolved')
    value=possible[0]
    def function_keys(binding):
        if binding is None:return set()
        if binding.kind=='function':return {(binding.value['path'],binding.value['symbol'])}
        if binding.kind=='sequence':return set().union(*(function_keys(b) for b in binding.value)) if binding.value else set()
        return set()
    spec=value.value
    # Only the runtime adapter's enrolled SDK is claimed here; other API
    # registrations are still useful structural output from SourceBindings.
    api=spec.get('api',spec.get('callee'))
    if api!='langchain.agents.create_agent':raise ValueError('closure_runtime_framework_not_enrolled')
    kwargs=spec['kwargs']
    if set(kwargs)-{'model','tools','middleware'}:
        raise ValueError('closure_registration_configuration_not_enrolled')
    registered_tools=kwargs.get('tools')
    if registered_tools is None or registered_tools.kind!='sequence' or len(registered_tools.value)!=1:
        raise ValueError('closure_runtime_requires_single_selected_tool_registration')
    middleware=kwargs.get('middleware')
    if tool not in function_keys(kwargs.get('tools')) or middleware is None or middleware.kind!='sequence' or len(middleware.value)!=1 or function_keys(middleware)!={guard}:
        raise ValueError('closure_guard_tool_registration_mismatch')
    return Closure(resolver,functions,bindings,guard,tool,dict(effect),value.as_dict())
