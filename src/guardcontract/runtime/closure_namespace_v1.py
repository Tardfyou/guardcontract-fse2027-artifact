"""Build only the authenticated namespaces required by an enrolled closure."""
import ast
from guardcontract.analysis.source_closure_v1 import EXTERNALS


def namespaces(closure,external,function_value,object_factory,builtins):
    cache={}
    def materialize(binding):
        if binding.kind=='constant':return binding.value
        if binding.kind=='function':
            key=(binding.value['path'],binding.value['symbol'])
            if key in {closure.guard,closure.tool} and binding.value.get('decorators'):
                raise ValueError('decorated_sdk_entry_is_not_plain_helper')
            return function_value(key)
        if binding.kind=='external':
            if binding.value in external:return external[binding.value]
            raise ValueError('external_namespace_not_implemented:'+binding.value)
        if binding.kind=='module':return object_factory({})
        # Mutable global alias identity is not represented by structural Binding
        # values; refuse it rather than merge equal-but-distinct containers.
        raise ValueError('runtime_global_value_profile:'+binding.kind)
    def put(root,names,value):
        fields=root.fields if hasattr(root,'fields') else vars(root)
        for name in names[:-1]:
            if name not in fields:fields[name]=object_factory({})
            child=fields[name];fields=child.fields if hasattr(child,'fields') else vars(child)
        fields[names[-1]]=value
    for key,bindings in closure.globals.items():
        current=dict(builtins)
        for name,binding in bindings.items():current[name]=materialize(binding)
        for expr in ast.walk(closure.functions[key]):
            if not isinstance(expr,ast.Attribute):continue
            root=expr;names=[]
            while isinstance(root,ast.Attribute):names.insert(0,root.attr);root=root.value
            if not isinstance(root,ast.Name) or root.id not in bindings or bindings[root.id].kind!='module':continue
            bound=closure.resolver.resolve_expr(key[0],expr)
            if bound.kind=='function':put(current[root.id],names,materialize(bound))
        cache[key]=current
    return cache
