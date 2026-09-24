"""Factory calls cannot discard unverified subcall side effects."""
import ast
from guardcontract.analysis.source_bindings_v1 import SourceBindings as BindingsV1,unknown
from guardcontract.analysis.source_bindings_v2 import SourceBindings as BindingsV2


class UnverifiedFactoryCall(ValueError):
    pass


class StrictFactoryCalls:
    def _factory(self,*args,**kwargs):
        depth=getattr(self,'_factory_depth',0);self._factory_depth=depth+1
        try:
            try:return super()._factory(*args,**kwargs)
            except UnverifiedFactoryCall:return unknown('factory_has_unverified_subcall')
        finally:self._factory_depth=depth

    def _expr(self,path,node,seen,local):
        result=super()._expr(path,node,seen,local)
        if isinstance(node,ast.Call) and getattr(self,'_factory_depth',0)>0 and result.kind=='unknown':
            raise UnverifiedFactoryCall('factory_subcall_not_proven_pure')
        return result


class SourceBindings(StrictFactoryCalls,BindingsV2):
    """Shared structural/deferred binder with strict factory subcalls."""


class RuntimeSourceBindings(StrictFactoryCalls,BindingsV1):
    """The same strict rule for the closed runtime enrollment vocabulary."""
