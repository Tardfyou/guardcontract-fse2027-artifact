"""Registration discovery with conservative same-class self-attribute binding."""
import ast
from collections import defaultdict
from guardcontract.discovery import registration as base

class RegistrationIndexV2(base.RegistrationIndex):
    def __init__(self,tree,path,**kwargs):
        super().__init__(tree,path,**kwargs);self.class_attributes=defaultdict(lambda:defaultdict(list))
        self.receiver_aliases = {}
        used_names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        for cls in (n for n in ast.walk(tree) if isinstance(n,ast.ClassDef) and id(n) in self.definitions):
            class_scope=self.definitions[id(cls)][1]
            for method in (n for n in cls.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))):
                for node in base.immediate_nodes(method.body):
                    if isinstance(node,(ast.Assign,ast.AnnAssign,ast.AugAssign,ast.Delete)):
                        targets=node.targets if isinstance(node,(ast.Assign,ast.Delete)) else [node.target]
                        for target in targets:
                            if isinstance(target,ast.Attribute) and isinstance(target.value,ast.Name) and target.value.id=="self":
                                # Only direct initializer assignments establish a candidate receiver.
                                certain = (method.name == "__init__" and not method.decorator_list
                                           and node in method.body and isinstance(node, (ast.Assign, ast.AnnAssign)))
                                value = (node.value, self.definitions[id(method)][1]) if certain else None
                                self.class_attributes[class_scope][target.attr].append(value)
        for scope,(nodes,bindings) in self.scopes.items():
            for node in nodes:
                if not isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):continue
                for decorator in node.decorator_list:
                    target=decorator.func if isinstance(decorator,ast.Call) else decorator
                    receiver=target.value if isinstance(target,ast.Attribute) else None
                    if not isinstance(receiver,ast.Attribute) or not isinstance(receiver.value,ast.Name) or receiver.value.id!="self":continue
                    class_scope=self._class_scope(scope);values=self.class_attributes.get(class_scope,{}).get(receiver.attr,[])
                    if len(values)==1 and values[0] is not None:
                        alias = next((name for (owner, name), value in self.receiver_aliases.items()
                                      if owner == scope and value == values[0]), None)
                        if alias is None:
                            alias="__guardcontract_self_"+receiver.attr
                            while alias in used_names:
                                alias += "_"
                            used_names.add(alias)
                            self.receiver_aliases[(scope, alias)] = values[0]
                        target.value=ast.copy_location(ast.Name(id=alias,ctx=ast.Load()),receiver)
                    else:self.unresolved.append({"path":self.path,"line":target.lineno,"reason":"class_attribute_receiver_ambiguous"})
    def _class_scope(self,scope):
        current=scope
        while current is not None:
            if current in self.class_attributes:return current
            current=self.parent.get(current)
        return None
    def scoped(self,expression,scope,seen=()):
        if isinstance(expression, ast.Name) and (scope, expression.id) in self.receiver_aliases:
            value, origin_scope = self.receiver_aliases[(scope, expression.id)]
            return super().scoped(value, origin_scope, seen)
        if isinstance(expression,ast.Attribute) and isinstance(expression.value,ast.Name) and expression.value.id=="self":
            class_scope=self._class_scope(scope);values=self.class_attributes.get(class_scope,{}).get(expression.attr,[])
            if len(values)==1 and values[0] is not None:
                key=(class_scope,"self."+expression.attr)
                value, origin_scope = values[0]
                if key not in seen:return self.scoped(value,origin_scope,(*seen,key))
            return None,class_scope
        return super().scoped(expression,scope,seen)

def discover_registrations(root,**kwargs):
    return base.discover_registrations(root, index_class=RegistrationIndexV2, **kwargs)
