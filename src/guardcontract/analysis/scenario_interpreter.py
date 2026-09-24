"""Closed, non-executing interpreter for a registered synchronous slice scenario.

Values come from JSON and internal capabilities only. No Python eval/exec,
repository imports, attribute getters, user magic methods, or real I/O execute.
Unsupported syntax stays unknown. Results are scoped predictions, never labels.
"""
import ast
from dataclasses import dataclass
import hashlib
import json


class Unresolved(ValueError):
    pass


class Returned(Exception):
    def __init__(self,value): self.value=value


@dataclass
class Object:
    fields: dict


@dataclass
class Capability:
    function: object


@dataclass
class Message:
    content: str
    call_id: str
    origin: str


def data(value):
    return json.loads(json.dumps(value,allow_nan=False))


class Interpreter:
    def __init__(self, namespace):
        self.namespace=namespace
        self.steps=0

    def expr(self,n,env):
        self.steps+=1
        if self.steps>10000: raise Unresolved('expression_budget')
        if n is None:return None
        if isinstance(n,ast.Constant):
            if type(n.value) not in (str,int,float,bool,type(None)):raise Unresolved('literal_type')
            return n.value
        if isinstance(n,ast.Name):
            if n.id in env:return env[n.id]
            if n.id in self.namespace:return self.namespace[n.id]
            raise Unresolved('name:'+n.id)
        if isinstance(n,ast.Dict):
            if any(k is None for k in n.keys):raise Unresolved('dict_unpack')
            return {self.expr(k,env):self.expr(v,env) for k,v in zip(n.keys,n.values)}
        if isinstance(n,(ast.List,ast.Tuple)):
            return [self.expr(e,env) for e in n.elts]
        if isinstance(n,ast.Attribute):
            value=self.expr(n.value,env)
            if isinstance(value,Object) and n.attr in value.fields:return value.fields[n.attr]
            if type(value) is dict and n.attr=='get':return Capability(value.get)
            if type(value) is str and n.attr=='lower':return Capability(value.lower)
            raise Unresolved('attribute:'+n.attr)
        if isinstance(n,ast.Subscript):
            value,key=self.expr(n.value,env),self.expr(n.slice,env)
            if type(value) not in (dict,list,str):raise Unresolved('subscript_object')
            return value[key]
        if isinstance(n,ast.Call):
            fn=self.expr(n.func,env)
            if not isinstance(fn,Capability):raise Unresolved('unregistered_callable')
            if any(isinstance(a,ast.Starred) for a in n.args) or any(k.arg is None for k in n.keywords):
                raise Unresolved('argument_unpack')
            return fn.function(*[self.expr(a,env) for a in n.args],
                               **{k.arg:self.expr(k.value,env) for k in n.keywords})
        if isinstance(n,ast.UnaryOp) and isinstance(n.op,ast.Not):
            return not self.truth(self.expr(n.operand,env))
        if isinstance(n,ast.Compare):
            if len(n.ops)!=1:raise Unresolved('chained_comparison')
            left,right=self.expr(n.left,env),self.expr(n.comparators[0],env)
            if type(left) not in (str,int,float,bool,type(None)) or type(right) not in (str,int,float,bool,type(None)):
                raise Unresolved('comparison_object')
            if isinstance(n.ops[0],ast.Eq):return left==right
            if isinstance(n.ops[0],ast.NotEq):return left!=right
            raise Unresolved('comparison_operator')
        if isinstance(n,ast.JoinedStr):
            values=[]
            for part in n.values:
                if isinstance(part,ast.Constant):values.append(part.value)
                elif isinstance(part,ast.FormattedValue) and part.format_spec is None and part.conversion==-1:
                    value=self.expr(part.value,env)
                    if type(value) not in (str,int,float,bool,type(None)):raise Unresolved('format_object')
                    values.append(str(value))
                else:raise Unresolved('format_specification')
            return ''.join(values)
        raise Unresolved('expression:'+type(n).__name__)

    def truth(self,value):
        if type(value) not in (str,int,float,bool,dict,list,type(None)):raise Unresolved('truth_object')
        return bool(value)

    def block(self,body,env):
        for n in body:
            if isinstance(n,ast.Return):raise Returned(self.expr(n.value,env))
            if isinstance(n,ast.Expr):self.expr(n.value,env)
            elif isinstance(n,ast.If):self.block(n.body if self.truth(self.expr(n.test,env)) else n.orelse,env)
            elif isinstance(n,ast.Assign):
                value=self.expr(n.value,env)
                for target in n.targets:
                    if isinstance(target,ast.Name):env[target.id]=value
                    elif isinstance(target,ast.Subscript):
                        obj,key=self.expr(target.value,env),self.expr(target.slice,env)
                        if type(obj) is not dict:raise Unresolved('assignment_object')
                        obj[key]=value
                    else:raise Unresolved('assignment_target')
            elif isinstance(n,ast.Try):
                # Supported calls have deterministic success semantics. Analysis
                # uncertainty must not be swallowed by repository except blocks.
                if n.finalbody:raise Unresolved('finally_control')
                self.block(n.body,env)
                self.block(n.orelse,env)
            elif isinstance(n,ast.Pass):pass
            elif not isinstance(n,(ast.Return,ast.Expr,ast.If,ast.Assign)):
                raise Unresolved('statement:'+type(n).__name__)

    def function(self,node,arguments):
        if not isinstance(node,ast.FunctionDef) or node.args.vararg or node.args.kwarg or node.args.kwonlyargs:
            raise Unresolved('function_shape')
        names=[a.arg for a in node.args.posonlyargs+node.args.args]
        if set(names)!=set(arguments):raise Unresolved('function_arguments')
        try:self.block(node.body,dict(arguments))
        except Returned as result:return result.value
        return None


def predict(guard,tool,item):
    if len(item['cases'])!=2 or {c.get('expected_verdict') for c in item['cases']}!={'ALLOW','DENY'}:
        return {'prediction':'unknown','reason':'paired_case_inventory','traces':[],'behavior_label':None}
    traces=[]
    for case in item['cases']:
        events=[]
        phase='guard'
        call_id=case.get('invocation_id')
        expected_id=hashlib.sha256((item['sample_id']+':'+case['expected_verdict']).encode()).hexdigest()[:24]
        if call_id!=expected_id:
            return {'prediction':'unknown','reason':'invocation_identity_not_frozen','traces':traces,'behavior_label':None}
        response=data(item['http_response'])

        def http_get(*args,**kwargs):
            if phase!='tool':raise Unresolved('effect_outside_bound_tool')
            events.append('effect')
            return Object({'status_code':200,'json':Capability(lambda:response)})

        namespace={'str':Capability(str),'print':Capability(lambda *a,**k:None),
                   'input':Capability(lambda prompt:case.get('input_text','')),
                   'os':Object({'getenv':Capability(lambda k:item['environment'].get(k))}),
                   'st':Object({'session_state':data(case.get('state',{}))}),
                   'requests':Object({'get':Capability(http_get)}),
                   'ToolMessage':Capability(lambda content,tool_call_id:Message(content,tool_call_id,'guard_constructor'))}
        interp=Interpreter(namespace)
        def delegate(request):
            nonlocal phase
            call=request.fields['tool_call'] if isinstance(request,Object) else request['tool_call']
            previous=phase;phase='tool'
            try:value=interp.function(tool,data(call['args']))
            finally:phase=previous
            return Message(str(value),call['id'],'delegate')
        arguments=[a.arg for a in guard.args.posonlyargs+guard.args.args]
        try:
            if len(arguments)!=2:raise Unresolved('callback_arity')
            request=Object({'tool_call':{'name':tool.name,'args':data(item['tool_arguments']),'id':call_id}})
            value=interp.function(guard,{arguments[0]:request,arguments[1]:Capability(delegate)})
            if not isinstance(value,Message) or value.call_id!=call_id:raise Unresolved('callback_result')
            verdict=('DENY' if value.origin=='guard_constructor' and value.content in item['denial_messages']
                     else 'ALLOW' if value.origin=='delegate' else None)
            if verdict is None:raise Unresolved('undeclared_guard_message')
            traces.append({'stimulus_role':case['expected_verdict'],'derived_verdict':verdict,
                           'effect_reached':bool(events),'message_origin':value.origin})
        except (Unresolved,KeyError,TypeError,IndexError,ValueError) as exc:
            return {'prediction':'unknown','reason':str(exc),'traces':traces,
                    'behavior_label':None,'analysis':'closed_source_interpretation'}
    if len(traces)!=2 or any(t['derived_verdict']!=t['stimulus_role'] for t in traces):
        result,reason='unknown','paired_verdict_not_derived'
    elif not any(t['derived_verdict']=='ALLOW' and t['effect_reached'] for t in traces):
        result,reason='unknown','allow_effect_not_derived'
    elif any(t['derived_verdict']=='DENY' and t['effect_reached'] for t in traces):
        result,reason='present','closed_scenario_deny_and_effect_derived'
    else:result,reason='absent','closed_scenario_deny_skips_effect_derived'
    return {'prediction':result,'reason':reason,'traces':traces,'behavior_label':None,
            'analysis':'closed_source_interpretation','program_wide_proof':False}
