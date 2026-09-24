"""Closed, non-executing interpreter for a registered synchronous slice scenario.

Values come from JSON and internal capabilities only. No Python eval/exec,
repository imports, attribute getters, user magic methods, or real I/O execute.
Unsupported syntax stays unknown. Results are scoped predictions, never labels.
"""
import ast
from dataclasses import dataclass
import hashlib
import json
import symtable
import importlib.util
from pathlib import Path
from guardcontract.analysis.sdk_arguments_v2 import normalize, literal_defaults


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


def plain(value,seen=frozenset()):
    if id(value) in seen:return False
    seen=seen|{id(value)}
    if type(value) in (str,int,float,bool,type(None)):return True
    if type(value) in (list,tuple):return all(plain(v,seen) for v in value)
    if type(value) is dict:return all(plain(k,seen) and plain(v,seen) for k,v in value.items())
    return False


def source_str(*args,**kwargs):
    if kwargs or len(args)>1 or any(not plain(v) for v in args):raise Unresolved('str_argument_profile')
    return str(*args)


def source_print(*args,**kwargs):
    if any(not plain(v) for v in args) or set(kwargs)-{'sep','end','file','flush'}:raise Unresolved('print_argument_profile')
    if any(kwargs.get(k) is not None and type(kwargs[k]) is not str for k in ('sep','end')):raise Unresolved('invalid_print_separator')
    if kwargs.get('file') is not None or not plain(kwargs.get('flush',False)):raise Unresolved('print_output_profile')
    return None


class Interpreter:
    def __init__(self, namespace):
        self.namespace=namespace
        self.steps=0
        self.local_frames=[]

    def expr(self,n,env):
        self.steps+=1
        if self.steps>10000: raise Unresolved('expression_budget')
        if n is None:return None
        if isinstance(n,ast.Constant):
            if type(n.value) not in (str,int,float,bool,type(None)):raise Unresolved('literal_type')
            return n.value
        if isinstance(n,ast.Name):
            if n.id in env:return env[n.id]
            if self.local_frames and n.id in self.local_frames[-1]:raise Unresolved("unbound_local:"+n.id)
            if n.id in self.namespace:return self.namespace[n.id]
            raise Unresolved('name:'+n.id)
        if isinstance(n,ast.Dict):
            if any(k is None for k in n.keys):raise Unresolved('dict_unpack')
            return {self.expr(k,env):self.expr(v,env) for k,v in zip(n.keys,n.values)}
        if isinstance(n,ast.Tuple):
            return tuple(self.expr(e,env) for e in n.elts)
        if isinstance(n,ast.List):
            return [self.expr(e,env) for e in n.elts]
        if isinstance(n,ast.Attribute):
            value=self.expr(n.value,env)
            if isinstance(value,Object) and n.attr in value.fields:return value.fields[n.attr]
            if type(value) is dict and n.attr=='get':return Capability(value.get)
            if type(value) is str and n.attr=='lower':return Capability(value.lower)
            raise Unresolved('attribute:'+n.attr)
        if isinstance(n,ast.Subscript):
            value,key=self.expr(n.value,env),self.expr(n.slice,env)
            if type(value) not in (dict,list,tuple,str):raise Unresolved('subscript_object')
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
        if type(value) not in (str,int,float,bool,dict,list,tuple,type(None)):raise Unresolved('truth_object')
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
        if not isinstance(node,ast.FunctionDef) or node.args.vararg or node.args.kwarg or node.args.posonlyargs:
            raise Unresolved('function_shape')
        names=[a.arg for a in node.args.args+node.args.kwonlyargs]
        if set(names)!=set(arguments):raise Unresolved('function_arguments')
        table=symtable.symtable(ast.unparse(node),"<source-function>","exec").get_children()[0]
        self.local_frames.append({s.get_name() for s in table.get_symbols() if s.is_local()})
        try:
            try:self.block(node.body,dict(arguments))
            except Returned as result:return result.value
            return None
        finally:self.local_frames.pop()


def captured_dispatch_profile():
    path=Path(importlib.util.find_spec('langgraph.prebuilt.tool_node').origin)
    actual=hashlib.sha256(path.read_bytes()).hexdigest()
    if actual!='af6df67779000d219b2e1799401238f3618511658b26316a70a5e432891040d3':raise Unresolved('sdk_captured_dispatch_profile_not_enrolled')
    return {'tool_node_sha256':actual,'target_binding':'ToolCallRequest.tool captured before middleware',
        'injection_profile':'no injected state/store/runtime arguments', 'tool_call_name_is_dispatch_authority':False}


def predict(guard,tool,item):
    if len(item['cases'])!=2 or {c.get('expected_verdict') for c in item['cases']}!={'ALLOW','DENY'}:
        return {'prediction':'unknown','reason':'paired_case_inventory','traces':[],'behavior_label':None}
    traces=[]
    for case in item['cases']:
        events=[]
        normalizations=[]
        default_state=literal_defaults(tool)
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

        namespace={'str':Capability(source_str),'print':Capability(source_print),
                   'input':Capability(lambda prompt:case.get('input_text','')),
                   'os':Object({'getenv':Capability(lambda k:item['environment'].get(k))}),
                   'st':Object({'session_state':data(case.get('state',{}))}),
                   'requests':Object({'get':Capability(http_get)}),
                   'ToolMessage':Capability(lambda content,tool_call_id:Message(content,tool_call_id,'guard_constructor'))}
        interp=Interpreter(namespace)
        def delegate(request):
            nonlocal phase
            if request is not invocation_request:raise Unresolved('delegate_request_object_not_authenticated')
            call=request.fields['tool_call']
            if call['id']!=call_id:raise Unresolved('delegated_invocation_id_changed')
            if type(call['name']) is not str or not call['name']:raise Unresolved('delegated_name_shape')
            dispatch=captured_dispatch_profile()
            effective,receipt=normalize(tool,call['args'],default_state=default_state)
            receipt['dispatch_profile']=dispatch
            receipt['request_tool_name']=call['name']
            receipt['captured_tool_symbol']=tool.name
            normalizations.append(receipt)
            previous=phase;phase='tool'
            try:value=interp.function(tool,effective)
            finally:phase=previous
            return Message(str(value),call['id'],'delegate')
        arguments=[a.arg for a in guard.args.posonlyargs+guard.args.args]
        try:
            if len(arguments)!=2:raise Unresolved('callback_arity')
            invocation_request=Object({'tool_call':{'name':tool.name,'args':data(item['tool_arguments']),'id':call_id}})
            value=interp.function(guard,{arguments[0]:invocation_request,arguments[1]:Capability(delegate)})
            if not isinstance(value,Message) or value.call_id!=call_id:raise Unresolved('callback_result')
            verdict=('DENY' if value.origin=='guard_constructor' and value.content in item['denial_messages']
                     else 'ALLOW' if value.origin=='delegate' else None)
            if verdict is None:raise Unresolved('undeclared_guard_message')
            traces.append({'stimulus_role':case['expected_verdict'],'derived_verdict':verdict,
                           'effect_reached':bool(events),'message_origin':value.origin,'argument_normalizations':normalizations})
        except (Unresolved,KeyError,TypeError,IndexError,ValueError,RecursionError) as exc:
            return {'prediction':'unknown','reason':str(exc),'traces':traces,
                    'behavior_label':None,'analysis':'sdk_identity_preserving_source_interpretation_v4','status':'unsupported'}
    if len(traces)!=2 or any(t['derived_verdict']!=t['stimulus_role'] for t in traces):
        result,reason='unknown','paired_verdict_not_derived'
    elif not any(t['derived_verdict']=='ALLOW' and t['effect_reached'] for t in traces):
        result,reason='unknown','allow_effect_not_derived'
    elif any(t['derived_verdict']=='DENY' and t['effect_reached'] for t in traces):
        result,reason='present','closed_scenario_deny_and_effect_derived'
    else:result,reason='absent','closed_scenario_deny_skips_effect_derived'
    return {'prediction':result,'reason':reason,'traces':traces,'behavior_label':None,
            'analysis':'sdk_identity_preserving_source_interpretation_v4','program_wide_proof':False}
