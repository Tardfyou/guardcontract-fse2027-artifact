"""Interpret named source closures with explicit boundary and SDK capabilities."""
import ast
from copy import deepcopy
import hashlib
import inspect
from guardcontract.analysis.scenario_interpreter_v4 import Interpreter,Object,Message,Capability,Unresolved,data,plain,source_str,source_print,captured_dispatch_profile
from guardcontract.analysis.sdk_arguments_v2 import normalize,literal_defaults
from guardcontract.runtime.closure_namespace_v1 import namespaces


class ClosureInterpreter(Interpreter):
    def __init__(self,closure):
        super().__init__({});self.closure=closure;self.environments={};self.stack=[];self.site=None
        self.defaults={key:literal_defaults(node) for key,node in closure.functions.items()}
    def expr(self,node,env):
        old=self.site
        if isinstance(node,ast.Call) and self.stack:
            self.site={'path':self.stack[-1][0],'line':node.lineno,'column':node.col_offset,'end_column':node.end_col_offset}
        try:return super().expr(node,env)
        finally:self.site=old
    def invoke(self,key,*args,**kwargs):
        if len(self.stack)>=32:raise Unresolved('closure_call_depth')
        node=self.closure.functions[key];params=[]
        for a in node.args.args+node.args.kwonlyargs:
            kind=inspect.Parameter.KEYWORD_ONLY if a in node.args.kwonlyargs else inspect.Parameter.POSITIONAL_OR_KEYWORD
            params.append(inspect.Parameter(a.arg,kind,default=self.defaults[key].get(a.arg,inspect.Parameter.empty)))
        bound=inspect.Signature(params).bind(*args,**kwargs);bound.apply_defaults()
        previous=self.namespace;self.namespace=self.environments[key];self.stack.append(key)
        try:return self.function(node,dict(bound.arguments))
        finally:self.stack.pop();self.namespace=previous


def selected_site(site,effect,kind):
    return kind==effect['kind'] and all(site.get(k)==effect[k] for k in ('path','line','column','end_column') if k in effect)


def predict(closure,item):
    traces=[]
    if len(item['cases'])!=2 or {c['expected_verdict'] for c in item['cases']}!={'ALLOW','DENY'}:
        return {'prediction':'unknown','status':'unsupported','reason':'paired_case_inventory','traces':[]}
    for case in item['cases']:
        role=case['expected_verdict'];iid=hashlib.sha256((item['sample_id']+':'+role).encode()).hexdigest()[:24]
        if case.get('invocation_id')!=iid:raise ValueError('closure_invocation_identity')
        interp=ClosureInterpreter(closure);events=[];normalizations=[];phase='guard'
        def effect(kind,*args,**kwargs):
            match=selected_site(interp.site,closure.effect,kind)
            if match and phase!='tool':raise Unresolved('selected_effect_outside_selected_tool_phase')
            events.append({'site':deepcopy(interp.site),'kind':kind,'selected':match,'phase':phase,'args':data(args),'kwargs':data(kwargs)})
        def http(kind,*args,**kwargs):
            effect(kind,*args,**kwargs)
            return Object({'status_code':200,'json':Capability(lambda:data(item.get('http_response',{})))})
        def path(value):
            if type(value) is not str:raise Unresolved('file_path_argument')
            def write(content,encoding=None,errors=None,newline=None):
                if type(content) is not str or encoding not in (None,'utf-8') or errors is not None or newline is not None:
                    raise Unresolved('file_write_argument_profile')
                effect('file_write',value,content,encoding=encoding)
                return len(content)
            return Object({'write_text':Capability(write)})
        get,post=Capability(lambda *a,**k:http('http_get',*a,**k)),Capability(lambda *a,**k:http('http_post',*a,**k))
        getenv=Capability(lambda k:item.get('environment',{}).get(k));pathcap=Capability(path)
        def make_message(content,tool_call_id):
            from langchain_core.messages import ToolMessage
            value=ToolMessage(content=content,tool_call_id=tool_call_id)
            return Message(value.content,value.tool_call_id,'guard_constructor' if phase=='guard' else 'tool_constructor')
        msg=Capability(make_message)
        ext={'requests':Object({'get':get,'post':post}),'requests.get':get,'requests.post':post,
            'os':Object({'getenv':getenv}),'os.getenv':getenv,'pathlib':Object({'Path':pathcap}),'pathlib.Path':pathcap,
            'streamlit':Object({'session_state':data(case.get('state',{}))}),'langchain_core.messages.ToolMessage':msg,
            'langchain_core.messages':Object({'ToolMessage':msg}),'langchain_core':Object({'messages':Object({'ToolMessage':msg})})}
        builtins={'str':Capability(source_str),'print':Capability(source_print),'input':Capability(lambda prompt:case.get('input_text',''))}
        try:
            interp.environments=namespaces(closure,ext,lambda key:Capability(lambda *a,**k:interp.invoke(key,*a,**k)),Object,builtins)
            request=Object({'tool_call':{'name':closure.tool[1],'args':data(item['tool_arguments']),'id':iid}})
            def delegate(req):
                nonlocal phase
                if req is not request or req.fields['tool_call']['id']!=iid:raise Unresolved('closure_request_or_invocation_changed')
                call=req.fields['tool_call'];dispatch=captured_dispatch_profile()
                if type(call['name']) is not str or not call['name']:raise Unresolved('closure_tool_name_shape')
                args,receipt=normalize(closure.functions[closure.tool],call['args'],default_state=interp.defaults[closure.tool])
                receipt['dispatch_profile']=dispatch;normalizations.append(receipt)
                previous=phase;phase='tool'
                try:result=interp.invoke(closure.tool,**args)
                finally:phase=previous
                if isinstance(result,Message):return Message(result.content,result.call_id,'delegate')
                if not plain(result):raise Unresolved('closure_tool_output_profile')
                from langchain_core.tools.base import _format_output
                output=_format_output(result,None,iid,closure.tool[1],'success')
                return Message(output.content,output.tool_call_id,'delegate')
            result=interp.invoke(closure.guard,request,Capability(delegate))
            if not isinstance(result,Message) or result.call_id!=iid:raise Unresolved('closure_guard_result')
            verdict='DENY' if result.origin=='guard_constructor' and result.content in item['denial_messages'] else 'ALLOW' if result.origin=='delegate' else None
            if verdict is None:raise Unresolved('closure_guard_verdict_unknown')
            traces.append({'role':role,'verdict':verdict,'selected_effect_reached':any(e['selected'] for e in events),'events':events,'argument_normalizations':normalizations})
        except (ValueError,KeyError,TypeError,IndexError,RecursionError) as exc:
            return {'prediction':'unknown','status':'unsupported','reason':str(exc),'traces':traces}
    if any(t['role']!=t['verdict'] for t in traces) or not next(t for t in traces if t['role']=='ALLOW')['selected_effect_reached']:
        value,reason='unknown','paired_verdict_or_allow_effect_not_derived'
    elif next(t for t in traces if t['role']=='DENY')['selected_effect_reached']:value,reason='present','closed_source_joint_path'
    else:value,reason='absent','closed_source_deny_excludes_selected_effect'
    return {'prediction':value,'status':'completed','reason':reason,'traces':traces,'program_wide_proof':False,'source_bodies_executed':False}
