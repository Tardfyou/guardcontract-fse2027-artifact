"""Defer a CrewAI tool effect until its task guard allows the output."""
import ast,hashlib
from guardcontract.analysis.langchain_paths import dotted,function,unique
def sha(source):return hashlib.sha256(source.encode()).hexdigest()
def indent(line):return line[:len(line)-len(line.lstrip())]
def verify_patched(source,sdk_contract):
    tree=ast.parse(source);run=function(tree,"run_cell");tool=function(run,"write_canary");guard=function(run,"task_guardrail")
    writes=[c for c in ast.walk(tree) if isinstance(c,ast.Call) and dotted(c.func)=="marker.write_text"];pending=[r for r in run.body if isinstance(r,ast.AnnAssign) and isinstance(r.target,ast.Name) and r.target.id=="pending_effect"]
    allow=[r for r in guard.body if isinstance(r,ast.If) and isinstance(r.test,ast.Compare) and isinstance(r.test.left,ast.Name) and r.test.left.id=="verdict" and isinstance(r.test.comparators[0],ast.Constant) and r.test.comparators[0].value=="ALLOW"]
    tool_sets=[r for r in tool.body if isinstance(r,ast.Nonlocal) or isinstance(r,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="pending_effect" for t in r.targets)]
    if sdk_contract.get("schema_version")!="crewai-sdk-contract-1" or len(writes)!=len(pending)!=len(allow)!=1 or len(tool_sets)!=2 or not any(c is writes[0] for c in ast.walk(allow[0])):raise ValueError("crewai_repair_static_shape")
    guard_records=[c for c in calls_in_order(guard,"events.append")];sink_line=writes[0].lineno
    if len(guard_records)!=2 or not sink_line<guard_records[-1].lineno:raise ValueError("crewai_repair_allow_log_order")
    return {"status":"supported","mode":"task_output_deferred_commit","issue_prediction":False,"sink_line":sink_line,"deny_effect_occurs":False,"allow_effect_occurs":True}
def calls_in_order(node,name):return sorted((r for r in ast.walk(node) if isinstance(r,ast.Call) and dotted(r.func)==name),key=lambda r:r.lineno)
def propose(source,certificate,sdk_contract):
    if certificate.get("status")!="supported" or certificate.get("mode")!="task_output_post_effect" or certificate.get("issue_prediction") is not True or certificate.get("source_sha256")!=sha(source) or certificate.get("sdk_contract_sha256")!=sdk_contract.get("contract_sha256"):raise ValueError("crewai_repair_requires_verified_issue")
    tree=ast.parse(source);run=function(tree,"run_cell");tool=function(run,"write_canary");guard=function(run,"task_guardrail")
    events=unique((r for r in run.body if isinstance(r,ast.AnnAssign) and isinstance(r.target,ast.Name) and r.target.id=="events"),"crewai_repair_events");sink=unique((r for r in tool.body if isinstance(r,ast.Expr) and isinstance(r.value,ast.Call) and dotted(r.value.func)=="marker.write_text"),"crewai_repair_sink");effect=unique((r for r in tool.body if isinstance(r,ast.Expr) and isinstance(r.value,ast.Call) and dotted(r.value.func)=="events.append"),"crewai_repair_effect")
    if len(tool.body)!=4 or len(guard.body)!=3:raise ValueError("crewai_repair_source_shape")
    lines=source.splitlines(keepends=True);ri=indent(lines[events.lineno-1]);ti=indent(lines[effect.lineno-1]);gi=indent(lines[guard.body[1].lineno-1])
    tool_body=[ti+"nonlocal pending_effect\n",ti+"pending_effect = True\n",lines[tool.body[-1].lineno-1]]
    guard_body=[lines[guard.body[0].lineno-1],gi+"if verdict == 'ALLOW':\n",gi+"    if not pending_effect:\n",gi+"        raise RuntimeError('expected one pending effect')\n",gi+"    "+lines[effect.lineno-1].lstrip(),gi+"    "+lines[sink.lineno-1].lstrip(),lines[guard.body[1].lineno-1],lines[guard.body[2].lineno-1]]
    edits=[(events.end_lineno+1,events.end_lineno,[ri+"pending_effect = False\n"]),(tool.body[1].lineno,tool.body[-1].end_lineno,tool_body),(guard.body[0].lineno,guard.body[-1].end_lineno,guard_body)]
    for start,end,replacement in sorted(edits,reverse=True):lines=[*lines[:start-1],*replacement,*lines[end:]]
    patched="".join(lines);ast.parse(patched);post=verify_patched(patched,sdk_contract)
    return {"schema_version":"crewai-task-deferral-repair-1","strategy":"defer_tool_write_until_task_guard_allow_preserving_allow_event_order","original_sha256":sha(source),"patched_sha256":sha(patched),"patched_source":patched,"static_postcondition":post,"generated_patch":True,"runtime_verified":False}
