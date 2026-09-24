"""Deferral repair preserving Pydantic AI ALLOW observations."""
import ast,hashlib
from guardcontract.analysis.langchain_paths import dotted,function
from guardcontract.analysis.pydantic_paths import analyze

def sha(source):return hashlib.sha256(source.encode()).hexdigest()
def indent(line):return line[:len(line)-len(line.lstrip())]

def propose(source,helper_source,certificate,sdk_contract):
    if certificate.get("status")!="supported" or certificate.get("mode")!="direct_write" or certificate.get("issue_prediction") is not True or certificate.get("source_sha256")!=sha(source):raise ValueError("pydantic_repair_requires_verified_issue")
    tree=ast.parse(source);run=function(tree,"run_cell")
    tool=next(r for r in run.body if isinstance(r,ast.FunctionDef) and any(isinstance(d,ast.Attribute) and dotted(d)=="agent.tool_plain" for d in r.decorator_list))
    guard=next(r for r in run.body if isinstance(r,ast.FunctionDef) and any(isinstance(d,ast.Attribute) and dotted(d)=="agent.output_validator" for d in r.decorator_list))
    ledger=[r for r in run.body if isinstance(r,ast.Assign) and len(r.targets)==1 and isinstance(r.targets[0],ast.Name) and r.targets[0].id=="ledger"]
    sink=[r for r in tool.body if isinstance(r,ast.Expr) and isinstance(r.value,ast.Call) and dotted(r.value.func)=="marker.write_text"]
    protected=[r for r in tool.body if isinstance(r,ast.Expr) and isinstance(r.value,ast.Call) and dotted(r.value.func)=="record" and r.value.args and isinstance(r.value.args[0],ast.Constant) and r.value.args[0].value=="protected_effect"]
    if len(ledger)!=len(sink)!=len(protected) or len(ledger)!=1 or protected[0].lineno!=sink[0].end_lineno+1:raise ValueError("pydantic_repair_tool_shape")
    record_guard=guard.body[0];deny=guard.body[1];ret=guard.body[2]
    if not (isinstance(record_guard,ast.Expr) and dotted(record_guard.value.func)=="record" and isinstance(deny,ast.If) and isinstance(ret,ast.Return)):raise ValueError("pydantic_repair_guard_shape")
    lines=source.splitlines(keepends=True);li=indent(lines[ledger[0].lineno-1]);ti=indent(lines[tool.body[0].lineno-1]);gi=indent(lines[record_guard.lineno-1])
    edits=[(ledger[0].end_lineno+1,ledger[0].end_lineno,[li+"staged_payload: str | None = None\n"]),
        (tool.body[0].lineno,tool.body[0].lineno-1,[ti+"nonlocal staged_payload\n"]),
        (sink[0].lineno,protected[0].end_lineno,[ti+"ledger.stage_text_write(marker, payload, encoding='utf-8')\n",ti+"staged_payload = payload\n"]),
        (record_guard.lineno,ret.end_lineno,[gi+"if verdict == 'ALLOW':\n",gi+"    if ledger.commit() != 1:\n",gi+"        raise RuntimeError('expected exactly one committed effect')\n",
            gi+"    record('protected_effect', effect=EFFECT_ID, tool=TOOL_NAME, payload=staged_payload)\n",gi+"else:\n",gi+"    ledger.abort()\n",
            gi+"record('guard_verdict', guard='final_output_guard', verdict=verdict, decision_inputs=['final_output'], output=output)\n",
            gi+"if verdict == 'DENY':\n",gi+"    raise ModelRetry('GuardContract deterministic DENY')\n",gi+"return output\n"])]
    for start,end,replacement in sorted(edits,reverse=True):
        lines=[*lines[:start-1],*replacement,*lines[(start-1 if end<start else end):]]
    patched="".join(lines);ast.parse(patched)
    post=analyze(patched,helper_source,sdk_contract,repository_id="pydantic-repair@"+sha(patched),helper_path=certificate.get("helper_path","deferred_effects.py"))
    if post.get("status")!="supported" or post.get("issue_prediction") is not False:raise ValueError("pydantic_repair_static_validation")
    return {"schema_version":"pydantic-deferral-repair-1","strategy":"defer_tool_write_until_output_allow","original_sha256":sha(source),"patched_sha256":sha(patched),
        "patched_source":patched,"static_postcondition":post,"generated_patch":True,"runtime_verified":False}
