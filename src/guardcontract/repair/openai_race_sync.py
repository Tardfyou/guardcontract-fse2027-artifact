"""Synchronize an OpenAI Agents parallel input guard with its protected tool."""
import ast,hashlib

from guardcontract.analysis.openai_paths_v2 import analyze
from guardcontract.analysis.langchain_paths import dotted,function,unique

def sha(source):return hashlib.sha256(source.encode()).hexdigest()
def indent(line):return line[:len(line)-len(line.lstrip())]


def propose_input_short_circuit(source, certificate, sdk_contract):
    """Candidate for the owned immutable-string-verdict control, pending runtime checks."""
    if (certificate.get("source_sha256") != sha(source)
            or certificate.get("status") != "supported"
            or certificate.get("sdk_contract_sha256") != sdk_contract.get("contract_sha256")
            or certificate.get("mode") != "parallel_input_race"
            or certificate.get("issue_prediction") is not True):
        raise ValueError("input_gate_requires_race_certificate")
    recomputed = analyze(source, sdk_contract, repository_id="input-gate@" + sha(source))
    if recomputed.get("status") != "supported" or recomputed.get("mode") != "parallel_input_race":
        raise ValueError("input_gate_source_revalidation_failed")
    tree = ast.parse(source)
    run = function(tree, "run_cell")
    decide = function(run, "decide")
    tool = function(run, "write_canary")
    guard = function(run, "parallel_guard")
    if (sum(a.arg == "verdict" for a in ast.walk(run) if isinstance(a, ast.arg)) != 1
            or any(isinstance(n, ast.Name) and n.id == "verdict" and not isinstance(n.ctx, ast.Load)
                   for n in ast.walk(run))
            or len(decide.body) != 2 or not isinstance(decide.body[-1], ast.Return)
            or dotted(decide.body[-1].value) != "verdict"):
        raise ValueError("input_gate_verdict_not_immutable_input")
    ret = guard.body[-1]
    if not isinstance(ret, ast.Return) or not isinstance(ret.value, ast.Call):
        raise ValueError("input_gate_guard_shape")
    tripwire = next((k.value for k in ret.value.keywords if k.arg == "tripwire_triggered"), None)
    if tripwire is None or ast.dump(tripwire) != ast.dump(ast.parse("verdict == 'DENY'", mode="eval").body):
        raise ValueError("input_gate_output_dependent_policy")
    if not isinstance(tool, ast.FunctionDef) or len(tool.body) != 4:
        raise ValueError("input_gate_tool_shape")
    lines = source.splitlines(keepends=True)
    position = tool.body[1].lineno - 1
    prefix = indent(lines[position])
    lines[position:position] = [prefix + "if verdict == 'DENY':\n", prefix + "    return 'ok'\n"]
    patched = "".join(lines)
    ast.parse(patched)
    return {"strategy": "immutable_input_deny_short_circuit", "original_sha256": sha(source),
            "patched_sha256": sha(patched), "patched_source": patched, "generated_patch": True,
            "runtime_verified": False, "static_postcondition_verified": False,
            "scope": "owned_control_string_ALLOW_DENY_input_only",
            "proof_obligations": ["paired SDK execution across declared schedules", "DENY verdict observed",
                                  "DENY zero protected effect", "complete ALLOW observation preserved"]}

def propose(source,certificate,sdk_contract):
    if certificate.get("status")!="supported" or certificate.get("mode")!="parallel_input_race" or certificate.get("issue_prediction") is not True or certificate.get("source_sha256")!=sha(source) or certificate.get("sdk_contract_sha256")!=sdk_contract.get("contract_sha256"):raise ValueError("openai_repair_requires_verified_race")
    tree=ast.parse(source);run=function(tree,"run_cell");decide=function(run,"decide");tool=function(run,"write_canary");guard=function(run,"parallel_guard")
    events=unique((r for r in run.body if isinstance(r,ast.AnnAssign) and isinstance(r.target,ast.Name) and r.target.id=="events"),"openai_repair_events")
    if not isinstance(tool,ast.FunctionDef) or not isinstance(guard,ast.AsyncFunctionDef) or len(decide.body)!=2 or len(tool.body)!=4 or len(guard.body)!=3:raise ValueError("openai_repair_source_shape")
    sink=unique((r for r in tool.body if isinstance(r,ast.Expr) and isinstance(r.value,ast.Call) and dotted(r.value.func)=="marker.write_text"),"openai_repair_sink")
    effect=unique((r for r in tool.body if isinstance(r,ast.Expr) and isinstance(r.value,ast.Call) and dotted(r.value.func)=="events.append"),"openai_repair_effect")
    ret=unique((r for r in guard.body if isinstance(r,ast.Return)),"openai_repair_guard_return")
    lines=source.splitlines(keepends=True);ri=indent(lines[events.lineno-1]);di=indent(lines[decide.body[0].lineno-1]);ti=indent(lines[tool.body[1].lineno-1]);gi=indent(lines[ret.lineno-1])
    decision_body=[di+"nonlocal resolved_verdict\n",di+"resolved_verdict = verdict\n",di+"decision_ready.set()\n",di+"if record_event:\n",di+"    events.append({'kind': 'guard_verdict', 'verdict': verdict})\n",di+"return verdict\n"]
    tool_body=[ti+"await decision_ready.wait()\n",ti+"if resolved_verdict == 'DENY':\n",ti+"    await asyncio.Future()\n",lines[effect.lineno-1],lines[sink.lineno-1],ti+"events.append({'kind': 'guard_verdict', 'verdict': resolved_verdict})\n",lines[tool.body[-1].lineno-1]]
    guard_body=[gi+"decision = decide(record_event=verdict == 'DENY')\n",gi+"return GuardrailFunctionOutput(output_info={'verdict': decision}, tripwire_triggered=verdict == 'DENY')\n"]
    edits=[(events.end_lineno+1,events.end_lineno,[ri+"decision_ready = asyncio.Event()\n",ri+"resolved_verdict: str | None = None\n"]),
        (decide.lineno,decide.lineno,[lines[decide.lineno-1].replace("()", "(record_event: bool = True)",1)]),
        (decide.body[0].lineno,decide.body[-1].end_lineno,decision_body),(tool.lineno,tool.lineno,[lines[tool.lineno-1].replace("def write_canary", "async def write_canary",1)]),
        (tool.body[1].lineno,tool.body[-1].end_lineno,tool_body),(ret.lineno,ret.end_lineno,guard_body)]
    for start,end,replacement in sorted(edits,reverse=True):lines=[*lines[:start-1],*replacement,*lines[end:]]
    patched="".join(lines);ast.parse(patched)
    post=analyze(patched,sdk_contract,repository_id="openai-repair@"+sha(patched))
    if post.get("status")!="supported" or post.get("mode")!="synchronized_parallel_guard" or post.get("issue_prediction") is not False:raise ValueError("openai_repair_static_postcondition")
    return {"schema_version":"openai-parallel-race-sync-repair-1","strategy":"synchronize_parallel_guard_before_effect",
        "original_sha256":sha(source),"patched_sha256":sha(patched),"patched_source":patched,"generated_patch":True,"runtime_verified":False,
        "static_postcondition":post,
        "allow_schedule_preservation":"unverified_known_zero_delay_counterexample",
        "limitations":["ALLOW guard logging is moved after the tool effect; original schedules with earlier guard logging are not preserved"],
        "proof_obligations":["DENY cancels waiting tool before selected write","ALLOW complete return object equals original across declared schedules","one guard decision per path"]}
