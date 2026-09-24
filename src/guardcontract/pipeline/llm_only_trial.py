"""Budgeted LLM-only analyst/critic baseline on the four development controls."""
import argparse,ast,hashlib,json,tempfile
from pathlib import Path

from guardcontract.backends.recorded import RecordedTransport
from guardcontract.backends.replay import RecordedReplay,verify_inventory
from guardcontract.discovery.router import stable_node_id
from guardcontract.evidence.adk_sdk_contract import enroll as enroll_adk
from guardcontract.evidence.langchain_sdk_contract import enroll as enroll_langchain
from guardcontract.paths import project_root
from guardcontract.pipeline.review_execution import execute,write_new
from guardcontract.protocols.llm_only_issue import SYSTEM,decode,task

ROOT=project_root();DIRECTORY=ROOT/"experiments/llm-only-ablation-n237"
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_bytes())

def functions(source):
    result=[]
    def visit(node,prefix=""):
        for child in ast.iter_child_nodes(node):
            if isinstance(child,(ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef)):
                symbol=prefix+child.name
                if isinstance(child,(ast.FunctionDef,ast.AsyncFunctionDef)):result.append({"symbol":symbol,"start_line":child.lineno,"end_line":child.end_lineno})
                visit(child,symbol+".")
            else:visit(child,prefix)
    visit(ast.parse(source));return sorted(result,key=lambda r:(r["start_line"],r["symbol"]))

def site_candidates(repository_id,sources):
    rows=[]
    for path,source in sources.items():
        for node in ast.walk(ast.parse(source)):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr=="write_text":
                call=(ast.unparse(node.func) if hasattr(ast,"unparse") else node.func.attr)
                rows.append({"path":path,"line":node.lineno,"call":call,
                    "site_id":stable_node_id(repository_id,"effect",path,node.lineno,call)})
    rows.sort(key=lambda r:(r["path"],r["line"]));return [{"site":f"e{i}",**row} for i,row in enumerate(rows)]

def prepare():
    if DIRECTORY.exists():raise ValueError("llmonly237_existing_plan")
    normative_path=ROOT/"experiments/contract-protocol-n206/NORMATIVE_CONTRACT.json";normative=read(normative_path)
    lang_sdk=enroll_langchain(ROOT/"experiments/langchain-semantics-n197-i2");adk_sdk=enroll_adk(ROOT/"experiments/google-adk-contract-n50-dev")
    definitions=[("s001","langchain","experiments/registration-pipeline-n182/repositories/s001/app.py","experiments/registration-pipeline-n182/repositories/s001/deferred_effects.py",lang_sdk,"run_cell"),
        ("s009","langchain","experiments/registration-pipeline-n182/repositories/s009/app.py","experiments/registration-pipeline-n182/repositories/s009/deferred_effects.py",lang_sdk,"run_cell"),
        ("s005","google-adk","experiments/multiframework-control-n174-i2/source/s005.py","experiments/multiframework-control-n174-i2/source/s005.py",adk_sdk,"run_cell"),
        ("s008","google-adk","experiments/multiframework-control-n174-i2/source/s008.py","experiments/multiframework-control-n174-i2/source/s008.py",adk_sdk,"run_cell")]
    cells=[];inputs={str(normative_path.relative_to(ROOT)):sha(normative_path)}
    for sid,framework,app_path,helper_path,sdk,entrypoint in definitions:
        app=(ROOT/app_path).read_text();helper=(ROOT/helper_path).read_text();repository_id=f"controlled/{sid}@{hashlib.sha256(app.encode()).hexdigest()}"
        actors=[{"path":"app.py","symbol":r["symbol"],"start_line":r["start_line"],"end_line":r["end_line"]} for r in functions(app)]
        if helper!=app:actors += [{"path":"deferred_effects.py","symbol":r["symbol"],"start_line":r["start_line"],"end_line":r["end_line"]} for r in functions(helper)]
        context={"framework":framework,"entrypoint":entrypoint,"helper_path":"deferred_effects.py","normative_contract":normative,"sdk_contract":sdk,
                 "actors":actors,"sites":site_candidates(repository_id,{"app.py":app,**({"deferred_effects.py":helper} if helper!=app else {})})}
        payload,spec=task(context,app,helper,None,repository_id=repository_id);directory=DIRECTORY/"inputs"/sid;directory.mkdir(parents=True)
        write_new(directory/"ANALYST_INPUT.json",payload);write_new(directory/"ANALYST_SPEC.json",spec)
        input_path=str((directory/"ANALYST_INPUT.json").relative_to(ROOT));spec_path=str((directory/"ANALYST_SPEC.json").relative_to(ROOT))
        for relative in (app_path,helper_path,input_path,spec_path):inputs[relative]=sha(ROOT/relative)
        cells.append({"sample_id":sid,"repository_id":repository_id,"app_path":app_path,"helper_path":helper_path,
            "analyst_input":input_path,"analyst_spec":spec_path,"certificate":context})
    for path in (Path(__file__),ROOT/"src/guardcontract/protocols/llm_only_issue.py",ROOT/"src/guardcontract/pipeline/review_execution.py",
        ROOT/"src/guardcontract/backends/recorded.py",ROOT/"src/guardcontract/backends/replay.py"):
        inputs[str(path.relative_to(ROOT))]=sha(path)
    # Evaluation identities are frozen separately and are never read by execute().
    lang_ref=read(ROOT/"experiments/layered-oracle-n192-i3/EVALUATION_FRAME.json");control=read(ROOT/"experiments/control-oracle-calibration-n175/RESULT.json")
    lang={r["sample_id"]:r for r in lang_ref["samples"]};controls={r["sample_id"]:r for r in control["records"]}
    evaluation=[]
    for cell in cells:
        sid=cell["sample_id"];spec=read(ROOT/cell["analyst_spec"])
        if sid in lang:
            gold=lang[sid];sites={r["sink_site"]:{"relation":r["resource_relation"],"allow":r["allow_effect_occurs"],"deny":r["deny_effect_occurs"]} for r in gold["realizations"]};guard=gold["guard_symbol"];issue=gold["issue_present"]
        else:
            gold=controls[sid];site_id=next(iter(spec["sites"].values()))["site_id"];sites={site_id:{"relation":"same_logical_effect","allow":True,"deny":gold["oracle"]["effect_counts"]["DENY"]>0}};guard="_run_cell.decide";issue=gold["oracle"]["issue_present"]
        evaluation.append({"sample_id":sid,"issue":issue,"guard_symbol":guard,"sites":sites})
    plan={"schema_version":"llm-only-plan-1","result_schema_version":"llm-only-result-1","cells":cells,"inputs_sha256":inputs,"sdk_contract":None,
        "model":"DeepSeek-V4-Pro-0813","max_tokens":4096,"timeout_seconds":90,"max_calls":8,"max_total_tokens_stop_before_next_call":128000,
        "retries":0,"cache":"none","static_path_certificate_input":False,"study_use":"four_exposed_sample_llm_only_ablation","goal_completion_proven":False}
    DIRECTORY.mkdir(exist_ok=True);write_new(DIRECTORY/"RUN_PLAN.json",plan);write_new(DIRECTORY/"EVALUATION_PLAN.json",{
        "schema_version":"llm-only-eval-1","run_plan_sha256":sha(DIRECTORY/"RUN_PLAN.json"),"cells":evaluation,"scorer_sha256":sha(Path(__file__)),
        "planned_samples":4,"planned_positive":2,"planned_negative":2,"known_path_booleans":12,"holdout_eligible":False})
    print(json.dumps({"samples":4,"planned_calls":8,"budget":128000,"static_path_certificate_input":False}))

def freeze(plan):
    result={}
    for relative,expected in plan["inputs_sha256"].items():
        raw=(ROOT/relative).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=expected:raise ValueError("llmonly237_input_drift:"+relative)
        result[relative]=raw
    return result

def evaluate(evaluation,result,role):
    expected={r["sample_id"]:r for r in evaluation["cells"]};records={r["cell_id"].rsplit("-",1)[0]:r for r in result["records"] if r["role"]==role}
    infra=any(r["execution_state"] in {"error","missing"} for r in records.values());tp=fp=fn=tn=known=correct=guard_correct=0;rows=[]
    for sid,gold in expected.items():
        record=records[sid];prediction=record["review"] if record["execution_state"]=="completed" else None;issue=prediction["issue"] if prediction else None
        tp+=issue is True and gold["issue"] is True;fp+=issue is True and gold["issue"] is False;fn+=issue is not True and gold["issue"] is True;tn+=issue is False and gold["issue"] is False
        guard_correct+=prediction is not None and prediction["guard_symbol"]==gold["guard_symbol"]
        sites={r["site_id"]:r for r in prediction["sites"]} if prediction else {}
        for site_id,target in gold["sites"].items():
            actual=sites.get(site_id,{})
            for field,source in (("relation","relation"),("allow_occurs","allow"),("deny_occurs","deny")):
                if target[source] is None or target[source]=="unknown":continue
                known+=1;correct+=actual.get(field)==target[source]
        rows.append({"sample_id":sid,"execution_state":record["execution_state"],"reference_issue":gold["issue"],"prediction":issue})
    ratio=lambda n,d:{"numerator":n,"denominator":d,"value":n/d if d and not infra else None}
    return {"role":role,"rows":rows,"issue_precision":ratio(tp,tp+fp),"issue_recall":ratio(tp,tp+fn),"issue_accuracy":ratio(tp+tn,len(expected)),
        "guard_accuracy":ratio(guard_correct,len(expected)),"known_site_field_accuracy":ratio(correct,known),"scientific_status":"undetermined" if infra else "scored"}

def run(replay=False):
    plan=read(DIRECTORY/"RUN_PLAN.json");frozen=freeze(plan)
    if replay:
        evaluation=read(DIRECTORY/"EVALUATION_PLAN.json")
        if sha(DIRECTORY/"RUN_PLAN.json")!=evaluation["run_plan_sha256"] or sha(Path(__file__))!=evaluation["scorer_sha256"]:raise ValueError("llmonly237_evaluation_drift")
        replay_type=type("LlmOnly237Replay",(RecordedReplay,),{"source_root":DIRECTORY/"runs"})
        with tempfile.TemporaryDirectory(prefix="guardcontract-llmonly237-") as temporary:
            rebuilt=execute(plan,frozen,Path(temporary),"offline",root=ROOT,task_builder=task,decoder=decode,system=SYSTEM,transport_factory=replay_type)
            if rebuilt!=read(DIRECTORY/"RESULT.json"):raise ValueError("llmonly237_replay_result")
            verify_inventory(DIRECTORY/"runs",rebuilt["records"])
        output={"schema_version":"llm-only-score-1","analyst":evaluate(evaluation,rebuilt,"analyst"),"critic":evaluate(evaluation,rebuilt,"critic"),
            "actual_calls":rebuilt["actual_calls"],"actual_total_tokens":rebuilt["actual_total_tokens"],"summed_call_seconds":sum(c["duration_seconds"] for r in rebuilt["records"] for c in r["calls"]),
            "replay_verified":True,"scope":"four_exposed_development_samples_not_holdout","goal_completion_proven":False}
        write_new(DIRECTORY/"SCORES.json",output);print(json.dumps(output));return
    key=(Path.home()/".config/guardcontract/paratera.key").read_text().strip();result=execute(plan,frozen,DIRECTORY,key,root=ROOT,task_builder=task,decoder=decode,system=SYSTEM,transport_factory=RecordedTransport)
    write_new(DIRECTORY/"RUN_MANIFEST.json",{"schema_version":"llm-only-run-1","execution_health":"partial" if any(r["execution_state"] in {"error","missing"} for r in result["records"]) else "completed",
        "run_plan_sha256":sha(DIRECTORY/"RUN_PLAN.json"),"result_sha256":sha(DIRECTORY/"RESULT.json"),"files":{str(p.relative_to(DIRECTORY)):sha(p) for p in DIRECTORY.glob("runs/**/*") if p.is_file()},"goal_completion_proven":False})
    print(json.dumps({"calls":result["actual_calls"],"tokens":result["actual_total_tokens"],"states":[r["execution_state"] for r in result["records"]]}))

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("mode",choices=("prepare","run","replay"));mode=parser.parse_args().mode
    prepare() if mode=="prepare" else run(replay=mode=="replay")
if __name__=="__main__":main()
