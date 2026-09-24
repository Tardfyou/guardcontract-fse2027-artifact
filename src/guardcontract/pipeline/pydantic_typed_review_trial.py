"""Run blind typed analyst/critic path reconstruction for Pydantic AI."""
import argparse,hashlib,json,tempfile
from collections import Counter
from pathlib import Path

from guardcontract.backends.recorded import RecordedTransport
from guardcontract.backends.replay import RecordedReplay,verify_inventory
from guardcontract.paths import project_root
from guardcontract.pipeline.review_execution import call_model,write_new
from guardcontract.protocols.pydantic_typed_path_review import DOMAINS,SYSTEM,decode,task

ROOT=project_root();DIRECTORY=ROOT/"experiments/pydantic-typed-review-n248"
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_bytes())
def freeze(mapping):
    result={}
    for relative,expected in mapping.items():
        raw=(ROOT/relative).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=expected:raise ValueError("pydantic248_input_drift:"+relative)
        result[relative]=raw
    return result

def prepare():
    if DIRECTORY.exists():raise ValueError("pydantic248_existing_plan")
    source=ROOT/"experiments/pydantic-path-certificates-n244";path_plan=read(source/"RUN_PLAN.json");path_result=read(source/"RESULT.json")
    certificates={r["sample_id"]:r["certificate"] for r in path_result["records"]};inputs={str(p.relative_to(ROOT)):sha(p) for p in source.iterdir() if p.is_file()}
    helper=(ROOT/path_plan["helper_path"]).read_text();cells=[];evaluation=[]
    for cell in path_plan["cells"]:
        sid=cell["sample_id"];app=(ROOT/cell["source_path"]).read_text();role_inputs={};role_specs={}
        for role in ("analyst","critic"):
            payload,spec=task(certificates[sid],app,helper,path_plan["sdk_contract"],repository_id=cell["repository_id"],role=role)
            directory=DIRECTORY/"inputs"/sid;directory.mkdir(parents=True,exist_ok=True)
            ip=directory/(role.upper()+"_INPUT.json");sp=directory/(role.upper()+"_SPEC.json");write_new(ip,payload);write_new(sp,spec)
            role_inputs[role]=str(ip.relative_to(ROOT));role_specs[role]=str(sp.relative_to(ROOT));inputs[role_inputs[role]]=sha(ip);inputs[role_specs[role]]=sha(sp)
        for relative in (cell["source_path"],path_plan["helper_path"]):inputs[relative]=sha(ROOT/relative)
        cells.append({"sample_id":sid,"repository_id":cell["repository_id"],"role_inputs":role_inputs,"role_specs":role_specs,"certificate":certificates[sid]})
        evaluation.append({"sample_id":sid,"expected_fields":read(ROOT/role_specs["analyst"])["expected_fields"]})
    for path in (Path(__file__),ROOT/"src/guardcontract/protocols/pydantic_typed_path_review.py",ROOT/"src/guardcontract/protocols/pydantic_certificate_review.py",
        ROOT/"src/guardcontract/pipeline/review_execution.py",ROOT/"src/guardcontract/backends/recorded.py",ROOT/"src/guardcontract/backends/replay.py"):
        inputs[str(path.relative_to(ROOT))]=sha(path)
    plan={"schema_version":"pydantic-typed-review-plan-1","result_schema_version":"pydantic-typed-review-result-1","cells":cells,"inputs_sha256":inputs,
        "model":"DeepSeek-V4-Pro-0813","max_tokens":4096,"timeout_seconds":90,"max_calls":4,"max_total_tokens_stop_before_next_call":64000,"retries":0,"cache":"none",
        "roles":"analyst_and_blind_independent_critic","method":"typed_path_fields_with_deterministic_cross_field_gate","study_use":"two_exposed_pydantic_development_reviews","goal_completion_proven":False}
    DIRECTORY.mkdir(exist_ok=True);write_new(DIRECTORY/"RUN_PLAN.json",plan);write_new(DIRECTORY/"EVALUATION_PLAN.json",{"schema_version":"pydantic-typed-review-eval-1",
        "run_plan_sha256":sha(DIRECTORY/"RUN_PLAN.json"),"cells":evaluation,"field_verdicts_per_role":len(DOMAINS),"scorer_sha256":sha(Path(__file__)),"holdout_eligible":False})
    print(json.dumps({"samples":2,"fields":len(DOMAINS),"planned_calls":4,"roles":plan["roles"]}))

def execute(plan,frozen,output,key,transport_factory):
    if (output/"runs").exists():raise ValueError("pydantic248_existing_run")
    records=[];tokens=0;usage_known=True
    for cell in plan["cells"]:
        for role in ("analyst","critic"):
            directory=output/"runs"/f"{cell['sample_id']}-{role}";payload=json.loads(frozen[cell["role_inputs"][role]]);spec=json.loads(frozen[cell["role_specs"][role]])
            if not usage_known or tokens>=plan["max_total_tokens_stop_before_next_call"] or len(records)>=plan["max_calls"]:
                directory.mkdir(parents=True);row={"cell_id":directory.name,"role":role,"execution_state":"missing","review":None,"calls":[],"fault_domain":"budget","error_code":"unknown_usage_or_budget_stop"}
                write_new(directory/"ACTUAL_INPUT.json",payload);write_new(directory/"ACTUAL_SPEC.json",spec);write_new(directory/"RESULT.json",row)
            else:
                row,used,known=call_model(payload,spec,role,directory,plan,key,system=SYSTEM,decoder=decode,transport_factory=transport_factory);tokens+=used;usage_known&=known
            records.append(row)
    result={"schema_version":plan["result_schema_version"],"records":records,"actual_calls":sum(len(r["calls"]) for r in records),
        "actual_total_tokens":tokens if usage_known else None,"known_accounted_tokens":tokens,"usage_known":usage_known,"goal_completion_proven":False}
    write_new(output/"RESULT.json",result);return result

def invariants(fields):
    return {"issue_matches_deny_occurrence":fields["issue"]==("present" if fields["deny_effect_occurrence"]=="occurs" else "absent") if fields["deny_effect_occurrence"]!="unknown" else fields["issue"]=="unknown",
        "supported_scope_allow_occurs":fields["allow_effect_occurrence"]=="occurs",
        "direct_write_before_validator_implies_deny_occurs":not(fields["tool_effect_mode"]=="direct_write" and fields["output_validator_ordering"]=="tool_before_validator") or fields["deny_effect_occurrence"]=="occurs"}

def score(evaluation,result):
    expected={r["sample_id"]:r["expected_fields"] for r in evaluation["cells"]};states=Counter(r["execution_state"] for r in result["records"]);rows=[];correct=known=0;sample_gates={}
    infrastructure=any(r["execution_state"] in {"error","missing"} for r in result["records"])
    by={(r["cell_id"].rsplit("-",1)[0],r["role"]):r for r in result["records"]}
    for sid,target in expected.items():
        role_gates=[]
        for role in ("analyst","critic"):
            record=by[(sid,role)];fields=record["review"]["fields"] if record["execution_state"]=="completed" else {}
            for name,want in target.items():
                got=fields.get(name);rows.append({"sample_id":sid,"role":role,"field":name,"reference":want,"prediction":got,"correct":got==want})
                known+=record["execution_state"] not in {"error","missing"};correct+=record["execution_state"] not in {"error","missing"} and got==want
            checks=invariants(fields) if fields else {};role_gates.append(record["execution_state"]=="completed" and all(checks.values()) and fields==target and record["review"]["deterministic_evidence_attachment_verified"])
        sample_gates[sid]=all(role_gates)
    ratio=lambda n,d:{"numerator":n,"denominator":d,"value":None if infrastructure or not d else n/d}
    return {"execution_states":dict(states),"rows":rows,"typed_field_accuracy":ratio(correct,known),"sample_gates":sample_gates,
        "complete_blind_role_pairs":{"numerator":sum(sample_gates.values()),"denominator":len(sample_gates),"value":None if infrastructure else sum(sample_gates.values())/len(sample_gates)},
        "scientific_status":"undetermined_infrastructure_or_missing" if infrastructure else "scored_typed_path_review","goal_completion_proven":False}

def run(replay=False):
    plan=read(DIRECTORY/"RUN_PLAN.json");frozen=freeze(plan["inputs_sha256"])
    if replay:
        evaluation=read(DIRECTORY/"EVALUATION_PLAN.json")
        if sha(DIRECTORY/"RUN_PLAN.json")!=evaluation["run_plan_sha256"] or sha(Path(__file__))!=evaluation["scorer_sha256"]:raise ValueError("pydantic248_evaluation_drift")
        replay_type=type("Pydantic248Replay",(RecordedReplay,),{"source_root":DIRECTORY/"runs"})
        with tempfile.TemporaryDirectory(prefix="guardcontract-pydantic248-") as temporary:
            rebuilt=execute(plan,frozen,Path(temporary),"offline",replay_type)
            if rebuilt!=read(DIRECTORY/"RESULT.json"):raise ValueError("pydantic248_replay_result")
            verify_inventory(DIRECTORY/"runs",rebuilt["records"])
        scored={"schema_version":"pydantic-typed-review-score-1",**score(evaluation,rebuilt),"scope":"two_exposed_pydantic_reviews_not_holdout","replay_verified":True,
            "actual_calls":rebuilt["actual_calls"],"actual_total_tokens":rebuilt["actual_total_tokens"],"summed_call_seconds":sum(c["duration_seconds"] for r in rebuilt["records"] for c in r["calls"])}
        write_new(DIRECTORY/"SCORES.json",scored);print(json.dumps({k:v for k,v in scored.items() if k!="rows"}));return
    key=(Path.home()/".config/guardcontract/paratera.key").read_text().strip();result=execute(plan,frozen,DIRECTORY,key,RecordedTransport)
    write_new(DIRECTORY/"RUN_MANIFEST.json",{"schema_version":"pydantic-typed-review-run-1","execution_health":"partial" if any(r["execution_state"] in {"error","missing"} for r in result["records"]) else "completed",
        "run_plan_sha256":sha(DIRECTORY/"RUN_PLAN.json"),"result_sha256":sha(DIRECTORY/"RESULT.json"),"files":{str(p.relative_to(DIRECTORY)):sha(p) for p in DIRECTORY.glob("runs/**/*") if p.is_file()},"goal_completion_proven":False})
    print(json.dumps({"calls":result["actual_calls"],"tokens":result["actual_total_tokens"],"states":[r["execution_state"] for r in result["records"]]}))

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("mode",choices=("prepare","run","replay"));mode=parser.parse_args().mode;prepare() if mode=="prepare" else run(replay=mode=="replay")
if __name__=="__main__":main()
