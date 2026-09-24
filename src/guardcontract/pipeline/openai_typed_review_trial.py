"""Run blind typed analyst/critic reviews for OpenAI Agents controls."""
import argparse,hashlib,json,tempfile
from pathlib import Path
from guardcontract.backends.recorded import RecordedTransport
from guardcontract.backends.replay import RecordedReplay,verify_inventory
from guardcontract.paths import project_root
from guardcontract.pipeline.blind_typed_review import execute,score
from guardcontract.pipeline.review_execution import write_new
from guardcontract.protocols.openai_typed_path_review import DOMAINS,SYSTEM,decode,task

ROOT=project_root();DIRECTORY=ROOT/"experiments/openai-typed-review-n254"
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_bytes())
def freeze(mapping):
    result={}
    for relative,expected in mapping.items():
        raw=(ROOT/relative).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=expected:raise ValueError("openai254_input_drift:"+relative)
        result[relative]=raw
    return result
def invariants(fields):
    issue=(fields["issue"]==("present" if fields["deny_effect_occurrence"]=="occurs" else "absent")) if fields["deny_effect_occurrence"]!="unknown" else fields["issue"]=="unknown"
    order={"tool_input_pre_effect":"guard_before_effect","parallel_input_race":"concurrent_no_dominance"}.get(fields["guard_mode"])
    return {"issue_matches_deny":issue,"mode_matches_order":order is None or fields["guard_effect_order"]==order,"allow_occurs":fields["allow_effect_occurrence"]=="occurs"}
def prepare():
    if DIRECTORY.exists():raise ValueError("openai254_existing_plan")
    source=ROOT/"experiments/openai-path-certificates-n251";path_plan=read(source/"RUN_PLAN.json");path_result=read(source/"RESULT.json");certificates={r["sample_id"]:r["certificate"] for r in path_result["records"]};inputs={str(p.relative_to(ROOT)):sha(p) for p in source.iterdir() if p.is_file()};cells=[];evaluation=[]
    for cell in path_plan["cells"]:
        sid=cell["sample_id"];body=(ROOT/cell["source_path"]).read_text();role_inputs={};role_specs={}
        for role in ("analyst","critic"):
            payload,spec=task(certificates[sid],body,path_plan["sdk_contract"],repository_id=cell["repository_id"],role=role);directory=DIRECTORY/"inputs"/sid;directory.mkdir(parents=True,exist_ok=True)
            ip=directory/f"{role.upper()}_INPUT.json";sp=directory/f"{role.upper()}_SPEC.json";write_new(ip,payload);write_new(sp,spec);role_inputs[role]=str(ip.relative_to(ROOT));role_specs[role]=str(sp.relative_to(ROOT));inputs[role_inputs[role]]=sha(ip);inputs[role_specs[role]]=sha(sp)
        inputs[cell["source_path"]]=sha(ROOT/cell["source_path"]);cells.append({"sample_id":sid,"repository_id":cell["repository_id"],"role_inputs":role_inputs,"role_specs":role_specs,"certificate":certificates[sid]});evaluation.append({"sample_id":sid,"expected_fields":read(ROOT/role_specs["analyst"])["expected_fields"]})
    for path in (Path(__file__),ROOT/"src/guardcontract/protocols/openai_typed_path_review.py",ROOT/"src/guardcontract/pipeline/blind_typed_review.py",ROOT/"src/guardcontract/pipeline/review_execution.py",ROOT/"src/guardcontract/backends/recorded.py",ROOT/"src/guardcontract/backends/replay.py"):inputs[str(path.relative_to(ROOT))]=sha(path)
    plan={"schema_version":"openai-typed-review-plan-1","result_schema_version":"openai-typed-review-result-1","cells":cells,"inputs_sha256":inputs,"model":"DeepSeek-V4-Pro-0813","max_tokens":4096,"timeout_seconds":90,"max_calls":4,"max_total_tokens_stop_before_next_call":64000,"retries":0,"cache":"none","roles":"analyst_and_blind_independent_critic","llm_semantic_authority":False,"goal_completion_proven":False}
    DIRECTORY.mkdir(exist_ok=True);write_new(DIRECTORY/"RUN_PLAN.json",plan);write_new(DIRECTORY/"EVALUATION_PLAN.json",{"schema_version":"openai-typed-review-eval-1","run_plan_sha256":sha(DIRECTORY/"RUN_PLAN.json"),"cells":evaluation,"field_verdicts_per_role":len(DOMAINS),"scorer_sha256":sha(Path(__file__)),"holdout_eligible":False});print(json.dumps({"samples":2,"fields":len(DOMAINS),"planned_calls":4}))
def run(replay=False):
    plan=read(DIRECTORY/"RUN_PLAN.json");frozen=freeze(plan["inputs_sha256"])
    if replay:
        evaluation=read(DIRECTORY/"EVALUATION_PLAN.json")
        if sha(DIRECTORY/"RUN_PLAN.json")!=evaluation["run_plan_sha256"] or sha(Path(__file__))!=evaluation["scorer_sha256"]:raise ValueError("openai254_evaluation_drift")
        replay_type=type("OpenAI254Replay",(RecordedReplay,),{"source_root":DIRECTORY/"runs"})
        with tempfile.TemporaryDirectory(prefix="guardcontract-openai254-") as temporary:
            rebuilt=execute(plan,frozen,Path(temporary),"offline",system=SYSTEM,decoder=decode,transport_factory=replay_type)
            if rebuilt!=read(DIRECTORY/"RESULT.json"):raise ValueError("openai254_replay_result")
            verify_inventory(DIRECTORY/"runs",rebuilt["records"])
        scored={"schema_version":"openai-typed-review-score-1",**score(evaluation,rebuilt,invariants),"scope":"two_exposed_openai_reviews_not_holdout","replay_verified":True,"actual_calls":rebuilt["actual_calls"],"actual_total_tokens":rebuilt["actual_total_tokens"],"summed_call_seconds":sum(c["duration_seconds"] for r in rebuilt["records"] for c in r["calls"])};write_new(DIRECTORY/"SCORES.json",scored);print(json.dumps({k:v for k,v in scored.items() if k!="rows"}));return
    key=(Path.home()/".config/guardcontract/paratera.key").read_text().strip();result=execute(plan,frozen,DIRECTORY,key,system=SYSTEM,decoder=decode,transport_factory=RecordedTransport);write_new(DIRECTORY/"RUN_MANIFEST.json",{"schema_version":"openai-typed-review-run-1","execution_health":"partial" if any(r["execution_state"] in {"error","missing"} for r in result["records"]) else "completed","run_plan_sha256":sha(DIRECTORY/"RUN_PLAN.json"),"result_sha256":sha(DIRECTORY/"RESULT.json"),"files":{str(p.relative_to(DIRECTORY)):sha(p) for p in DIRECTORY.glob("runs/**/*") if p.is_file()},"goal_completion_proven":False});print(json.dumps({"calls":result["actual_calls"],"tokens":result["actual_total_tokens"],"states":[r["execution_state"] for r in result["records"]]}))
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("mode",choices=("prepare","run","replay"));mode=parser.parse_args().mode;prepare() if mode=="prepare" else run(replay=mode=="replay")
if __name__=="__main__":main()
