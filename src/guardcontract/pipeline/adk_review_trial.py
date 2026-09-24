"""Run analyst/critic review over Google ADK source certificates."""
import argparse,hashlib,json,tempfile
from pathlib import Path

from guardcontract.backends.recorded import RecordedTransport
from guardcontract.backends.replay import RecordedReplay,verify_inventory
from guardcontract.paths import project_root
from guardcontract.pipeline.review_execution import execute,score,write_new
from guardcontract.protocols.adk_certificate_review import SYSTEM,decode,task

ROOT=project_root();DIRECTORY=ROOT/"experiments/adk-certificate-review-n234"
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_bytes())
def freeze(mapping):
    result={}
    for relative,expected in mapping.items():
        raw=(ROOT/relative).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=expected:raise ValueError("adk234_input_drift:"+relative)
        result[relative]=raw
    return result


def prepare():
    if DIRECTORY.exists():raise ValueError("adk234_existing_plan")
    source=ROOT/"experiments/adk-path-certificates-n233";path_plan=read(source/"RUN_PLAN.json");path_result=read(source/"RESULT.json")
    records={r["sample_id"]:r["certificate"] for r in path_result["records"]};inputs={str(p.relative_to(ROOT)):sha(p) for p in source.iterdir() if p.is_file()}
    cells=[];evaluation=[]
    for cell in path_plan["cells"]:
        sid=cell["sample_id"];app=(ROOT/cell["source_path"]).read_text();payload,spec=task(records[sid],app,app,path_plan["sdk_contract"],repository_id=cell["repository_id"])
        directory=DIRECTORY/"inputs"/sid;directory.mkdir(parents=True);write_new(directory/"ANALYST_INPUT.json",payload);write_new(directory/"ANALYST_SPEC.json",spec)
        input_path=str((directory/"ANALYST_INPUT.json").relative_to(ROOT));spec_path=str((directory/"ANALYST_SPEC.json").relative_to(ROOT))
        for relative in (input_path,spec_path,cell["source_path"]):inputs[relative]=sha(ROOT/relative)
        cells.append({"sample_id":sid,"repository_id":cell["repository_id"],"app_path":cell["source_path"],"helper_path":cell["source_path"],
            "analyst_input":input_path,"analyst_spec":spec_path,"certificate":records[sid]})
        expectations={claim["claim_id"]:"contradicted" if claim["claim_id"].startswith("control-") else "supported" for claim in payload["claims"]}
        evaluation.append({"sample_id":sid,"claim_expectations":expectations,"claim_count":len(expectations)})
    for path in (Path(__file__),ROOT/"src/guardcontract/protocols/adk_certificate_review.py",ROOT/"src/guardcontract/protocols/certificate_review_atomic.py",
        ROOT/"src/guardcontract/pipeline/review_execution.py",ROOT/"src/guardcontract/backends/recorded.py",ROOT/"src/guardcontract/backends/replay.py"):
        inputs[str(path.relative_to(ROOT))]=sha(path)
    plan={"schema_version":"adk-review-plan-1","result_schema_version":"adk-review-result-1","cells":cells,"inputs_sha256":inputs,
        "sdk_contract":path_plan["sdk_contract"],"model":"DeepSeek-V4-Pro-0813","max_tokens":4096,"timeout_seconds":90,"max_calls":4,
        "max_total_tokens_stop_before_next_call":64000,"retries":0,"cache":"none","study_use":"two_exposed_adk_development_reviews","goal_completion_proven":False}
    DIRECTORY.mkdir(exist_ok=True);write_new(DIRECTORY/"RUN_PLAN.json",plan);write_new(DIRECTORY/"EVALUATION_PLAN.json",{
        "schema_version":"adk-review-eval-1","run_plan_sha256":sha(DIRECTORY/"RUN_PLAN.json"),"cells":evaluation,
        "substantive_claims":12,"negative_control_claims":4,"scorer_sha256":sha(Path(__file__)),"holdout_eligible":False})
    print(json.dumps({"samples":2,"claims":sum(r["claim_count"] for r in evaluation),"planned_calls":4}))


def run(replay=False):
    plan=read(DIRECTORY/"RUN_PLAN.json");frozen=freeze(plan["inputs_sha256"])
    if replay:
        evaluation=read(DIRECTORY/"EVALUATION_PLAN.json")
        if sha(DIRECTORY/"RUN_PLAN.json")!=evaluation["run_plan_sha256"] or sha(Path(__file__))!=evaluation["scorer_sha256"]:raise ValueError("adk234_evaluation_drift")
        replay_type=type("Adk234Replay",(RecordedReplay,),{"source_root":DIRECTORY/"runs"})
        with tempfile.TemporaryDirectory(prefix="guardcontract-adk234-") as temporary:
            rebuilt=execute(plan,frozen,Path(temporary),"offline",root=ROOT,task_builder=task,decoder=decode,system=SYSTEM,transport_factory=replay_type)
            if rebuilt!=read(DIRECTORY/"RESULT.json"):raise ValueError("adk234_replay_result")
            verify_inventory(DIRECTORY/"runs",rebuilt["records"])
        scored={"schema_version":"adk-review-score-1",**score(evaluation,rebuilt),"scope":"two_exposed_adk_reviews_not_holdout",
            "replay_verified":True,"actual_calls":rebuilt["actual_calls"],"actual_total_tokens":rebuilt["actual_total_tokens"],
            "summed_call_seconds":sum(c["duration_seconds"] for r in rebuilt["records"] for c in r["calls"])}
        write_new(DIRECTORY/"SCORES.json",scored);print(json.dumps({k:v for k,v in scored.items() if k!="rows"}));return
    key=(Path.home()/".config/guardcontract/paratera.key").read_text().strip();result=execute(plan,frozen,DIRECTORY,key,root=ROOT,task_builder=task,decoder=decode,system=SYSTEM,transport_factory=RecordedTransport)
    write_new(DIRECTORY/"RUN_MANIFEST.json",{"schema_version":"adk-review-run-1","execution_health":"partial" if any(r["execution_state"] in {"error","missing"} for r in result["records"]) else "completed",
        "run_plan_sha256":sha(DIRECTORY/"RUN_PLAN.json"),"result_sha256":sha(DIRECTORY/"RESULT.json"),
        "files":{str(p.relative_to(DIRECTORY)):sha(p) for p in DIRECTORY.glob("runs/**/*") if p.is_file()},"goal_completion_proven":False})
    print(json.dumps({"calls":result["actual_calls"],"tokens":result["actual_total_tokens"],"states":[r["execution_state"] for r in result["records"]]}))


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("mode",choices=("prepare","run","replay"));mode=parser.parse_args().mode
    prepare() if mode=="prepare" else run(replay=mode=="replay")
if __name__=="__main__":main()
