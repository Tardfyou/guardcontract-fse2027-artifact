"""Finalize ADK critic reviews and independently validate runtime paths."""
import argparse,hashlib,json
from pathlib import Path

from guardcontract.paths import project_root
from guardcontract.pipeline.reviewed_certificates import finalize

ROOT=project_root();DIRECTORY=ROOT/"experiments/adk-reviewed-certificates-n235"
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_bytes())
def write_new(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("x") as handle:json.dump(value,handle,indent=2,sort_keys=True);handle.write("\n")


def prepare():
    if DIRECTORY.exists():raise ValueError("adk235_existing_plan")
    review=ROOT/"experiments/adk-certificate-review-n234";inputs={str(p.relative_to(ROOT)):sha(p) for p in review.rglob("*") if p.is_file() and p.name not in {"EVALUATION_PLAN.json","SCORES.json"}}
    for path in (Path(__file__),ROOT/"src/guardcontract/pipeline/reviewed_certificates.py"):inputs[str(path.relative_to(ROOT))]=sha(path)
    runtime=ROOT/"experiments/multiframework-control-n174-i2/matrix"
    runtime_files=[runtime/(sid+"-"+decision+".json") for sid in ("s005","s008") for decision in ("ALLOW","DENY")]
    DIRECTORY.mkdir();write_new(DIRECTORY/"RUN_PLAN.json",{"schema_version":"adk-reviewed-plan-1","review_plan":str((review/"RUN_PLAN.json").relative_to(ROOT)),
        "review_result":str((review/"RESULT.json").relative_to(ROOT)),"review_manifest":str((review/"RUN_MANIFEST.json").relative_to(ROOT)),
        "inputs_sha256":inputs,"runtime_reference_read":False,"new_model_calls":0,"goal_completion_proven":False})
    write_new(DIRECTORY/"EVALUATION_PLAN.json",{"schema_version":"adk-reviewed-eval-1","run_plan_sha256":sha(DIRECTORY/"RUN_PLAN.json"),
        "runtime_files":{str(p.relative_to(ROOT)):sha(p) for p in runtime_files},"scorer_sha256":sha(Path(__file__)),"holdout_eligible":False})
    print(json.dumps({"samples":2,"new_model_calls":0,"runtime_reference_read":False}))


def run():
    plan=read(DIRECTORY/"RUN_PLAN.json")
    for relative,expected in plan["inputs_sha256"].items():
        if sha(ROOT/relative)!=expected:raise ValueError("adk235_input_drift:"+relative)
    review_plan,review_result,manifest=(read(ROOT/plan[k]) for k in ("review_plan","review_result","review_manifest"))
    if sha(ROOT/plan["review_plan"])!=manifest["run_plan_sha256"] or sha(ROOT/plan["review_result"])!=manifest["result_sha256"]:raise ValueError("adk235_review_drift")
    critic_inputs={cell["sample_id"]:read(ROOT/"experiments/adk-certificate-review-n234/runs"/(cell["sample_id"]+"-critic/ACTUAL_INPUT.json")) for cell in review_plan["cells"]}
    result=finalize(review_plan,review_result,critic_inputs);result.update(runtime_reference_read=False,new_model_calls=0)
    write_new(DIRECTORY/"RESULT.json",result);print(json.dumps({"accepted":result["accepted"],"inherited_model_calls":result["model_calls"]}))


def score():
    evaluation=read(DIRECTORY/"EVALUATION_PLAN.json");result=read(DIRECTORY/"RESULT.json")
    if sha(DIRECTORY/"RUN_PLAN.json")!=evaluation["run_plan_sha256"] or sha(Path(__file__))!=evaluation["scorer_sha256"]:raise ValueError("adk235_evaluation_drift")
    for relative,expected in evaluation["runtime_files"].items():
        if sha(ROOT/relative)!=expected:raise ValueError("adk235_runtime_drift:"+relative)
    rows=[]
    for record in result["records"]:
        sid=record["sample_id"];cells={decision:read(ROOT/f"experiments/multiframework-control-n174-i2/matrix/{sid}-{decision}.json") for decision in ("ALLOW","DENY")}
        site=record["sites"][0] if record["status"]=="accepted" and len(record["sites"])==1 else None
        allow=cells["ALLOW"]["fixture_observation"];deny=cells["DENY"]["fixture_observation"]
        runtime_issue=deny["effect_count"]>0;verified=bool(site) and site["allow_effect_occurs"]==(allow["effect_count"]>0) and site["deny_effect_occurs"]==runtime_issue and record["issue_prediction"]==runtime_issue and all(cells[d]["execution_health"]=="completed" for d in cells)
        rows.append({"sample_id":sid,"review_status":record["status"],"runtime_issue":runtime_issue,
            "prediction":record["issue_prediction"],"runtime_verified":verified,"allow_path_match":bool(site) and site["allow_effect_occurs"]==(allow["effect_count"]>0),
            "deny_path_match":bool(site) and site["deny_effect_occurs"]==runtime_issue})
    output={"schema_version":"adk-reviewed-score-1","rows":rows,"runtime_verified":{"numerator":sum(r["runtime_verified"] for r in rows),"denominator":len(rows)},
        "assembly_ready":all(r["runtime_verified"] for r in rows),"model_calls":result["model_calls"],"model_tokens":result["model_tokens"],
        "holdout_eligible":False,"scope":"static_plus_real_analyst_critic_plus_runtime_validation_on_two_exposed_adk_controls","goal_completion_proven":False}
    write_new(DIRECTORY/"SCORES.json",output);print(json.dumps({"runtime_verified":output["runtime_verified"],"assembly_ready":output["assembly_ready"],"model_calls":output["model_calls"],"model_tokens":output["model_tokens"]}))


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("mode",choices=("prepare","run","score"));{"prepare":prepare,"run":run,"score":score}[parser.parse_args().mode]()
if __name__=="__main__":main()
