"""Freeze and score OpenAI Agents path certificates on owned controls."""
import argparse,hashlib,json
from pathlib import Path

from guardcontract.analysis.openai_paths import analyze
from guardcontract.evidence.openai_sdk_contract import enroll
from guardcontract.paths import project_root

ROOT=project_root();DIRECTORY=ROOT/"experiments/openai-path-certificates-n251"
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_bytes())
def write_new(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("x") as handle:json.dump(value,handle,indent=2,sort_keys=True);handle.write("\n")

def prepare():
    if DIRECTORY.exists():raise ValueError("openai251_existing_plan")
    source_dir=ROOT/"experiments/multiframework-control-n174-i2/source";census=ROOT/"experiments/framework-contract-census-n48-dev"
    site=ROOT/".venv-openai/lib/python3.12/site-packages/agents";run_source=site/"run.py";tool_source=site/"run_internal/tool_execution.py"
    reference=ROOT/"experiments/control-oracle-calibration-n175/RESULT.json";inputs={};cells=[]
    for sid in ("s004","s010"):
        path=source_dir/f"{sid}.py";inputs[str(path.relative_to(ROOT))]=sha(path);cells.append({"sample_id":sid,"repository_id":f"controlled/{sid}@{sha(path)}","source_path":str(path.relative_to(ROOT))})
    for path in (census/"CENSUS_CONFIG.json",census/"raw-evidence.json",census/"RUN_MANIFEST.json",run_source,tool_source,Path(__file__),ROOT/"src/guardcontract/analysis/openai_paths.py",ROOT/"src/guardcontract/evidence/openai_sdk_contract.py"):
        inputs[str(path.relative_to(ROOT))]=sha(path)
    DIRECTORY.mkdir();write_new(DIRECTORY/"RUN_PLAN.json",{"schema_version":"openai-path-plan-1","cells":cells,"inputs_sha256":inputs,
        "sdk_contract":enroll(census,run_source,tool_source),"runtime_reference_read":False,"model_calls":0,
        "scope":"two_exposed_owned_openai_agents_controls","goal_completion_proven":False})
    write_new(DIRECTORY/"EVALUATION_PLAN.json",{"schema_version":"openai-path-eval-1","run_plan_sha256":sha(DIRECTORY/"RUN_PLAN.json"),
        "reference_path":str(reference.relative_to(ROOT)),"reference_sha256":sha(reference),"scorer_sha256":sha(Path(__file__)),"samples":2,"holdout_eligible":False})
    print(json.dumps({"samples":2,"model_calls":0,"runtime_reference_read":False}))

def run():
    plan=read(DIRECTORY/"RUN_PLAN.json")
    for relative,expected in plan["inputs_sha256"].items():
        if sha(ROOT/relative)!=expected:raise ValueError("openai251_input_drift:"+relative)
    rows=[]
    for cell in plan["cells"]:
        source=(ROOT/cell["source_path"]).read_text();rows.append({"sample_id":cell["sample_id"],"certificate":analyze(source,plan["sdk_contract"],repository_id=cell["repository_id"])})
    write_new(DIRECTORY/"RESULT.json",{"schema_version":"openai-path-result-1","records":rows,"runtime_reference_read":False,"model_calls":0,"goal_completion_proven":False})
    print(json.dumps({"states":[r["certificate"]["status"] for r in rows],"model_calls":0}))

def score():
    evaluation,result=read(DIRECTORY/"EVALUATION_PLAN.json"),read(DIRECTORY/"RESULT.json")
    if sha(DIRECTORY/"RUN_PLAN.json")!=evaluation["run_plan_sha256"] or sha(ROOT/evaluation["reference_path"])!=evaluation["reference_sha256"] or sha(Path(__file__))!=evaluation["scorer_sha256"]:raise ValueError("openai251_evaluation_drift")
    gold={r["sample_id"]:r["oracle"]["issue_present"] for r in read(ROOT/evaluation["reference_path"])["records"] if r["sample_id"] in {"s004","s010"}}
    rows=[];tp=fp=fn=tn=0
    for record in result["records"]:
        target=gold[record["sample_id"]];prediction=record["certificate"].get("issue_prediction");tp+=target and prediction is True;fp+=not target and prediction is True;fn+=target and prediction is not True;tn+=not target and prediction is False
        rows.append({"sample_id":record["sample_id"],"reference":target,"prediction":prediction,"correct":prediction==target})
    ratio=lambda n,d:{"numerator":n,"denominator":d,"value":n/d if d else None};output={"schema_version":"openai-path-score-1","rows":rows,
        "issue_precision":ratio(tp,tp+fp),"issue_recall":ratio(tp,tp+fn),"issue_accuracy":ratio(tp+tn,len(rows)),"holdout_eligible":False,"model_calls":0,
        "scope":"two_exposed_openai_agents_development_controls","goal_completion_proven":False}
    write_new(DIRECTORY/"SCORES.json",output);print(json.dumps({k:output[k] for k in ("issue_precision","issue_recall","issue_accuracy")}))

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("mode",choices=("prepare","run","score"));{"prepare":prepare,"run":run,"score":score}[parser.parse_args().mode]()
if __name__=="__main__":main()
