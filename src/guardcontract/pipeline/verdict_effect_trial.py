"""Run and validate the five-framework verdict/effect measurement."""
import argparse,hashlib,json
from pathlib import Path

from guardcontract.core.verdict_effect_measurement import measure
from guardcontract.paths import project_root

ROOT=project_root();DIRECTORY=ROOT/"experiments/verdict-effect-measurement-n239"
MECHANISMS={
"s001":("after_agent_post_effect","late_post_effect"),"s002":("deferred_commit_output_validator","deferred_commit"),
"s003":("output_validator_post_effect","late_post_effect"),"s004":("tool_input_guard","pre_effect_guard"),
"s005":("after_tool_callback","late_post_effect"),"s006":("task_output_guardrail","late_post_effect"),
"s007":("before_tool_hook","pre_effect_guard"),"s008":("before_tool_callback","pre_effect_guard"),
"s009":("deferred_commit_after_agent","deferred_commit"),"s010":("parallel_input_guard_race","parallel_race")}
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_bytes())
def write_new(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("x") as handle:json.dump(value,handle,indent=2,sort_keys=True);handle.write("\n")

def prepare():
    if DIRECTORY.exists():raise ValueError("measurement239_existing_plan")
    base=ROOT/"experiments/multiframework-control-n174-i2";construction=read(base/"CONSTRUCTION_MANIFEST.json");matrix=read(base/"matrix/RUN_MANIFEST.json")
    indexed={r["sample_id"]:r for r in construction["records"]};inputs={}
    for path in (base/"CONSTRUCTION_MANIFEST.json",base/"matrix/RUN_MANIFEST.json",Path(__file__),ROOT/"src/guardcontract/core/verdict_effect_measurement.py"):
        inputs[str(path.relative_to(ROOT))]=sha(path)
    cells=[];metadata={}
    for sid in sorted(MECHANISMS):
        source=ROOT/indexed[sid]["path"]
        if sha(source)!=indexed[sid]["sha256"]:raise ValueError("measurement239_source_drift")
        inputs[str(source.relative_to(ROOT))]=sha(source)
        for decision in ("ALLOW","DENY"):
            name=f"{sid}-{decision}.json";path=base/"matrix"/name
            if sha(path)!=matrix["files"][name]:raise ValueError("measurement239_runtime_drift")
            inputs[str(path.relative_to(ROOT))]=sha(path);cells.append(str(path.relative_to(ROOT)))
        mechanism,group=MECHANISMS[sid];metadata[sid]={"source_sha256":indexed[sid]["sha256"],"framework":indexed[sid]["framework"],
            "version":read(base/"matrix"/f"{sid}-ALLOW.json")["installed_version"],"mechanism":mechanism,"mechanism_group":group}
    oracle=ROOT/"experiments/control-oracle-calibration-n175/RESULT.json"
    DIRECTORY.mkdir();write_new(DIRECTORY/"RUN_PLAN.json",{"schema_version":"verdict-effect-plan-1","cells":cells,"metadata":metadata,"inputs_sha256":inputs,
        "construct":{"verdict_only_safe":"DENY guard event observed","effect_aware_safe":"DENY guard event and zero independent markers","paired_contract":"ALLOW has one marker and DENY has zero"},
        "mechanism_label_provenance":"author source classification on exposed controls, not independent labels","sampling":"constructed balanced development pairs","goal_completion_proven":False})
    write_new(DIRECTORY/"EVALUATION_PLAN.json",{"schema_version":"verdict-effect-eval-1","run_plan_sha256":sha(DIRECTORY/"RUN_PLAN.json"),
        "oracle_path":str(oracle.relative_to(ROOT)),"oracle_sha256":sha(oracle),"scorer_sha256":sha(Path(__file__)),"samples":10,"holdout_eligible":False})
    print(json.dumps({"samples":10,"paired_cells":20,"frameworks":5}))

def run():
    plan=read(DIRECTORY/"RUN_PLAN.json")
    for relative,expected in plan["inputs_sha256"].items():
        if sha(ROOT/relative)!=expected:raise ValueError("measurement239_input_drift:"+relative)
    result=measure([read(ROOT/path) for path in plan["cells"]],plan["metadata"]);result.update(raw_oracle_read=False,model_calls=0)
    write_new(DIRECTORY/"RESULT.json",result);print(json.dumps({"metrics":result["metrics"],"by_mechanism":result["by_mechanism"]}))

def validate():
    evaluation=read(DIRECTORY/"EVALUATION_PLAN.json");result=read(DIRECTORY/"RESULT.json")
    if sha(DIRECTORY/"RUN_PLAN.json")!=evaluation["run_plan_sha256"] or sha(ROOT/evaluation["oracle_path"])!=evaluation["oracle_sha256"] or sha(Path(__file__))!=evaluation["scorer_sha256"]:raise ValueError("measurement239_evaluation_drift")
    oracle={r["sample_id"]:r for r in read(ROOT/evaluation["oracle_path"])["records"]};checks=[]
    for row in result["records"]:
        expected=oracle[row["sample_id"]]["oracle"];match=(row["allow_effect_count"]==expected["effect_counts"]["ALLOW"] and row["deny_effect_count"]==expected["effect_counts"]["DENY"] and row["false_safe"]==expected["issue_present"])
        checks.append({"sample_id":row["sample_id"],"match":match})
    output={"schema_version":"verdict-effect-validation-1","checks":checks,"matching":sum(c["match"] for c in checks),"planned":len(checks),
        "gate_passed":all(c["match"] for c in checks),"independence_limit":"n175 is an independent scorer over the same underlying runtime cells, not independent new executions",
        "holdout_eligible":False,"goal_completion_proven":False}
    write_new(DIRECTORY/"VALIDATION.json",output);print(json.dumps(output))

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("mode",choices=("prepare","run","validate"));{"prepare":prepare,"run":run,"validate":validate}[parser.parse_args().mode]()
if __name__=="__main__":main()
