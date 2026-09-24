"""Assemble Pydantic certificates with LLM diagnostics and deterministic gates."""
import argparse,hashlib,json
from pathlib import Path

from guardcontract.paths import project_root
from guardcontract.protocols.pydantic_typed_path_review import expected_fields

ROOT=project_root();DIRECTORY=ROOT/"experiments/pydantic-deterministic-assembly-n249"
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_bytes())
def write_new(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("x") as handle:json.dump(value,handle,indent=2,sort_keys=True);handle.write("\n")

def prepare():
    if DIRECTORY.exists():raise ValueError("pydantic249_existing_plan")
    typed=ROOT/"experiments/pydantic-typed-review-n248";path=ROOT/"experiments/pydantic-path-certificates-n244"
    inputs={str(p.relative_to(ROOT)):sha(p) for directory in (typed,path) for p in directory.rglob("*") if p.is_file() and p.name not in {"SCORES.json","EVALUATION_PLAN.json"}}
    for code in (Path(__file__),ROOT/"src/guardcontract/protocols/pydantic_typed_path_review.py"):inputs[str(code.relative_to(ROOT))]=sha(code)
    runtime=ROOT/"experiments/multiframework-control-n174-i2/matrix";runtime_files=[runtime/f"{sid}-{decision}.json" for sid in ("s002","s003") for decision in ("ALLOW","DENY")]
    repair=ROOT/"experiments/pydantic-pipeline-n243/RESULT.json"
    DIRECTORY.mkdir();write_new(DIRECTORY/"RUN_PLAN.json",{"schema_version":"pydantic-deterministic-assembly-plan-1","path_plan":"experiments/pydantic-path-certificates-n244/RUN_PLAN.json",
        "path_result":"experiments/pydantic-path-certificates-n244/RESULT.json","typed_plan":"experiments/pydantic-typed-review-n248/RUN_PLAN.json",
        "typed_result":"experiments/pydantic-typed-review-n248/RESULT.json","typed_manifest":"experiments/pydantic-typed-review-n248/RUN_MANIFEST.json",
        "inputs_sha256":inputs,"new_model_calls":0,"decision_authority":"deterministic_source_certificate_plus_independent_runtime_oracle",
        "llm_role":"required_executed_advisory_diagnostics","goal_completion_proven":False})
    write_new(DIRECTORY/"EVALUATION_PLAN.json",{"schema_version":"pydantic-deterministic-assembly-eval-1","run_plan_sha256":sha(DIRECTORY/"RUN_PLAN.json"),
        "runtime_files":{str(p.relative_to(ROOT)):sha(p) for p in runtime_files},"repair_result":str(repair.relative_to(ROOT)),"repair_result_sha256":sha(repair),
        "scorer_sha256":sha(Path(__file__)),"holdout_eligible":False})
    print(json.dumps({"samples":2,"new_model_calls":0,"decision_authority":"deterministic"}))

def run():
    plan=read(DIRECTORY/"RUN_PLAN.json")
    for relative,expected in plan["inputs_sha256"].items():
        if sha(ROOT/relative)!=expected:raise ValueError("pydantic249_input_drift:"+relative)
    typed_plan,typed_result,manifest=(read(ROOT/plan[k]) for k in ("typed_plan","typed_result","typed_manifest"));path_result=read(ROOT/plan["path_result"])
    if sha(ROOT/plan["typed_plan"])!=manifest["run_plan_sha256"] or sha(ROOT/plan["typed_result"])!=manifest["result_sha256"]:raise ValueError("pydantic249_typed_review_drift")
    reviews={(r["cell_id"].rsplit("-",1)[0],r["role"]):r for r in typed_result["records"]};rows=[]
    for path_record in path_result["records"]:
        sid=path_record["sample_id"];certificate=path_record["certificate"];expected=expected_fields(certificate);role_rows=[]
        for role in ("analyst","critic"):
            record=reviews[(sid,role)];valid=record["execution_state"]=="completed" and record["review"]["deterministic_evidence_attachment_verified"] and record["review"]["blind_independent_role"]
            disagreements=[name for name,value in record["review"]["fields"].items() if value!=expected[name]] if valid else list(expected)
            role_rows.append({"role":role,"execution_state":record["execution_state"],"structurally_valid":valid,"field_disagreements":disagreements})
        source_gate=certificate["status"]=="supported" and certificate["source_semantics_verified"] and len([s for s in certificate["sites"] if s["relation"]=="same_logical_effect"])==1
        llm_execution_gate=all(r["structurally_valid"] for r in role_rows)
        rows.append({"sample_id":sid,"certificate":certificate,"source_gate":source_gate,"llm_execution_gate":llm_execution_gate,"llm_diagnostics":role_rows,
            "status":"candidate" if source_gate and llm_execution_gate else "unknown","decision_authority":plan["decision_authority"]})
    result={"schema_version":"pydantic-deterministic-assembly-result-1","records":rows,"inherited_model_calls":typed_result["actual_calls"],
        "inherited_model_tokens":typed_result["actual_total_tokens"],"new_model_calls":0,"goal_completion_proven":False}
    write_new(DIRECTORY/"RESULT.json",result);print(json.dumps({"candidates":sum(r["status"]=="candidate" for r in rows),"inherited_model_calls":result["inherited_model_calls"]}))

def score():
    evaluation,result=read(DIRECTORY/"EVALUATION_PLAN.json"),read(DIRECTORY/"RESULT.json")
    if sha(DIRECTORY/"RUN_PLAN.json")!=evaluation["run_plan_sha256"] or sha(Path(__file__))!=evaluation["scorer_sha256"] or sha(ROOT/evaluation["repair_result"])!=evaluation["repair_result_sha256"]:raise ValueError("pydantic249_evaluation_drift")
    for relative,expected in evaluation["runtime_files"].items():
        if sha(ROOT/relative)!=expected:raise ValueError("pydantic249_runtime_drift:"+relative)
    rows=[]
    for record in result["records"]:
        sid=record["sample_id"];certificate=record["certificate"];site=next((s for s in certificate["sites"] if s["relation"]=="same_logical_effect"),None)
        cells={d:read(ROOT/f"experiments/multiframework-control-n174-i2/matrix/{sid}-{d}.json") for d in ("ALLOW","DENY")};allow=cells["ALLOW"]["fixture_observation"];deny=cells["DENY"]["fixture_observation"]
        runtime_issue=deny["effect_count"]>0;runtime_gate=bool(site) and site["allow_effect_occurs"]==(allow["effect_count"]>0) and site["deny_effect_occurs"]==runtime_issue and certificate["issue_prediction"]==runtime_issue and all(cells[d]["execution_health"]=="completed" for d in cells)
        accepted=record["status"]=="candidate" and runtime_gate
        rows.append({"sample_id":sid,"prediction":certificate["issue_prediction"] if accepted else None,"runtime_issue":runtime_issue,"runtime_gate":runtime_gate,"accepted":accepted,
            "llm_field_disagreements":{r["role"]:r["field_disagreements"] for r in record["llm_diagnostics"]}})
    repair=read(ROOT/evaluation["repair_result"]);repair_gate=repair["effective_repairs"]==1 and repair["discovered_and_effectively_repaired"]==1 and repair["verification"]["gate_passed"]
    output={"schema_version":"pydantic-deterministic-assembly-score-1","rows":rows,"accepted":{"numerator":sum(r["accepted"] for r in rows),"denominator":len(rows)},
        "runtime_verified":{"numerator":sum(r["runtime_gate"] for r in rows),"denominator":len(rows)},"assembly_ready":all(r["accepted"] for r in rows),
        "repair_gate_passed":repair_gate,"model_calls":result["inherited_model_calls"],"model_tokens":result["inherited_model_tokens"],"holdout_eligible":False,
        "llm_semantic_authority":False,"scope":"three-part_pydantic_development_pipeline_with_llm_diagnostics_and_deterministic_release","goal_completion_proven":False}
    write_new(DIRECTORY/"SCORES.json",output);print(json.dumps({k:output[k] for k in ("accepted","runtime_verified","assembly_ready","repair_gate_passed","model_calls","model_tokens")}))

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("mode",choices=("prepare","run","score"));{"prepare":prepare,"run":run,"score":score}[parser.parse_args().mode]()
if __name__=="__main__":main()
