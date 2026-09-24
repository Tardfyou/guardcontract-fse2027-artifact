"""Assemble CrewAI certificates with LLM diagnostics and deterministic gates."""
import argparse,hashlib,json
from pathlib import Path
from guardcontract.paths import project_root
from guardcontract.protocols.crewai_typed_path_review import expected_fields
ROOT=project_root();DIRECTORY=ROOT/"experiments/crewai-deterministic-assembly-n259"
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_bytes())
def write_new(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("x") as handle:json.dump(value,handle,indent=2,sort_keys=True);handle.write("\n")
def prepare():
    if DIRECTORY.exists():raise ValueError("crewai259_existing_plan")
    review=ROOT/"experiments/crewai-typed-review-n258";path=ROOT/"experiments/crewai-path-certificates-n256";repair=ROOT/"experiments/crewai-repair-n257/RESULT.json";inputs={}
    for directory in (review,path):
        for item in directory.rglob("*"):
            if item.is_file() and item.name not in {"SCORES.json","EVALUATION_PLAN.json"}:inputs[str(item.relative_to(ROOT))]=sha(item)
    for item in (repair,Path(__file__),ROOT/"src/guardcontract/protocols/crewai_typed_path_review.py"):inputs[str(item.relative_to(ROOT))]=sha(item)
    runtime=ROOT/"experiments/multiframework-control-n174-i2/matrix";runtime_files=[runtime/f"{sid}-{decision}.json" for sid in ("s006","s007") for decision in ("ALLOW","DENY")]
    DIRECTORY.mkdir();write_new(DIRECTORY/"RUN_PLAN.json",{"schema_version":"crewai-deterministic-assembly-plan-1","path_result":"experiments/crewai-path-certificates-n256/RESULT.json","review_plan":"experiments/crewai-typed-review-n258/RUN_PLAN.json","review_result":"experiments/crewai-typed-review-n258/RESULT.json","review_manifest":"experiments/crewai-typed-review-n258/RUN_MANIFEST.json","repair_result":str(repair.relative_to(ROOT)),"inputs_sha256":inputs,"new_model_calls":0,"decision_authority":"deterministic_source_certificate_plus_independent_runtime_oracle","llm_role":"required_executed_advisory_diagnostics","goal_completion_proven":False})
    write_new(DIRECTORY/"EVALUATION_PLAN.json",{"schema_version":"crewai-deterministic-assembly-eval-1","run_plan_sha256":sha(DIRECTORY/"RUN_PLAN.json"),"runtime_files":{str(p.relative_to(ROOT)):sha(p) for p in runtime_files},"scorer_sha256":sha(Path(__file__)),"holdout_eligible":False});print(json.dumps({"samples":2,"new_model_calls":0}))
def run():
    plan=read(DIRECTORY/"RUN_PLAN.json")
    for relative,expected in plan["inputs_sha256"].items():
        if sha(ROOT/relative)!=expected:raise ValueError("crewai259_input_drift:"+relative)
    review_plan,review_result,manifest=(read(ROOT/plan[k]) for k in ("review_plan","review_result","review_manifest"));path_result=read(ROOT/plan["path_result"])
    if sha(ROOT/plan["review_plan"])!=manifest["run_plan_sha256"] or sha(ROOT/plan["review_result"])!=manifest["result_sha256"]:raise ValueError("crewai259_review_drift")
    reviews={(r["cell_id"].rsplit("-",1)[0],r["role"]):r for r in review_result["records"]};rows=[]
    for path_record in path_result["records"]:
        sid=path_record["sample_id"];certificate=path_record["certificate"];expected=expected_fields(certificate);role_rows=[]
        for role in ("analyst","critic"):
            record=reviews[(sid,role)];valid=record["execution_state"]=="completed" and record["review"]["deterministic_evidence_attachment_verified"] and record["review"]["blind_independent_role"];fields=record["review"]["fields"] if valid else {};role_rows.append({"role":role,"execution_state":record["execution_state"],"structurally_valid":valid,"field_disagreements":[name for name,value in fields.items() if value!=expected[name]] if valid else list(expected)})
        source_gate=certificate["status"]=="supported" and certificate["source_semantics_verified"] and len([s for s in certificate["sites"] if s["relation"]=="same_logical_effect"])==1;llm_gate=all(r["structurally_valid"] for r in role_rows);rows.append({"sample_id":sid,"certificate":certificate,"source_gate":source_gate,"llm_execution_gate":llm_gate,"llm_diagnostics":role_rows,"status":"candidate" if source_gate and llm_gate else "unknown"})
    result={"schema_version":"crewai-deterministic-assembly-result-1","records":rows,"inherited_model_calls":review_result["actual_calls"],"inherited_model_tokens":review_result["actual_total_tokens"],"new_model_calls":0,"goal_completion_proven":False};write_new(DIRECTORY/"RESULT.json",result);print(json.dumps({"candidates":sum(r["status"]=="candidate" for r in rows),"inherited_model_calls":result["inherited_model_calls"]}))
def score():
    evaluation,result=read(DIRECTORY/"EVALUATION_PLAN.json"),read(DIRECTORY/"RESULT.json")
    if sha(DIRECTORY/"RUN_PLAN.json")!=evaluation["run_plan_sha256"] or sha(Path(__file__))!=evaluation["scorer_sha256"]:raise ValueError("crewai259_evaluation_drift")
    for relative,expected in evaluation["runtime_files"].items():
        if sha(ROOT/relative)!=expected:raise ValueError("crewai259_runtime_drift:"+relative)
    rows=[]
    for record in result["records"]:
        sid=record["sample_id"];certificate=record["certificate"];site=certificate["sites"][0];cells={d:read(ROOT/f"experiments/multiframework-control-n174-i2/matrix/{sid}-{d}.json") for d in ("ALLOW","DENY")};allow=cells["ALLOW"]["fixture_observation"];deny=cells["DENY"]["fixture_observation"];runtime_issue=deny["protected_tool_effect"];runtime_gate=site["allow_effect_occurs"]==allow["protected_tool_effect"] and site["deny_effect_occurs"]==runtime_issue and certificate["issue_prediction"]==runtime_issue and all(cells[d]["execution_health"]=="completed" for d in cells);accepted=record["status"]=="candidate" and runtime_gate;rows.append({"sample_id":sid,"prediction":certificate["issue_prediction"] if accepted else None,"runtime_issue":runtime_issue,"runtime_gate":runtime_gate,"accepted":accepted,"llm_field_disagreements":{r["role"]:r["field_disagreements"] for r in record["llm_diagnostics"]}})
    repair=read(ROOT/read(DIRECTORY/"RUN_PLAN.json")["repair_result"]);repair_gate=repair["effective_repairs"]==repair["discovered_and_effectively_repaired"]==1 and repair["verification"]["gate_passed"] and repair["verification"]["allow_exact_match"]
    output={"schema_version":"crewai-deterministic-assembly-score-1","rows":rows,"accepted":{"numerator":sum(r["accepted"] for r in rows),"denominator":len(rows)},"runtime_verified":{"numerator":sum(r["runtime_gate"] for r in rows),"denominator":len(rows)},"assembly_ready":all(r["accepted"] for r in rows),"repair_gate_passed":repair_gate,"model_calls":result["inherited_model_calls"],"model_tokens":result["inherited_model_tokens"],"holdout_eligible":False,"llm_semantic_authority":False,"scope":"crewai_development_pipeline_with_llm_diagnostics_and_deterministic_release","goal_completion_proven":False};write_new(DIRECTORY/"SCORES.json",output);print(json.dumps({k:output[k] for k in ("accepted","runtime_verified","assembly_ready","repair_gate_passed","model_calls","model_tokens")}))
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("mode",choices=("prepare","run","score"));{"prepare":prepare,"run":run,"score":score}[parser.parse_args().mode]()
if __name__=="__main__":main()
