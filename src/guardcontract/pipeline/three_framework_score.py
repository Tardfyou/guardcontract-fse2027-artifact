"""Aggregate the three-framework exposed development pipeline milestone."""
import hashlib,json
from pathlib import Path

from guardcontract.paths import project_root

ROOT=project_root();DIRECTORY=ROOT/"experiments/three-framework-score-n250"
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_bytes())
def ratio(n,d):return {"numerator":n,"denominator":d,"value":n/d if d else None}

def main():
    if DIRECTORY.exists():raise ValueError("three250_existing_result")
    paths={"two_framework":ROOT/"experiments/cross-framework-score-n236/SCORES.json",
        "pydantic_assembly":ROOT/"experiments/pydantic-deterministic-assembly-n249/SCORES.json",
        "pydantic_review":ROOT/"experiments/pydantic-typed-review-n248/SCORES.json",
        "pydantic_repair":ROOT/"experiments/pydantic-pipeline-n243/RESULT.json","code":Path(__file__)}
    values={key:read(path) for key,path in paths.items() if key!="code"};inputs={str(path.relative_to(ROOT)):sha(path) for path in paths.values()}
    two=values["two_framework"];assembly=values["pydantic_assembly"];review=values["pydantic_review"];repair=values["pydantic_repair"]
    if not assembly["assembly_ready"] or not assembly["repair_gate_passed"]:raise ValueError("three250_pydantic_gate")
    detection=list(two["detection_rows"])+[{"framework":"pydantic-ai-slim","sample_id":row["sample_id"],"prediction":row["prediction"],
        "reference":row["runtime_issue"],"runtime_verified":row["runtime_gate"]} for row in assembly["rows"]]
    tp=sum(r["prediction"] is True and r["reference"] is True for r in detection);fp=sum(r["prediction"] is True and r["reference"] is False for r in detection)
    fn=sum(r["prediction"] is not True and r["reference"] is True for r in detection);tn=sum(r["prediction"] is False and r["reference"] is False for r in detection)
    positives=sum(r["reference"] for r in detection);proposed=two["repair"]["solution_proposed"]["numerator"]+repair["proposed_solutions"]
    generated=two["repair"]["patch_generated"]["numerator"]+repair["generated_patches"];effective=two["repair"]["effective_repair"]["numerator"]+repair["effective_repairs"]
    joint=two["repair"]["discovered_and_effectively_repaired"]["numerator"]+repair["discovered_and_effectively_repaired"]
    exact=two["repair"]["allow_exact_preservation"]["numerator"]+int(repair["verification"]["allow_exact_match"])
    output={"schema_version":"three-framework-development-score-1","detection_rows":detection,
        "detection":{"precision":ratio(tp,tp+fp),"recall":ratio(tp,tp+fn),"accuracy":ratio(tp+tn,len(detection)),"runtime_verified":ratio(sum(r["runtime_verified"] for r in detection),len(detection))},
        "repair":{"problem_positives":positives,"solution_proposed":ratio(proposed,positives),"patch_generated":ratio(generated,positives),
            "effective_repair":ratio(effective,positives),"discovered_and_effectively_repaired":ratio(joint,positives),"allow_exact_preservation":ratio(exact,positives)},
        "review":{"actual_calls":two["review"]["actual_calls"]+review["actual_calls"],"actual_tokens":two["review"]["actual_tokens"]+review["actual_total_tokens"],
            "summed_call_seconds":two["review"]["summed_call_seconds"]+review["summed_call_seconds"],
            "role_policies":{"langchain":"critic_semantic_gate_plus_deterministic_evidence_and_runtime","google-adk":"critic_semantic_gate_plus_deterministic_evidence_and_runtime",
                "pydantic-ai-slim":"blind_analyst_critic_diagnostics_plus_deterministic_source_and_runtime_gate"},
            "pydantic_typed_field_accuracy":review["typed_field_accuracy"],"pydantic_llm_semantic_authority":False},
        "coverage":{"frameworks":3,"samples":len(detection),"positive":positives,"negative":len(detection)-positives,"source_families":3,"languages":["python"],"holdout_eligible_samples":0},
        "inputs_sha256":inputs,"holdout_eligible":False,"scope":"three_framework_six_sample_exposed_development_pipeline_not_confirmatory_holdout",
        "claim_boundary":"Static certificates and deterministic runtime evidence own detection and release. LLM review policies differ by framework and do not support a pooled semantic-accuracy claim.",
        "goal_completion_proven":False}
    DIRECTORY.mkdir();
    with (DIRECTORY/"SCORES.json").open("x") as handle:json.dump(output,handle,indent=2,sort_keys=True);handle.write("\n")
    print(json.dumps({"detection":output["detection"],"repair":output["repair"],"review_calls":output["review"]["actual_calls"],"review_tokens":output["review"]["actual_tokens"],"coverage":output["coverage"]}))
if __name__=="__main__":main()
