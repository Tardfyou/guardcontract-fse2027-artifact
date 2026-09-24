"""Aggregate the five-framework exposed development pipeline milestone."""
import hashlib,json
from pathlib import Path
from guardcontract.paths import project_root
ROOT=project_root();DIRECTORY=ROOT/"experiments/five-framework-score-n260"
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_bytes())
def ratio(n,d):return {"numerator":n,"denominator":d,"value":n/d if d else None}
def main():
    # Frozen score directories are immutable. Re-running the command is a
    # read-only verification/report operation instead of an accidental write.
    existing=DIRECTORY/"SCORES.json"
    if existing.exists():
        prior=read(existing)
        print(json.dumps({"frozen":True,"path":str(existing.relative_to(ROOT)),"detection":prior.get("detection"),"repair":prior.get("repair"),"coverage":prior.get("coverage")},sort_keys=True))
        return
    if DIRECTORY.exists():raise ValueError("five260_incomplete_result_directory")
    paths={"three":ROOT/"experiments/three-framework-score-n250/SCORES.json","openai_assembly":ROOT/"experiments/openai-deterministic-assembly-n255/SCORES.json","openai_review":ROOT/"experiments/openai-typed-review-n254/SCORES.json","openai_repair":ROOT/"experiments/openai-repair-n253/RESULT.json","crewai_assembly":ROOT/"experiments/crewai-deterministic-assembly-n259/SCORES.json","crewai_review":ROOT/"experiments/crewai-typed-review-n258/SCORES.json","crewai_repair":ROOT/"experiments/crewai-repair-n257/RESULT.json","code":Path(__file__)}
    values={k:read(p) for k,p in paths.items() if k!="code"};inputs={str(p.relative_to(ROOT)):sha(p) for p in paths.values()};three=values["three"]
    if not values["openai_assembly"]["assembly_ready"] or not values["crewai_assembly"]["assembly_ready"]:raise ValueError("five260_assembly_gate")
    detection=list(three["detection_rows"])
    for framework,key in (("openai-agents","openai_assembly"),("crewai","crewai_assembly")):
        detection.extend({"framework":framework,"sample_id":r["sample_id"],"prediction":r["prediction"],"reference":r["runtime_issue"],"runtime_verified":r["runtime_gate"]} for r in values[key]["rows"])
    tp=sum(r["prediction"] is True and r["reference"] is True for r in detection);fp=sum(r["prediction"] is True and r["reference"] is False for r in detection);fn=sum(r["prediction"] is not True and r["reference"] is True for r in detection);tn=sum(r["prediction"] is False and r["reference"] is False for r in detection);positives=sum(r["reference"] for r in detection)
    repairs=[values["openai_repair"],values["crewai_repair"]];proposed=three["repair"]["solution_proposed"]["numerator"]+sum(r["proposed_solutions"] for r in repairs);generated=three["repair"]["patch_generated"]["numerator"]+sum(r["generated_patches"] for r in repairs);effective=three["repair"]["effective_repair"]["numerator"]+sum(r["effective_repairs"] for r in repairs);joint=three["repair"]["discovered_and_effectively_repaired"]["numerator"]+sum(r["discovered_and_effectively_repaired"] for r in repairs);exact=three["repair"]["allow_exact_preservation"]["numerator"]+sum(r["verification"]["allow_exact_match"] for r in repairs)
    review_calls=three["review"]["actual_calls"]+sum(values[k]["actual_calls"] for k in ("openai_review","crewai_review"));review_tokens=three["review"]["actual_tokens"]+sum(values[k]["actual_total_tokens"] for k in ("openai_review","crewai_review"));review_seconds=three["review"]["summed_call_seconds"]+sum(values[k]["summed_call_seconds"] for k in ("openai_review","crewai_review"))
    output={"schema_version":"five-framework-development-score-1","detection_rows":detection,"detection":{"precision":ratio(tp,tp+fp),"recall":ratio(tp,tp+fn),"accuracy":ratio(tp+tn,len(detection)),"runtime_verified":ratio(sum(r["runtime_verified"] for r in detection),len(detection))},"repair":{"problem_positives":positives,"solution_proposed":ratio(proposed,positives),"patch_generated":ratio(generated,positives),"effective_repair":ratio(effective,positives),"discovered_and_effectively_repaired":ratio(joint,positives),"allow_exact_preservation":ratio(exact,positives)},"review":{"actual_calls":review_calls,"actual_tokens":review_tokens,"summed_call_seconds":review_seconds,"semantic_authority":"heterogeneous_historical_for_first_two_diagnostic_only_for_last_three","pooled_semantic_accuracy_reported":False,"typed_field_accuracy":{"pydantic-ai-slim":three["review"]["pydantic_typed_field_accuracy"],"openai-agents":values["openai_review"]["typed_field_accuracy"],"crewai":values["crewai_review"]["typed_field_accuracy"]}},"coverage":{"frameworks":5,"samples":len(detection),"positive":positives,"negative":len(detection)-positives,"source_families":5,"languages":["python"],"holdout_eligible_samples":0},"inputs_sha256":inputs,"holdout_eligible":False,"scope":"five_framework_ten_sample_exposed_development_pipeline_not_confirmatory_holdout","claim_boundary":"All detection and repair scores are owned exposed controls. Static certificates and runtime evidence own release; LLM semantic accuracy is not pooled and does not support detection-improvement claims.","goal_completion_proven":False}
    DIRECTORY.mkdir();
    with (DIRECTORY/"SCORES.json").open("x") as handle:json.dump(output,handle,indent=2,sort_keys=True);handle.write("\n")
    print(json.dumps({"detection":output["detection"],"repair":output["repair"],"review_calls":review_calls,"review_tokens":review_tokens,"coverage":output["coverage"]}))
if __name__=="__main__":main()
