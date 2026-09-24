"""Aggregate comparable development detection, review, and repair metrics."""
import hashlib,json
from pathlib import Path

from guardcontract.paths import project_root

ROOT=project_root();DIRECTORY=ROOT/"experiments/cross-framework-score-n236"
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_bytes())
def ratio(n,d):return {"numerator":n,"denominator":d,"value":n/d if d else None}


def main():
    if DIRECTORY.exists():raise ValueError("cross236_existing_result")
    paths={
        "lang_review":ROOT/"experiments/certificate-review-n225/SCORES.json",
        "lang_reviewed":ROOT/"experiments/reviewed-certificates-n226/RESULT.json",
        "lang_runtime":ROOT/"experiments/runtime-validated-certificates-n227/RESULT.json",
        "lang_repair":ROOT/"experiments/langchain-repair-n228/RESULT.json",
        "adk_review":ROOT/"experiments/adk-certificate-review-n234/SCORES.json",
        "adk_reviewed":ROOT/"experiments/adk-reviewed-certificates-n235/RESULT.json",
        "adk_runtime":ROOT/"experiments/adk-reviewed-certificates-n235/SCORES.json",
        "adk_repair":ROOT/"experiments/adk-repair-n232/RESULT.json",
        "code":Path(__file__),
    }
    inputs={str(path.relative_to(ROOT)):sha(path) for path in paths.values()};values={key:read(path) for key,path in paths.items() if key!="code"}
    if not values["lang_runtime"]["assembly_ready"] or not values["adk_runtime"]["assembly_ready"]:raise ValueError("cross236_runtime_gate")
    detection=[]
    verified_lang={row["sample_id"]:row["runtime_verified"] for row in values["lang_runtime"]["records"]}
    for row in values["lang_reviewed"]["records"]:
        detection.append({"framework":"langchain","sample_id":row["sample_id"],"prediction":row["issue_prediction"],
                          "reference":row["sample_id"]=="s001","runtime_verified":verified_lang[row["sample_id"]]})
    for row in values["adk_runtime"]["rows"]:
        detection.append({"framework":"google-adk","sample_id":row["sample_id"],"prediction":row["prediction"],
                          "reference":row["runtime_issue"],"runtime_verified":row["runtime_verified"]})
    tp=sum(r["prediction"] is True and r["reference"] is True for r in detection);fp=sum(r["prediction"] is True and r["reference"] is False for r in detection)
    fn=sum(r["prediction"] is not True and r["reference"] is True for r in detection);tn=sum(r["prediction"] is False and r["reference"] is False for r in detection)
    repairs=[("langchain",values["lang_repair"]),("google-adk",values["adk_repair"])]
    positive_count=sum(r["reference"] for r in detection)
    proposed=sum(row["proposed_solutions"] for _,row in repairs);generated=sum(row["generated_patches"] for _,row in repairs)
    effective=sum(row["effective_repairs"] for _,row in repairs);joint=sum(row["discovered_and_effectively_repaired"] for _,row in repairs)
    repair_gates={"langchain":values["lang_repair"]["verification"]["gates"],"google-adk":values["adk_repair"]["gates"]}
    review_calls=sum(values[key]["actual_calls"] for key in ("lang_review","adk_review"));review_tokens=sum(values[key]["actual_total_tokens"] for key in ("lang_review","adk_review"))
    review_seconds=sum(values[key]["summed_call_seconds"] for key in ("lang_review","adk_review"))
    output={"schema_version":"cross-framework-development-score-1","detection_rows":detection,
        "detection":{"precision":ratio(tp,tp+fp),"recall":ratio(tp,tp+fn),"accuracy":ratio(tp+tn,len(detection)),"runtime_verified":ratio(sum(r["runtime_verified"] for r in detection),len(detection))},
        "repair":{"problem_positives":positive_count,"solution_proposed":ratio(proposed,positive_count),"patch_generated":ratio(generated,positive_count),
                  "effective_repair":ratio(effective,positive_count),"discovered_and_effectively_repaired":ratio(joint,positive_count),
                  "allow_exact_preservation":ratio(sum(repair_gates[framework]["allow_observable_behavior_preserved"] for framework,_ in repairs),len(repairs))},
        "review":{"actual_calls":review_calls,"actual_tokens":review_tokens,"summed_call_seconds":review_seconds,
                  "langchain_negative_control_accuracy":values["lang_review"]["negative_control_accuracy"],
                  "google_adk_negative_control_accuracy":values["adk_review"]["negative_control_accuracy"]},
        "coverage":{"frameworks":2,"samples":4,"positive":positive_count,"negative":len(detection)-positive_count,
                    "source_families":2,"languages":["python"],"holdout_eligible_samples":0},
        "inputs_sha256":inputs,"holdout_eligible":False,
        "scope":"two_framework_four_sample_exposed_development_pipeline_not_confirmatory_holdout",
        "goal_completion_proven":False}
    DIRECTORY.mkdir();path=DIRECTORY/"SCORES.json"
    with path.open("x") as handle:json.dump(output,handle,indent=2,sort_keys=True);handle.write("\n")
    print(json.dumps({"detection":output["detection"],"repair":output["repair"],"review_cost":output["review"],"coverage":output["coverage"]}))
if __name__=="__main__":main()
