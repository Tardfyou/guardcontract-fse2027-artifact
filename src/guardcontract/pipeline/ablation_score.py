"""Budget-matched four-arm development ablation over the shared four samples."""
import hashlib,json
from pathlib import Path

from guardcontract.paths import project_root

ROOT=project_root();DIRECTORY=ROOT/"experiments/four-arm-ablation-n238"
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_bytes())
def ratio(n,d):return {"numerator":n,"denominator":d,"value":n/d if d else None}

def metrics(rows):
    tp=sum(r["prediction"] is True and r["reference"] is True for r in rows);fp=sum(r["prediction"] is True and r["reference"] is False for r in rows)
    fn=sum(r["prediction"] is not True and r["reference"] is True for r in rows);tn=sum(r["prediction"] is False and r["reference"] is False for r in rows)
    return {"precision":ratio(tp,tp+fp),"recall":ratio(tp,tp+fn),"accuracy":ratio(tp+tn,len(rows)),
            "known_prediction_coverage":ratio(sum(r["prediction"] is not None for r in rows),len(rows))}

def main():
    if DIRECTORY.exists():raise ValueError("ablation238_existing_score")
    paths={"cross":ROOT/"experiments/cross-framework-score-n236/SCORES.json","llm":ROOT/"experiments/llm-only-ablation-n237/SCORES.json",
        "lang_review":ROOT/"experiments/certificate-review-n225/RESULT.json","lang_eval":ROOT/"experiments/certificate-review-n225/EVALUATION_PLAN.json",
        "adk_review":ROOT/"experiments/adk-certificate-review-n234/RESULT.json","adk_eval":ROOT/"experiments/adk-certificate-review-n234/EVALUATION_PLAN.json",
        "lang_plan":ROOT/"experiments/certificate-review-n225/RUN_PLAN.json","adk_plan":ROOT/"experiments/adk-certificate-review-n234/RUN_PLAN.json",
        "llm_plan":ROOT/"experiments/llm-only-ablation-n237/RUN_PLAN.json","code":Path(__file__)}
    inputs={str(p.relative_to(ROOT)):sha(p) for p in paths.values()};values={k:read(p) for k,p in paths.items() if k!="code"}
    if any(values[k]["model"]!="DeepSeek-V4-Pro-0813" for k in ("lang_plan","adk_plan","llm_plan")):raise ValueError("ablation238_model_mismatch")
    if values["lang_plan"]["max_total_tokens_stop_before_next_call"]+values["adk_plan"]["max_total_tokens_stop_before_next_call"]!=128000 or values["llm_plan"]["max_total_tokens_stop_before_next_call"]!=128000:raise ValueError("ablation238_budget_mismatch")
    gold={r["sample_id"]:r["reference"] for r in values["cross"]["detection_rows"]};static={r["sample_id"]:r["prediction"] for r in values["cross"]["detection_rows"]}
    static_rows=[{"sample_id":sid,"reference":gold[sid],"prediction":static[sid]} for sid in gold]
    llm_critic={r["sample_id"]:r["prediction"] for r in values["llm"]["critic"]["rows"]};llm_rows=[{"sample_id":sid,"reference":gold[sid],"prediction":llm_critic[sid]} for sid in gold]
    analyst_gate={}
    for prefix in ("lang","adk"):
        expected={r["sample_id"]:r["claim_expectations"] for r in values[prefix+"_eval"]["cells"]}
        records=[r for r in values[prefix+"_review"]["records"] if r["role"]=="analyst"]
        for record in records:
            sid=record["cell_id"].rsplit("-",1)[0];actual={r["claim_id"]:r["verdict"] for r in record["review"]["claims"]} if record["execution_state"]=="completed" else {}
            analyst_gate[sid]=set(actual)==set(expected[sid]) and all(actual[k]==v for k,v in expected[sid].items())
    analyst_rows=[{"sample_id":sid,"reference":gold[sid],"prediction":static[sid] if analyst_gate[sid] else None,"analyst_gate":analyst_gate[sid]} for sid in gold]
    analyst_calls=[c for prefix in ("lang","adk") for r in values[prefix+"_review"]["records"] if r["role"]=="analyst" for c in r["calls"]]
    arms=[
        {"arm":"static","rows":static_rows,"actual_calls":0,"actual_tokens":0,"summed_call_seconds":0.0,"deterministic_runtime_validation":False},
        {"arm":"llm_only","rows":llm_rows,"actual_calls":values["llm"]["actual_calls"],"actual_tokens":values["llm"]["actual_total_tokens"],"summed_call_seconds":values["llm"]["summed_call_seconds"],"deterministic_runtime_validation":False},
        {"arm":"static_plus_llm_analyst","rows":analyst_rows,"actual_calls":len(analyst_calls),"actual_tokens":sum(c["usage"]["total_tokens"] for c in analyst_calls),"summed_call_seconds":sum(c["duration_seconds"] for c in analyst_calls),"deterministic_runtime_validation":False},
        {"arm":"static_plus_llm_analyst_critic_plus_deterministic_validation","rows":static_rows,"actual_calls":values["cross"]["review"]["actual_calls"],
         "actual_tokens":values["cross"]["review"]["actual_tokens"],"summed_call_seconds":values["cross"]["review"]["summed_call_seconds"],"deterministic_runtime_validation":True},]
    for arm in arms:arm["metrics"]=metrics(arm["rows"]);arm["budget_ceiling_tokens"]=128000;arm["budget_policy"]="stop_before_next_call"
    output={"schema_version":"four-arm-ablation-1","arms":arms,"shared_samples":list(gold),"shared_model":"DeepSeek-V4-Pro-0813",
        "shared_budget_ceiling_tokens":128000,"max_output_tokens_per_call":4096,"timeout_seconds":90,"retries":0,"cache":"none",
        "inputs_sha256":inputs,"holdout_eligible":False,"causal_limit":"Arms reuse independently frozen runs; actual calls/tokens differ and static inputs differ by design. This is a budget-ceiling comparison, not equal realized spend.",
        "scope":"four_exposed_development_samples_two_frameworks","goal_completion_proven":False}
    DIRECTORY.mkdir();path=DIRECTORY/"SCORES.json"
    with path.open("x") as handle:json.dump(output,handle,indent=2,sort_keys=True);handle.write("\n")
    print(json.dumps({"arms":[{"arm":a["arm"],"metrics":a["metrics"],"calls":a["actual_calls"],"tokens":a["actual_tokens"]} for a in arms]}))
if __name__=="__main__":main()
