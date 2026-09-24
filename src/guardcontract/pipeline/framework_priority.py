"""Rank framework adapters by available static sample volume and current support."""
import json
from pathlib import Path

PARTIAL={"langchain","openai-agents","crewai"}
CORE={"langchain","google-adk","pydantic-ai","openai-agents","crewai"}

def rank(path):
    payload=json.loads(Path(path).read_text()); counts=payload["by_framework"]
    rows=[]
    for framework,samples in counts.items():
        if framework in PARTIAL: support="partial"
        elif framework in CORE: support="unsupported-repository"
        else: support="discovery-only"
        priority=(0 if framework in CORE else 1, -samples)
        rows.append({"framework":framework,"samples":samples,"current_repository_support":support,"priority_key":priority})
    rows.sort(key=lambda row: row["priority_key"])
    for index,row in enumerate(rows,1): row["priority_rank"]=index
    return {"schema_version":"framework-priority-1","rows":rows,"claim_boundary":"Planning priority only; sample volume is not prevalence and support labels are not correctness claims."}

if __name__=="__main__":
    result=rank("experiments/static-full-frame-n322/FRAME.json"); out=Path("experiments/framework-priority-n324"); out.mkdir(exist_ok=True); (out/"RESULT.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n"); print(json.dumps(result["rows"][:10],sort_keys=True))
