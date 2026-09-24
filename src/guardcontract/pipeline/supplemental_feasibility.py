"""Freeze feasibility evidence for paper-oriented supplemental frameworks."""
import json
from collections import Counter
from pathlib import Path

TARGETS=("langgraph","microsoft-agent-framework","vercel-ai-sdk")

def assess(path):
    payload=json.loads(Path(path).read_text(encoding="utf-8")); rows=payload.get("included_records",[]); result=[]
    for framework in TARGETS:
        subset=[r for r in rows if r.get("framework")==framework]
        result.append({"framework":framework,"static_sites":len(subset),"repositories":len({r.get("repository") for r in subset}),"languages":dict(Counter(r.get("language","unknown") for r in subset)),"source_files":len({r.get("source_file_sha256") for r in subset}),"feasibility":"candidate_inclusion" if len(subset)>=50 else "defer","required_work":"framework adapter, lifecycle semantics, repair and independent runtime validation"})
    return {"schema_version":"supplemental-feasibility-1","frameworks":result,"selection_rule":"Include only after static direct sample count, distinct lifecycle semantics, and an executable owned validation fixture are all available.","claim_boundary":"Feasibility evidence only; static site counts are not adoption, issue labels, or runtime results."}

if __name__=="__main__":
    result=assess("experiments/framework-source-expansion-n75-dev/STRICT_DIRECT_STATISTICAL_FRAME_I4.json"); out=Path("experiments/supplemental-feasibility-n326"); out.mkdir(exist_ok=True); (out/"RESULT.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n"); print(json.dumps(result["frameworks"],sort_keys=True))
