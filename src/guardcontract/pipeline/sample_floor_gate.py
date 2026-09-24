"""Enforce the sample target as a floor while preserving all available records."""
import json
from pathlib import Path

MINIMUM=1000

def evaluate(path, minimum=MINIMUM):
    payload=json.loads(Path(path).read_text(encoding="utf-8"))
    count=payload.get("counts",{}).get("static_auditable_sites",len(payload.get("records",payload.get("included_records",[]))))
    return {"schema_version":"sample-floor-gate-1","minimum":minimum,"available":count,"passed":count>=minimum,"all_records_retained":count==len(payload.get("records",payload.get("included_records",[]))),"claim_boundary":"Minimum static sample scale only; no behavior, prevalence, or holdout claim."}

if __name__=="__main__":
    result=evaluate("experiments/static-full-frame-n322/FRAME.json"); out=Path("experiments/sample-floor-gate-n323"); out.mkdir(exist_ok=True); (out/"RESULT.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n"); print(json.dumps(result,sort_keys=True))
