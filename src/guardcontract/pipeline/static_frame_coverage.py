"""Summarize coverage and uncertainty of the validated static direct frame."""
import json
from collections import Counter
from pathlib import Path

def summarize(path):
    payload=json.loads(Path(path).read_text(encoding="utf-8")); rows=payload.get("included_records",[])
    def counts(field): return dict(sorted(Counter(row.get(field,"unknown") or "unknown" for row in rows).items()))
    return {"schema_version":"static-frame-coverage-1","counts":{"sites":len(rows),"repositories":len({r["repository"] for r in rows}),"frameworks":len({r["framework"] for r in rows}),"languages":len({r["language"] for r in rows}),"source_layers":len({r.get("source_layer","unknown") for r in rows})},"by_framework":counts("framework"),"by_language":counts("language"),"by_timing":counts("timing"),"by_source_layer":counts("source_layer"),"claim_boundary":"Coverage of a static direct-relevance frame. Timing unknown is retained and is not an issue label; no runtime, prevalence, or holdout claim."}

if __name__=="__main__":
    source=Path("experiments/framework-source-expansion-n75-dev/STRICT_DIRECT_STATISTICAL_FRAME_I4.json")
    result=summarize(source); out=Path("experiments/static-frame-coverage-n319"); out.mkdir(exist_ok=True); (out/"RESULT.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n"); print(json.dumps(result["counts"],sort_keys=True))
