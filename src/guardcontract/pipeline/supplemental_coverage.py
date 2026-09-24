"""Summarize lifecycle and effect coverage for supplemental candidates."""
import json
from collections import Counter
from pathlib import Path

TARGETS=("langgraph","microsoft-agent-framework","vercel-ai-sdk")
def summarize(path):
    rows=json.loads(Path(path).read_text())["records"]; result=[]
    for framework in TARGETS:
        subset=[r for r in rows if r.get("framework")==framework]
        result.append({"framework":framework,"sites":len(subset),"repositories":len({r["repository"] for r in subset}),"source_families":len({r["source_file_sha256"] for r in subset}),"timing":dict(sorted(Counter(r.get("timing","unknown") or "unknown" for r in subset).items())),"surfaces":dict(sorted(Counter(r.get("surface","unknown") or "unknown" for r in subset).items())),"current_tool_status":"discovery_only","next_gate":"registration binding, effect binding, path proof, owned behavior fixture"})
    return {"schema_version":"supplemental-coverage-1","frameworks":result,"claim_boundary":"Static coverage only; no runtime or issue prevalence claim."}
if __name__=="__main__":
    out=Path("experiments/supplemental-coverage-n328"); out.mkdir(exist_ok=True); outp=summarize("experiments/static-full-frame-n322/FRAME.json"); (out/"RESULT.json").write_text(json.dumps(outp,indent=2,sort_keys=True)+"\n"); print(json.dumps(outp["frameworks"],sort_keys=True))
