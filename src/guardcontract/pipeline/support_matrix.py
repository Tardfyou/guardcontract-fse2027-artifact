"""Build an explicit framework/language support matrix from the frozen sample."""
import json
from collections import Counter
from pathlib import Path

CORE={"langchain","google-adk","pydantic-ai","openai-agents","crewai"}
REPO_PARTIAL={"langchain":"registration-candidate","openai-agents":"repository-partial","crewai":"repository-partial","pydantic-ai":"registration-candidate","google-adk":"registration-candidate"}

def build(path):
    frame=json.loads(Path(path).read_text()); rows=frame["selected"]
    counts=Counter(r["framework"] for r in rows); languages=Counter(r["language"] for r in rows)
    matrix=[]
    for framework in sorted(counts):
        if framework in CORE:
            discovery="closed-control-and-static"
            repair="controlled-fixture-only"
            verification="controlled-runtime-only"
            status="core-development-closed"
            repository_detection="partial" if framework in REPO_PARTIAL else "unsupported"
            repository_repair="unsupported"
            repository_verification="unsupported"
        elif framework in REPO_PARTIAL:
            discovery=REPO_PARTIAL[framework]
            repair="unsupported"
            verification="unsupported"
            status="repository-partial"
            repository_detection=discovery
            repository_repair="unsupported"
            repository_verification="unsupported"
        else:
            discovery="static-direct-frame-only"
            repair="unsupported"
            verification="unsupported"
            status="discovery-only"
            repository_detection="static-direct-frame-only"
            repository_repair="unsupported"
            repository_verification="unsupported"
        matrix.append({"framework":framework,"samples":counts[framework],"status":status,"detection":discovery,"decision":discovery,"repair":repair,"verification":verification,"repository_detection":repository_detection,"repository_detection_implemented":repository_detection in {"partial","registration-candidate","repository-partial","supported"},"repository_detection_fully_supported":repository_detection == "supported","repository_repair":repository_repair,"repository_verification":repository_verification})
    return {"schema_version":"support-matrix-2","matrix":matrix,"languages":dict(sorted(languages.items())),"counts":{"control_detection_supported":sum(r["status"] == "core-development-closed" for r in matrix),"repository_detection_implemented":sum(r["repository_detection_implemented"] for r in matrix),"repository_detection_fully_supported":sum(r["repository_detection_fully_supported"] for r in matrix)},"claim_boundary":"Support inventory for the frozen static sample. Implemented repository detection includes partial candidate analyzers; fully supported means an explicit repository_detection=supported status. Neither status implies ecosystem prevalence or runtime correctness."}

if __name__=="__main__":
    import argparse
    parser=argparse.ArgumentParser(description="Write a support matrix without overwriting an existing result")
    parser.add_argument("--frame",default="experiments/static-sample-selection-n320/FRAME.json")
    parser.add_argument("--output",default="experiments/support-matrix-n321/RESULT.json")
    args=parser.parse_args()
    result=build(args.frame)
    result["frame_sha256"]=__import__("hashlib").sha256(Path(args.frame).read_bytes()).hexdigest()
    result["generator"]="guardcontract.pipeline.support_matrix"
    out=Path(args.output); out.parent.mkdir(parents=True,exist_ok=True)
    if out.exists(): raise ValueError("support_matrix_output_exists")
    out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n"); print(json.dumps({"frameworks":len(result["matrix"]),"languages":len(result["languages"]),"output":str(out)},sort_keys=True))
