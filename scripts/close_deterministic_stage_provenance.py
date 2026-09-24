"""Add honest post-run provenance sidecars to deterministic historical stages."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import time

ROOT=Path(__file__).resolve().parents[1]
def read(path):return json.loads(Path(path).read_bytes())
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--result",type=Path,required=True)
    parser.add_argument("--stage",required=True);args=parser.parse_args();result=args.result.resolve();directory=result.parent
    plan_path,manifest_path=directory/"RUN_PLAN.json",directory/"RUN_MANIFEST.json"
    if plan_path.exists() or manifest_path.exists():parser.error("sidecar already exists")
    value=read(result);inputs=dict(value.get("inputs") or {})
    inputs[str(Path(__file__).resolve().relative_to(ROOT))]=sha(Path(__file__))
    plan={"schema_version":"deterministic-stage-retrospective-plan-1","stage":args.stage,
          "task_version":"retrospective-provenance-1-1","created_time_ns":time.time_ns(),
          "provenance_timing":"post_run_sidecar_for_preexisting_deterministic_result",
          "inputs":inputs,"output":str(result.relative_to(ROOT)),"model_calls":0,"network":"none",
          "claim_boundary":"This sidecar authenticates a deterministic preexisting result; it is not a claim of prospective preregistration."}
    plan_path.write_text(json.dumps(plan,indent=2,sort_keys=True)+"\n")
    manifest={"schema_version":"deterministic-stage-retrospective-manifest-1","stage":args.stage,
              "plan_sha256":sha(plan_path),"result_sha256":sha(result),"execution_health":value.get("execution_health","completed"),
              "scientific_outcome":"deterministic_result_authenticated","provenance_timing":plan["provenance_timing"],
              "finished_time_ns":time.time_ns()}
    manifest_path.write_text(json.dumps(manifest,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"stage":args.stage,"plan":str(plan_path.relative_to(ROOT)),"manifest":str(manifest_path.relative_to(ROOT))}))


if __name__=="__main__":main()
