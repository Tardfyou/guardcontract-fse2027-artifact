"""Close the real-repository repair queue without inventing unconfirmed candidates."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import time

ROOT = Path(__file__).resolve().parents[1]
def read(path): return json.loads(Path(path).read_bytes())
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def close(dec, confirmation):
    vp = {row["contract_id"] for row in dec["rows"]
          if row["protocol_group"] == "compiled_agent_bound_v4"
          and row["DEC_label"] == "VIOLATION-PRESENT"}
    confirmed = set(confirmation["real_repository_queue"]["contract_ids"])
    queue = sorted(vp & confirmed)
    if queue:
        status = "ready_requires_separate_patch_execution"
    else:
        status = "closed_empty_no_independently_confirmed_strict_vp"
    return {"schema_version": "p0-real-repository-repair-closure-1",
            "queue_contract_ids": queue, "counts": {"strict_vp": len(vp),
                                                     "independently_confirmed_vp": len(queue),
                                                     "patches_attempted": 0,
                                                     "verified_repairs": 0,
                                                     "repair_failures": 0},
            "status": status,
            "verified_repair_rate": None,
            "controlled_repair_evidence_is_separate": True,
            "claim_boundary": ("No real repository is patched without both a strict VP witness and independent "
                               "behavior confirmation. An empty queue is not a zero repair rate and does not "
                               "negate the separately reported controlled repair experiments.")}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--dec",type=Path,required=True)
    parser.add_argument("--confirmation",type=Path,required=True);parser.add_argument("--out",type=Path,required=True)
    args=parser.parse_args();paths=[args.dec.resolve(),args.confirmation.resolve(),Path(__file__).resolve()];out=args.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT/"experiments"):parser.error("output must be new under experiments")
    inputs={str(path.relative_to(ROOT)):sha(path) for path in paths};out.mkdir(parents=True)
    plan={"schema_version":"p0-real-repository-repair-plan-1","task_version":"real-repair-closure-1-1",
          "created_time_ns":time.time_ns(),"inputs":inputs,"enrollment":"strict_vp_and_independent_confirmation"}
    (out/"RUN_PLAN.json").write_text(json.dumps(plan,indent=2,sort_keys=True)+"\n")
    result=close(read(paths[0]),read(paths[1]));result["inputs"]=inputs
    (out/"RESULT.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    manifest={"schema_version":"p0-real-repository-repair-manifest-1","plan_sha256":sha(out/"RUN_PLAN.json"),
              "result_sha256":sha(out/"RESULT.json"),"execution_health":"completed",
              "scientific_outcome":"empty_eligible_queue" if not result["queue_contract_ids"] else "queue_ready",
              "planned":len(result["queue_contract_ids"]),"completed":0,"finished_time_ns":time.time_ns()}
    (out/"RUN_MANIFEST.json").write_text(json.dumps(manifest,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"status":result["status"],"counts":result["counts"]},sort_keys=True))


if __name__=="__main__":main()
