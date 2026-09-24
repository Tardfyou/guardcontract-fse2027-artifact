"""Scan materialized repositories with the shared registration index."""
import json
from pathlib import Path
from guardcontract.discovery.registration import discover_registrations

def scan(frame_path, materialization_path, output_path):
    frame=json.loads(Path(frame_path).read_text()); material=json.loads(Path(materialization_path).read_text())
    roots={r["repository"]:Path(r["destination"]) for r in material.get("repositories",[]) if r.get("status")=="completed"}
    rows=[]
    for item in frame.get("selected",[]):
        name=item.get("repository",{}).get("full_name"); root=roots.get(name)
        if root is None: continue
        result=discover_registrations(root)
        rows.append({"repository":name,"framework":item.get("framework"),"groups":result["groups"],"unresolved_registrations":result["unresolved_registrations"],"execution_health":result["execution_health"]})
    output={"schema_version":"registration-batch-scan-1","rows":rows,"counts":{"repositories":len(rows),"groups":sum(len(r["groups"]) for r in rows),"unresolved":sum(len(r["unresolved_registrations"]) for r in rows)},"claim_boundary":"Registration candidates only; no path, behavior, issue, or prevalence claim."}
    Path(output_path).write_text(json.dumps(output,indent=2,sort_keys=True)+"\n"); return output

if __name__=="__main__":
    root=Path("experiments/prospective-effect-selection-n311"); result=scan(root/"FRAME.json",root/"RESULT.json",root/"REGISTRATION_SCAN.json"); print(json.dumps(result["counts"],sort_keys=True))
