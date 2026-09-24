"""Create an independent, execution-free oracle queue for verified paths."""
import json
from pathlib import Path

def queue(path_audit):
    payload=json.loads(Path(path_audit).read_text()); rows=[]
    for row in payload.get("rows",[]):
        if row.get("status") != "path_supported": continue
        rows.append({"repository":row["repository"],"framework":row["framework"],"path":row["path"],"static_label":"behavior_candidate","guard_verdict":"DENY","protected_effect":"outbound-search","runtime_state":"unverified","oracle_basis":"framework output-guard lifecycle plus explicit WebSearchTool constructor","requires_runtime_confirmation":True})
    return {"schema_version":"behavior-oracle-queue-1","rows":rows,"counts":{"queued":len(rows),"runtime_verified":0},"claim_boundary":"Independent oracle queue only; static evidence is not runtime behavior."}

if __name__=="__main__":
    root=Path("experiments/prospective-effect-batch-n303")
    result=queue(root/"EFFECT_PATH_AUDIT.json")
    (root/"BEHAVIOR_ORACLE_QUEUE.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(json.dumps(result["counts"],sort_keys=True))
