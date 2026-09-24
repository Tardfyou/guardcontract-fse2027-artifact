"""Deterministic static oracle for queued framework-tool candidates."""
import json
from pathlib import Path

def score(queue_path, path_audit_path):
    queue=json.loads(Path(queue_path).read_text()); audit=json.loads(Path(path_audit_path).read_text())
    supported={r["repository"] for r in audit["rows"] if r["status"]=="path_supported"}
    rows=[]
    for row in queue.get("rows",[]):
        eligible=(row["repository"] in supported and row["framework"]=="openai-agents" and row["guard_verdict"]=="DENY" and row["protected_effect"]=="outbound-search")
        rows.append({**row,"static_oracle":"issue_candidate" if eligible else "unassured","runtime_state":"unverified"})
    return {"schema_version":"static-oracle-1","rows":rows,"counts":{"issue_candidates":sum(r["static_oracle"]=="issue_candidate" for r in rows),"unassured":sum(r["static_oracle"]=="unassured" for r in rows),"runtime_verified":0},"claim_boundary":"Static oracle hypothesis only; runtime behavior and repair remain unverified."}

if __name__=="__main__":
    root=Path("experiments/prospective-effect-batch-n303"); out=score(root/"BEHAVIOR_ORACLE_QUEUE.json",root/"EFFECT_PATH_AUDIT.json")
    (root/"STATIC_ORACLE_RESULT.json").write_text(json.dumps(out,indent=2,sort_keys=True)+"\n"); print(json.dumps(out["counts"],sort_keys=True))
