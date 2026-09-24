"""Apply the final auditable-sample gates without changing source artifacts."""
import json
from collections import Counter
from pathlib import Path

def gate(discovery_paths, path_audits, family_ledger, runtime_queues):
    discoveries=[]
    for path in discovery_paths:
        discoveries.extend(json.loads(Path(path).read_text()).get("repositories", []))
    path_rows={}
    for path in path_audits:
        for row in json.loads(Path(path).read_text()).get("rows", []):
            path_rows[(row.get("repository"),row.get("path"))]=row
    family=json.loads(Path(family_ledger).read_text())
    family_by_repo={m.get("repository"): f["sha256"] for f in family.get("families", []) for m in f.get("members", [])}
    runtime=set()
    for path in runtime_queues:
        payload=json.loads(Path(path).read_text())
        runtime.update((r.get("repository"),r.get("path")) for r in payload.get("rows", []) if r.get("runtime_state")=="verified")
    rows=[]
    for repo in discoveries:
        for site in repo.get("sites", []):
            effects=site.get("tool_evidence", {}).get("explicit_effects", [])
            key=(repo.get("repository"),site.get("path")); evidence=path_rows.get(key, {})
            checks={"explicit_effect":bool(effects),"path_supported":evidence.get("status")=="path_supported","family_known":repo.get("repository") in family_by_repo,"runtime_verified":key in runtime}
            status="behavior_verified" if all(checks.values()) else "static_auditable" if checks["explicit_effect"] and checks["path_supported"] and checks["family_known"] else "candidate" if checks["explicit_effect"] and checks["path_supported"] else "excluded"
            rows.append({"repository":repo.get("repository"),"framework":repo.get("framework"),"path":site.get("path"),"line":site.get("line"),"family_sha256":family_by_repo.get(repo.get("repository")),"status":status,"checks":checks})
    counts=Counter(row["status"] for row in rows)
    counts["static_auditable_samples"]=counts.get("static_auditable",0)+counts.get("behavior_verified",0)
    counts["behavior_verified_samples"]=counts.get("behavior_verified",0)
    return {"schema_version":"sample-gate-2","rows":rows,"counts":dict(counts),"claim_boundary":"Static-auditable rows have effect, path and family evidence; behavior-verified rows additionally require an independent runtime oracle. Neither tier is a prevalence or holdout claim."}

if __name__=="__main__":
    root=Path("experiments")
    result=gate(
        [root/"prospective-effect-batch-n303/DISCOVERY_RESULT.json",root/"prospective-effect-batch-n304/DISCOVERY_RESULT.json",root/"prospective-effect-selection-n307/DISCOVERY_RESULT.json",root/"prospective-effect-selection-n311/DISCOVERY_RESULT.json"],
        [root/"prospective-effect-batch-n303/EFFECT_PATH_AUDIT.json",root/"prospective-effect-batch-n304/EFFECT_PATH_AUDIT.json",root/"prospective-effect-selection-n307/EFFECT_PATH_AUDIT.json",root/"prospective-effect-selection-n311/EFFECT_PATH_AUDIT.json"],
        root/"prospective-cross-batch-family-ledger-n312/LEDGER.json",
        [root/"prospective-effect-batch-n303/BEHAVIOR_ORACLE_QUEUE.json",root/"prospective-effect-batch-n304/BEHAVIOR_ORACLE_QUEUE.json",root/"prospective-effect-selection-n307/BEHAVIOR_ORACLE_QUEUE.json",root/"prospective-effect-selection-n311/BEHAVIOR_ORACLE_QUEUE.json"])
    out=root/"prospective-sample-gate-n316"; out.mkdir(exist_ok=True); (out/"RESULT.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n"); print(json.dumps(result["counts"],sort_keys=True))
