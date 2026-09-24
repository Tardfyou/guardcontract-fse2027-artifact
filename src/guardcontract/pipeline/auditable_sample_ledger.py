"""Aggregate prospective discovery outputs without inflating duplicate families."""
import hashlib,json
from collections import Counter
from pathlib import Path

def build(paths):
    repositories={}; sites=[]
    for path in paths:
        payload=json.loads(Path(path).read_text())
        for row in payload.get("repositories",[]):
            key=(row.get("repository"),row.get("commit"))
            repositories[key]={"repository":row.get("repository"),"framework":row.get("framework"),"commit":row.get("commit"),"status":row.get("status"),"source":str(path)}
            for site in row.get("sites",[]):
                effects=site.get("tool_evidence",{}).get("explicit_effects",[])
                sites.append({"repository":row.get("repository"),"framework":row.get("framework"),"commit":row.get("commit"),"path":site.get("path"),"line":site.get("line"),"effect":bool(effects),"path_status":site.get("path_status","unverified"),"source":str(path)})
    unique_sites={(s["repository"],s["commit"],s["path"],s["line"]):s for s in sites}
    counts=Counter("auditable" if s["effect"] and s["path_status"]=="path_verified" else "effect_candidate" if s["effect"] else "guard_only" for s in unique_sites.values())
    return {"schema_version":"auditable-sample-ledger-1","repositories":list(repositories.values()),"sites":list(unique_sites.values()),"counts":{"repositories":len(repositories),"sites":len(unique_sites),**counts},"claim_boundary":"Prospective static ledger only; no behavior oracle or prevalence claim."}

if __name__=="__main__":
    root=Path("experiments"); out=build([root/"prospective-batch-materialization-n302/DISCOVERY_RESULT.json",root/"prospective-effect-batch-n303/DISCOVERY_RESULT.json"])
    target=root/"prospective-auditable-ledger-n305"; target.mkdir(exist_ok=True)
    (target/"LEDGER.json").write_text(json.dumps(out,indent=2,sort_keys=True)+"\n")
    print(json.dumps(out["counts"],sort_keys=True))
