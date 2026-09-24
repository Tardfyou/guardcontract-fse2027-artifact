"""Merge exact effect-source family audits across prospective batches."""
import json
from collections import defaultdict
from pathlib import Path

def merge(paths):
    families=defaultdict(list)
    for path in paths:
        payload=json.loads(Path(path).read_text())
        for family in payload.get("families",[]):
            families[family["sha256"]].extend(family.get("members",[]))
    rows=[]
    for digest,members in sorted(families.items()):
        unique={(m.get("repository"),m.get("path")):m for m in members}
        rows.append({"sha256":digest,"members":list(unique.values())})
    repositories=sum(len(row["members"]) for row in rows)
    return {"schema_version":"cross-batch-effect-family-ledger-1","families":rows,
            "counts":{"families":len(rows),"repositories":repositories,
                      "duplicate_repositories":repositories-len(rows)},
            "claim_boundary":"Exact effect-source family identity across named batches; near-copy and behavior independence remain unverified."}

if __name__ == "__main__":
    root=Path("experiments")
    result=merge([root/"prospective-effect-batch-n303/EFFECT_FAMILY_AUDIT.json",
                  root/"prospective-effect-batch-n304/EFFECT_FAMILY_AUDIT.json",
                  root/"prospective-effect-selection-n307/EFFECT_FAMILY_AUDIT.json"])
    out=root/"prospective-cross-batch-family-ledger-n309"
    out.mkdir(exist_ok=True)
    (out/"LEDGER.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(json.dumps(result["counts"],sort_keys=True))
