"""Expose every statically auditable record; 1,000 is a floor, not a cap."""
import json
from collections import Counter
from pathlib import Path

def build(path):
    payload=json.loads(Path(path).read_text(encoding="utf-8")); rows=payload["included_records"]
    valid=[]; rejected=[]
    for row in rows:
        source=Path(row["destination"])/row["path"]
        if all(row.get(k) for k in ("commit","tree","source_file_sha256","same_unit_import_provenance")) and source.is_file(): valid.append(row)
        else: rejected.append({"record_id":row.get("record_id"),"reason":"missing_static_evidence"})
    family_first={}
    for row in valid: family_first.setdefault(row["source_file_sha256"], row)
    return {"schema_version":"static-full-frame-1","records":valid,"family_representatives":list(family_first.values()),"counts":{"static_auditable_sites":len(valid),"source_file_families":len(family_first),"repositories":len({r["repository"] for r in valid}),"frameworks":len({r["framework"] for r in valid}),"languages":len({r["language"] for r in valid}),"rejected":len(rejected)},"by_framework":dict(sorted(Counter(r["framework"] for r in valid).items())),"by_language":dict(sorted(Counter(r["language"] for r in valid).items())),"claim_boundary":"All available statically auditable records are retained; 1,000 is a minimum scale target. No behavior labels, prevalence, or holdout claim."}

if __name__=="__main__":
    result=build("experiments/framework-source-expansion-n75-dev/STRICT_DIRECT_STATISTICAL_FRAME_I4.json"); out=Path("experiments/static-full-frame-n322"); out.mkdir(exist_ok=True); (out/"FRAME.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n"); print(json.dumps(result["counts"],sort_keys=True))
