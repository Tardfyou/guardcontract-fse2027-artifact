"""Validate the existing strict direct statistical frame for static auditing."""
import json
from collections import Counter
from pathlib import Path

REQUIRED=("commit","tree","source_file_sha256","same_unit_import_provenance")

def gate(path):
    payload=json.loads(Path(path).read_text(encoding="utf-8")); accepted=[]; rejected=[]
    for row in payload.get("included_records",[]):
        source=Path(row["destination"])/row["path"]
        if all(row.get(key) for key in REQUIRED) and source.is_file(): accepted.append(row)
        else: rejected.append({"record_id":row.get("record_id"),"repository":row.get("repository"),"reason":"missing_static_evidence"})
    logical={(r["repository"],r["path"],r["line"]) for r in accepted}
    source_families={r["source_file_sha256"] for r in accepted}
    return {"schema_version":"legacy-static-frame-gate-1","rows":accepted,"rejected":rejected,
            "counts":{"included_records":len(payload.get("included_records",[])),"static_auditable_sites":len(accepted),"unique_logical_sites":len(logical),"repositories":len({r["repository"] for r in accepted}),"source_file_families":len(source_families),"rejected":len(rejected),"frameworks":len({r["framework"] for r in accepted}),"languages":len({r["language"] for r in accepted})},
            "timing":dict(Counter(r.get("timing","unknown") for r in accepted)),
            "claim_boundary":"Static direct-relevance frame only. It does not provide issue labels, runtime behavior, independent holdout, or prevalence."}

if __name__=="__main__":
    source=Path("experiments/framework-source-expansion-n75-dev/STRICT_DIRECT_STATISTICAL_FRAME_I4.json")
    result=gate(source); out=Path("experiments/legacy-static-frame-gate-n318"); out.mkdir(exist_ok=True); (out/"RESULT.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n"); print(json.dumps(result["counts"],sort_keys=True))
