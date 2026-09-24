"""Validate externally supplied behavior-oracle results without executing code."""
import json
from pathlib import Path

REQUIRED=("guard_verdict","effect_occurred","events","allow_return")

def validate(path):
    payload=json.loads(Path(path).read_text()); rows=[]
    for row in payload.get("rows",[]):
        missing=[k for k in REQUIRED if k not in row]
        event_order=isinstance(row.get("events"),list) and all(isinstance(x,str) for x in row.get("events",[]))
        fields_valid=(row.get("guard_verdict") in ("ALLOW", "DENY")
                      and type(row.get("effect_occurred")) is bool)
        schema_valid=not missing and event_order and fields_valid
        rows.append({"case_id":row.get("case_id"),"status":"schema_valid" if schema_valid else "schema_invalid","runtime_state":"unverified","missing_fields":missing,"events_valid":event_order,"fields_valid":fields_valid,"verification_authorized":False})
    return {"schema_version":"behavior-result-validator-2","rows":rows,"counts":{"verified":0,"unverified":len(rows),"schema_valid":sum(r["status"]=="schema_valid" for r in rows)},"claim_boundary":"Schema validation only; submitted runtime_state is not evidence. Authentication and independent behavior recomputation are required for verification."}

if __name__=="__main__":
    path=Path("experiments/prospective-effect-selection-n307/BEHAVIOR_ORACLE_QUEUE_V3.json"); result=validate(path); out=path.with_name("BEHAVIOR_RESULT_VALIDATION.json"); out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n"); print(json.dumps(result["counts"],sort_keys=True))
