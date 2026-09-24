"""Freeze behavior-oracle plans for statically bound registration groups."""
import json
from pathlib import Path

def build(path):
    source=json.loads(Path(path).read_text()); rows=[]
    for i,row in enumerate(source.get("rows",[]),1):
        rows.append({"case_id":f"registration-{i:03d}","repository":row["repository"],"framework":"openai-agents","source_path":row["path"],"registration_line":row["registration_line"],"guard_symbols":[g["symbol"] for g in row["guards"]],"tool_symbols":[t["symbol"] for t in row["tools"]],"effect_families":sorted({e["family"] for e in row["effects"]}),"oracle_observations":["guard_verdict_event","effect_event_or_marker","event_order","ALLOW_return_object"],"execution_policy":"do_not_execute_public_repository; require isolated owned reproduction or authorized external oracle","status":"awaiting_independent_behavior_oracle"})
    return {"schema_version":"registration-behavior-plan-1","cases":rows,"counts":{"cases":len(rows),"runtime_verified":0},"claim_boundary":"Static registration binding plan only; no public code execution or issue label."}

if __name__=="__main__":
    root=Path("experiments/prospective-effect-selection-n307"); result=build(root/"REGISTRATION_PATH_AUDIT.json"); (root/"REGISTRATION_BEHAVIOR_PLAN.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n"); print(json.dumps(result["counts"],sort_keys=True))
