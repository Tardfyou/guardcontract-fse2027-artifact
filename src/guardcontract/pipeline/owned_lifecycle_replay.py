"""Replay the two owned lifecycle topologies used by the static oracle queue."""
import json
from pathlib import Path

def run(mode, decision):
    events=[]
    if mode=="output_guard_original":
        events.append("effect:web-search")
        events.append(f"guard_verdict:{decision}")
    elif mode=="pre_effect_repair":
        events.append(f"guard_verdict:{decision}")
        if decision=="ALLOW": events.append("effect:web-search")
    else: raise ValueError("lifecycle_mode")
    return {"mode":mode,"decision":decision,"events":events,"effect_occurred":"effect:web-search" in events,"allow_return":{"status":"allowed"} if decision=="ALLOW" else {"status":"denied"}}

def main():
    rows=[]
    for family in ("06e87b9daf6ca6fb002383be4f32680d67b607feae4321310edc394d6dde0893","2cf518e4a54fa01bb37b2452391304189b69297c35659e397af3e134c994e957"):
        original={d:run("output_guard_original",d) for d in ("ALLOW","DENY")}
        repaired={d:run("pre_effect_repair",d) for d in ("ALLOW","DENY")}
        rows.append({"source_family_sha256":family,"original":original,"repaired":repaired,"checks":{"original_deny_effect":original["DENY"]["effect_occurred"],"repaired_deny_zero_effect":not repaired["DENY"]["effect_occurred"],"allow_exact":repaired["ALLOW"]["allow_return"]==original["ALLOW"]["allow_return"]}})
    result={"schema_version":"owned-lifecycle-replay-1","rows":rows,"claim_boundary":"Owned inert topology replay only; does not execute public repositories or prove their runtime behavior."}
    out=Path("experiments/prospective-effect-batch-n303/OWNED_LIFECYCLE_REPLAY.json"); out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n"); print(json.dumps({"families":len(rows),"all_checks":all(all(r["checks"].values()) for r in rows)}))
if __name__=="__main__": main()
