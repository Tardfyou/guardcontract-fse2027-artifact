"""Freeze a stratified 1,000-site static audit sample."""
import json
from collections import defaultdict, Counter
from pathlib import Path

def select(path, target=1000):
    payload=json.loads(Path(path).read_text(encoding="utf-8")); rows=payload["included_records"]
    strata=defaultdict(list)
    for row in rows:
        strata[(row.get("framework","unknown"),row.get("language","unknown"),row.get("timing","unknown"))].append(row)
    for values in strata.values(): values.sort(key=lambda r:(r.get("record_id",""),r.get("repository",""),r.get("path",""),r.get("line",0)))
    selected=[]; used_families=set(); cursor=0; keys=sorted(strata)
    while len(selected)<target and keys:
        progressed=False
        for key in keys:
            values=strata[key]
            while values and values[0].get("source_file_sha256") in used_families: values.pop(0)
            if not values: continue
            row=values.pop(0); selected.append(row); used_families.add(row["source_file_sha256"]); progressed=True
            if len(selected)>=target: break
        if not progressed: break
    selected_ids={r.get("record_id") for r in selected}
    excluded=[{"record_id":r.get("record_id"),"repository":r.get("repository"),"reason":"not_selected_after_stratified_family_round_robin"} for r in rows if r.get("record_id") not in selected_ids]
    return {"schema_version":"static-sample-selection-1","selected":selected,"excluded":excluded,"counts":{"target":target,"selected":len(selected),"excluded":len(excluded),"source_file_families":len({r["source_file_sha256"] for r in selected}),"repositories":len({r["repository"] for r in selected}),"frameworks":len({r["framework"] for r in selected}),"languages":len({r["language"] for r in selected})},"by_framework":dict(sorted(Counter(r["framework"] for r in selected).items())),"by_language":dict(sorted(Counter(r["language"] for r in selected).items())),"by_timing":dict(sorted(Counter(r.get("timing","unknown") for r in selected).items())),"claim_boundary":"Static stratified sample only; no behavior labels, prevalence, or holdout claim."}

if __name__=="__main__":
    source=Path("experiments/framework-source-expansion-n75-dev/STRICT_DIRECT_STATISTICAL_FRAME_I4.json")
    result=select(source); out=Path("experiments/static-sample-selection-n320"); out.mkdir(exist_ok=True); (out/"FRAME.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n"); print(json.dumps(result["counts"],sort_keys=True))
