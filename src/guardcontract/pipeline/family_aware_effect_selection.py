"""Select effect candidates while avoiding exact blob and organization repeats."""
import json
from collections import defaultdict
from pathlib import Path

def select(source, used_frames, per_framework=6):
    used_names=set(); used_blobs=set()
    for path in used_frames:
        payload=json.loads(Path(path).read_text())
        for row in payload.get("selected",[]):
            used_names.add(row["repository"]["full_name"])
            for location in row.get("locations",row.get("matched_files",[])):
                if location.get("blob_sha"): used_blobs.add(location["blob_sha"])
    records=json.loads(Path(source).read_text())["records"]
    selected=[]; organizations=set()
    for framework in sorted({r["framework"] for r in records}):
        pool=[r for r in records if r.get("status")=="pinned" and r["framework"]==framework]
        for row in pool:
            name=row["repository"]["full_name"]; org=name.split("/",1)[0]
            blobs={x.get("blob_sha") for x in row.get("locations",[]) if x.get("blob_sha")}
            if name in used_names or blobs & used_blobs or org in organizations: continue
            selected.append(row); organizations.add(org)
            if sum(x["framework"]==framework for x in selected)>=per_framework: break
    return {"schema_version":"family-aware-effect-selection-1","selected":selected,"counts":{"selected":len(selected),"by_framework":{f:sum(x["framework"]==f for x in selected) for f in sorted({x["framework"] for x in selected})}},"claim_boundary":"Selection diversity heuristic only; family identity requires source materialization."}

if __name__=="__main__":
    root=Path("experiments"); out=select(root/"prospective-guard-effect-commit-n281/RESULT.json",[root/"prospective-effect-batch-n303/FRAME.json",root/"prospective-effect-batch-n304/FRAME.json"])
    target=root/"prospective-effect-selection-n307"; target.mkdir(exist_ok=True); (target/"FRAME.json").write_text(json.dumps(out,indent=2,sort_keys=True)+"\n"); print(json.dumps(out["counts"],sort_keys=True))
