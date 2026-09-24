"""Measure framework-neutral registration routing yield on the frozen guard pilot."""
import hashlib,json
from collections import Counter
from pathlib import Path
from guardcontract.discovery.registration_router import route_registration_repository
from guardcontract.paths import project_root
ROOT=project_root();DIRECTORY=ROOT/"experiments/prospective-registration-yield-n277"
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_bytes())
def write_new(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("x") as handle:json.dump(value,handle,indent=2,sort_keys=True);handle.write("\n")
def prepare():
    if DIRECTORY.exists():raise ValueError("registration277_existing")
    frame=ROOT/"experiments/prospective-guard-materialization-n275/FRAME.json";material=ROOT/"experiments/prospective-guard-materialization-n275/RESULT.json";code=[Path(__file__),ROOT/"src/guardcontract/discovery/registration_router.py",ROOT/"src/guardcontract/discovery/registration.py",ROOT/"src/guardcontract/discovery/router.py",ROOT/"src/guardcontract/evidence/slicing.py",ROOT/"src/guardcontract/evidence/validation.py",ROOT/"src/guardcontract/core/schemas.py"]
    DIRECTORY.mkdir();write_new(DIRECTORY/"RUN_PLAN.json",{"schema_version":"registration-yield-plan-1","frame":str(frame.relative_to(ROOT)),"materialization":str(material.relative_to(ROOT)),"inputs_sha256":{str(p.relative_to(ROOT)):sha(p) for p in [frame,material,*code]},"repositories":25,"max_jobs_per_repository":40,"max_total_bytes":65536,"max_slice_bytes":32768,"context_lines":8,"mode":"local","configuration_frozen_before_analysis":True,"holdout_admission_authorized":False,"goal_completion_proven":False});print(json.dumps({"repositories":25,"configuration_frozen":True}))
def run():
    plan=read(DIRECTORY/"RUN_PLAN.json")
    for relative,expected in plan["inputs_sha256"].items():
        if sha(ROOT/relative)!=expected:raise ValueError("registration277_input_drift:"+relative)
    frame=read(ROOT/plan["frame"]);material=read(ROOT/plan["materialization"]);roots={r["repository"]:ROOT/r["destination"] for r in material["repositories"] if r["status"]=="completed"};rows=[]
    for selected in frame["selected"]:
        name=selected["repository"]["full_name"]
        try:
            jobs,accounting=route_registration_repository(roots[name],f"{name}@{selected['pinned_commit']}",selected["framework"],mode=plan["mode"],max_jobs=plan["max_jobs_per_repository"],max_total_bytes=plan["max_total_bytes"],max_slice_bytes=plan["max_slice_bytes"],context_lines=plan["context_lines"]);groups=accounting["discovery"]["groups"]
            rows.append({"repository":name,"framework":selected["framework"],"status":"completed","groups":len(groups),"groups_with_effects":sum(bool(g["effects"]) for g in groups),"routed_jobs":len(jobs),"not_routed":accounting["counts"]["not_routed"],"groups_budget_deferred":accounting["counts"]["groups_budget_deferred"],"group_kinds":dict(Counter(g["kind"] for g in groups))})
        except Exception as exc:rows.append({"repository":name,"framework":selected["framework"],"status":"error","error_kind":type(exc).__name__})
    counts={"repositories":len(rows),"completed":sum(r["status"]=="completed" for r in rows),"errors":sum(r["status"]=="error" for r in rows),"repositories_with_groups":sum(r.get("groups",0)>0 for r in rows),"repositories_with_effect_groups":sum(r.get("groups_with_effects",0)>0 for r in rows),"repositories_with_routed_jobs":sum(r.get("routed_jobs",0)>0 for r in rows),"groups":sum(r.get("groups",0) for r in rows),"groups_with_effects":sum(r.get("groups_with_effects",0) for r in rows),"routed_jobs":sum(r.get("routed_jobs",0) for r in rows),"by_framework":{f:{"repositories":sum(r["framework"]==f for r in rows),"with_groups":sum(r["framework"]==f and r.get("groups",0)>0 for r in rows),"with_routed_jobs":sum(r["framework"]==f and r.get("routed_jobs",0)>0 for r in rows)} for f in sorted({r["framework"] for r in rows})}}
    result={"schema_version":"registration-yield-result-1","rows":rows,"counts":counts,"execution_health":"completed" if not counts["errors"] else "partial","study_use":"post_freeze_registration_yield_not_holdout_scoring","source_content_persisted":False,"holdout_admission_authorized":False,"goal_completion_proven":False};write_new(DIRECTORY/"RESULT.json",result);print(json.dumps(counts,sort_keys=True))
def main():
    import argparse;p=argparse.ArgumentParser(description=__doc__);p.add_argument("mode",choices=("prepare","run"));{"prepare":prepare,"run":run}[p.parse_args().mode]()
if __name__=="__main__":main()
