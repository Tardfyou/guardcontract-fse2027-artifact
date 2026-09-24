"""Freeze and run fail-closed repository discovery on the second source batch."""
import hashlib,json
from pathlib import Path
from guardcontract.discovery.repository_analysis_v2 import analyze
from guardcontract.paths import project_root
ROOT=project_root();DIRECTORY=ROOT/"experiments/prospective-discovery-confirm-n270"
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_bytes())
def write_new(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("x") as handle:json.dump(value,handle,indent=2,sort_keys=True);handle.write("\n")
def prepare():
    if DIRECTORY.exists():raise ValueError("discovery270_existing")
    source_frame=ROOT/"experiments/prospective-materialization-confirm-n269/FRAME.json";materialization=ROOT/"experiments/prospective-materialization-confirm-n269/RESULT.json";source=read(source_frame);frame={**source,"schema_version":"prospective-discovery-confirm-frame-1","selected":[{**r,"matched_files":[]} for r in source["selected"]]};config={"schema_version":1,"task_version":"270-1","split":"prospective_second_frozen_identity_source_yield_confirmation_not_holdout_metrics","frame":"experiments/prospective-discovery-confirm-n270/FRAME.json","materialization":str(materialization.relative_to(ROOT)),"repository_list_field":"selected","max_python_file_bytes":1048576,"max_repository_python_files":5000,"max_config_file_bytes":1048576,"max_repository_config_files":2000,"claim_use":"Frozen source-yield, supported-route and unsupported-gap measurement only."};DIRECTORY.mkdir();write_new(DIRECTORY/"FRAME.json",frame);write_new(DIRECTORY/"CONFIG.json",config)
    code=[Path(__file__),ROOT/"src/guardcontract/discovery/repository_analysis_v2.py",ROOT/"src/guardcontract/discovery/repository_analysis.py",*[ROOT/f"src/guardcontract/discovery/dependencies/analyze_guard_repositories_i{i}.py" for i in range(2,7)]];inputs={str(p.relative_to(ROOT)):sha(p) for p in [source_frame,materialization,DIRECTORY/"FRAME.json",DIRECTORY/"CONFIG.json",*code]};write_new(DIRECTORY/"RUN_PLAN.json",{"schema_version":"prospective-discovery-plan-2","inputs_sha256":inputs,"repositories":25,"configuration_frozen_before_analysis":True,"replacement_after_n268_failure":False,"identity_rank_window":[6,10],"holdout_admission_authorized":False,"goal_completion_proven":False});print(json.dumps({"repositories":25,"configuration_frozen":True,"router":"fail_closed_v2"}))
def run():
    plan=read(DIRECTORY/"RUN_PLAN.json")
    for relative,expected in plan["inputs_sha256"].items():
        if sha(ROOT/relative)!=expected:raise ValueError("discovery270_input_drift:"+relative)
    result=analyze(read(DIRECTORY/"CONFIG.json"));result.update(configuration_frozen_before_analysis=True,holdout_admission_authorized=False,goal_completion_proven=False);write_new(DIRECTORY/"RESULT.json",result);print(json.dumps(result["counts"],sort_keys=True))
def main():
    import argparse;parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("mode",choices=("prepare","run"));{"prepare":prepare,"run":run}[parser.parse_args().mode]()
if __name__=="__main__":main()
