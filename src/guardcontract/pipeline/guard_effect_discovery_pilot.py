"""Run frozen repository discovery on the guard/effect co-occurrence pilot."""
import hashlib,json
from pathlib import Path
from guardcontract.discovery.repository_analysis_v2 import analyze
from guardcontract.paths import project_root
ROOT=project_root();DIRECTORY=ROOT/"experiments/prospective-guard-effect-discovery-n283"
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_bytes())
def write_new(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("x") as handle:json.dump(value,handle,indent=2,sort_keys=True);handle.write("\n")
def prepare():
    if DIRECTORY.exists():raise ValueError("guard283_existing")
    frame=ROOT/"experiments/prospective-guard-effect-materialization-n282/FRAME.json";material=ROOT/"experiments/prospective-guard-effect-materialization-n282/RESULT.json";config={"schema_version":1,"task_version":"283-1","split":"prospective_guard_effect_cooccurrence_pilot_not_holdout_metrics","frame":str(frame.relative_to(ROOT)),"materialization":str(material.relative_to(ROOT)),"repository_list_field":"selected","max_python_file_bytes":1048576,"max_repository_python_files":5000,"max_config_file_bytes":1048576,"max_repository_config_files":2000,"claim_use":"Frozen path/effect yield and unsupported-gap measurement only; query polarity is not a label."};DIRECTORY.mkdir();write_new(DIRECTORY/"CONFIG.json",config);code=[Path(__file__),ROOT/"src/guardcontract/discovery/repository_analysis_v2.py",ROOT/"src/guardcontract/discovery/repository_analysis.py",*[ROOT/f"src/guardcontract/discovery/dependencies/analyze_guard_repositories_i{i}.py" for i in range(2,7)]];write_new(DIRECTORY/"RUN_PLAN.json",{"schema_version":"guard-effect-discovery-plan-1","inputs_sha256":{str(p.relative_to(ROOT)):sha(p) for p in [frame,material,DIRECTORY/"CONFIG.json",*code]},"repositories":30,"configuration_frozen_before_analysis":True,"holdout_admission_authorized":False,"goal_completion_proven":False});print(json.dumps({"repositories":30,"configuration_frozen":True}))
def run():
    plan=read(DIRECTORY/"RUN_PLAN.json")
    for relative,expected in plan["inputs_sha256"].items():
        if sha(ROOT/relative)!=expected:raise ValueError("guard283_input_drift:"+relative)
    result=analyze(read(DIRECTORY/"CONFIG.json"));result.update(configuration_frozen_before_analysis=True,query_polarity_used_as_label=False,holdout_admission_authorized=False,goal_completion_proven=False);write_new(DIRECTORY/"RESULT.json",result);print(json.dumps(result["counts"],sort_keys=True))
def main():
    import argparse;p=argparse.ArgumentParser(description=__doc__);p.add_argument("mode",choices=("prepare","run"));{"prepare":prepare,"run":run}[p.parse_args().mode]()
if __name__=="__main__":main()
