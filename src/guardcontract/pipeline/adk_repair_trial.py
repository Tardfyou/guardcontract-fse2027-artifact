"""Generate and independently verify exact-ALLOW Google ADK repair."""
import argparse,hashlib,json,os,subprocess
from pathlib import Path

from guardcontract.evidence.adk_sdk_contract import enroll
from guardcontract.paths import project_root
from guardcontract.repair.adk_placement import propose

ROOT=project_root();DIRECTORY=ROOT/"experiments/adk-repair-n232"
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_bytes())
def write_new(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("x") as handle:json.dump(value,handle,indent=2,sort_keys=True);handle.write("\n")


def prepare():
    if DIRECTORY.exists():raise ValueError("adk232_existing_plan")
    certificates=ROOT/"experiments/adk-path-certificates-n231";result=read(certificates/"RESULT.json")
    cert=next(r["certificate"] for r in result["records"] if r["sample_id"]=="s005")
    if cert.get("status")!="supported" or cert.get("issue_prediction") is not True:raise ValueError("adk232_issue_not_ready")
    source=ROOT/"experiments/multiframework-control-n174-i2/source/s005.py";sdk=ROOT/"experiments/google-adk-contract-n50-dev"
    runner=ROOT/"src/guardcontract/runtime/adk_repair_runner.py";interpreter=ROOT/".venv-google-adk-270/bin/python"
    inputs={str(p.relative_to(ROOT)):sha(p) for p in (certificates/"RUN_PLAN.json",certificates/"RESULT.json",certificates/"SCORES.json",source,
        Path(__file__),ROOT/"src/guardcontract/repair/adk_placement.py",runner,ROOT/"src/guardcontract/runtime/offline.py")}
    for path in sdk.iterdir():
        if path.is_file():inputs[str(path.relative_to(ROOT))]=sha(path)
    DIRECTORY.mkdir();write_new(DIRECTORY/"RUN_PLAN.json",{"schema_version":"adk-repair-plan-1","sample_id":"s005","inputs_sha256":inputs,
        "source_path":str(source.relative_to(ROOT)),"certificate":cert,"sdk_contract":enroll(sdk),"interpreter":str(interpreter),
        "interpreter_sha256":sha(interpreter.resolve()),"strategy":"deny_before_allow_after","planned_solutions":1,"planned_patches":1,
        "allow_oracle":"exact complete run_cell return equality","deny_oracle":"effect_count=0 and marker absent",
        "network":"kernel seccomp before SDK import","model_calls":0,"goal_completion_proven":False})
    print(json.dumps({"planned_solutions":1,"planned_patches":1,"model_calls":0}))


def run_one(plan,label,path):
    output=DIRECTORY/(label.upper()+"_RUNTIME.json");command=[plan["interpreter"],"-m","guardcontract.runtime.adk_repair_runner","--source",str(path),"--output",str(output)]
    completed=subprocess.run(command,cwd=ROOT,env=dict(os.environ,PYTHONPATH=str(ROOT/"src"),PYTHONDONTWRITEBYTECODE="1"),capture_output=True,timeout=120)
    if completed.returncode!=0 or not output.exists():raise ValueError("adk232_runtime_failure:"+label)
    return read(output),{"label":label,"returncode":completed.returncode,"stdout_sha256":hashlib.sha256(completed.stdout).hexdigest(),"stderr_sha256":hashlib.sha256(completed.stderr).hexdigest()}


def run():
    plan=read(DIRECTORY/"RUN_PLAN.json")
    for relative,expected in plan["inputs_sha256"].items():
        if sha(ROOT/relative)!=expected:raise ValueError("adk232_input_drift:"+relative)
    if sha(Path(plan["interpreter"]).resolve())!=plan["interpreter_sha256"]:raise ValueError("adk232_interpreter_drift")
    source=ROOT/plan["source_path"];proposal=propose(source.read_text(),plan["certificate"],plan["sdk_contract"])
    patched=DIRECTORY/"patched/app.py";patched.parent.mkdir();patched.write_text(proposal.pop("patched_source"));write_new(DIRECTORY/"PATCH.json",proposal)
    original,command1=run_one(plan,"original",source);repaired,command2=run_one(plan,"patched",patched)
    allow_equal=original["cells"]["ALLOW"]==repaired["cells"]["ALLOW"]
    deny_zero=repaired["cells"]["DENY"]["effect_count"]==0 and repaired["cells"]["DENY"]["marker_exists"] is False
    original_issue=original["cells"]["DENY"]["effect_count"]==1 and original["cells"]["DENY"]["marker_exists"] is True
    network=all(row["network_enforcement"]["socket_creation_probe"]=="EPERM" for row in (original,repaired))
    gates={"original_issue_reproduced":original_issue,"deny_zero_effect":deny_zero,"allow_observable_behavior_preserved":allow_equal,
           "source_changed":original["source_sha256"]!=repaired["source_sha256"],"network_enforced":network}
    result={"schema_version":"adk-repair-result-1","proposed_solutions":1,"generated_patches":1,"effective_repairs":int(all(gates.values())),
        "discovered_and_effectively_repaired":int(all(gates.values())),"gates":gates,"commands":[command1,command2],"model_calls":0,"goal_completion_proven":False}
    write_new(DIRECTORY/"RESULT.json",result);print(json.dumps(result))


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("mode",choices=("prepare","run"));{"prepare":prepare,"run":run}[parser.parse_args().mode]()
if __name__=="__main__":main()
