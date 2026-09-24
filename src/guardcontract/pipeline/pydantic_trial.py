"""Pydantic AI source detection and exact-ALLOW repair trial."""
import argparse,hashlib,json,os,subprocess
from pathlib import Path
from guardcontract.analysis.pydantic_paths import analyze
from guardcontract.evidence.pydantic_sdk_contract import enroll
from guardcontract.paths import project_root
from guardcontract.repair.pydantic_deferral import propose
from guardcontract.repair.verification import compare
ROOT=project_root();DIRECTORY=ROOT/"experiments/pydantic-pipeline-n243"
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_bytes())
def write_new(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("x") as h:json.dump(value,h,indent=2,sort_keys=True);h.write("\n")
def prepare():
    if DIRECTORY.exists():raise ValueError("pydantic242_existing")
    src=ROOT/"experiments/multiframework-control-n174-i2/source";helper=ROOT/"experiments/registration-pipeline-n182/repositories/s001/deferred_effects.py";sdk=ROOT/"experiments/framework-contract-n47-dev";oracle=ROOT/"experiments/control-oracle-calibration-n175/RESULT.json";interpreter=ROOT/".venv-pydantic-ai/bin/python"
    paths=[src/"s002.py",src/"s003.py",helper,oracle,Path(__file__),ROOT/"src/guardcontract/analysis/pydantic_paths.py",ROOT/"src/guardcontract/repair/pydantic_deferral.py",ROOT/"src/guardcontract/runtime/paired_fixture_runner.py"]+[p for p in sdk.iterdir() if p.is_file()]
    inputs={str(p.relative_to(ROOT)):sha(p) for p in paths};DIRECTORY.mkdir();write_new(DIRECTORY/"RUN_PLAN.json",{"schema_version":"pydantic-pipeline-plan-2","cells":[{"sample_id":"s002","source":str((src/"s002.py").relative_to(ROOT)),"expected_issue":False},{"sample_id":"s003","source":str((src/"s003.py").relative_to(ROOT)),"expected_issue":True}],"helper":str(helper.relative_to(ROOT)),"sdk_contract":enroll(sdk),"inputs_sha256":inputs,"interpreter":str(interpreter),"interpreter_sha256":sha(interpreter.resolve()),"planned_repairs":1,"network_mode":"python_socket_connect_patch","isolation_limit":"not_kernel_enforced","model_calls":0,"goal_completion_proven":False})
    print(json.dumps({"samples":2,"planned_repairs":1,"model_calls":0}))
def runtime(plan,label,app,helper):
    output=DIRECTORY/(label+".json");cmd=[plan["interpreter"],"-m","guardcontract.runtime.paired_fixture_runner","--app",str(app),"--helper",str(helper),"--network-mode",plan["network_mode"],"--output",str(output)]
    done=subprocess.run(cmd,cwd=ROOT,env=dict(os.environ,PYTHONPATH=str(ROOT/"src"),PYTHONDONTWRITEBYTECODE="1"),capture_output=True,timeout=120)
    if done.returncode or not output.exists():raise ValueError("pydantic242_runtime:"+label)
    return read(output)
def run():
    plan=read(DIRECTORY/"RUN_PLAN.json")
    for p,h in plan["inputs_sha256"].items():
        if sha(ROOT/p)!=h:raise ValueError("pydantic242_drift:"+p)
    if sha(Path(plan["interpreter"]).resolve())!=plan["interpreter_sha256"]:raise ValueError("pydantic242_interpreter")
    helper=ROOT/plan["helper"];certificates=[]
    for cell in plan["cells"]:
        source=ROOT/cell["source"];cert=analyze(source.read_text(),helper.read_text(),plan["sdk_contract"],repository_id=f"controlled/{cell['sample_id']}@{sha(source)}")
        certificates.append({"sample_id":cell["sample_id"],"expected_issue":cell["expected_issue"],"prediction":cert.get("issue_prediction"),"status":cert["status"],"certificate":cert})
    positive=next(r for r in certificates if r["sample_id"]=="s003");source=ROOT/next(c["source"] for c in plan["cells"] if c["sample_id"]=="s003")
    proposal=propose(source.read_text(),helper.read_text(),positive["certificate"],plan["sdk_contract"]);patched=DIRECTORY/"patched/app.py";patched.parent.mkdir();patched.write_text(proposal.pop("patched_source"));(patched.parent/"deferred_effects.py").write_bytes(helper.read_bytes());write_new(DIRECTORY/"PATCH.json",proposal)
    original=runtime(plan,"ORIGINAL_RUNTIME",source,helper);repaired=runtime(plan,"PATCHED_RUNTIME",patched,patched.parent/"deferred_effects.py");verification=compare(original,repaired,plan["network_mode"])
    detection=sum(r["prediction"]==r["expected_issue"] for r in certificates);result={"schema_version":"pydantic-pipeline-result-1","certificates":certificates,"detection_accuracy":{"numerator":detection,"denominator":2},"proposed_solutions":1,"generated_patches":1,"effective_repairs":int(verification["gate_passed"]),"discovered_and_effectively_repaired":int(verification["gate_passed"]),"verification":verification,"model_calls":0,"goal_completion_proven":False}
    write_new(DIRECTORY/"RESULT.json",result);print(json.dumps({"detection_accuracy":result["detection_accuracy"],"effective_repairs":result["effective_repairs"],"gates":verification["gates"]}))
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("mode",choices=("prepare","run"));{"prepare":prepare,"run":run}[p.parse_args().mode]()
if __name__=="__main__":main()
