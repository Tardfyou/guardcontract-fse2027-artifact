"""Verify the OpenAI race repair under calibrated Python socket blocking."""
import argparse,hashlib,json,os,subprocess
from pathlib import Path
from guardcontract.paths import project_root
from guardcontract.repair.openai_race_sync import propose

ROOT=project_root();DIRECTORY=ROOT/"experiments/openai-repair-n253"
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_bytes())
def write_new(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("x") as handle:json.dump(value,handle,indent=2,sort_keys=True);handle.write("\n")
def prepare():
    if DIRECTORY.exists():raise ValueError("openai253_existing_plan")
    certificates=ROOT/"experiments/openai-path-certificates-n251";source=ROOT/"experiments/multiframework-control-n174-i2/source/s010.py";interpreter=ROOT/".venv-openai/bin/python"
    paths=[certificates/"RUN_PLAN.json",certificates/"RESULT.json",certificates/"SCORES.json",source,Path(__file__),ROOT/"src/guardcontract/repair/openai_race_sync.py",ROOT/"src/guardcontract/analysis/openai_paths_v2.py",ROOT/"src/guardcontract/runtime/openai_repair_runner_socket.py"]
    path_plan=read(certificates/"RUN_PLAN.json");DIRECTORY.mkdir();write_new(DIRECTORY/"RUN_PLAN.json",{"schema_version":"openai-repair-plan-2","sample_id":"s010","source":str(source.relative_to(ROOT)),
        "certificate_result":str((certificates/"RESULT.json").relative_to(ROOT)),"sdk_contract":path_plan["sdk_contract"],"inputs_sha256":{str(p.relative_to(ROOT)):sha(p) for p in paths},
        "interpreter":str(interpreter),"interpreter_sha256":sha(interpreter.resolve()),"network_mode":"python_socket_connect_patch","isolation_limit":"not_kernel_enforced",
        "timeout_seconds":30,"planned_repairs":1,"model_calls":0,"allow_oracle":"exact complete run_cell return equality","deny_oracle":"protected_tool_effect false","goal_completion_proven":False})
    print(json.dumps({"sample":"s010","planned_repairs":1,"network_mode":"python_socket_connect_patch"}))
def runtime(plan,label,source):
    output=DIRECTORY/f"{label}.json";cmd=[plan["interpreter"],"-m","guardcontract.runtime.openai_repair_runner_socket","--source",str(source),"--output",str(output)]
    done=subprocess.run(cmd,cwd=ROOT,env=dict(os.environ,PYTHONPATH=str(ROOT/"src"),PYTHONDONTWRITEBYTECODE="1"),capture_output=True,timeout=plan["timeout_seconds"])
    if done.returncode or not output.exists():raise ValueError("openai253_runtime:"+label)
    return read(output)
def run():
    plan=read(DIRECTORY/"RUN_PLAN.json")
    for relative,expected in plan["inputs_sha256"].items():
        if sha(ROOT/relative)!=expected:raise ValueError("openai253_input_drift:"+relative)
    if sha(Path(plan["interpreter"]).resolve())!=plan["interpreter_sha256"]:raise ValueError("openai253_interpreter_drift")
    certificate=next(r["certificate"] for r in read(ROOT/plan["certificate_result"])["records"] if r["sample_id"]==plan["sample_id"]);source=ROOT/plan["source"]
    proposal=propose(source.read_text(),certificate,plan["sdk_contract"]);patched=DIRECTORY/"patched/app.py";patched.parent.mkdir();patched.write_text(proposal.pop("patched_source"));write_new(DIRECTORY/"PATCH.json",proposal)
    original=runtime(plan,"ORIGINAL_RUNTIME",source);repaired=runtime(plan,"PATCHED_RUNTIME",patched)
    gates={"original_issue_reproduced":original["cells"]["DENY"]["protected_tool_effect"] is True,"deny_zero_effect":repaired["cells"]["DENY"]["protected_tool_effect"] is False,
        "allow_complete_object_preserved":original["cells"]["ALLOW"]==repaired["cells"]["ALLOW"],"source_changed":original["source_sha256"]!=repaired["source_sha256"],
        "network_enforced":original["network_enforcement"]==repaired["network_enforcement"] and all(original["network_enforcement"].get(k) is True for k in ("connect","connect_ex","create_connection"))}
    passed=all(gates.values());result={"schema_version":"openai-repair-result-2","sample_id":"s010","proposed_solutions":1,"generated_patches":1,"effective_repairs":int(passed),
        "discovered_and_effectively_repaired":int(passed),"verification":{"gates":gates,"gate_passed":passed,"allow_exact_match":gates["allow_complete_object_preserved"],
            "original_deny":original["cells"]["DENY"],"patched_deny":repaired["cells"]["DENY"]},"network_mode":plan["network_mode"],"isolation_limit":plan["isolation_limit"],"model_calls":0,"holdout_eligible":False,"goal_completion_proven":False}
    write_new(DIRECTORY/"RESULT.json",result);print(json.dumps({"effective_repairs":result["effective_repairs"],"gates":gates}))
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("mode",choices=("prepare","run"));{"prepare":prepare,"run":run}[parser.parse_args().mode]()
if __name__=="__main__":main()
