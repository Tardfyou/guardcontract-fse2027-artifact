"""Pin the guard-API-enriched identity pool with GitHub GraphQL metadata."""
import hashlib,json,subprocess,time
from pathlib import Path
from guardcontract.corpus.guard_code_pin import pin
from guardcontract.paths import project_root
ROOT=project_root();DIRECTORY=ROOT/"experiments/prospective-guard-commit-freeze-n274"
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_bytes())
def request(query):
    done=subprocess.run(["gh","api","graphql","-f","query="+query],capture_output=True,text=True,timeout=90)
    if done.returncode:raise RuntimeError("github_graphql_error")
    return json.loads(done.stdout)
def main():
    if DIRECTORY.exists():raise ValueError("pin274_existing")
    source=ROOT/"experiments/prospective-guard-identity-freeze-n273/RESULT.json";identity=read(source);started=time.perf_counter();result=pin(identity["selected"],request);result.update(duration_seconds=time.perf_counter()-started,identity_sha256=identity["identity_sha256"],inputs_sha256={str(p.relative_to(ROOT)):sha(p) for p in (source,Path(__file__),ROOT/"src/guardcontract/corpus/guard_code_pin.py")},execution_health="completed" if result["counts"]["errors"]==0 else "partial",credential_handling="gh credential store; no token read or serialized",goal_completion_proven=False);DIRECTORY.mkdir()
    with (DIRECTORY/"RESULT.json").open("x") as handle:json.dump(result,handle,indent=2,sort_keys=True);handle.write("\n")
    print(json.dumps({"execution_health":result["execution_health"],**result["counts"],"duration_seconds":result["duration_seconds"]}))
if __name__=="__main__":main()
