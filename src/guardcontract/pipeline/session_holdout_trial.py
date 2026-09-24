"""Build the session-aware conservative prospective identity pool."""
import hashlib,json
from pathlib import Path
from guardcontract.corpus.session_holdout import build
from guardcontract.paths import project_root
ROOT=project_root();DIRECTORY=ROOT/"experiments/session-aware-holdout-n263"
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_bytes())
def main():
    if DIRECTORY.exists():raise ValueError("holdout263_existing")
    ledger_path=ROOT/"experiments/holdout-readiness-n240/RESULT.json";session_path=ROOT/"experiments/session-exposure-n262/RESULT.json";result=build(read(ledger_path),read(session_path));result["inputs_sha256"]={str(p.relative_to(ROOT)):sha(p) for p in (ledger_path,session_path,Path(__file__),ROOT/"src/guardcontract/corpus/session_holdout.py")};result["goal_completion_proven"]=False
    DIRECTORY.mkdir();
    with (DIRECTORY/"RESULT.json").open("x") as handle:json.dump(result,handle,indent=2,sort_keys=True);handle.write("\n")
    print(json.dumps({"counts":result["counts"],"session_mentions":result["session_mentioned_repositories"],"family_tainted":result["session_family_tainted_repositories"],"prospective_candidates":len(result["prospective_freeze_candidates"])}))
if __name__=="__main__":main()
