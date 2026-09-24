"""Snapshot local Codex session repository mentions without copying content."""
import hashlib,json
from pathlib import Path
from guardcontract.corpus.session_exposure import build
from guardcontract.paths import project_root
ROOT=project_root();DIRECTORY=ROOT/"experiments/session-exposure-n262";SESSION_ROOT=Path.home()/".codex"
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_bytes())
def main():
    if DIRECTORY.exists():raise ValueError("session262_existing")
    ledger_path=ROOT/"experiments/holdout-readiness-n240/RESULT.json";universe={r["repository"] for r in read(ledger_path)["rows"]};files=sorted([*SESSION_ROOT.glob("sessions/**/*.jsonl"),*SESSION_ROOT.glob("archived_sessions/*.jsonl")])
    result=build(universe,files,SESSION_ROOT);result.update(source_ledger=str(ledger_path.relative_to(ROOT)),source_ledger_sha256=sha(ledger_path),scanner_sha256=sha(Path(__file__)),implementation_sha256=sha(ROOT/"src/guardcontract/corpus/session_exposure.py"),holdout_admission_authorized=False,goal_completion_proven=False)
    DIRECTORY.mkdir();
    with (DIRECTORY/"RESULT.json").open("x") as handle:json.dump(result,handle,indent=2,sort_keys=True);handle.write("\n")
    print(json.dumps(result["counts"]))
if __name__=="__main__":main()
