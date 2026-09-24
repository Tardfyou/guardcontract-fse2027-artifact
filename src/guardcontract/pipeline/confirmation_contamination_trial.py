"""Audit and revise the unread confirmation family pool without replacement."""
import hashlib,json
from pathlib import Path
from guardcontract.corpus.confirmation_contamination import audit
from guardcontract.paths import project_root
ROOT=project_root();DIRECTORY=ROOT/"experiments/confirmation-contamination-audit-n299"
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_bytes())
def main():
    if DIRECTORY.exists():raise ValueError("audit299_existing")
    split=ROOT/"experiments/prospective-family-split-n294/RESULT.json";prior=[ROOT/p for p in ("experiments/prospective-materialization-pilot-n267/RESULT.json","experiments/prospective-materialization-confirm-n269/RESULT.json","experiments/prospective-guard-materialization-n275/RESULT.json","experiments/prospective-guard-effect-materialization-n282/RESULT.json")];result=audit(read(split),[read(p) for p in prior]);inputs=[split,*prior,Path(__file__),ROOT/"src/guardcontract/corpus/confirmation_contamination.py"];result.update(inputs_sha256={str(p.relative_to(ROOT)):sha(p) for p in inputs},goal_completion_proven=False);DIRECTORY.mkdir()
    with (DIRECTORY/"RESULT.json").open("x") as handle:json.dump(result,handle,indent=2,sort_keys=True);handle.write("\n")
    print(json.dumps(result["counts"]))
if __name__=="__main__":main()
