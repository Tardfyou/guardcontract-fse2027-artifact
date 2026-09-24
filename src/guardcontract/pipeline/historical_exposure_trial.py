"""Inventory persisted model/manual exposure without admitting a holdout."""
import hashlib,json
from pathlib import Path
from guardcontract.corpus.historical_exposure import build
from guardcontract.paths import project_root
ROOT=project_root();DIRECTORY=ROOT/"experiments/historical-exposure-n261"
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_bytes())
def main():
    if DIRECTORY.exists():raise ValueError("exposure261_existing")
    ledger_path=ROOT/"experiments/holdout-readiness-n240/RESULT.json";ledger=read(ledger_path);universe={r["repository"] for r in ledger["rows"]}
    model=sorted((ROOT/"experiments").glob("**/ACTUAL_INPUT.json"));manual=sorted({p for p in (ROOT/"experiments").glob("*/*.json") if "ADJUDICATION" in p.name.upper() or p.name.upper().startswith("ANNOTATOR_")});evaluation=sorted((ROOT/"experiments").glob("*/EVALUATION_PLAN.json"))
    inputs={str(p.relative_to(ROOT)):sha(p) for p in [ledger_path,*model,*manual,*evaluation,Path(__file__),ROOT/"src/guardcontract/corpus/historical_exposure.py"]}
    result=build(universe,{str(p.relative_to(ROOT)):read(p) for p in model},{str(p.relative_to(ROOT)):read(p) for p in manual},{str(p.relative_to(ROOT)):read(p) for p in evaluation});result["inputs_sha256"]=inputs;result["new_definite_exposures_beyond_n240"]=sorted(set(result["definite_exposure_repositories"])-{r["repository"] for r in ledger["rows"] if r["status"]!="pending_global_exposure_audit"});result["goal_completion_proven"]=False
    DIRECTORY.mkdir();
    with (DIRECTORY/"RESULT.json").open("x") as handle:json.dump(result,handle,indent=2,sort_keys=True);handle.write("\n")
    print(json.dumps({**result["counts"],"definite_exposures":len(result["definite_exposure_repositories"]),"new_beyond_n240":len(result["new_definite_exposures_beyond_n240"]),"identity_only":len(result["identity_only_repositories"])}))
if __name__=="__main__":main()
