"""Build the conservative holdout-readiness ledger from frozen family audits."""
import hashlib,json
from pathlib import Path
from guardcontract.corpus.holdout_eligibility import build
from guardcontract.paths import project_root

ROOT=project_root();DIRECTORY=ROOT/"experiments/holdout-readiness-n240"
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_bytes())
def main():
    if DIRECTORY.exists():raise ValueError("holdout240_existing_result")
    exact_path=ROOT/"experiments/relevance-family-exposure-n163/RESULT.json";near_path=ROOT/"experiments/relevance-nearcopy-n164/RESULT.json"
    exact,near=read(exact_path),read(near_path)
    if exact["exposure_inventory_complete"] or exact["nearcopy_audit_complete"] or near["holdout_admission_authorized"]:raise ValueError("holdout240_unexpected_prior_state")
    inputs={str(p.relative_to(ROOT)):sha(p) for p in (exact_path,near_path,Path(__file__),ROOT/"src/guardcontract/corpus/holdout_eligibility.py")}
    result=build(exact,near);result["inputs_sha256"]=inputs
    DIRECTORY.mkdir();path=DIRECTORY/"RESULT.json"
    with path.open("x") as handle:json.dump(result,handle,indent=2,sort_keys=True);handle.write("\n")
    print(json.dumps({k:result[k] for k in ("repositories","known_exposure_seeds","potential_exposure_seeds","unavailable_source_repositories","unverified_source_repositories","provisionally_clean_pending_audit","holdout_eligible_repositories","holdout_admission_authorized","counts")}))
if __name__=="__main__":main()
