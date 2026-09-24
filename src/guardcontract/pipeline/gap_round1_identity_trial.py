"""Freeze incremental exact families discovered by gap-search round one."""
import hashlib,json
from pathlib import Path
from guardcontract.corpus.family_first_identity import select
from guardcontract.paths import project_root
ROOT=project_root();DIRECTORY=ROOT/"experiments/prospective-gap-round1-identity-n288"
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_bytes())
def main():
    if DIRECTORY.exists():raise ValueError("round288_existing")
    raw=ROOT/"experiments/prospective-gap-search-round1-n287/RAW_RESULT.json";old=ROOT/"experiments/holdout-readiness-n240/RESULT.json";first=ROOT/"experiments/prospective-identity-freeze-n265/RESULT.json";second=ROOT/"experiments/prospective-guard-identity-freeze-n273/RESULT.json";session=ROOT/"experiments/session-exposure-n262/RESULT.json";binding=ROOT/"experiments/binding-evidence-n160/RESULT_I2.json";pilot=ROOT/"experiments/prospective-guard-effect-materialization-n282/FRAME.json";base=ROOT/"experiments/prospective-family-first-identity-n286/RESULT.json"
    excluded={r["repository"] for r in read(old)["rows"]}|{r["repository"]["full_name"] for r in read(first)["selected"]}|{r["full_name"] for r in read(second)["selected"]}|{r["full_name"] for r in read(base)["selected"]}|set(read(session)["mentioned_repositories"]);blobs={r["integrity"].get("git_blob") for r in read(binding)["records"] if r["integrity"].get("git_blob")}|{loc["blob_sha"] for r in read(pilot)["selected"] for loc in r["matched_files"] if loc.get("blob_sha")}|{loc["blob_sha"] for r in read(base)["selected"] for loc in r["locations"] if loc.get("blob_sha")};strata=[f+"-"+p for f in ("langchain","google-adk","pydantic-ai","openai-agents","crewai") for p in ("post","pre")];result=select(read(raw),excluded,blobs,{"langchain-ai/langchain","google/adk-python","pydantic/pydantic-ai","openai/openai-agents-python","crewaiinc/crewai"},strata=strata,target=50,seed="guardcontract-gap-round1-v1-20260909");inputs=(raw,old,first,second,session,binding,pilot,base,Path(__file__),ROOT/"src/guardcontract/corpus/family_first_identity.py");result.update(schema_version="prospective-gap-round1-identity-freeze-1",inputs_sha256={str(p.relative_to(ROOT)):sha(p) for p in inputs},round=1,goal_completion_proven=False);DIRECTORY.mkdir()
    with (DIRECTORY/"RESULT.json").open("x") as handle:json.dump(result,handle,indent=2,sort_keys=True);handle.write("\n")
    print(json.dumps(result["counts"]))
if __name__=="__main__":main()
