"""Freeze up to 20 guard/effect identities in each lifecycle query stratum."""
import hashlib,json
from pathlib import Path
from guardcontract.corpus.guard_effect_identity import select
from guardcontract.paths import project_root
ROOT=project_root();DIRECTORY=ROOT/"experiments/prospective-guard-effect-identity-n280"
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_bytes())
def main():
    if DIRECTORY.exists():raise ValueError("identity280_existing")
    raw=ROOT/"experiments/prospective-guard-effect-code-n279/RAW_RESULT.json";config=ROOT/"experiments/prospective-guard-effect-code-n279/CONFIG.json";protocol=ROOT/"experiments/prospective-guard-effect-code-n279/PROTOCOL.json";old=ROOT/"experiments/holdout-readiness-n240/RESULT.json";first=ROOT/"experiments/prospective-identity-freeze-n265/RESULT.json";second=ROOT/"experiments/prospective-guard-identity-freeze-n273/RESULT.json";session=ROOT/"experiments/session-exposure-n262/RESULT.json"
    excluded={r["repository"] for r in read(old)["rows"]}|{r["repository"]["full_name"] for r in read(first)["selected"]}|{r["full_name"] for r in read(second)["selected"]}|set(read(session)["mentioned_repositories"]);official={"langchain-ai/langchain","google/adk-python","pydantic/pydantic-ai","openai/openai-agents-python","crewaiinc/crewai"};strata=[f+"-"+p for f in ("langchain","google-adk","pydantic-ai","openai-agents","crewai") for p in ("post","pre")];result=select(read(raw),excluded,official,strata=strata,target=20,seed="guardcontract-guard-effect-v1-20260909");result["inputs_sha256"]={str(p.relative_to(ROOT)):sha(p) for p in (raw,config,protocol,old,first,second,session,Path(__file__),ROOT/"src/guardcontract/corpus/guard_effect_identity.py")};result["goal_completion_proven"]=False;DIRECTORY.mkdir()
    with (DIRECTORY/"RESULT.json").open("x") as handle:json.dump(result,handle,indent=2,sort_keys=True);handle.write("\n")
    print(json.dumps(result["counts"]))
if __name__=="__main__":main()
