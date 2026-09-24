"""Freeze 50 guard-API-enriched identities per target framework."""
import hashlib,json
from pathlib import Path
from guardcontract.corpus.guard_code_identity import select
from guardcontract.paths import project_root
ROOT=project_root();DIRECTORY=ROOT/"experiments/prospective-guard-identity-freeze-n273"
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_bytes())
def main():
    if DIRECTORY.exists():raise ValueError("identity273_existing")
    raw_path=ROOT/"experiments/prospective-guard-code-collection-n272/RAW_RESULT.json";config=ROOT/"experiments/prospective-guard-code-collection-n272/CONFIG.json";protocol=ROOT/"experiments/prospective-guard-code-collection-n272/PROTOCOL.json";old_path=ROOT/"experiments/holdout-readiness-n240/RESULT.json";first_path=ROOT/"experiments/prospective-identity-freeze-n265/RESULT.json";session_path=ROOT/"experiments/session-exposure-n262/RESULT.json"
    excluded={r["repository"] for r in read(old_path)["rows"]}|{r["repository"]["full_name"] for r in read(first_path)["selected"]}|set(read(session_path)["mentioned_repositories"]);official={"langchain-ai/langchain","google/adk-python","pydantic/pydantic-ai","openai/openai-agents-python","crewaiinc/crewai"};result=select(read(raw_path),excluded,official,frameworks=["langchain","google-adk","pydantic-ai","openai-agents","crewai"],per_framework=50,seed="guardcontract-guard-api-v1-20260909")
    result["inputs_sha256"]={str(p.relative_to(ROOT)):sha(p) for p in (raw_path,config,protocol,old_path,first_path,session_path,Path(__file__),ROOT/"src/guardcontract/corpus/guard_code_identity.py")};result["goal_completion_proven"]=False;DIRECTORY.mkdir()
    with (DIRECTORY/"RESULT.json").open("x") as handle:json.dump(result,handle,indent=2,sort_keys=True);handle.write("\n")
    print(json.dumps(result["counts"]))
if __name__=="__main__":main()
