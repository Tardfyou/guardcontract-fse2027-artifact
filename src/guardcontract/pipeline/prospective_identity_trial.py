"""Freeze 80 metadata-only repository identities per target framework."""
import hashlib,json
from pathlib import Path
from guardcontract.corpus.prospective_identity import select
from guardcontract.paths import project_root
ROOT=project_root();DIRECTORY=ROOT/"experiments/prospective-identity-freeze-n265"
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_bytes())
def main():
    if DIRECTORY.exists():raise ValueError("identity265_existing")
    raw_path=ROOT/"experiments/prospective-identity-collection-n264/RAW_RESULT.json";config=ROOT/"experiments/prospective-identity-collection-n264/CONFIG.json";protocol=ROOT/"experiments/prospective-identity-collection-n264/PROTOCOL.json";old_path=ROOT/"experiments/holdout-readiness-n240/RESULT.json";session_path=ROOT/"experiments/session-exposure-n262/RESULT.json"
    excluded={r["repository"] for r in read(old_path)["rows"]}|set(read(session_path)["mentioned_repositories"]);result=select(read(raw_path),excluded,frameworks=["langchain","google-adk","pydantic-ai","openai-agents","crewai"],per_framework=80,seed="guardcontract-prospective-v1-20260909")
    result["inputs_sha256"]={str(p.relative_to(ROOT)):sha(p) for p in (raw_path,config,protocol,old_path,session_path,Path(__file__),ROOT/"src/guardcontract/corpus/prospective_identity.py")};result["goal_completion_proven"]=False;DIRECTORY.mkdir()
    with (DIRECTORY/"RESULT.json").open("x") as handle:json.dump(result,handle,indent=2,sort_keys=True);handle.write("\n")
    print(json.dumps(result["counts"]))
if __name__=="__main__":main()
