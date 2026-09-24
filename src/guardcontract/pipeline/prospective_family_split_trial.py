"""Freeze development and unread confirmation splits over 366 exact families."""
import hashlib,json
from pathlib import Path
from guardcontract.corpus.prospective_family_split import split
from guardcontract.paths import project_root
ROOT=project_root();DIRECTORY=ROOT/"experiments/prospective-family-split-n294"
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_bytes())
def main():
    if DIRECTORY.exists():raise ValueError("split294_existing")
    identities=[ROOT/"experiments/prospective-family-first-identity-n286/RESULT.json",ROOT/"experiments/prospective-gap-round1-identity-n288/RESULT.json",ROOT/"experiments/prospective-gap-round2-identity-n291/RESULT.json"];pins=[ROOT/"experiments/prospective-family-first-commit-n293/RESULT.json",ROOT/"experiments/prospective-gap-round1-commit-n289/RESULT.json",ROOT/"experiments/prospective-gap-round2-commit-n292/RESULT.json"];selected=[r for p in identities for r in read(p)["selected"]];pinned=[r for p in pins for r in read(p)["records"]];result=split(selected,pinned,seed="guardcontract-family-dev-confirm-v1-20260909",development_fraction=0.2,min_development=2);inputs=[*identities,*pins,Path(__file__),ROOT/"src/guardcontract/corpus/prospective_family_split.py"];result.update(inputs_sha256={str(p.relative_to(ROOT)):sha(p) for p in inputs},source_family_overlap=0,query_polarity_used_as_label=False,goal_completion_proven=False);DIRECTORY.mkdir()
    with (DIRECTORY/"RESULT.json").open("x") as handle:json.dump(result,handle,indent=2,sort_keys=True);handle.write("\n")
    print(json.dumps(result["counts"]))
if __name__=="__main__":main()
