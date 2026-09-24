"""Freeze exact matched-blob families for the guard/effect identity pool."""
import hashlib,json
from pathlib import Path
from guardcontract.corpus.blob_family import build
from guardcontract.paths import project_root
ROOT=project_root();DIRECTORY=ROOT/"experiments/prospective-blob-families-n285"
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_bytes())
def main():
    if DIRECTORY.exists():raise ValueError("family285_existing")
    source=ROOT/"experiments/prospective-guard-effect-identity-n280/RESULT.json";result=build(read(source)["selected"]);result.update(inputs_sha256={str(p.relative_to(ROOT)):sha(p) for p in (source,Path(__file__),ROOT/"src/guardcontract/corpus/blob_family.py")},holdout_admission_authorized=False,goal_completion_proven=False);DIRECTORY.mkdir()
    with (DIRECTORY/"RESULT.json").open("x") as handle:json.dump(result,handle,indent=2,sort_keys=True);handle.write("\n")
    print(json.dumps(result["counts"]))
if __name__=="__main__":main()
