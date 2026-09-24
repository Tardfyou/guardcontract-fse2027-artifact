"""Run exact framework-import yield diagnostics on the first two source batches."""
import hashlib,json
from pathlib import Path
from guardcontract.corpus.framework_import_yield import scan
from guardcontract.paths import project_root
ROOT=project_root();DIRECTORY=ROOT/"experiments/framework-import-yield-n271"
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_bytes())
def main():
    if DIRECTORY.exists():raise ValueError("yield271_existing")
    pairs=[(ROOT/"experiments/prospective-materialization-pilot-n267/FRAME.json",ROOT/"experiments/prospective-materialization-pilot-n267/RESULT.json"),(ROOT/"experiments/prospective-materialization-confirm-n269/FRAME.json",ROOT/"experiments/prospective-materialization-confirm-n269/RESULT.json")];frames=[];materials=[]
    for frame,material in pairs:frames.extend(read(frame)["selected"]);materials.extend(read(material)["repositories"])
    result=scan({"selected":frames},{"repositories":materials});inputs=[p for pair in pairs for p in pair]+[Path(__file__),ROOT/"src/guardcontract/corpus/framework_import_yield.py"];result.update(inputs_sha256={str(p.relative_to(ROOT)):sha(p) for p in inputs},study_use="post_freeze_exploratory_query_yield_not_holdout_scoring",holdout_admission_authorized=False,goal_completion_proven=False);DIRECTORY.mkdir()
    with (DIRECTORY/"RESULT.json").open("x") as handle:json.dump(result,handle,indent=2,sort_keys=True);handle.write("\n")
    print(json.dumps(result["counts"]))
if __name__=="__main__":main()
