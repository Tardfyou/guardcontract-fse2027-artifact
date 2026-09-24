"""Run the predeclared candidate effect-call inventory on the guard pilot."""
import hashlib,json
from pathlib import Path
from guardcontract.corpus.effect_gap_inventory import scan
from guardcontract.paths import project_root
ROOT=project_root();DIRECTORY=ROOT/"experiments/effect-gap-inventory-n278"
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_bytes())
def main():
    if DIRECTORY.exists():raise ValueError("effect278_existing")
    frame=ROOT/"experiments/prospective-guard-materialization-n275/FRAME.json";material=ROOT/"experiments/prospective-guard-materialization-n275/RESULT.json";result=scan(read(frame),read(material));result.update(inputs_sha256={str(p.relative_to(ROOT)):sha(p) for p in (frame,material,Path(__file__),ROOT/"src/guardcontract/corpus/effect_gap_inventory.py")},study_use="post_freeze_exploratory_effect_model_gap_inventory",holdout_admission_authorized=False,goal_completion_proven=False);DIRECTORY.mkdir()
    with (DIRECTORY/"RESULT.json").open("x") as handle:json.dump(result,handle,indent=2,sort_keys=True);handle.write("\n")
    print(json.dumps(result["counts"]))
if __name__=="__main__":main()
