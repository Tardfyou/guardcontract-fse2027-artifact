"""Execute one owned Google ADK fixture under kernel network isolation."""
import argparse, hashlib, importlib.util, json, sys
from pathlib import Path
from tempfile import TemporaryDirectory

from guardcontract.runtime.offline import install


def load(path):
    spec=importlib.util.spec_from_file_location("guardcontract_adk_repair_fixture",path)
    if spec is None or spec.loader is None: raise ValueError("adk_runner_module")
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module);return module


def execute(path):
    network=install();module=load(path);cells={}
    with TemporaryDirectory(prefix="guardcontract-adk-repair-") as temporary:
        for decision in ("ALLOW","DENY"):cells[decision]=module.run_cell(Path(temporary)/decision.lower(),decision)
    return {"schema_version":"adk-repair-runtime-1","source_sha256":hashlib.sha256(path.read_bytes()).hexdigest(),
            "network_enforcement":network,"cells":cells,"execution_health":"completed"}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--source",type=Path,required=True);parser.add_argument("--output",type=Path,required=True);args=parser.parse_args()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open("x") as handle:json.dump(execute(args.source),handle,indent=2,sort_keys=True);handle.write("\n")
if __name__=="__main__":main()
