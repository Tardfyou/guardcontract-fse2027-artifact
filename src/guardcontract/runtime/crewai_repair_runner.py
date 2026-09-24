"""Execute a CrewAI fixture with Python socket connections blocked."""
import argparse,hashlib,importlib.util,json,os,socket,sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from guardcontract.runtime.control_instance import observe_guards
def blocked(*args,**kwargs):raise RuntimeError("crewai_repair_network_disabled")
def load(path):
    spec=importlib.util.spec_from_file_location("guardcontract_crewai_repair_fixture",path)
    if spec is None or spec.loader is None:raise ValueError("crewai_runner_module")
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module);return module
def execute(path):
    os.environ.update(OTEL_SDK_DISABLED="true",CREWAI_DISABLE_TELEMETRY="true",CREWAI_TRACING_ENABLED="false");network={"mechanism":"python_socket_connect_patch","connect":True,"connect_ex":True,"create_connection":True,"kernel_enforced":False};cells={}
    with patch.multiple(socket.socket,connect=blocked,connect_ex=blocked),patch.object(socket,"create_connection",blocked):
        module=load(path)
        with TemporaryDirectory(prefix="guardcontract-crewai-repair-") as temporary:
            for decision in ("ALLOW","DENY"):
                cell_root = Path(temporary) / decision.lower()
                with observe_guards(path.resolve(), ["run_cell.task_guardrail", "run_cell.before_tool_hook"]) as observation:
                    cells[decision]=module.run_cell(cell_root,decision)
                cells[decision]["guard_observation"] = observation
                marker_files = [{"relative_path": str(item.relative_to(cell_root)), "bytes": item.stat().st_size,
                                 "sha256": hashlib.sha256(item.read_bytes()).hexdigest()}
                                for item in sorted(cell_root.rglob("*.txt"))]
                cells[decision]["effect_observation"] = {"attempt_events": [e for e in cells[decision].get("events", []) if e.get("kind") in {"protected_effect", "effect_attempt"}], "marker_count": len(marker_files), "marker_observation": "collected", "marker_files": marker_files}
    return {"schema_version":"crewai-repair-runtime-1","source_sha256":hashlib.sha256(path.read_bytes()).hexdigest(),"network_enforcement":network,"cells":cells,"execution_health":"completed"}
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--source",type=Path,required=True);parser.add_argument("--output",type=Path,required=True);args=parser.parse_args();args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open("x") as handle:json.dump(execute(args.source),handle,indent=2,sort_keys=True);handle.write("\n")
if __name__=="__main__":main()
