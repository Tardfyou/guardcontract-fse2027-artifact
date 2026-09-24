"""Execute paired owned fixture cells with an explicit network-isolation mode."""
import argparse, hashlib, json, socket
from contextlib import nullcontext
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from guardcontract.runtime.langchain_repair_runner import load, load_helper
from guardcontract.runtime.offline import install

def blocked(*args, **kwargs): raise RuntimeError("paired_fixture_network_disabled")

def execute(app_path, helper_path, helper_module="deferred_effects", network_mode="kernel_seccomp"):
    if network_mode == "kernel_seccomp": network, context = install(), nullcontext()
    elif network_mode == "python_socket_connect_patch":
        network={"mechanism":network_mode,"connect":True,"connect_ex":True,"create_connection":True,"kernel_enforced":False}
        context=patch.multiple(socket.socket,connect=blocked,connect_ex=blocked)
    else: raise ValueError("paired_fixture_network_mode")
    with context:
        outer=patch.object(socket,"create_connection",blocked) if network_mode=="python_socket_connect_patch" else nullcontext()
        with outer:
            load_helper(helper_module,helper_path);module=load("guardcontract_paired_fixture",app_path);cells={}
            with TemporaryDirectory(prefix="guardcontract-paired-") as temporary:
                for decision in ("ALLOW","DENY"): cells[decision]=module.run_cell(Path(temporary)/decision.lower(),decision)
    return {"schema_version":"paired-fixture-runtime-1","app_sha256":hashlib.sha256(app_path.read_bytes()).hexdigest(),"helper_sha256":hashlib.sha256(helper_path.read_bytes()).hexdigest(),"network_enforcement":network,"cells":cells,"execution_health":"completed"}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--app",type=Path,required=True);p.add_argument("--helper",type=Path,required=True);p.add_argument("--helper-module",default="deferred_effects");p.add_argument("--network-mode",choices=("kernel_seccomp","python_socket_connect_patch"),required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args();a.output.parent.mkdir(parents=True,exist_ok=True)
    with a.output.open("x") as h: json.dump(execute(a.app,a.helper,a.helper_module,a.network_mode),h,indent=2,sort_keys=True);h.write("\n")
if __name__=="__main__": main()
