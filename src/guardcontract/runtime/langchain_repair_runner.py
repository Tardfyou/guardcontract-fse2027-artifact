"""Execute one original or patched owned LangChain fixture under seccomp."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from types import ModuleType

from guardcontract.runtime.offline import install
from guardcontract.runtime.control_instance import observe_guards


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError("repair_runner_module_spec")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def load_helper(name, path):
    if not isinstance(name, str) or not name or any(not part.isidentifier() for part in name.split(".")):
        raise ValueError("repair_runner_helper_module")
    parts = name.split(".")
    for number in range(1, len(parts)):
        package_name = ".".join(parts[:number])
        package = ModuleType(package_name)
        package.__path__ = [str(path.parents[len(parts) - number - 1])]
        sys.modules[package_name] = package
    return load(name, path)


def execute(app_path, helper_path, helper_module="deferred_effects"):
    network = install()
    helper = load_helper(helper_module, helper_path)
    app = load("guardcontract_repair_fixture", app_path)
    cells = {}
    with TemporaryDirectory(prefix="guardcontract-repair-runtime-") as temporary:
        root = Path(temporary)
        for decision in ("ALLOW", "DENY"):
            cell_root = root / decision.lower()
            with observe_guards(app_path.resolve(), ["ContractMiddleware.after_agent", "ContractMiddleware.wrap_tool_call"]) as observation:
                cells[decision] = app.run_cell(cell_root, decision)
            cells[decision]["guard_observation"] = observation
            cells[decision]["effect_observation"] = {
                "attempt_events": [event for event in cells[decision].get("events", [])
                                    if event.get("kind") in {"protected_effect", "effect_attempt"}],
                "marker_count": sum(1 for path in cell_root.rglob("*.txt")),
                "marker_observation": "collected",
                "marker_files": [{"relative_path": str(path.relative_to(cell_root)),
                                  "bytes": path.stat().st_size,
                                  "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                                 for path in sorted(cell_root.rglob("*.txt"))],
            }
    return {"schema_version": "langchain-repair-runtime-1", "app_sha256": hashlib.sha256(app_path.read_bytes()).hexdigest(),
            "helper_sha256": hashlib.sha256(helper_path.read_bytes()).hexdigest(), "network_enforcement": network,
            "cells": cells, "execution_health": "completed"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--helper", type=Path, required=True)
    parser.add_argument("--helper-module", default="deferred_effects")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = execute(args.app, args.helper, args.helper_module)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as handle:
        json.dump(result, handle, indent=2, sort_keys=True)
        handle.write("\n")


if __name__ == "__main__":
    main()
