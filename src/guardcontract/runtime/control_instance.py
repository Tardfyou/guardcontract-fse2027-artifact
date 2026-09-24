"""Execute exactly one registered project-owned instance in its fixed SDK env."""
if __package__ in (None, ""):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from guardcontract.paths import project_root
from guardcontract.runtime import deferred_effects
from contextlib import contextmanager
import argparse
import asyncio
import dis
import hashlib
import importlib.metadata
import importlib.util
import inspect
import json
import os
import re
from pathlib import Path
import socket
import sys
import uuid
from tempfile import TemporaryDirectory
from unittest.mock import patch

ROOT = project_root()
sys.path.insert(0, str(ROOT / "src"))


def blocked(*args, **kwargs):
    raise RuntimeError("controlled_instance_network_disabled")


@contextmanager
def fixture_imports():
    """Expose the historical helper name only while loading a controlled fixture."""
    missing = object()
    previous = sys.modules.get("deferred_effects", missing)
    sys.modules["deferred_effects"] = deferred_effects
    try:
        yield
    finally:
        if previous is missing:
            sys.modules.pop("deferred_effects", None)
        else:
            sys.modules["deferred_effects"] = previous


def outcome_summary(value, depth=0):
    """Bounded return metadata; never invoke repr or model serialization."""
    if value is None or type(value) in {bool, int, float}:
        return value
    if type(value) is str:
        return value[:256]
    if depth < 2 and type(value) in {tuple, list}:
        return [outcome_summary(item, depth + 1) for item in value[:8]]
    result = {"type": type(value).__module__ + "." + type(value).__qualname__}
    if depth < 2:
        try:
            attributes = vars(value)
        except TypeError:
            attributes = {}
        for name in ("tripwire_triggered", "behavior"):
            if name in attributes:
                result[name] = outcome_summary(attributes[name], depth + 1)
    return result


@contextmanager
def observe_guards(source, symbols):
    """Observe owned callbacks in the current thread, including async completion."""
    if not symbols:
        yield None
        return
    if not isinstance(symbols, list) or any(not isinstance(s, str) or not s for s in symbols) or len(set(symbols)) != len(symbols):
        raise ValueError("guard_observer_symbols")
    if sys.gettrace() is not None:
        raise ValueError("guard_observer_existing_tracer")
    data = {"invocation_id": uuid.uuid4().hex, "requested_symbols": symbols, "calls": [], "errors": [],
            "thread_scope": "current_thread_only", "attempt_binding": "unverified",
            "denial_classification": "not_performed", "semantic_proof": False}
    active = {}
    filename = str(source)
    def trace(frame, event, arg):
        if frame.f_code.co_filename != filename:
            return None
        symbol = frame.f_code.co_qualname.replace(".<locals>.", ".")
        if symbol not in symbols:
            return None
        frame.f_trace_lines = False
        try:
            key = id(frame)
            if event == "call" and key not in active:
                row = {"call_id": len(data["calls"]), "symbol": symbol,
                       "definition_line": frame.f_code.co_firstlineno, "outcome": "incomplete"}
                data["calls"].append(row)
                active[key] = {"row": row, "exception": None}
            if event == "exception" and key in active:
                active[key]["exception"] = arg[0].__module__ + "." + arg[0].__qualname__
            if event == "return" and key in active:
                opcode = dis.opname[frame.f_code.co_code[frame.f_lasti]]
                if opcode in {"YIELD_VALUE", "YIELD_FROM"}:
                    return trace
                state = active.pop(key)
                if opcode in {"RETURN_VALUE", "RETURN_CONST"}:
                    state["row"].update(outcome="returned", value=outcome_summary(arg))
                elif state["exception"]:
                    state["row"].update(outcome="raised", exception_type=state["exception"])
                else:
                    state["row"].update(outcome="unresolved_exit", opcode=opcode)
        except Exception as exc:
            data["errors"].append(type(exc).__name__)
        return trace
    sys.settrace(trace)
    try:
        yield data
    finally:
        sys.settrace(None)


def run(entry, decision):
    source = ROOT / entry["path"]
    if hashlib.sha256(source.read_bytes()).hexdigest() != entry["sha256"]:
        raise ValueError("instance_changed")
    for key in ("OTEL_SDK_DISABLED", "CREWAI_DISABLE_TELEMETRY"):
        os.environ[key] = "true"
    os.environ["CREWAI_TRACING_ENABLED"] = "false"
    with fixture_imports(), patch.object(socket.socket, "connect", blocked), patch.object(socket.socket, "connect_ex", blocked), patch.object(socket, "create_connection", blocked):
        spec = importlib.util.spec_from_file_location("registered_instance", source)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        requests = []
        if hasattr(module, "CanaryModel"):
            original_response = module.CanaryModel.get_response
            async def observed_response(self, *args, **kwargs):
                response = await original_response(self, *args, **kwargs)
                for item in response.output:
                    if getattr(item, "type", None) == "function_call":
                        requests.append({"tool": item.name, "arguments": item.arguments})
                return response
            module.CanaryModel.get_response = observed_response
        if hasattr(module, "ScriptedLLM"):
            original_call = module.ScriptedLLM.call
            def observed_call(self, *args, **kwargs):
                response = original_call(self, *args, **kwargs)
                if isinstance(response, str) and re.search(r"(?m)^Action: write_canary$", response) and re.search(r"(?m)^Action Input: \{\}$", response):
                    requests.append({"tool": "write_canary", "arguments": "{}"})
                return response
            module.ScriptedLLM.call = observed_call
        if hasattr(module, "set_tracing_disabled"):
            module.set_tracing_disabled(True)
        with TemporaryDirectory(prefix="guardcontract-instance-") as temporary:
            out = Path(temporary) / "cell"
            with observe_guards(source, entry.get("guard_symbols", [])) as guard_observation:
                value = module.run_cell(out, decision)
                if inspect.isawaitable(value):
                    value = asyncio.run(value)
            markers = [{"relative_path": str(p.relative_to(out)), "payload": p.read_text(),
                        "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(out.rglob("*.txt"))] if out.exists() else []
    result = {"task_version": "174-2", "sample_id": entry["sample_id"], "decision": decision,
            "source_sha256": entry["sha256"], "distribution": entry["distribution"],
            "installed_version": importlib.metadata.version(entry["distribution"]),
            "execution_health": "completed", "fixture_observation": value, "independent_markers": markers,
            "observed_model_requests": requests}
    if guard_observation is not None:
        result["guard_observation"] = guard_observation
        result["observation_scope"] = "Single owned invocation; guard outcomes and final markers are separate observations, not an authenticated per-attempt oracle."
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--sample-id", required=True)
    parser.add_argument("--decision", choices=("DENY", "ALLOW"), required=True)
    parser.add_argument("--result", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_bytes())
    entry = next(r for r in manifest["records"] if r["sample_id"] == args.sample_id)
    try:
        result = run(entry, args.decision)
    except Exception as exc:
        result = {"task_version": "174-1", "sample_id": args.sample_id, "decision": args.decision,
                  "source_sha256": entry["sha256"], "execution_health": "error", "error_kind": type(exc).__name__}
    with args.result.open("x") as handle:
        json.dump(result, handle, indent=2, sort_keys=True)
        handle.write("\n")
