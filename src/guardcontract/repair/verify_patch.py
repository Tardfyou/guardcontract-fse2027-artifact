from __future__ import annotations
if __package__ in (None, ""):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import argparse
import ast
import asyncio
import copy
import importlib.util
import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable


FIXED_UUID_HEX = "12345678abcdef0012345678abcdef00"


class _FixedUUID:
    @staticmethod
    def uuid4() -> SimpleNamespace:
        return SimpleNamespace(hex=FIXED_UUID_HEX)


class _Policy:
    @staticmethod
    def redact_secrets(value: str) -> str:
        return value


class _Audit:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def record(self, event: str, **details: Any) -> None:
        self.events.append({"event": event, "details": details})


class _Context:
    def __init__(self, root: Path, ledger: Any) -> None:
        self.workspace_root = root
        self.deferred_effects = ledger
        self.policy = _Policy()
        self.audit = _Audit()
        self.phase = "planning"

    def reserve_budget(self, tool_name: str, estimated_cost_usd: float) -> None:
        self.audit.record(
            "budget_reserved",
            tool_name=tool_name,
            estimated_cost_usd=estimated_cost_usd,
        )


def load_runtime(path: Path) -> Any:
    spec = importlib.util.spec_from_file_location("guardcontract_generated_runtime", path)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot load generated runtime {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(spec.name, None)
        raise
    return module


def find_unique_function(tree: ast.Module, name: str) -> ast.AsyncFunctionDef:
    matches = [
        node for node in ast.walk(tree) if isinstance(node, ast.AsyncFunctionDef) and node.name == name
    ]
    if len(matches) != 1:
        raise ValueError(f"expected one async function {name}, found {len(matches)}")
    return matches[0]


def compile_extracted_function(path: Path, name: str) -> Callable[..., Any]:
    tree = ast.parse(path.read_bytes(), filename=path.as_posix())
    function = copy.deepcopy(find_unique_function(tree, name))
    function.decorator_list = []
    module = ast.Module(
        body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0), function],
        type_ignores=[],
    )
    ast.fix_missing_locations(module)
    namespace: dict[str, Any] = {"json": json, "uuid": _FixedUUID}
    exec(compile(module, path.as_posix(), "exec"), namespace)
    return namespace[name]


def snapshot(root: Path) -> dict[str, Any]:
    folder = root / "artifacts"
    target = folder / "CR-12345678.json"
    return {
        "directory_created": folder.is_dir(),
        "file_written": target.is_file(),
        "effect_count": int(folder.is_dir()) + int(target.is_file()),
        "payload": target.read_text(encoding="utf-8") if target.is_file() else None,
    }


def normalize(value: Any, root: Path) -> Any:
    if isinstance(value, str):
        return value.replace(root.as_posix(), "<ROOT>")
    if isinstance(value, list):
        return [normalize(item, root) for item in value]
    if isinstance(value, dict):
        return {key: normalize(item, root) for key, item in value.items()}
    return value


def execute_cell(
    function: Callable[..., Any],
    runtime: Any,
    *,
    repaired: bool,
    allow: bool,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        context = _Context(root, runtime.DeferredEffectLedger())
        tool_context = SimpleNamespace(context=context)

        class Owner:
            def __init__(self) -> None:
                self.context = context
                self.before_decision: dict[str, Any] | None = None

            async def run(self) -> str:
                result = await function(
                    tool_context,
                    "canary title",
                    "canary summary",
                    "medium",
                    "staging",
                    ["rollback canary"],
                    False,
                )
                self.before_decision = snapshot(root)
                if not allow:
                    raise RuntimeError("DENY")
                return result

        if repaired:
            Owner.run = runtime.deferred_effect_scope(Owner.run)
        owner = Owner()
        output = None
        decision = "ALLOW"
        try:
            output = asyncio.run(owner.run())
        except RuntimeError as exc:
            if str(exc) != "DENY":
                raise
            decision = "DENY"
        return {
            "repaired": repaired,
            "decision": decision,
            "before_decision": owner.before_decision,
            "after_decision": snapshot(root),
            "output": normalize(output, root),
            "audit": normalize(context.audit.events, root),
            "pending_after_decision": context.deferred_effects.pending_count,
        }


def call_attributes(function: ast.AsyncFunctionDef) -> list[str]:
    return [
        node.func.attr
        for node in ast.walk(function)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    ]


def static_patch_checks(
    original_path: Path,
    patched_path: Path,
    context_path: Path,
    runner_path: Path,
    plan: dict[str, Any],
) -> dict[str, Any]:
    function_name = plan["effects"][0]["function"]
    original = find_unique_function(ast.parse(original_path.read_bytes()), function_name)
    patched = find_unique_function(ast.parse(patched_path.read_bytes()), function_name)
    original_calls = call_attributes(original)
    patched_calls = call_attributes(patched)
    expected_original = [item["call"].rsplit(".", 1)[-1] for item in plan["effects"]]
    expected_staged = [
        {"filesystem_mkdir": "stage_mkdir", "filesystem_text_write": "stage_text_write",
         "filesystem_bytes_write": "stage_bytes_write"}[item["backend"]]
        for item in plan["effects"]
    ]
    context_tree = ast.parse(context_path.read_bytes())
    context_classes = [
        node
        for node in ast.walk(context_tree)
        if isinstance(node, ast.ClassDef) and node.name == plan["context"]["class"]
    ]
    context_has_ledger = len(context_classes) == 1 and any(
        isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == "deferred_effects"
        for node in context_classes[0].body
    )
    runner = find_unique_function(ast.parse(runner_path.read_bytes()), plan["runner"]["function"])
    runner_scoped = any(
        isinstance(item, ast.Name) and item.id == "deferred_effect_scope" for item in runner.decorator_list
    )
    return {
        "expected_original_calls": expected_original,
        "expected_staged_calls": expected_staged,
        "original_effect_calls_present": all(original_calls.count(name) == 1 for name in expected_original),
        "patched_direct_effect_calls_absent": all(name not in patched_calls for name in expected_original),
        "patched_staged_calls_present": all(patched_calls.count(name) == 1 for name in expected_staged),
        "context_ledger_present": context_has_ledger,
        "runner_scope_present": runner_scoped,
    }


def oracle_checks(plan: dict[str, Any], comparison: dict[str, Any]) -> dict[str, Any]:
    repository = plan["repository"]
    expected = {
        (item["path"], int(item["line"]), item["call"].rsplit(".", 1)[-1]) for item in plan["effects"]
    }
    exact = {
        (item["path"], int(item["line"]), item["operation"])
        for item in comparison.get("observations", [])
        if item.get("repository") == repository and item.get("codeql_exact_match") is True
    }
    reachability = {
        (item["sink_path"], int(item["sink_line"]), item["operation"])
        for item in comparison.get("reachability_observations", [])
        if item.get("repository") == repository and item.get("codeql_exact_match") is True
    }
    return {
        "planned_effects": len(expected),
        "codeql_exact_sink_matches": len(expected & exact),
        "codeql_exact_reachability_matches": len(expected & reachability),
        "all_planned_sinks_independently_matched": expected <= exact,
        "all_planned_reachability_independently_matched": expected <= reachability,
    }


def verify(
    original_repo: Path,
    patched_root: Path,
    plan: dict[str, Any],
    oracle_comparison: dict[str, Any],
) -> dict[str, Any]:
    effects_path = plan["effects"][0]["path"]
    if any(item["path"] != effects_path or item["function"] != plan["effects"][0]["function"] for item in plan["effects"]):
        raise ValueError("bounded verifier requires one extracted effect function")
    original_path = original_repo / effects_path
    patched_path = patched_root / effects_path
    runtime_path = patched_root / Path(plan["context"]["path"]).parent / "guardcontract_runtime.py"
    runtime = load_runtime(runtime_path)
    original_function = compile_extracted_function(original_path, plan["effects"][0]["function"])
    patched_function = compile_extracted_function(patched_path, plan["effects"][0]["function"])
    cells = [
        execute_cell(original_function, runtime, repaired=False, allow=False),
        execute_cell(original_function, runtime, repaired=False, allow=True),
        execute_cell(patched_function, runtime, repaired=True, allow=False),
        execute_cell(patched_function, runtime, repaired=True, allow=True),
    ]
    vulnerable_deny, original_allow, repaired_deny, repaired_allow = cells
    static = static_patch_checks(
        original_path,
        patched_path,
        patched_root / plan["context"]["path"],
        patched_root / plan["runner"]["path"],
        plan,
    )
    oracle = oracle_checks(plan, oracle_comparison)
    gates = {
        "oracle_binding": all(
            [
                oracle["all_planned_sinks_independently_matched"],
                oracle["all_planned_reachability_independently_matched"],
            ]
        ),
        "exact_source_transformation": all(
            value for key, value in static.items() if key not in {"expected_original_calls", "expected_staged_calls"}
        ),
        "vulnerability_reproduced": vulnerable_deny["after_decision"]["effect_count"] == 2,
        "repaired_deny_zero_effect": repaired_deny["after_decision"]["effect_count"] == 0,
        "allow_effect_preserved": repaired_allow["after_decision"] == original_allow["after_decision"],
        "allow_output_preserved": repaired_allow["output"] == original_allow["output"],
        "allow_audit_preserved": repaired_allow["audit"] == original_allow["audit"],
        "all_ledgers_drained": all(cell["pending_after_decision"] == 0 for cell in cells),
    }
    return {
        "schema_version": 1,
        "task_version": "27-2",
        "execution_health": "completed",
        "scientific_outcome": "success" if all(gates.values()) else "failure",
        "execution_boundary": "extracted original and generated-patch function bodies with generated runtime; no network or third-party service",
        "oracle": oracle,
        "static_patch_checks": static,
        "cells": cells,
        "gates": gates,
        "gate_passed": all(gates.values()),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args()
    config = json.loads(args.config.read_text(encoding="utf-8"))
    original_repo = Path(config["original_repo"])
    patched_root = Path(config["patched_root"])
    plan_path = Path(config["plan"])
    oracle_path = Path(config["oracle_comparison"])
    result = verify(
        original_repo,
        patched_root,
        json.loads(plan_path.read_text(encoding="utf-8")),
        json.loads(oracle_path.read_text(encoding="utf-8")),
    )
    args.result.parent.mkdir(parents=True, exist_ok=True)
    args.result.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"gates": result["gates"], "gate_passed": result["gate_passed"]}, sort_keys=True))
    return 0 if result["gate_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
