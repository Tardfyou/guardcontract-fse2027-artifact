"""Reconcile completed shards and materialize one complete 456-unit compilation."""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import shutil
import time

import compile_p0_ecological_contracts as compilation


def _result_path(directory: Path, unit: str) -> Path:
    return directory / "results" / (unit.split(":")[-1] + ".json")


def _parent_contract(parent_unit: str, contract: dict) -> dict:
    core = {key: value for key, value in contract.items()
            if key not in {"contract_id", "verification_ready", "missing_evidence_roles"}}
    roles = {row["role"] for row in core["evidence"]}
    core["contract_id"] = "ecological-contract:" + compilation.digest([parent_unit, core])[:32]
    core["verification_ready"] = (compilation.ROLES <= roles
                                  and core["agent_mediation"] != "not_established")
    core["missing_evidence_roles"] = sorted(compilation.ROLES - roles)
    return core


def _validate_completed_result(result: dict, unit: str) -> None:
    if result.get("state") != "completed" or result.get("unit") != unit:
        raise ValueError("incomplete_or_mismatched_result:" + unit)
    if result.get("compiled", {}).get("unit_id") != unit:
        raise ValueError("compiled_unit_identity:" + unit)


def _nested_recovery(run: Path, parent_shard_plan: dict) -> tuple[str, dict, dict[str, str]]:
    """Reconcile a second-level split into its missing first-level shard."""
    plan_path, map_path = run / "RUN_PLAN.json", run / "SHARD_MAP.json"
    result_path = run / "COMPILATION.json"
    plan, mapping, aggregate = (compilation.read(path) for path in (plan_path, map_path, result_path))
    unit = mapping["parent_unit_id"]
    if (unit not in parent_shard_plan["tasks"] or aggregate["unit_errors"]
            or aggregate["units_completed"] != aggregate["units_planned"]
            or set(plan["tasks"]) != {row["unit_id"] for row in mapping["shards"]}):
        raise ValueError("nested_recovery_incomplete:" + unit)
    parent_task = parent_shard_plan["tasks"][unit]
    contracts, missing, provenance, covered = {}, set(), [], []
    inputs = {compilation.rel(path): compilation.sha(path)
              for path in (plan_path, map_path, result_path, run / "RUN_MANIFEST.json")}
    for shard in mapping["shards"]:
        child = shard["unit_id"]
        path = _result_path(run, child)
        result = compilation.read(path)
        _validate_completed_result(result, child)
        inputs[compilation.rel(path)] = compilation.sha(path)
        covered.extend(shard["opinion_indices"])
        for raw in result["compiled"]["contracts"]:
            for evidence in raw["evidence"]:
                receipt = parent_task["receipts"].get(evidence["path"])
                if not receipt or receipt["sha256"] != evidence["source_sha256"]:
                    raise ValueError("nested_parent_source_identity:" + child)
            contract = _parent_contract(unit, raw)
            contracts.setdefault(contract["contract_id"], contract)
        missing.update(str(item) for item in result["compiled"]["missing_information"])
        provenance.append({"unit": child, "result_sha256": compilation.sha(path),
                           "request_sha256": result["request_sha256"],
                           "response_sha256": result["response_sha256"],
                           "attempt": result["attempt"], "tokens": result.get("tokens")})
    if sorted(covered) != list(range(mapping["opinion_count"])):
        raise ValueError("nested_opinion_partition_incomplete:" + unit)
    compiled = {"unit_id": unit, "repository": parent_task["payload"]["repository"],
                "contracts": [contracts[key] for key in sorted(contracts)],
                "missing_information": sorted(missing), "source_enumeration_complete": False,
                "behavior_label": None}
    row = {"state": "completed", "unit": unit, "compiled": compiled,
           "attempt": "complete_nested_shard_reconciliation",
           "request_sha256": compilation.digest([row["request_sha256"] for row in provenance]),
           "response_sha256": compilation.digest([row["response_sha256"] for row in provenance]),
           "tokens": sum(row["tokens"] for row in provenance if type(row["tokens"]) is int),
           "nested_shard_provenance": provenance}
    return unit, row, inputs


def finalize(canonical_plan_path: Path, base_run: Path, shard_run: Path,
             shard_map_path: Path, out: Path, nested_runs: list[Path] | None = None) -> dict:
    if out.exists() or not out.is_relative_to(compilation.ROOT / "experiments"):
        raise ValueError("output_must_be_new_under_experiments")
    canonical = compilation.read(canonical_plan_path)
    shard_plan_path = shard_run / "RUN_PLAN.json"
    shard_plan = compilation.read(shard_plan_path)
    shard_map = compilation.read(shard_map_path)
    if shard_map_path.parent != shard_run:
        raise ValueError("shard_map_run_mismatch")
    if shard_map["counts"]["shards"] != len(shard_plan["tasks"]):
        raise ValueError("shard_count_mismatch")
    nested_rows, nested_inputs = {}, {}
    for run in nested_runs or []:
        unit, row, inputs = _nested_recovery(run, shard_plan)
        if unit in nested_rows:
            raise ValueError("duplicate_nested_recovery:" + unit)
        nested_rows[unit] = row
        nested_inputs.update(inputs)

    base_rows: dict[str, tuple[Path, dict]] = {}
    for path in sorted((base_run / "results").glob("*.json")):
        row = compilation.read(path)
        _validate_completed_result(row, row.get("unit", ""))
        if row["unit"] in base_rows:
            raise ValueError("duplicate_base_unit:" + row["unit"])
        base_rows[row["unit"]] = (path, row)

    parent_specs = {row["parent_unit_id"]: row for row in shard_map["parents"]}
    expected = set(canonical["tasks"])
    if set(base_rows) & set(parent_specs):
        raise ValueError("base_shard_parent_overlap")
    if set(base_rows) | set(parent_specs) != expected:
        raise ValueError("final_parent_partition_incomplete")

    reconciled: dict[str, dict] = {}
    consumed_shards: set[str] = set()
    for parent_unit in sorted(parent_specs):
        mapping = parent_specs[parent_unit]
        parent_task = canonical["tasks"][parent_unit]
        contracts: dict[str, dict] = {}
        missing: set[str] = set()
        provenance = []
        covered = []
        for shard in mapping["shards"]:
            unit = shard["unit_id"]
            if unit in consumed_shards or unit not in shard_plan["tasks"]:
                raise ValueError("duplicate_or_unplanned_shard:" + unit)
            consumed_shards.add(unit)
            spec = shard_plan["tasks"][unit]
            if compilation.digest(spec["payload"]) != spec["task_sha256"]:
                raise ValueError("shard_task_drift:" + unit)
            path = _result_path(shard_run, unit)
            result = compilation.read(path) if path.is_file() else nested_rows.get(unit)
            if result is None:
                raise ValueError("missing_shard_result:" + unit)
            _validate_completed_result(result, unit)
            covered.extend(shard["opinion_indices"])
            for raw in result["compiled"]["contracts"]:
                for evidence in raw["evidence"]:
                    receipt = parent_task["receipts"].get(evidence["path"])
                    if not receipt or receipt["sha256"] != evidence["source_sha256"]:
                        raise ValueError("parent_source_identity:" + unit)
                contract = _parent_contract(parent_unit, raw)
                contracts.setdefault(contract["contract_id"], contract)
            missing.update(str(item) for item in result["compiled"]["missing_information"])
            provenance.append({
                "unit": unit,
                "result_sha256": compilation.sha(path) if path.is_file() else compilation.digest(result),
                "request_sha256": result["request_sha256"],
                "response_sha256": result["response_sha256"],
                "attempt": result["attempt"],
                "tokens": result.get("tokens"),
            })
        if sorted(covered) != list(range(mapping["opinion_count"])):
            raise ValueError("parent_opinion_partition_incomplete:" + parent_unit)
        compiled = {
            "unit_id": parent_unit,
            "repository": parent_task["payload"]["repository"],
            "contracts": [contracts[key] for key in sorted(contracts)],
            "missing_information": sorted(missing),
            "source_enumeration_complete": False,
            "behavior_label": None,
        }
        reconciled[parent_unit] = {
            "state": "completed",
            "unit": parent_unit,
            "compiled": compiled,
            "attempt": "complete_shard_reconciliation",
            "request_sha256": compilation.digest([row["request_sha256"] for row in provenance]),
            "response_sha256": compilation.digest([row["response_sha256"] for row in provenance]),
            "tokens": sum(row["tokens"] for row in provenance if type(row["tokens"]) is int),
            "shard_provenance": provenance,
        }
    if consumed_shards != set(shard_plan["tasks"]):
        raise ValueError("unconsumed_shards")
    if set(nested_rows) != {unit for unit in nested_rows if not _result_path(shard_run, unit).is_file()}:
        raise ValueError("unused_or_shadowed_nested_recovery")

    all_rows = {unit: row for unit, (_path, row) in base_rows.items()} | reconciled
    if set(all_rows) != expected or len(all_rows) != 456:
        raise ValueError("canonical_unit_count_mismatch")
    new_contracts = [contract for unit in sorted(all_rows)
                     for contract in all_rows[unit]["compiled"]["contracts"]]
    counts = Counter("verification_ready" if row["verification_ready"] else "missing_evidence_roles"
                     for row in new_contracts)

    inputs = {
        compilation.rel(canonical_plan_path): compilation.sha(canonical_plan_path),
        compilation.rel(shard_plan_path): compilation.sha(shard_plan_path),
        compilation.rel(shard_map_path): compilation.sha(shard_map_path),
        compilation.rel(Path(__file__).resolve()): compilation.sha(Path(__file__).resolve()),
    }
    inputs.update(nested_inputs)
    for unit, (path, _row) in base_rows.items():
        inputs[compilation.rel(path)] = compilation.sha(path)
    for parent in parent_specs.values():
        for shard in parent["shards"]:
            path = _result_path(shard_run, shard["unit_id"])
            if path.is_file():
                inputs[compilation.rel(path)] = compilation.sha(path)

    out.mkdir(parents=True)
    (out / "results").mkdir()
    for unit, (path, _row) in base_rows.items():
        shutil.copyfile(path, _result_path(out, unit))
    for unit, row in reconciled.items():
        compilation.write_new(_result_path(out, unit), row)
    final_plan = {
        "schema_version": "ecological-contract-compilation-finalization-plan-1",
        "task_version": "contract-compilation-v4-complete-reconciled",
        "created_time_ns": time.time_ns(),
        "model": canonical["model"],
        "system_sha256": canonical["system_sha256"],
        "inputs": inputs,
        "units": sorted(all_rows),
        "base_units": sorted(base_rows),
        "reconciled_parent_units": sorted(reconciled),
        "nested_recovery_units": sorted(nested_rows),
        "inherited_contracts": canonical["inherited_contracts"],
        "claim_boundary": (
            "Complete parent-unit materialization of source-bound contract hypotheses. "
            "No shard is counted independently and no DEC or behavior label is assigned."
        ),
    }
    compilation.write_new(out / "RUN_PLAN.json", final_plan)
    result = {
        "schema_version": "ecological-contract-compilation-1",
        "units_planned": len(expected),
        "units_completed": len(all_rows),
        "unit_errors": [],
        "new_contracts": new_contracts,
        "inherited_contracts": canonical["inherited_contracts"],
        "counts": dict(counts),
        "budget": {
            "reconciled_shard_run": compilation.read(shard_run / "COMPILATION.json").get("budget", {}),
            "nested_recovery_runs": [compilation.read(run / "COMPILATION.json").get("budget", {})
                                     for run in (nested_runs or [])],
            "base_completed_units_reused": len(base_rows),
        },
        "source_enumeration_complete": False,
        "semantic_ground_truth_established": False,
        "behavior_ground_truth_established": False,
        "claim_boundary": (
            "Typed source-bound contract hypotheses. Verification-ready means evidence roles "
            "are present, not semantically proven."
        ),
    }
    compilation.write_new(out / "COMPILATION.json", result)
    manifest = {
        "plan_sha256": compilation.sha(out / "RUN_PLAN.json"),
        "result_sha256": compilation.sha(out / "COMPILATION.json"),
        "execution_health": "completed",
        "scientific_outcome": "contract_hypotheses_only",
        "finished_time_ns": time.time_ns(),
        "counts": {
            "canonical_units": len(expected),
            "base_units": len(base_rows),
            "reconciled_parent_units": len(reconciled),
            "consumed_shards": len(consumed_shards),
        },
    }
    compilation.write_new(out / "RUN_MANIFEST.json", manifest)
    return {"units": len(all_rows), "new_contracts": len(new_contracts),
            "inherited_contracts": len(canonical["inherited_contracts"]),
            "reconciled_parents": len(reconciled), "consumed_shards": len(consumed_shards)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--canonical-plan", type=Path, required=True)
    parser.add_argument("--base-run", type=Path, required=True)
    parser.add_argument("--shard-run", type=Path, required=True)
    parser.add_argument("--shard-map", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--nested-run", type=Path, action="append", default=[])
    args = parser.parse_args()
    value = finalize(args.canonical_plan.resolve(), args.base_run.resolve(),
                     args.shard_run.resolve(), args.shard_map.resolve(), args.out.resolve(),
                     [path.resolve() for path in args.nested_run])
    print(json.dumps(value, sort_keys=True))


if __name__ == "__main__":
    main()
