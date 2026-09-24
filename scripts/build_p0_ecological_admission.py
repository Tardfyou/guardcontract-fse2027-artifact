"""Build a provenance-preserving contract ledger from formal compilation."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PLAN = ROOT / "experiments/p0-source-recovery-v4-round129-n1827/RUN_PLAN.json"
SCREENING = ROOT / "experiments/p0-screening-completion-redecoded-round158-n2002/SCREENING_LEDGER-000.json"
BASE = ROOT / "experiments/p0-expanded-admission-freeze-round153-n1887/ADMISSION_FREEZE.json"
GIT = ROOT / "experiments/p0-complete-git-source-round125-n1823"
COMPILATION_SOURCE_PLAN = ROOT / "experiments/p0-ecological-contract-compilation-round159-n2007/RUN_PLAN.json"


def read(path): return json.loads(Path(path).read_bytes())
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def digest(value): return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def evidence_key(contract):
    evidence = sorted((row["role"], row["path"], row["line_start"], row["line_end"], row["source_sha256"])
                      for row in contract["evidence"])
    return [contract["effect_stratum"], contract["agent_mediation"], evidence]


def evidence_identity_basis(evidence, exported, receipts):
    expected = evidence["source_sha256"]
    if exported.get(evidence["path"], {}).get("sha256") == expected:
        return "git_inventory_export"
    if receipts.get(evidence["path"], {}).get("sha256") == expected:
        return "frozen_screening_source_receipt"
    raise ValueError("compiled_source_identity")


def build(compilation, manifest):
    screening, source_plan, base = read(SCREENING), read(SOURCE_PLAN), read(BASE)
    compilation_source_plan = read(COMPILATION_SOURCE_PLAN)
    if manifest.get("execution_health") != "completed" or manifest["result_sha256"] != sha(compilation):
        raise ValueError("compilation_manifest_binding")
    compiled = read(compilation)
    if compiled["unit_errors"] or compiled["units_completed"] != compiled["units_planned"]:
        raise ValueError("compilation_incomplete")
    units = {row["sample_id"]: row for row in source_plan["units"]}
    screening_rows = {row["unit"]: row for row in screening["rows"]}
    grouped, excluded = {}, []
    result_files = sorted(compilation.parent.joinpath("results").glob("*.json"))
    new_contracts = []
    for result_path in result_files:
        row = read(result_path)
        if row["state"] != "completed": continue
        unit = row["unit"]
        identity = units[unit]
        repo_key = hashlib.sha256(identity["repository"].encode()).hexdigest()[:24]
        inventory_path = GIT / "repositories" / repo_key / "RESULT.json"
        inventory = read(inventory_path)
        if inventory["commit"] != identity.get("source_commit", inventory["commit"]):
            raise ValueError("source_commit_drift")
        exported = {file["path"]: file for file in inventory["exported"]}
        receipts = compilation_source_plan["tasks"][unit]["receipts"]
        for contract in row["compiled"]["contracts"]:
            source_identity_bases = sorted({evidence_identity_basis(evidence, exported, receipts)
                                            for evidence in contract["evidence"]})
            record = {**contract, "repository": identity["repository"], "framework": identity["framework"],
                      "source_family": identity["source_family"], "source_commit": inventory["commit"],
                      "parent_sample_ids": [unit], "admission_evidence": contract["evidence"],
                      "source_identity_bases": source_identity_bases,
                      "admission_status": "applicable", "prediction_read_for_admission": False,
                      "behavior_label": None, "protocol_group": "compiled_agent_bound_v4"}
            record.pop("evidence")
            if not record["verification_ready"]:
                excluded.append({"unit": unit, "repository": identity["repository"], "candidate": record,
                                 "reason": "agent_mediation_or_required_evidence_not_established"})
                continue
            key = digest([identity["repository"], inventory["commit"], evidence_key(contract)])
            if key not in grouped:
                grouped[key] = record
                grouped[key]["compiler_contract_ids"] = [contract["contract_id"]]
            else:
                grouped[key]["parent_sample_ids"] = sorted(set(grouped[key]["parent_sample_ids"] + [unit]))
                grouped[key]["compiler_contract_ids"].append(contract["contract_id"])
                grouped[key].setdefault("text_variants", []).append({field: record[field] for field in
                    ("protection_obligation", "forbidden_condition", "protected_operation", "protected_resource", "declared_mechanism", "commit_point")})
            grouped[key]["contract_id"] = "protection-contract:v4:" + key[:32]
    inherited = [{**contract, "protocol_group": "inherited_legacy_admission"} for contract in compiled["inherited_contracts"]]
    contracts = inherited + [grouped[key] for key in sorted(grouped)]
    by_parent = defaultdict(list)
    for contract in contracts:
        for unit in contract["parent_sample_ids"]: by_parent[unit].append(contract["contract_id"])
    ledger = []
    for original in base["ledger"]:
        unit = original["sample_id"]
        status = screening_rows[unit]["status"]
        ids = sorted(by_parent[unit])
        ledger.append({"sample_id": unit, "repository": original["repository"], "framework": original["framework"],
                       "screening_status": status, "contract_ids": ids, "admitted_contract_found": bool(ids),
                       "source_enumeration_complete": False})
    protocol_counts = Counter(contract["protocol_group"] for contract in contracts)
    screening_counts = Counter(row["screening_status"] for row in ledger)
    return {"schema_version": "p0-ecological-contract-admission-1", "ledger": ledger, "contracts": contracts,
            "excluded_compiler_candidates": excluded, "counts": {"ledger_units": len(ledger), "contracts": len(contracts),
                "excluded_compiler_candidates": len(excluded), "by_protocol": dict(protocol_counts),
                "screening_statuses": dict(screening_counts)},
            "full_source_screening_execution_complete": screening["full_772_screening_execution_complete"],
            "new_compilation_complete": True, "homogeneous_contract_measurement_ready": not inherited,
            "semantic_ground_truth_established": False, "behavior_ground_truth_established": False,
            "claim_boundary": "Compiled agent-bound contract hypotheses plus a separately identified legacy group; no DEC label or prevalence."}


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--compilation", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True); parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(); value = build(args.compilation.resolve(), read(args.manifest))
    value["inputs"] = {str(path.resolve().relative_to(ROOT)): sha(path) for path in
                       (args.compilation, args.manifest, SOURCE_PLAN, SCREENING, BASE,
                        COMPILATION_SOURCE_PLAN, Path(__file__))}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("x") as handle: json.dump(value, handle, indent=2, sort_keys=True); handle.write("\n")
    print(json.dumps(value["counts"]))


if __name__ == "__main__": main()
