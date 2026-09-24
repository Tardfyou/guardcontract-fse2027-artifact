"""Build the preregistered broad, descriptive DEC-RISK-CANDIDATE panel."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_OPERATION_ROLES = {"protected_operation", "commit_point", "agent_entry_binding"}
GUARD_ROLES = {"guard_registration", "forbidden_condition"}
BINDING_TERMS = ("bind", "same request", "same resource", "identity", "argument", "instance",
                 "attempt", "propagat", "correlat", "alias", "dataflow", "data flow")
PATH_TERMS = ("async", "await", "background", "sibling", "callback", "indirect", "exception",
              "alternate", "alternative", "bypass", "fallback", "retry", "concurrent")
GAP_TERMS = ("unresolved", "not established", "no established", "not verified", "not covered", "without coverage",
             "missing", "unknown", "unclear", "not supplied", "may bypass", "could bypass",
             "potential bypass", "coverage gap")
EMPTY_PENDING = {"", "none", "no pending information", "not applicable", "n/a", "unknown"}


def read(path: Path):
    return json.loads(path.read_bytes())


def sha(path: Path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _quantile_type7(values: list[int], probability: float):
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    value = ordered[lower] + fraction * (ordered[upper] - ordered[lower])
    return int(value) if value.is_integer() else value


def _meaningful(values) -> list[str]:
    return [str(value).strip() for value in values
            if str(value).strip().lower().rstrip(".") not in EMPTY_PENDING]


def classify(contract: dict, structural: dict) -> tuple[list[str], dict]:
    evidence = contract["admission_evidence"]
    roles = {row["role"] for row in evidence}
    if (contract["protocol_group"] != "compiled_agent_bound_v4"
            or contract["agent_mediation"] == "not_established"
            or not REQUIRED_OPERATION_ROLES <= roles
            or not roles & GUARD_ROLES
            or not structural.get("source_identity_verified")
            or not structural.get("agent_entry_anchor")
            or not structural.get("operation_syntax_anchor")
            or not structural.get("commit_syntax_anchor")):
        return [], {}

    reasons = []
    basis: dict[str, object] = {}
    orderings = set(structural.get("same_function_orderings", []))
    if "after" in orderings:
        reasons.append("POST_COMMIT_GUARD_ORDER")
        basis["POST_COMMIT_GUARD_ORDER"] = sorted(orderings)
    if len(orderings) > 1 or "same_line" in orderings:
        reasons.append("MIXED_OR_AMBIGUOUS_ORDERING")
        basis["MIXED_OR_AMBIGUOUS_ORDERING"] = sorted(orderings)

    pending = _meaningful(contract.get("pending_binding_information", []))
    scope = _meaningful(contract.get("scope_limits", []))
    pending_text = " ".join(pending).lower()
    path_rows = [row for row in pending + scope
                 if any(term in row.lower() for term in PATH_TERMS)
                 and any(term in row.lower() for term in GAP_TERMS)]
    path_text = " ".join(path_rows).lower()
    binding_hits = sorted({term for term in BINDING_TERMS if term in pending_text})
    if binding_hits:
        reasons.append("UNRESOLVED_OR_MISMATCHED_BINDING")
        basis["UNRESOLVED_OR_MISMATCHED_BINDING"] = {
            "matched_terms": binding_hits, "pending_binding_information": pending}
    path_hits = sorted({term for term in PATH_TERMS if term in path_text})
    if path_hits:
        reasons.append("INDIRECT_ASYNC_EXCEPTION_OR_ALTERNATE_PATH")
        basis["INDIRECT_ASYNC_EXCEPTION_OR_ALTERNATE_PATH"] = {
            "matched_terms": path_hits, "source_bounded_limits_or_questions": path_rows}
    return reasons, basis


def build(admission: dict, structural: dict) -> dict:
    if not admission.get("new_compilation_complete"):
        raise ValueError("admission_compilation_incomplete")
    if structural.get("execution_health") != "completed" or structural.get("errors"):
        raise ValueError("structural_verification_incomplete")
    structural_rows = {row["contract_id"]: row for row in structural["rows"]}
    if len(structural_rows) != len(structural["rows"]):
        raise ValueError("duplicate_structural_contract")

    rows = []
    for contract in admission["contracts"]:
        facts = structural_rows.get(contract["contract_id"])
        if facts is None:
            raise ValueError("missing_structural_contract:" + contract["contract_id"])
        reasons, basis = classify(contract, facts)
        if not reasons:
            continue
        samples = sorted(contract["parent_sample_ids"])
        rows.append({
            "label": "DEC-RISK-CANDIDATE",
            "contract_id": contract["contract_id"],
            "sample_id": samples[0] if len(samples) == 1 else None,
            "sample_ids": samples,
            "repository": contract["repository"],
            "source_family_candidate_id": contract["source_family"],
            "framework": contract["framework"],
            "effect_stratum": contract["effect_stratum"],
            "agent_mediation": contract["agent_mediation"],
            "risk_reason_codes": reasons,
            "risk_signal_basis": basis,
            "evidence": contract["admission_evidence"],
            "protocol_group": contract["protocol_group"],
            "execution_health": "completed",
            "DEC_label": None,
        })

    units = {unit for row in rows for unit in row["sample_ids"]}
    repositories = {row["repository"] for row in rows}
    families = {row["source_family_candidate_id"] for row in rows}
    per_repository = Counter(row["repository"] for row in rows)
    distribution = list(per_repository.values())
    strata = {}
    for field in ("framework", "effect_stratum", "agent_mediation", "protocol_group"):
        strata[field] = dict(sorted(Counter(row[field] for row in rows).items()))
    strata["risk_reason_code"] = dict(sorted(Counter(
        reason for row in rows for reason in row["risk_reason_codes"]).items()))
    return {
        "schema_version": "p0-ecological-dec-risk-candidates-1",
        "estimand": "descriptive_source_backed_triage",
        "rows": rows,
        "counts": {
            "candidate_contracts_or_items": len(rows),
            "screening_units_with_candidate": len(units),
            "screening_unit_auxiliary_denominator": 772,
            "repositories_with_candidate": len(repositories),
            "repository_auxiliary_denominator": 695,
            "source_family_candidate_ids": len(families),
        },
        "per_repository_distribution": {
            "median": _quantile_type7(distribution, 0.5),
            "q1": _quantile_type7(distribution, 0.25),
            "q3": _quantile_type7(distribution, 0.75),
            "maximum": max(distribution) if distribution else None,
            "quantile_method": "Hyndman-Fan type 7",
            "counts": dict(sorted(per_repository.items())),
        },
        "strata": strata,
        "semantic_ground_truth_established": False,
        "behavior_ground_truth_established": False,
        "DEC_prevalence_available": False,
        "claim_boundary": (
            "DEC-RISK-CANDIDATE is a broad source-backed triage result, not a vulnerability, "
            "confirmed violation, DEC label, prevalence estimate, or precision/recall outcome."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--admission", type=Path, required=True)
    parser.add_argument("--structural", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    admission_path, structural_path = args.admission.resolve(), args.structural.resolve()
    value = build(read(admission_path), read(structural_path))
    value["inputs"] = {
        str(admission_path.relative_to(ROOT)): sha(admission_path),
        str(structural_path.relative_to(ROOT)): sha(structural_path),
        str(Path(__file__).resolve().relative_to(ROOT)): sha(Path(__file__).resolve()),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps(value["counts"], sort_keys=True))


if __name__ == "__main__":
    main()
