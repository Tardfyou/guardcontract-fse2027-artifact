"""Score pre-oracle predictions, keeping verification outcomes separate."""

from collections import Counter
import re


EXECUTION_STATES = {"completed", "unknown", "unsupported", "error", "truncated", "not_run"}
ARMS = {"static", "llm_only", "static_analyst", "static_analyst_critic_validated"}


def ratio(numerator, denominator):
    return {"numerator": numerator, "denominator": denominator,
            "value": numerator / denominator if denominator else None}


def score(predictions, references, verification=None, *, execution_states=None):
    if not references or set(predictions) != set(references):
        raise ValueError("detection_inventory")
    if any(type(value) is not bool for value in references.values()):
        raise ValueError("detection_reference_domain")
    if any(value is not None and type(value) is not bool for value in predictions.values()):
        raise ValueError("detection_prediction_domain")
    if verification is not None and (set(verification) != set(references)
            or any(value is not None and type(value) is not bool for value in verification.values())):
        raise ValueError("verification_inventory_or_domain")
    if execution_states is not None and (set(execution_states) != set(references)
            or any(value not in EXECUTION_STATES for value in execution_states.values())):
        raise ValueError("execution_inventory_or_domain")
    tp = sum(predictions[sid] is True and gold for sid, gold in references.items())
    fp = sum(predictions[sid] is True and not gold for sid, gold in references.items())
    fn = sum(predictions[sid] is not True and gold for sid, gold in references.items())
    tn = sum(predictions[sid] is False and not gold for sid, gold in references.items())
    result = {"tp": tp, "fp": fp, "fn_including_abstained_positives": fn, "tn": tn,
            "unknown": sum(value is None for value in predictions.values()),
            "precision": ratio(tp, tp + fp), "recall": ratio(tp, tp + fn),
            "accuracy": ratio(tp + tn, len(references)),
            "known_prediction_coverage": ratio(sum(v is not None for v in predictions.values()), len(references)),
            "verification_passes": None if verification is None else ratio(sum(v is True for v in verification.values()), len(references)),
            "boundary": "Inputs must be predictions frozen before oracle access. Verification never removes a prediction. Infrastructure faults must be reported separately and cannot be supplied as ordinary model abstentions."}
    if execution_states is not None:
        result["execution_counts"] = dict(sorted(Counter(execution_states.values()).items()))
        result["unknown_by_execution_state"] = dict(sorted(Counter(
            execution_states[sid] for sid, value in predictions.items() if value is None).items()))
    return result


def compare_arms(arms, references, *, comparability=None):
    """Score a fixed inventory without filtering failed or abstained cases."""
    if set(arms) != ARMS:
        raise ValueError("four_arm_inventory")
    result = {}
    for name, arm in arms.items():
        result[name] = {
            "detection": score(arm["predictions"], references, execution_states=arm["execution_states"]),
        }
    reasons = []
    budget_verified = holdout_verified = source_family_verified = oracle_manifest_verified = False
    if comparability is None:
        reasons.append("comparability_metadata_missing")
    elif set(comparability) != ARMS:
        reasons.append("comparability_arm_inventory")
    else:
        required = {"inventory_sha256", "source_family_manifest_sha256", "oracle_manifest_sha256",
                    "budget_cap", "preoracle_frozen", "holdout_eligible"}
        rows = [comparability[name] for name in sorted(ARMS)]
        if any(not isinstance(row, dict) or set(row) != required for row in rows):
            reasons.append("comparability_metadata_shape")
        else:
            for field in ("inventory_sha256", "source_family_manifest_sha256", "oracle_manifest_sha256"):
                if any(not isinstance(row[field], str) or re.fullmatch(r"[0-9a-f]{64}", row[field]) is None for row in rows):
                    reasons.append(f"comparability_{field}_format")
            if any(type(row["budget_cap"]) not in {int, float} or isinstance(row["budget_cap"], bool) or row["budget_cap"] <= 0 for row in rows):
                reasons.append("comparability_budget_format")
            if len({row["inventory_sha256"] for row in rows}) != 1:
                reasons.append("comparability_inventory_mismatch")
            if len({row["source_family_manifest_sha256"] for row in rows}) != 1:
                reasons.append("comparability_source_family_mismatch")
            if len({row["oracle_manifest_sha256"] for row in rows}) != 1:
                reasons.append("comparability_oracle_manifest_mismatch")
            if len({row["budget_cap"] for row in rows}) != 1:
                reasons.append("comparability_budget_mismatch")
            if not all(type(row["preoracle_frozen"]) is bool for row in rows) or not all(row["preoracle_frozen"] for row in rows):
                reasons.append("comparability_preoracle_not_frozen")
            if not all(type(row["holdout_eligible"]) is bool for row in rows) or not all(row["holdout_eligible"] for row in rows):
                reasons.append("comparability_holdout_ineligible")
            budget_verified = not any(reason.startswith("comparability_budget_") for reason in reasons)
            holdout_verified = "comparability_holdout_ineligible" not in reasons
            source_family_verified = not any(reason.startswith("comparability_source_family_") for reason in reasons)
            oracle_manifest_verified = not any(reason.startswith("comparability_oracle_manifest_") for reason in reasons)
    return {"arms": result, "case_count": len(references),
            "budget_comparability_verified": budget_verified, "holdout_eligibility_verified": holdout_verified,
            "source_family_comparability_verified": source_family_verified,
            "oracle_manifest_comparability_verified": oracle_manifest_verified,
            "comparability_reasons": reasons,
            "boundary": "Common-inventory arithmetic only. Independently verify pre-oracle freezing, source families, oracle provenance, and equal budget caps before using this as a controlled experiment."}
