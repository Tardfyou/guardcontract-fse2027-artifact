"""Complete four-arm reports over authenticated scope-level gold.

No intervals or cross-quantifier aggregate are inferred here. Partial arms and
pending/missing gold remain in the enrolled denominator. Admitted gold must be
the process-local result of prediction_seal.admit_gold, not a JSON flag.
"""
from collections import Counter

from guardcontract.evaluation.scoped_issue import digest
from guardcontract.evaluation.prediction_seal import (
    ARMS, GoldAdmission, inventory_entries, _prediction_inventory,
)


def _rate(numerator, denominator):
    return numerator / denominator if denominator else None


def _summarize(rows, quantifier):
    raw = Counter(tp=0, fp=0, fn=0, tn=0, unknown_truth=0)
    weighted = Counter(tp=0.0, fp=0.0, fn=0.0, tn=0.0, unknown_truth=0.0)
    statuses = Counter({k: 0 for k in ("completed", "missing", "error", "unsupported")})
    matrix = {truth: {prediction: 0 for prediction in ("present", "absent", "unknown")}
              for truth in ("present", "absent", "unknown")}
    total = known = decisions = 0.0
    for row in rows:
        truth, prediction, weight = row["gold_label"], row["prediction"], row["weight"]
        total += weight
        known += weight * (truth != "unknown")
        decisions += weight * (prediction != "unknown")
        statuses[row["prediction_status"]] += 1
        matrix[truth][prediction] += 1
        if truth == "unknown":
            bucket = "unknown_truth"
        elif truth == "present":
            bucket = "tp" if prediction == "present" else "fn"
        else:
            # An abstention on a known negative is not a true negative claim.
            bucket = "fp" if prediction == "present" else "tn" if prediction == "absent" else None
        if bucket:
            raw[bucket] += 1
            weighted[bucket] += weight
    end_to_end_recall = _rate(weighted["tp"], weighted["tp"] + weighted["fn"])
    precision = _rate(weighted["tp"], weighted["tp"] + weighted["fp"])
    if quantifier == "exists_in_open_domain":
        precision = end_to_end_recall = None
    n = len(rows)
    return {"enrolled": n, "known_gold": sum(r["gold_label"] != "unknown" for r in rows),
            "unknown_gold": raw["unknown_truth"],
            "pending_gold": sum(r["gold_status"] == "pending" for r in rows),
            "missing_gold": sum(r["gold_status"] == "missing" for r in rows),
            "confusion": dict(raw), "weighted_confusion": dict(weighted),
            "truth_by_prediction": matrix, "prediction_status_counts": dict(statuses),
            "prediction_unknown": sum(r["prediction"] == "unknown" for r in rows),
            "completed_unknown": sum(r["prediction_status"] == "completed" and r["prediction"] == "unknown" for r in rows),
            "known_negative_abstentions": matrix["absent"]["unknown"],
            "raw_decision_coverage": _rate(sum(r["prediction"] != "unknown" for r in rows), n),
            "weighted_decision_coverage": _rate(decisions, total),
            "raw_oracle_coverage": _rate(sum(r["gold_label"] != "unknown" for r in rows), n),
            "oracle_coverage": _rate(known, total), "weighted_known": known, "weighted_total": total,
            "precision_known": precision, "recall_known": end_to_end_recall,
            "metric_status": ("open_positive_selection_not_population_performance" if quantifier == "exists_in_open_domain"
                              else "conditional_on_known_gold"),
            "confidence_interval": None}


def build_fault_preserving_report(scope_inventory, predictions, *, gold_admissions=(), pending_gold=()):
    """Keep each enrolled scope once per arm, even if an entire arm failed.

    GoldAdmission objects are returned by admit_gold. Their audit JSON cannot be
    passed in their place; saved gold must be reverified before a new scoring run.
    """
    entries = inventory_entries(scope_inventory)
    _prediction_inventory(predictions, entries)
    inventory_hash, prediction_hash = digest(scope_inventory), digest(predictions)
    gold, pending, seals = {}, {}, set()

    def check(row):
        sid = row.get("sample_id")
        if (sid not in entries or row.get("scope_id") != entries[sid]["scope"]["scope_id"]
                or row.get("quantifier") != entries[sid]["scope"]["quantifier"]
                or row.get("scope_inventory_sha256") != inventory_hash
                or row.get("predictions_sha256") != prediction_hash):
            raise ValueError("report_gold_identity_mismatch")
        seals.add(row.get("prediction_seal_id"))
        if len(seals) != 1:
            raise ValueError("report_mixed_prediction_seals")
        return sid

    for admission in gold_admissions:
        if not isinstance(admission, GoldAdmission):
            raise ValueError("report_requires_recomputed_gold_admission")
        row = admission.as_dict()
        if digest({k: v for k, v in row.items() if k != "admission_id"}) != row["admission_id"]:
            raise ValueError("report_gold_receipt_drift")
        sid = check(row)
        if sid in gold:
            raise ValueError("duplicate_gold_admission")
        gold[sid] = row
    for row in pending_gold:
        sid = check(row)
        if (row.get("schema_version") != "scoped-pending-gold-1" or row.get("admission_status") != "pending"
                or digest({k: v for k, v in row.items() if k != "gold_id"}) != row.get("gold_id")):
            raise ValueError("report_pending_gold_identity")
        if sid in pending or sid in gold:
            raise ValueError("duplicate_gold_inventory")
        pending[sid] = row
    arms = {}
    for arm in ARMS:
        indexed = {r["sample_id"]: r for r in predictions["arms"].get(arm, [])}
        joined, groups = [], {}
        for sid, entry in entries.items():
            original = indexed.get(sid, {})
            status = original.get("status", "missing")
            prediction = original.get("prediction", "unknown") if status == "completed" else "unknown"
            truth = gold[sid]["label"] if sid in gold else "unknown"
            quantifier = entry["scope"]["quantifier"]
            row = {"sample_id": sid, "scope_id": entry["scope"]["scope_id"], "quantifier": quantifier,
                   "source_family": entry["source_family"], "inclusion_probability": entry["inclusion_probability"],
                   "weight": 1.0 / entry["inclusion_probability"], "prediction": prediction,
                   "reported_prediction": original.get("prediction"), "prediction_status": status,
                   "fault_domain": original.get("fault_domain"), "reason": original.get("reason"),
                   "gold_label": truth, "gold_status": "admitted" if sid in gold else "pending" if sid in pending else "missing",
                   "gold_admission_id": gold[sid]["admission_id"] if sid in gold else None}
            joined.append(row)
            groups.setdefault(quantifier, []).append(row)
        arms[arm] = {"arm_missing": arm not in predictions["arms"], "rows": joined,
                     "by_quantifier": {kind: _summarize(rows, kind) for kind, rows in sorted(groups.items())}}
    return {"schema_version": "fault-preserving-four-arm-report-1",
            "scope_inventory_sha256": inventory_hash, "predictions_sha256": prediction_hash,
            "prediction_seal_id": next(iter(seals)) if seals else None,
            "arms": arms, "aggregate_across_quantifiers": None, "final_holdout_admission": False,
            "costs": None, "cost_status": "attach_authenticated_shared_call_ledger_separately",
            "claim_boundary": "Complete enrolled four-arm arithmetic. Unknown truth is not negative; unknown predictions on known positives count as misses. No population, independence, confidence interval or holdout claim."}
