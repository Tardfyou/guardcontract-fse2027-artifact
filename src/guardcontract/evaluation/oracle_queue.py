"""Freeze a label-free behavior-oracle queue from a screening census."""
import hashlib
import json


def freeze(census, *, oracle_manifest, protocol="paired ALLOW/DENY effect observation"):
    if not isinstance(census, dict) or census.get("schema_version") != "behavior-screening-census-1":
        raise ValueError("oracle_queue_census")
    if not isinstance(oracle_manifest, dict) or oracle_manifest.get("schema_version") != "independent-oracle-manifest-1":
        raise ValueError("oracle_queue_manifest")
    oracle_manifest_sha256 = oracle_manifest.get("manifest_sha256")
    if not isinstance(oracle_manifest_sha256, str) or len(oracle_manifest_sha256) != 64 or any(c not in "0123456789abcdef" for c in oracle_manifest_sha256):
        raise ValueError("oracle_queue_manifest_hash")
    if not isinstance(protocol, str) or not protocol.strip():
        raise ValueError("oracle_queue_protocol")
    rows = []
    census_ids = {row.get("sample_id") for row in census.get("rows", []) if isinstance(row, dict)}
    manifest_ids = {row.get("sample_id") for row in oracle_manifest.get("inventory", []) if isinstance(row, dict)}
    if census_ids != manifest_ids or not census_ids:
        raise ValueError("oracle_queue_inventory_mismatch")
    for row in census.get("rows", []):
        if not isinstance(row, dict) or not isinstance(row.get("sample_id"), str):
            raise ValueError("oracle_queue_row")
        if row.get("behavior_label") is not None or row.get("runtime_state") != "unverified":
            raise ValueError("oracle_queue_label_leak")
        rows.append({"sample_id": row["sample_id"], "repository": row.get("repository"),
                     "framework": row.get("framework", "unknown"), "stratum": row.get("framework", "unknown"),
                     "source_path": row.get("source_path"), "guard": row.get("guard"),
                     "registration_line": row.get("registration_line"),
                     "lifecycle_position": row.get("lifecycle_position", "unknown"),
                     "static_candidate_status": row.get("static_candidate_status"),
                     "observations_required": ["guard_verdict", "effect_attempt_or_skip", "effect_commit", "event_order"],
                     "runtime_state": "unverified", "behavior_label": None,
                     "requires_independent_oracle": True})
    rows.sort(key=lambda row: row["sample_id"])
    queue_digest = hashlib.sha256(json.dumps(rows, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"schema_version": "behavior-oracle-queue-4", "source_census_sha256": census.get("source_static_sha256"),
            "oracle_manifest_sha256": oracle_manifest_sha256, "protocol": protocol, "rows": rows,
            "queue_sha256": queue_digest, "labels_read": False, "runtime_verified": 0,
            "holdout_admission_authorized": False,
            "claim_boundary": "Label-free oracle queue only; static screening is not behavior truth and no evaluator or label correctness is authenticated here."}


def freeze_ledger(ledger, *, ledger_validation, oracle_manifest,
                  protocol="paired ALLOW/DENY invocation-correlated effect observation"):
    if not isinstance(ledger, dict) or ledger.get("schema_version") != "prospective-confirmation-ledger-2":
        raise ValueError("oracle_queue_ledger")
    if not isinstance(ledger_validation, dict) or ledger_validation.get("schema_version") != "prospective-ledger-validation-1":
        raise ValueError("oracle_queue_ledger_validation")
    if ledger_validation.get("valid") is not True:
        raise ValueError("oracle_queue_ledger_invalid")
    if ledger_validation.get("inventory_sha256") != ledger.get("inventory_sha256"):
        raise ValueError("oracle_queue_ledger_inventory")
    if not isinstance(oracle_manifest, dict) or oracle_manifest.get("schema_version") != "independent-oracle-manifest-1":
        raise ValueError("oracle_queue_manifest")
    if not isinstance(protocol, str) or not protocol.strip():
        raise ValueError("oracle_queue_protocol")
    rows = ledger.get("rows", [])
    ledger_ids = {row.get("sample_id") for row in rows if isinstance(row, dict)}
    manifest_ids = {row.get("sample_id") for row in oracle_manifest.get("inventory", []) if isinstance(row, dict)}
    if not ledger_ids or ledger_ids != manifest_ids or len(ledger_ids) != len(rows):
        raise ValueError("oracle_queue_inventory_mismatch")
    if any(ledger.get(field) is not None for field in ("issue_labels", "precision", "recall")):
        raise ValueError("oracle_queue_label_leak")
    queue_rows = []
    for row in rows:
        queue_rows.append({
            "sample_id": row["sample_id"],
            "repository": row.get("repository"),
            "framework": row.get("framework", "unknown"),
            "stratum": row.get("stratum", f"{row.get('framework', 'unknown')}|{row.get('status', 'unknown')}"),
            "prediction": row.get("prediction"),
            "prediction_artifact_sha256": row.get("prediction_artifact_sha256"),
            "measurement_artifact_sha256": row.get("measurement_artifact_sha256"),
            "fixture_artifact_sha256": row.get("fixture_artifact_sha256"),
            "observations_required": ["guard_verdict", "effect_attempt_or_skip", "effect_commit", "event_order"],
            "runtime_state": "unverified",
            "behavior_label": None,
            "requires_independent_oracle": True,
        })
    queue_rows.sort(key=lambda row: row["sample_id"])
    queue_digest = hashlib.sha256(json.dumps(queue_rows, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {
        "schema_version": "behavior-oracle-queue-3",
        "source_ledger_sha256": ledger_validation.get("ledger_sha256"),
        "source_inventory_sha256": ledger.get("inventory_sha256"),
        "oracle_manifest_sha256": oracle_manifest.get("manifest_sha256"),
        "protocol": protocol,
        "rows": queue_rows,
        "queue_sha256": queue_digest,
        "labels_read": False,
        "runtime_verified": 0,
        "holdout_admission_authorized": False,
        "claim_boundary": "Label-free oracle queue bound to a validated prospective ledger; evaluator independence and labels remain external and unverified.",
    }
