"""Freeze an independent behavior-oracle inventory before labels are supplied."""
import hashlib
import json


def _digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def freeze(rows, *, evaluator_id, protocol, version="1"):
    if not isinstance(evaluator_id, str) or not evaluator_id.strip():
        raise ValueError("oracle_evaluator_required")
    if not isinstance(protocol, str) or not protocol.strip():
        raise ValueError("oracle_protocol_required")
    if not isinstance(rows, list) or not rows:
        raise ValueError("oracle_rows_required")
    inventory = []
    seen = set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("sample_id"), str) or not row["sample_id"]:
            raise ValueError("oracle_sample_identity")
        if row["sample_id"] in seen:
            raise ValueError("oracle_duplicate_sample")
        seen.add(row["sample_id"])
        source_sha = row.get("source_sha256")
        if source_sha is not None and (not isinstance(source_sha, str) or len(source_sha) != 64 or any(c not in "0123456789abcdef" for c in source_sha)):
            raise ValueError("oracle_source_hash")
        evidence_hashes = {}
        for field in ("prediction_artifact_sha256", "measurement_artifact_sha256", "fixture_artifact_sha256"):
            value = row.get(field)
            if value is not None and (not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value)):
                raise ValueError("oracle_evidence_hash")
            if value is not None:
                evidence_hashes[field] = value
        inventory.append({"sample_id": row["sample_id"], "repository": row.get("repository"),
                          "framework": row.get("framework", "unknown"), "source_sha256": source_sha,
                          "stratum": row.get("stratum", "unknown"), "behavior_label": None,
                          **evidence_hashes})
    inventory.sort(key=lambda row: row["sample_id"])
    manifest = {"schema_version": "independent-oracle-manifest-1", "version": version,
                "evaluator_id": evaluator_id, "protocol": protocol, "inventory": inventory,
                "labels_bound": False, "label_count": 0, "holdout_admission_authorized": False,
                "manifest_sha256": _digest({"version": version, "evaluator_id": evaluator_id,
                                             "protocol": protocol, "inventory": inventory}),
                "claim_boundary": "Pre-label oracle manifest only; evaluator independence and later label correctness require separate authentication."}
    return manifest


def bind_labels(manifest, labels, *, label_artifact_sha256, attestation_id):
    if not isinstance(manifest, dict) or manifest.get("schema_version") != "independent-oracle-manifest-1":
        raise ValueError("oracle_manifest_shape")
    if manifest.get("labels_bound"):
        raise ValueError("oracle_labels_already_bound")
    evaluator_id = manifest.get("evaluator_id")
    if not isinstance(evaluator_id, str) or evaluator_id.strip().lower().startswith(("pending", "todo", "unassigned")):
        raise ValueError("oracle_evaluator_unresolved")
    if not isinstance(labels, dict) or set(labels) != {row["sample_id"] for row in manifest.get("inventory", [])}:
        raise ValueError("oracle_label_inventory")
    if any(value not in {"present", "absent", "unknown"} for value in labels.values()):
        raise ValueError("oracle_label_domain")
    if not isinstance(label_artifact_sha256, str) or len(label_artifact_sha256) != 64 or any(c not in "0123456789abcdef" for c in label_artifact_sha256):
        raise ValueError("oracle_label_artifact_hash")
    if not isinstance(attestation_id, str) or not attestation_id.strip():
        raise ValueError("oracle_attestation_id")
    result = dict(manifest)
    result["inventory"] = [{**row, "behavior_label": labels[row["sample_id"]]} for row in manifest["inventory"]]
    result["labels_bound"] = True; result["label_count"] = len(labels)
    result["label_artifact_sha256"] = label_artifact_sha256; result["attestation_id"] = attestation_id
    result["claim_boundary"] = "Externally supplied oracle labels bound to a frozen inventory; this function validates identity and schema but does not certify evaluator independence or label correctness."
    return result
