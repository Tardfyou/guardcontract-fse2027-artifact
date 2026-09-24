"""Content seals and scoring-only gold admission.

These pure functions do not read files, inspect labels during prediction, or
provide trusted timestamps. The application owns isolation and the verifier
registry. Gold JSON is always pending: only a code-owned verifier, pinned in
the sealed protocol, can produce a GoldAdmission consumed by the reporter.
The verifier receives an evidence manifest and authenticated artifact bytes;
it must independently recompute scope observations, not echo supplied labels.
"""
from copy import deepcopy
from dataclasses import dataclass, field
import hashlib
import math
from pathlib import PurePosixPath

from guardcontract.evaluation.scoped_issue import admit, digest, validate_scope


ARMS = ("static", "llm_only", "static_analyst", "full")
_TOKEN = object()


def _sha(value):
    if not isinstance(value, bytes):
        raise ValueError("artifact_bytes_required")
    return hashlib.sha256(value).hexdigest()


def _hashes(values, *, nonempty=False):
    if not isinstance(values, dict) or (nonempty and not values):
        raise ValueError("artifact_inventory_required")
    result = {}
    for name, value in values.items():
        if (not isinstance(name, str) or not name or "\\" in name
                or PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts
                or str(PurePosixPath(name)) != name or name == "."):
            raise ValueError("artifact_identity_invalid")
        result[name] = _sha(value)
    return result


def inventory_entries(scope_inventory):
    """Validate the frozen four-arm inventory, including sampling weights."""
    if not isinstance(scope_inventory, dict):
        raise ValueError("scope_inventory_required")
    arms = scope_inventory.get("expected_arms")
    if not isinstance(arms, list) or len(arms) != len(ARMS) or set(arms) != set(ARMS):
        raise ValueError("four_arm_inventory_required")
    entries = scope_inventory.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ValueError("scope_entries_required")
    indexed, scopes = {}, set()
    for entry in entries:
        sid = entry.get("sample_id")
        if not isinstance(sid, str) or not sid or sid in indexed:
            raise ValueError("duplicate_or_invalid_sample_identity")
        scope = validate_scope(entry["scope"])
        if scope["scope_id"] in scopes:
            raise ValueError("duplicate_scope_unit")
        probability = entry.get("inclusion_probability")
        if (type(probability) not in (float, int) or not math.isfinite(probability)
                or not 0 < probability <= 1):
            raise ValueError("scope_inclusion_probability")
        if not isinstance(entry.get("source_family"), str) or not entry["source_family"]:
            raise ValueError("scope_family_required")
        indexed[sid] = entry
        scopes.add(scope["scope_id"])
    return indexed


def _prediction_inventory(predictions, entries):
    arms = predictions.get("arms") if isinstance(predictions, dict) else None
    if not isinstance(arms, dict) or set(arms) - set(ARMS):
        raise ValueError("prediction_arm_inventory")
    # Missing arms/rows are intentional fault records, never silently removed.
    for rows in arms.values():
        if not isinstance(rows, list):
            raise ValueError("prediction_rows_required")
        seen = set()
        for row in rows:
            sid = row.get("sample_id")
            if sid not in entries or sid in seen:
                raise ValueError("prediction_sample_inventory")
            if row.get("scope_id") != entries[sid]["scope"]["scope_id"]:
                raise ValueError("prediction_scope_mismatch")
            if row.get("prediction", "unknown") not in {"present", "absent", "unknown"}:
                raise ValueError("prediction_value")
            if row.get("status", "missing") not in {"completed", "missing", "error", "unsupported"}:
                raise ValueError("prediction_status")
            seen.add(sid)


def create_prediction_seal(scope_inventory, protocol, predictions, *, inputs, responses):
    """Seal exact JSON contents and named raw input/response bytes.

    Partial predictions can be sealed; missing records remain missing for all
    later scoring. The seal authenticates contents, not chronology or secrecy.
    """
    entries = inventory_entries(scope_inventory)
    _prediction_inventory(predictions, entries)
    if (not isinstance(protocol, dict) or not protocol.get("schema_version")
            or protocol.get("expected_arms") != scope_inventory["expected_arms"]):
        raise ValueError("sealed_protocol_arm_inventory")
    result = {"schema_version": "prediction-content-seal-1",
              "expected_arms": list(scope_inventory["expected_arms"]),
              "scope_inventory_sha256": digest(scope_inventory),
              "protocol_sha256": digest(protocol), "predictions_sha256": digest(predictions),
              "input_sha256": _hashes(inputs, nonempty=True),
              "response_sha256": _hashes(responses),
              "trusted_timestamp": False, "label_isolation_proven": False}
    return {**result, "seal_id": digest(result)}


def _validate_seal_identity(seal):
    keys = {"schema_version", "expected_arms", "scope_inventory_sha256", "protocol_sha256",
            "predictions_sha256", "input_sha256", "response_sha256", "trusted_timestamp",
            "label_isolation_proven", "seal_id"}
    if (not isinstance(seal, dict) or set(seal) != keys
            or seal["schema_version"] != "prediction-content-seal-1"
            or seal["trusted_timestamp"] is not False or seal["label_isolation_proven"] is not False
            or digest({k: v for k, v in seal.items() if k != "seal_id"}) != seal["seal_id"]):
        raise ValueError("prediction_seal_identity")


def validate_prediction_seal(seal, scope_inventory, protocol, predictions, *, inputs, responses):
    _validate_seal_identity(seal)
    if seal != create_prediction_seal(scope_inventory, protocol, predictions, inputs=inputs, responses=responses):
        raise ValueError("prediction_seal_content_drift")
    return deepcopy(seal)


def _entry_and_seal(scope_inventory, seal, sample_id):
    _validate_seal_identity(seal)
    entries = inventory_entries(scope_inventory)
    if (seal["scope_inventory_sha256"] != digest(scope_inventory)
            or seal["expected_arms"] != scope_inventory["expected_arms"] or sample_id not in entries):
        raise ValueError("gold_scope_inventory_mismatch")
    return entries[sample_id]


def make_pending_gold(scope_inventory, seal, *, sample_id, label, evidence_kind, evidence, adjudication):
    """Create scoring-only pending JSON. No declaration grants admission."""
    entry = _entry_and_seal(scope_inventory, seal, sample_id)
    if label not in {"present", "absent", "unknown"}:
        raise ValueError("gold_label")
    if evidence_kind not in {"paired_runtime", "finite_exhaustive", "open_positive_witness"}:
        raise ValueError("gold_evidence_kind")
    result = {"schema_version": "scoped-pending-gold-1", "sample_id": sample_id,
              "scope_id": entry["scope"]["scope_id"], "quantifier": entry["scope"]["quantifier"],
              "prediction_seal_id": seal["seal_id"],
              "scope_inventory_sha256": seal["scope_inventory_sha256"],
              "predictions_sha256": seal["predictions_sha256"],
              "label": label, "evidence_kind": evidence_kind,
              "evidence_sha256": digest(evidence), "adjudication_sha256": digest(adjudication),
              "admission_status": "pending"}
    return {**result, "gold_id": digest(result)}


@dataclass(frozen=True)
class GoldAdmission:
    """Process-local admission receipt; JSON exports must be readmitted."""
    _record: dict = field(repr=False)
    _token: object = field(repr=False)

    def __post_init__(self):
        if self._token is not _TOKEN:
            raise ValueError("gold_admission_requires_verifier")

    def as_dict(self):
        return deepcopy(self._record)


def admit_gold(envelope, *, scope_inventory, protocol, seal, evidence, adjudication,
               artifacts, verifier_id, verifier_code, verifier):
    """Recompute observations using an application-owned, protocol-pinned verifier.

    ``evidence`` requires scope_id, quantifier and artifact_sha256 (all named
    raw bytes). ``adjudication`` is an exact record documented by the checks
    below. Verifier callbacks are trusted application code, never uploaded code.
    Hashes alone do not establish semantic correctness or reviewer independence.
    """
    entry = _entry_and_seal(scope_inventory, seal, envelope["sample_id"])
    expected = make_pending_gold(scope_inventory, seal, sample_id=envelope["sample_id"],
                                label=envelope["label"], evidence_kind=envelope["evidence_kind"],
                                evidence=evidence, adjudication=adjudication)
    if envelope != expected:
        raise ValueError("gold_envelope_content_drift")
    if digest(protocol) != seal["protocol_sha256"]:
        raise ValueError("gold_protocol_drift")
    code_hash = _sha(verifier_code)
    registry = protocol.get("gold_verifiers")
    if (not callable(verifier) or not isinstance(verifier_id, str)
            or not isinstance(registry, dict) or registry.get(verifier_id) != code_hash):
        raise ValueError("gold_verifier_not_registered")
    scope = entry["scope"]
    if (not isinstance(evidence, dict) or evidence.get("scope_id") != scope["scope_id"]
            or evidence.get("quantifier") != scope["quantifier"]
            or evidence.get("artifact_sha256") != _hashes(artifacts, nonempty=True)):
        raise ValueError("gold_evidence_identity")
    expected_adjudication = {"schema_version", "scope_id", "quantifier", "label",
                             "evidence_sha256", "prediction_seal_id", "reviewer_id",
                             "decision", "rationale"}
    if (not isinstance(adjudication, dict) or set(adjudication) != expected_adjudication
            or adjudication["schema_version"] != "scoped-gold-adjudication-1"
            or adjudication["scope_id"] != scope["scope_id"]
            or adjudication["quantifier"] != scope["quantifier"]
            or adjudication["label"] != envelope["label"]
            or adjudication["evidence_sha256"] != digest(evidence)
            or adjudication["prediction_seal_id"] != seal["seal_id"]
            or adjudication["decision"] != "accept"
            or any(not isinstance(adjudication[k], str) or not adjudication[k].strip()
                   for k in ("reviewer_id", "rationale"))):
        raise ValueError("gold_adjudication_identity")
    kind, label, quantifier = envelope["evidence_kind"], envelope["label"], scope["quantifier"]
    if ((quantifier == "fixed_scenario" and kind != "paired_runtime")
            or (quantifier == "exists_in_finite_domain" and kind not in {"paired_runtime", "finite_exhaustive"})
            or (quantifier == "exists_in_finite_domain" and label == "absent" and kind != "finite_exhaustive")
            or (quantifier == "exists_in_open_domain" and (label != "present" or kind != "open_positive_witness"))):
        raise ValueError("gold_quantifier_evidence_mismatch")
    observations = verifier(deepcopy(evidence), dict(artifacts))
    result = admit(scope, observations)
    if kind == "finite_exhaustive" and result["observed_scenarios"] != result["enrolled_scenarios"]:
        raise ValueError("gold_finite_evidence_incomplete")
    if result["label"] != label:
        raise ValueError("gold_label_not_recomputed")
    receipt = {**expected,
               "admission_status": "admitted", "verifier_id": verifier_id,
               "verifier_code_sha256": code_hash, "recomputed_admission": result}
    receipt["schema_version"] = "scoped-gold-admission-1"
    receipt["admission_id"] = digest(receipt)
    return GoldAdmission(deepcopy(receipt), _TOKEN)
