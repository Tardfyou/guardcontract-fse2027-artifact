"""Atomic review with a wire-shaped prior; evidence remains in its own catalog.

This is a development protocol variant, not a reinterpretation of old responses.
"""
from guardcontract.protocols import certificate_review_atomic as atomic
from guardcontract.protocols.certificate_review_v2 import digest

SYSTEM = atomic.SYSTEM
decode = atomic.decode


def task(certificate, app_source, helper_source, sdk_contract, *, repository_id,
         role="analyst", previous=None):
    prior = None
    if previous is not None:
        # Decoded reviews include full evidence attachments and optional null
        # annotations. They are bookkeeping, not part of the response schema.
        prior = {"input_id": previous["input_id"],
                 "claims": [{key: row[key] for key in ("claim_id", "verdict", "reason")}
                            for row in previous["claims"]]}
        if isinstance(previous.get("explanation"), str):
            prior["explanation"] = previous["explanation"]
        if "missing_evidence" in previous:
            prior["missing_evidence"] = previous["missing_evidence"]
    payload, spec = atomic.task(certificate, app_source, helper_source, sdk_contract,
                               repository_id=repository_id, role=role, previous=prior)
    identity = {key: value for key, value in payload.items() if key != "input_id"}
    payload["input_id"] = "review-compact-prior:" + digest({"system": SYSTEM, "payload": identity})[:24]
    spec = {**spec, "input_id": payload["input_id"], "model_input_sha256": digest(payload),
            "prior_representation": "wire_claims_without_evidence_attachments"}
    return payload, spec
