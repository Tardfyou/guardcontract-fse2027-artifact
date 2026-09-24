"""Combine scoped decoding and source checks without oracle-based filtering."""
from guardcontract.evidence.slice_completeness import audit
from guardcontract.protocols.full_source_evidence import digest
from guardcontract.protocols.scoped_path_review import decode


def review(payload, spec, response, sources):
    if digest(payload) != spec["model_input_sha256"] or payload["input_id"] != spec["input_id"]:
        raise ValueError("review_payload_identity")
    decoded = decode(response, spec)
    checks = [audit(source, payload["evidence"], path) for path, source in sources.items()]
    referenced = {e["path"] for e in payload["evidence"].values() if "path" in e}
    complete = bool(checks) and referenced == set(sources) and all(
        c["decorator_coverage_complete"] and
        len(c["authenticated_covered_lines"]) == len(sources[c["path"]].splitlines())
        for c in checks)
    claim = decoded["consistency"]["derived_claim"]
    if not complete:
        status = "evidence_incomplete"
    elif not decoded["consistency"]["consistent"]:
        status = "inconsistent_claims"
    elif claim == "unknown":
        status = "unresolved_claims"
    else:
        status = "awaiting_independent_validation"
    return {"raw_derived_claim": claim, "quality_status": status, "source_checks": checks,
            "decoded": decoded, "release_authorized": False,
            "boundary": "Raw claims are retained for scoring. Full-source coverage and consistency do not establish semantics; independent source/runtime validation remains required."}
