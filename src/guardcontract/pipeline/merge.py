from __future__ import annotations

from typing import Any

from guardcontract.core.schemas import EvidenceJob, FindingEnvelope
from guardcontract.evidence.validation import validate_finding
from pathlib import Path


def hypothesis_record(repo: Path, job: EvidenceJob, finding: FindingEnvelope) -> dict[str, Any]:
    validation = validate_finding(repo, job, finding)
    actionable = validation.accepted and finding.verdict in {"supported", "refuted"}
    return {
        "job_id": job.job_id,
        "finding_id": finding.finding_id,
        "claim": finding.claim,
        "model_verdict": finding.verdict,
        "validation": {
            "accepted": validation.accepted,
            "confidence": validation.confidence,
            "errors": list(validation.errors),
        },
        "merge_status": "hypothesis_only" if actionable else ("no_claim" if validation.accepted else "rejected"),
        "proved": False,
        "requires_deterministic_revalidation": actionable,
        "path_edges": [edge.to_dict() for edge in finding.path_edges] if actionable else [],
        "effect": finding.effect.to_dict() if actionable and finding.effect else None,
    }
