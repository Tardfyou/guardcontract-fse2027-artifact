from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping

from guardcontract.evidence.artifacts import write_patch_bundle
from guardcontract.backends.base import BackendError, BackendIdentity, ModelBackend
from guardcontract.core.schemas import EvidenceJob, EvidenceSpan, FindingEnvelope, RepairJob
from guardcontract.evidence.slicing import EvidenceSlice
from guardcontract.evidence.validation import validate_finding


def _roots(materialization: Mapping[str, Any]) -> dict[str, Path]:
    return {
        row["repository"]: Path(row["destination"])
        for row in materialization.get("repositories", [])
        if isinstance(row, Mapping) and row.get("status") == "completed"
        and isinstance(row.get("repository"), str) and isinstance(row.get("destination"), str)
    }


def _slices(value: Any) -> list[EvidenceSlice]:
    if not isinstance(value, list):
        raise ValueError("queue slices must be an array")
    result = []
    for item in value:
        if not isinstance(item, Mapping):
            raise ValueError("queue slice must be an object")
        unknown = set(item) - {"span", "content", "redactions", "untrusted"}
        if unknown or not isinstance(item.get("content"), str) or not isinstance(item.get("redactions"), int) or not isinstance(item.get("untrusted"), bool):
            raise ValueError("invalid queue slice")
        result.append(EvidenceSlice(EvidenceSpan.from_dict(item.get("span")), item["content"], item["redactions"], item["untrusted"]))
    return result


def _final_finding(record: Mapping[str, Any]) -> FindingEnvelope:
    iterations = record.get("iterations")
    if not isinstance(iterations, list):
        raise ValueError("analysis record has no iterations")
    accepted = [
        item["finding"] for item in iterations
        if isinstance(item, Mapping) and isinstance(item.get("validation"), Mapping)
        and item["validation"].get("accepted") is True and isinstance(item.get("finding"), Mapping)
    ]
    if not accepted:
        raise ValueError("analysis record has no accepted finding")
    return FindingEnvelope.from_dict(accepted[-1])


def run_repair_candidates(
    analysis_result: Mapping[str, Any],
    queue: Mapping[str, Any],
    materialization: Mapping[str, Any],
    backend: ModelBackend,
    *,
    backend_identity: BackendIdentity,
    output_root: Path,
    max_files: int = 3,
    max_changed_lines: int = 80,
) -> dict[str, Any]:
    if not 1 <= max_files <= 20 or not 1 <= max_changed_lines <= 5000:
        raise ValueError("invalid repair budget")
    queue_jobs = {}
    for item in queue.get("jobs", []):
        if not isinstance(item, Mapping) or not isinstance(item.get("job"), Mapping):
            raise ValueError("invalid queue job")
        job_id = item["job"].get("job_id")
        if not isinstance(job_id, str) or job_id in queue_jobs:
            raise ValueError("queue job IDs must be present and unique")
        queue_jobs[job_id] = item
    roots = _roots(materialization)
    records = []
    selected = [
        record for record in analysis_result.get("records", [])
        if isinstance(record, Mapping) and isinstance(record.get("hypothesis"), Mapping)
        and record["hypothesis"].get("review_priority") in {"high", "medium"}
        and record.get("consensus") in {"stable", "single_pass"}
    ]
    for record in selected:
        job_id = record.get("job_id")
        output: dict[str, Any] = {"job_id": job_id, "execution_health": "completed", "candidate": None}
        try:
            queued = queue_jobs[job_id]
            evidence_job = EvidenceJob.from_dict(queued["job"])
            finding = _final_finding(record)
            repository, revision = evidence_job.repository_id.rsplit("@", 1)
            repo = roots[repository]
            validation = validate_finding(repo, evidence_job, finding)
            if not validation.accepted or finding.verdict != "supported":
                raise ValueError("finding is no longer an accepted supported hypothesis")
            allowed_paths = tuple(dict.fromkeys(span.path for span in evidence_job.evidence))[:max_files]
            repair_id = "repair:" + hashlib.sha256(job_id.encode()).hexdigest()
            repair_job = RepairJob(
                repair_id,
                evidence_job.repository_id,
                revision,
                {
                    "strategy": "explicit_pre_effect_authorization",
                    "security_goal": "DENY implies zero protected effects",
                    "allow_contract": "preserve observable ALLOW behavior",
                    "source_finding_id": finding.finding_id,
                },
                allowed_paths,
                max_files,
                max_changed_lines,
                evidence_job.evidence,
                evidence_job.mode,
            )
            evidence_slices = _slices(queued.get("slices"))
            patch = backend.propose_patch(repair_job, [item.to_dict() for item in evidence_slices])
            artifact = write_patch_bundle(
                repo,
                output_root,
                repair_job,
                patch,
                backend_fingerprint=backend_identity.cache_namespace,
            )
            bundle = Path(artifact["bundle"]).resolve().relative_to(output_root.resolve()).as_posix()
            output["candidate"] = {"bundle": bundle, "manifest": artifact["manifest"]}
        except (BackendError, KeyError, OSError, ValueError) as exc:
            output["execution_health"] = "error"
            output["error"] = {"type": type(exc).__name__, "message": str(exc)[:500]}
        records.append(output)
    errors = sum(item["execution_health"] == "error" for item in records)
    return {
        "task_version": "166-1",
        "execution_health": "completed" if errors == 0 else ("partial" if errors < len(records) else "error"),
        "scientific_outcome": "unscored",
        "source_tree_writes": 0,
        "claim_boundary": "Candidates may be proposed for supported high/medium-priority hypotheses. A proposal is not a verified repair; independent DENY-zero-effect and ALLOW-preservation validation is still required.",
        "counts": {"input_records": len(analysis_result.get("records", [])), "not_selected": len(analysis_result.get("records", [])) - len(selected), "selected": len(selected), "candidates": len(selected) - errors, "errors": errors, "independently_verified": 0},
        "records": records,
    }
