"""Execute source-bound analyst/critic reviews over pivotal contract predicates."""
from __future__ import annotations

from collections import Counter
import time
from pathlib import Path
from typing import Any, Callable, Mapping

from guardcontract.backends.base import BackendError, BackendIdentity
from guardcontract.discovery.router import RoutedJob
from guardcontract.evidence.validation import verify_span
from guardcontract.protocols.contract_predicates import SYSTEM, build_request, consensus, decode


def _repository_name(repository_id: str) -> str:
    if "@" not in repository_id:
        raise ValueError("repository_id does not contain a revision")
    return repository_id.rsplit("@", 1)[0]


def _roots(materialization: Mapping[str, Any]) -> dict[str, Path]:
    return {
        row["repository"]: Path(row["destination"])
        for row in materialization.get("repositories", [])
        if isinstance(row, Mapping) and row.get("status") == "completed"
        and isinstance(row.get("repository"), str) and isinstance(row.get("destination"), str)
    }


def _unknown_response(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "guardcontract-predicate-assertions-1",
        "candidates": [{
            "candidate_id": row["candidate_id"],
            "facts": {field: "unknown" for field in row["query_fields"]},
            "sources": {field: [] for field in row["query_fields"]},
        } for row in payload["candidates"]],
    }


def _call(backend, identity: BackendIdentity, payload, *, max_response_bytes, max_retries,
          retry_delay_seconds, sleep: Callable[[float], None]):
    attempts, calls, error = 0, [], None
    while attempts <= max_retries:
        attempts += 1
        try:
            if identity.wire_api == "none":
                value = _unknown_response(payload)
            elif not hasattr(backend, "complete_json"):
                raise BackendError("backend lacks bounded JSON completion", category="backend_contract")
            else:
                value = backend.complete_json(SYSTEM, payload, max_response_bytes=max_response_bytes)
            metadata = getattr(backend, "last_call_metadata", None)
            if isinstance(metadata, Mapping):
                calls.append(dict(metadata))
            return value, attempts, calls, None
        except BackendError as exc:
            metadata = getattr(backend, "last_call_metadata", None)
            if isinstance(metadata, Mapping):
                calls.append(dict(metadata))
            error = exc
            if not exc.retryable or attempts > max_retries:
                break
            sleep(retry_delay_seconds * (2 ** (attempts - 1)))
    return None, attempts, calls, error


def run_contract_reviews(routed_jobs: list[RoutedJob], materialization: Mapping[str, Any], backend, *,
                         backend_identity: BackendIdentity, iterations: int = 2, max_retries: int = 0,
                         retry_delay_seconds: float = 1.0,
                         sleep: Callable[[float], None] = time.sleep, **_ignored) -> dict[str, Any]:
    if iterations != 2:
        raise ValueError("contract_review_requires_analyst_and_critic")
    if not 0 <= max_retries <= 5 or not 0 <= retry_delay_seconds <= 60:
        raise ValueError("contract_review_retry_configuration")
    roots = _roots(materialization)
    records = []
    for routed in routed_jobs:
        job = routed.job
        record = {"job_id": job.job_id, "repository_id": job.repository_id,
                  "execution_health": "completed", "scientific_outcome": "unscored",
                  "iterations": [], "consensus": None}
        try:
            root = roots[_repository_name(job.repository_id)]
            supplied = {(span.path, span.start_line, span.end_line, span.sha256) for span in job.evidence}
            sliced = {(item.span.path, item.span.start_line, item.span.end_line, item.span.sha256)
                      for item in routed.slices}
            if supplied != sliced:
                raise ValueError("job evidence and routed slices do not match")
            for span in job.evidence:
                verify_span(root, span)
            excerpts = {
                f"s{index}": {**item.span.to_dict(), "content": item.content}
                for index, item in enumerate(routed.slices)
            }
            plan = routed.context.get("contract_query_plan")
            analyst_payload, analyst_spec = build_request(plan, excerpts, role="analyst")
            raw, attempts, calls, error = _call(
                backend, backend_identity, analyst_payload,
                max_response_bytes=job.max_response_bytes, max_retries=max_retries,
                retry_delay_seconds=retry_delay_seconds, sleep=sleep,
            )
            if raw is None:
                assert error is not None
                record["execution_health"] = "error"
                record["iterations"].append({"role": "analyst", "attempts": attempts,
                                             "calls": calls, "execution_health": "error",
                                             "error": {"type": type(error).__name__,
                                                       "category": error.category,
                                                       "message": str(error)[:500]}})
                records.append(record)
                continue
            analyst_iteration = {"role": "analyst", "attempts": attempts, "calls": calls,
                                 "execution_health": "completed", "raw": raw}
            record["iterations"].append(analyst_iteration)
            analyst = decode(raw, analyst_spec)
            analyst_iteration["decoded"] = analyst
            critic_payload, critic_spec = build_request(plan, excerpts, role="critic", prior=raw)
            raw_critic, attempts, calls, error = _call(
                backend, backend_identity, critic_payload,
                max_response_bytes=job.max_response_bytes, max_retries=max_retries,
                retry_delay_seconds=retry_delay_seconds, sleep=sleep,
            )
            if raw_critic is None:
                assert error is not None
                record["execution_health"] = "error"
                record["iterations"].append({"role": "critic", "attempts": attempts,
                                             "calls": calls, "execution_health": "error",
                                             "error": {"type": type(error).__name__,
                                                       "category": error.category,
                                                       "message": str(error)[:500]}})
            else:
                critic_iteration = {"role": "critic", "attempts": attempts, "calls": calls,
                                    "execution_health": "completed", "raw": raw_critic}
                record["iterations"].append(critic_iteration)
                critic = decode(raw_critic, critic_spec)
                critic_iteration["decoded"] = critic
                record["consensus"] = consensus(plan, analyst, critic)
        except (KeyError, OSError, ValueError) as exc:
            record["execution_health"] = "error"
            record["error"] = {"type": type(exc).__name__, "category": "execution_error",
                               "message": str(exc)[:500]}
        records.append(record)
    calls = [call for row in records for iteration in row["iterations"] for call in iteration.get("calls", [])]
    expected_calls = sum(iteration.get("attempts", 0) for row in records for iteration in row["iterations"])
    reported, missing = {}, {}
    for field in ("input_tokens", "output_tokens", "total_tokens"):
        values = [call[field] for call in calls if type(call.get(field)) is int and call[field] >= 0]
        reported[field] = sum(values)
        missing[field] = max(0, expected_calls - len(values)) if backend_identity.wire_api != "none" else 0
    assessments = [candidate["assessment"] for row in records if row.get("consensus")
                   for candidate in row["consensus"]["candidates"]]
    statuses = Counter(row["classification"] for row in assessments)
    completed = sum(row["execution_health"] == "completed" for row in records)
    return {
        "task_version": "contract-review-1",
        "execution_health": "completed" if completed == len(records) else "partial" if completed else "error",
        "scientific_outcome": "unscored",
        "backend": backend_identity.to_dict(),
        "counts": {
            "planned": len(routed_jobs),
            "completed": completed,
            "error": len(records) - completed,
            "contract_candidates": len(assessments),
            "known_predictions": sum(row["issue_prediction"] is not None for row in assessments),
            "prediction_statuses": dict(sorted(statuses.items())),
            "network_attempts": expected_calls if backend_identity.wire_api != "none" else 0,
        },
        "usage": {
            "calls_with_metadata": len(calls),
            "reported_token_subtotals": reported,
            "calls_missing_token_usage": missing,
            "input_tokens": None if missing["input_tokens"] else reported["input_tokens"],
            "output_tokens": None if missing["output_tokens"] else reported["output_tokens"],
            "total_tokens": None if missing["total_tokens"] else reported["total_tokens"],
            "summed_call_duration_seconds": round(sum(float(call.get("duration_seconds", 0)) for call in calls), 6),
            "cost_usd": None,
        },
        "records": records,
        "claim_boundary": (
            "Predictions are analyst/critic consensus over source-bound local predicates. "
            "They remain unscored until compared with an independently hidden oracle after prediction freeze."
        ),
    }
