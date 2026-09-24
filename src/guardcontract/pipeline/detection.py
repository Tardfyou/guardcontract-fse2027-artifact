from __future__ import annotations

import hashlib
from collections import Counter
import argparse
from dataclasses import replace
import json
import time
from pathlib import Path
from typing import Any, Callable, Mapping

from guardcontract.backends.base import BackendError, BackendIdentity, ModelBackend
from guardcontract.backends.base import DeterministicUnknownBackend, OpenAICompatibleBackend
from guardcontract.pipeline.merge import hypothesis_record
from guardcontract.evidence.revalidation import revalidate_finding
from guardcontract.discovery.router import RoutedJob
from guardcontract.core.schemas import FindingEnvelope
from guardcontract.core.evidence_gate import assess_actionable
from guardcontract.evidence.validation import validate_finding, verify_span


PIPELINE_VERSION = "166-1"

def static_prediction(certificate, evidence_gate=None):
    """Return a tri-state prediction and preserve why evidence was withheld."""
    if not isinstance(certificate, Mapping) or certificate.get("status") != "supported":
        return {"prediction": None, "status": "unknown", "reason": "static_certificate_unsupported"}
    gate = evidence_gate or {}
    if gate.get("ready_for_actionable_detection") is not True:
        reason = gate.get("reason", "evidence_gate_not_ready")
        missing = gate.get("missing_evidence")
        if isinstance(missing, list) and missing:
            reason += ":" + ",".join(str(item) for item in missing)
        return {"prediction": None, "status": "unknown", "reason": reason}
    value = certificate.get("issue_prediction")
    if type(value) is not bool:
        return {"prediction": None, "status": "unknown", "reason": "certificate_issue_prediction_missing_or_invalid"}
    return {"prediction": value, "status": "known", "reason": "certificate_and_evidence_gate_verified"}


def run_config(config):
    """Execute one pinned repository using the shared registration pipeline."""
    split_path = config.get("development_split")
    split_hash = None
    if split_path is not None:
        raw_split = Path(split_path).read_bytes()
        split = json.loads(raw_split)
        allowed = {row["full_name"] for row in split["development"]}
        if _repository_name(config["repository_id"]) not in allowed:
            raise ValueError("repository_not_in_declared_development_split")
        split_hash = hashlib.sha256(raw_split).hexdigest()
    backend_config = dict(config.get("backend", {"kind": "offline"}))
    kind = backend_config.pop("kind")
    if "api_key" in backend_config:
        raise ValueError("use_api_key_file_not_inline_credentials")
    if kind == "offline":
        if backend_config:
            raise ValueError("unexpected_offline_backend_options")
        backend = DeterministicUnknownBackend()
    elif kind == "openai_compatible":
        key_path = backend_config.pop("api_key_file", None)
        key = Path(key_path).read_text().strip() if key_path else None
        backend = OpenAICompatibleBackend(api_key=key, **backend_config)
    elif kind == "compact_references":
        from guardcontract.backends.compact import CompactFindingBackend
        from guardcontract.backends.base import _urllib_transport
        key = Path(backend_config.pop("api_key_file")).read_text().strip()
        backend = CompactFindingBackend(api_key=key, transport=_urllib_transport, **backend_config)
    else:
        raise ValueError("unknown_detection_backend")
    material_path = Path(config["materialization"])
    material = json.loads(material_path.read_bytes())
    run_options = dict(config.get("execution", {}))
    run_options.setdefault("max_retries", 0)
    routing_options = dict(config.get("routing", {}))
    attestation_hash = None
    attestation_file = config.get("effect_attestations_file")
    if attestation_file is not None:
        attestation_path = Path(attestation_file)
        raw_attestations = attestation_path.read_bytes()
        loaded_attestations = json.loads(raw_attestations)
        if not isinstance(loaded_attestations, dict):
            raise ValueError("effect_attestations_file_mapping")
        routing_options["effect_attestations_by_id"] = loaded_attestations
        attestation_hash = hashlib.sha256(raw_attestations).hexdigest()
    result = run_registration_repository(config["root"], config["repository_id"],
        config["framework"], material, backend, backend_identity=backend.identity,
        routing_options=routing_options, sdk_contract_directory=config.get("sdk_contract_sources", config.get("sdk_contract_directory")),
        analysis_contract=config.get("analysis_contract"), analysis_mode=config.get("analysis_mode", "finding"),
        generate_repair=config.get("generate_repair", False),
        repair_strategy=config.get("repair_strategy", "default"), **run_options)
    result["materialization_sha256"] = hashlib.sha256(material_path.read_bytes()).hexdigest()
    result["development_split_sha256"] = split_hash
    result["effect_attestations_sha256"] = attestation_hash
    return result


def main():
    parser = argparse.ArgumentParser(description="Run registration discovery and analyst/critic evidence analysis")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("detection_output_exists")
    raw = args.config.read_bytes()
    result = run_config(json.loads(raw))
    result["config_sha256"] = hashlib.sha256(raw).hexdigest()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as handle:
        json.dump(result, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps({"execution_health": result["execution_health"], "counts": result["counts"]}))


def run_registration_repository(root, repository_id, framework, materialization, backend, *,
                                backend_identity, routing_options=None, sdk_contract_directory=None,
                                analysis_contract=None, analysis_mode="finding", generate_repair=False,
                                repair_strategy="default", **run_options):
    """Route registered candidates through the existing model/evidence pipeline."""
    from guardcontract.discovery.registration_router import route_registration_repository

    if repair_strategy not in {"default", "immutable_input_short_circuit"}:
        raise ValueError("unknown_repair_strategy")
    if analysis_mode not in {"finding", "predicate_contract"}:
        raise ValueError("unknown_analysis_mode")
    if repair_strategy != "default" and framework != "openai-agents":
        raise ValueError("repair_strategy_framework_mismatch")

    if generate_repair and (framework not in {"google-adk", "pydantic-ai", "langchain", "openai-agents", "crewai"} or sdk_contract_directory is None):
        raise ValueError("repair_requires_adk_sdk_certificate")

    repository = _repository_name(repository_id)
    revision = repository_id.rsplit("@", 1)[1]
    matches = [row for row in materialization.get("repositories", [])
               if row.get("repository") == repository and row.get("status") == "completed"]
    if (len(matches) != 1 or not revision or matches[0].get("commit") != revision
            or Path(matches[0].get("destination", "")).resolve() != Path(root).resolve()):
        raise ValueError("registration_materialization_identity_mismatch")
    options = dict(routing_options or {})
    options.setdefault("mode", backend_identity.deployment)
    max_contract_candidates = int(options.pop("max_contract_candidates", 200))
    jobs, routing = route_registration_repository(root, repository_id, framework, **options)
    contract = None
    reference = None
    if sdk_contract_directory is not None:
        if framework not in {"google-adk", "pydantic-ai", "langchain", "openai-agents", "crewai"}:
            raise ValueError("unsupported_sdk_reference_framework")
        if framework == "google-adk":
            from guardcontract.evidence.adk_sdk_contract import enroll
            from guardcontract.analysis.adk_paths import analyze as analyze_paths
            from guardcontract.repair.adk_placement import propose
        elif framework == "pydantic-ai":
            from guardcontract.evidence.pydantic_sdk_contract import enroll
            from guardcontract.analysis.pydantic_paths import analyze as analyze_paths
            from guardcontract.repair.pydantic_deferral import propose
        elif framework == "langchain":
            from guardcontract.evidence.langchain_sdk_contract import enroll
            from guardcontract.analysis.langchain_paths import analyze as analyze_paths
            from guardcontract.repair.langchain_deferral import propose
        elif framework == "openai-agents":
            from guardcontract.evidence.openai_sdk_contract import enroll
            from guardcontract.analysis.openai_paths_v2 import analyze as analyze_paths
            from guardcontract.repair.openai_race_sync import propose
            if repair_strategy == "immutable_input_short_circuit":
                from guardcontract.repair.openai_race_sync import propose_input_short_circuit as propose
        else:
            from guardcontract.evidence.crewai_sdk_contract import enroll
            from guardcontract.analysis.crewai_paths import analyze as analyze_paths
            from guardcontract.repair.crewai_task_deferral import propose
        contract = enroll(**sdk_contract_directory) if isinstance(sdk_contract_directory, Mapping) else enroll(sdk_contract_directory)
        application = Path(root) / "app.py"
        helper = Path(root) / "deferred_effects.py"
        source_args = []
        needs_helper = framework in {"pydantic-ai", "langchain"}
        if application.is_file() and (not needs_helper or helper.is_file()):
            source_args = [application.read_text(encoding="utf-8")]
            if needs_helper:
                source_args.append(helper.read_text(encoding="utf-8"))
            routing["static_path_certificate"] = analyze_paths(
                *source_args, contract, repository_id=repository_id)
        else:
            routing["static_path_certificate"] = {"status": "unknown", "gaps": ["app_source_unavailable"]}
        if generate_repair:
            certificate = routing["static_path_certificate"]
            routing["repair"] = {"status": "not_generated", "runtime_verified": False}
            if certificate.get("status") == "supported" and certificate.get("issue_prediction") is True:
                try:
                    routing["repair"] = {"status": "generated", **propose(
                        *source_args, certificate, contract)}
                except (ValueError, SyntaxError) as exc:
                    routing["repair"] = {"status": "generation_failed", "generated_patch": False,
                                         "runtime_verified": False, "error": _safe_error(exc)}
        certificate = routing.get("static_path_certificate", {})
        routing["evidence_gate"] = {
            "policy_scope_status": routing.get("policy_scope_status", "unknown"),
            "guard_effect_path_status": "supported" if certificate.get("status") == "supported" else "unknown",
            "independent_order_witness": False,
            "ready_for_actionable_detection": False,
            "reason": "application_policy_scope_and_independent_order_witness_are_not_inferred_from_sdk_contract",
        }
        reference = json.dumps(contract, sort_keys=True)
        routing["sdk_reference"] = contract
    from guardcontract.analysis.registration_contracts import plan_registration_contracts, distribute_analysis_contract
    scoped_contracts = distribute_analysis_contract(analysis_contract, [job.context for job in jobs])
    enriched = []
    contract_plans = []
    for routed, scoped_contract in zip(jobs, scoped_contracts):
        plan = plan_registration_contracts(
            routed.context, framework=framework, sdk_contract=contract,
            analysis_contract=scoped_contract,
            max_candidates=max_contract_candidates,
        )
        contract_plans.append(plan)
        compact_plan = {
            "schema_version": plan["schema_version"],
            "candidates": [{
                "candidate_id": row["candidate_id"],
                "facts": row["facts"],
                "query_fields": row["query_plan"]["query_fields"],
                "lifecycle": row["lifecycle"],
            } for row in plan["candidates"]],
        }
        additions = [
            "\nDeterministic guard-contract query plan. Treat known facts as fixed and address only "
            "the listed unresolved predicates; the final issue verdict is derived outside the model. "
            + json.dumps(compact_plan, sort_keys=True)
        ]
        context = {**routed.context, "contract_query_plan": plan}
        identity_parts = [routed.job.job_id, json.dumps(compact_plan, sort_keys=True)]
        if reference is not None:
            additions.insert(0,
                "\nSDK reference from owned controls. Apply only after checking version and listed limits; "
                "this is not an application path proof or a source excerpt citation. " + reference)
            context["sdk_reference"] = contract
            identity_parts.append(reference)
        question = routed.job.question + "".join(additions)
        if len(question.encode()) + sum(len(s.content.encode()) for s in routed.slices) > options.get("max_total_bytes", 65536):
            raise ValueError("contract_query_context_budget")
        job_id = "job:" + hashlib.sha256("\0".join(identity_parts).encode()).hexdigest()
        for record in routing["routing"]:
            if record.get("job_id") == routed.job.job_id:
                record["job_id"] = job_id
        enriched.append(replace(routed, job=replace(routed.job, job_id=job_id, question=question), context=context))
    jobs = enriched
    routing["contract_query_plans"] = contract_plans
    routing["counts"].update(
        contract_candidates=sum(plan["counts"]["contract_candidates"] for plan in contract_plans),
        pivotal_unknown_predicates=sum(plan["counts"]["pivotal_unknown_predicates"] for plan in contract_plans),
        contract_known_predictions=sum(plan["counts"]["known_predictions"] for plan in contract_plans),
    )
    if analysis_mode == "predicate_contract":
        from guardcontract.pipeline.contract_review import run_contract_reviews
        result = run_contract_reviews(jobs, materialization, backend,
                                      backend_identity=backend_identity, **run_options)
    else:
        result = run_jobs(jobs, materialization, backend, backend_identity=backend_identity, **run_options)
    result["analysis_mode"] = analysis_mode
    result["registration_routing"] = routing
    result_counts = result.setdefault("counts", {})
    for field in ("effect_attestations_supplied", "effect_attestations_applied", "effect_attestations_unmatched",
                  "pivotal_unknown_predicates", "contract_known_predictions"):
        result_counts[field] = routing["counts"].get(field, 0)
    result_counts["contract_candidates_planned"] = routing["counts"].get("contract_candidates", 0)
    stages = {
        "discovery": routing["discovery"]["execution_health"],
        "routing": "partial" if (any(row["status"] == "evidence_unavailable"
                                     for row in routing["routing"])
                                     or routing["counts"].get("effect_attestations_unmatched", 0)) else "completed",
        "model_execution": result["execution_health"],
    }
    result["stage_execution_health"] = stages
    if generate_repair:
        stages["repair_generation"] = "error" if routing.get("repair", {}).get("status") == "generation_failed" else "completed"
    if result["execution_health"] == "completed" and any(s != "completed" for s in stages.values()):
        result["execution_health"] = "partial"
    return result


def _repository_roots(materialization: Mapping[str, Any]) -> dict[str, Path]:
    roots: dict[str, Path] = {}
    for row in materialization.get("repositories", []):
        if not isinstance(row, Mapping) or row.get("status") != "completed":
            continue
        repository, destination = row.get("repository"), row.get("destination")
        if isinstance(repository, str) and isinstance(destination, str):
            roots[repository] = Path(destination)
    return roots


def _repository_name(repository_id: str) -> str:
    if "@" not in repository_id:
        raise ValueError("repository_id does not contain a revision")
    return repository_id.rsplit("@", 1)[0]


def _safe_error(exc: BaseException) -> dict[str, Any]:
    return {
        "type": type(exc).__name__,
        "category": getattr(exc, "category", "execution_error"),
        "message": str(exc)[:500],
        "retryable": bool(getattr(exc, "retryable", False)),
    }


def _finding_signature(value: Mapping[str, Any]) -> str:
    edges = []
    for edge in value.get("path_edges", []):
        if isinstance(edge, Mapping):
            edges.append({"from": edge.get("from"), "to": edge.get("to"), "kind": edge.get("kind")})
    effect = value.get("effect")
    effect_semantics = None
    if isinstance(effect, Mapping):
        effect_semantics = {"family": effect.get("family"), "retractability": effect.get("retractability")}
    material = {
        "claim": value.get("claim"),
        "verdict": value.get("verdict"),
        "path_edges": sorted(edges, key=lambda item: json.dumps(item, sort_keys=True)),
        "effect": effect_semantics,
    }
    return hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def run_jobs(
    routed_jobs: list[RoutedJob],
    materialization: Mapping[str, Any],
    backend: ModelBackend,
    *,
    backend_identity: BackendIdentity,
    iterations: int = 2,
    max_retries: int = 2,
    retry_delay_seconds: float = 1.0,
    sleep: Callable[[float], None] = time.sleep,
    skip_deterministic_pre_effect: bool = False,
) -> dict[str, Any]:
    if not 1 <= iterations <= 3:
        raise ValueError("iterations must be between 1 and 3")
    if not 0 <= max_retries <= 5:
        raise ValueError("max_retries must be between 0 and 5")
    if retry_delay_seconds < 0 or retry_delay_seconds > 60:
        raise ValueError("retry_delay_seconds must be between 0 and 60")

    roots = _repository_roots(materialization)
    records: list[dict[str, Any]] = []
    network_attempts = 0

    for routed in routed_jobs:
        job = routed.job
        record: dict[str, Any] = {
            "job_id": job.job_id,
            "repository_id": job.repository_id,
            "reason": routed.reason,
            "execution_health": "completed",
            "scientific_outcome": "unscored",
            "iterations": [],
            "consensus": "none",
            "hypothesis": None,
        }
        try:
            repository = _repository_name(job.repository_id)
            repo = roots[repository]
            if job.mode != backend_identity.deployment and backend_identity.wire_api != "none":
                raise ValueError("job mode does not match backend deployment")
            supplied = {(span.path, span.start_line, span.end_line, span.sha256) for span in job.evidence}
            sliced = {(item.span.path, item.span.start_line, item.span.end_line, item.span.sha256) for item in routed.slices}
            if supplied != sliced:
                raise ValueError("job evidence and routed slices do not match")
            for span in job.evidence:
                verify_span(repo, span)
            if hasattr(backend, "bind_context"):
                backend.bind_context(job, routed.context)

            if (
                skip_deterministic_pre_effect
                and routed.context.get("ast_tool_effect_binding") is True
                and routed.context.get("decidability") == "pre_effect_decidable"
            ):
                record["deterministic_triage"] = {
                    "status": "skip_withheld_requires_blocking_proof",
                    "reason": "Decision availability is not proof that all protected effects wait for DENY enforcement.",
                    "model_called": True,
                }

            candidate: Mapping[str, Any] | None = None
            feedback: tuple[str, ...] = ()
            accepted: list[Mapping[str, Any]] = []
            for iteration in range(iterations):
                finding = None
                call_error: BaseException | None = None
                attempts = 0
                call_metadata: list[dict[str, Any]] = []
                while attempts <= max_retries:
                    attempts += 1
                    network_attempts += int(backend_identity.deployment == "cloud")
                    try:
                        finding = backend.analyze(
                            job,
                            [item.to_dict() for item in routed.slices],
                            candidate=candidate,
                            feedback=feedback,
                        )
                        metadata = getattr(backend, "last_call_metadata", None)
                        if isinstance(metadata, Mapping):
                            call_metadata.append(dict(metadata))
                        call_error = None
                        break
                    except BackendError as exc:
                        metadata = getattr(backend, "last_call_metadata", None)
                        if isinstance(metadata, Mapping):
                            call_metadata.append(dict(metadata))
                        call_error = exc
                        if not exc.retryable or attempts > max_retries:
                            break
                        sleep(retry_delay_seconds * (2 ** (attempts - 1)))
                if finding is None:
                    assert call_error is not None
                    record["iterations"].append({
                        "index": iteration,
                        "role": "analyst" if iteration == 0 else "critic",
                        "attempts": attempts,
                        "calls": call_metadata,
                        "execution_health": "error",
                        "error": _safe_error(call_error),
                    })
                    record["execution_health"] = "error"
                    break

                validation = validate_finding(repo, job, finding)
                finding_dict = finding.to_dict()
                record["iterations"].append({
                    "index": iteration,
                    "role": "analyst" if iteration == 0 else "critic",
                    "attempts": attempts,
                    "calls": call_metadata,
                    "execution_health": "completed",
                    "finding": finding_dict,
                    "validation": {
                        "accepted": validation.accepted,
                        "confidence": validation.confidence,
                        "errors": list(validation.errors),
                    },
                })
                if validation.accepted:
                    accepted.append(finding_dict)
                candidate = finding_dict
                feedback = validation.errors

            if accepted and len(accepted) == iterations and len(record["iterations"]) == iterations:
                signatures = {_finding_signature(item) for item in accepted}
                if len(signatures) == 1:
                    record["consensus"] = "stable" if len(accepted) > 1 else "single_pass"
                    final_finding = next(
                        item["finding"] for item in reversed(record["iterations"])
                        if item.get("validation", {}).get("accepted")
                    )
                    final_envelope = FindingEnvelope.from_dict(final_finding)
                    hypothesis = hypothesis_record(repo, job, final_envelope)
                    deterministic = revalidate_finding(repo, final_envelope, context=dict(routed.context))
                    hypothesis["deterministic_revalidation"] = deterministic
                    policy_scope = routed.context.get("policy_scope_status", "unknown")
                    source_path_status = routed.context.get("guard_effect_path_status", "unknown")
                    hypothesis["evidence_gate"] = assess_actionable(
                        policy_scope_status=policy_scope,
                        guard_effect_path_status=source_path_status,
                        effect_status=deterministic["effect"],
                        ordering_status=deterministic["ordering"],
                    )
                    evidence_ready = hypothesis["evidence_gate"]["ready_for_actionable_detection"]
                    hypothesis["static_prediction"] = static_prediction(
                        {"status": "supported", "issue_prediction": hypothesis.get("model_verdict") == "supported"},
                        hypothesis["evidence_gate"])
                    hypothesis["review_priority"] = (
                        "high" if evidence_ready
                        else "medium" if deterministic["effect"] == "confirmed" and deterministic["ordering"] == "model_supported_pending_path_oracle"
                        else "ordinary"
                    )
                    record["hypothesis"] = hypothesis
                else:
                    record["consensus"] = "conflict"
                    record["scientific_outcome"] = "confounded"
            elif accepted:
                record["consensus"] = "insufficient_review"
            elif record["execution_health"] == "completed":
                record["consensus"] = "invalid"
        except (KeyError, OSError, ValueError) as exc:
            record["execution_health"] = "error"
            record["error"] = _safe_error(exc)
        records.append(record)

    completed = sum(item["execution_health"] == "completed" for item in records)
    errors = len(records) - completed
    supported_hypotheses = sum(
        (item.get("hypothesis") or {}).get("model_verdict") == "supported"
        for item in records
    )
    high_priority = sum(
        (item.get("hypothesis") or {}).get("review_priority") == "high"
        for item in records
    )
    evidence_gated = sum(bool((item.get("hypothesis") or {}).get("evidence_gate")) for item in records)
    evidence_ready = sum((item.get("hypothesis") or {}).get("evidence_gate", {}).get("ready_for_actionable_detection") is True for item in records)
    prediction_statuses = Counter((item.get("hypothesis") or {}).get("static_prediction", {}).get("status", "not_evaluated") for item in records)
    prediction_reasons = Counter((item.get("hypothesis") or {}).get("static_prediction", {}).get("reason", "not_evaluated") for item in records)
    confirmed_effects = sum(
        ((item.get("hypothesis") or {}).get("deterministic_revalidation") or {}).get("effect") == "confirmed"
        for item in records
    )
    deterministic_dismissals = sum(item["consensus"] == "deterministic_pre_effect" for item in records)
    calls = [call for item in records for iteration in item["iterations"] for call in iteration.get("calls", [])]
    attempts = sum(i.get("attempts", 0) for r in records for i in r["iterations"])
    expected_usage = attempts if backend_identity.wire_api != "none" else len(calls)
    reported = {}
    missing = {}
    for field in ("input_tokens", "output_tokens", "total_tokens"):
        values = [c[field] for c in calls if type(c.get(field)) is int and c[field] >= 0]
        reported[field] = sum(values)
        missing[field] = max(0, expected_usage - len(values))
    input_tokens = None if missing["input_tokens"] else reported["input_tokens"]
    output_tokens = None if missing["output_tokens"] else reported["output_tokens"]
    total_tokens = None if missing["total_tokens"] else reported["total_tokens"]
    duration_seconds = sum(float(call.get("duration_seconds", 0)) for call in calls)
    conflicts = sum(item["consensus"] == "conflict" for item in records)
    return {
        "task_version": PIPELINE_VERSION,
        "execution_health": "completed" if errors == 0 else ("partial" if completed else "error"),
        "scientific_outcome": "unscored",
        "backend": backend_identity.to_dict(),
        "configuration_status": (
            "offline_smoke" if backend_identity.wire_api == "none"
            else "pinned_model_unscored" if backend_identity.revision_status == "pinned"
            else "exploratory_floating_model"
        ),
        "counts": {
            "planned": len(routed_jobs),
            "completed": completed,
            "scored": 0,
            "unscored": len(routed_jobs),
            "confounded": conflicts,
            "error": errors,
            "actionable_hypotheses": high_priority,
            "evidence_gate_evaluated": evidence_gated,
            "evidence_gate_ready": evidence_ready,
            "static_prediction_statuses": dict(sorted(prediction_statuses.items())),
            "static_prediction_reasons": dict(sorted(prediction_reasons.items())),
            "model_supported_not_evidence_ready": sum(
                (item.get("hypothesis") or {}).get("model_verdict") == "supported"
                and (item.get("hypothesis") or {}).get("evidence_gate", {}).get("ready_for_actionable_detection") is not True
                for item in records),
            "model_supported_hypotheses": supported_hypotheses,
            "deterministically_confirmed_effects": confirmed_effects,
            "deterministic_pre_effect_dismissals": deterministic_dismissals,
            "network_attempts": network_attempts,
        },
        "usage": {
            "calls_with_metadata": len(calls),
            "reported_token_subtotals": reported,
            "calls_missing_token_usage": missing,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": total_tokens,
            "summed_call_duration_seconds": round(duration_seconds, 6),
            "cost_usd": None,
        },
        "records": records,
        "claim_boundary": "Decidability does not imply actual mediation. Model-supported issue hypotheses and patch proposals still require independent DENY/effect and ALLOW verification.",
    }


if __name__ == "__main__":
    main()
