"""Account for every input while routing neutral API-identity review jobs."""
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

from guardcontract.discovery.router import RoutedJob, stable_node_id
from guardcontract.core.schemas import EvidenceJob
from guardcontract.evidence.slicing import slice_file
from guardcontract.evidence.repository_evidence import safe_path

ROUTER_VERSION = "162-1"


def route_relevance(evidence, selection, verifier, root, config):
    for field, upper in (("max_jobs", 10000), ("context_lines", 200), ("max_slice_bytes", 65536)):
        if type(config.get(field)) is not int or not 1 <= config[field] <= upper:
            raise ValueError("invalid_" + field)
    if config.get("mode") not in {"local", "cloud"}:
        raise ValueError("invalid_mode")
    rows = evidence["records"]
    by_id = {r["source_record_id"]: r for r in rows}
    if len(by_id) != len(rows):
        raise ValueError("duplicate_input_record")
    selected = [sid for repo in selection["repositories"] for sid in repo["selected_ids"]]
    if len(selected) != len(set(selected)) or not set(selected) <= set(by_id):
        raise ValueError("invalid_selection_identity")
    if any(by_id[sid]["repository"] != repo.get("repository") for repo in selection["repositories"] for sid in repo["selected_ids"]):
        raise ValueError("selection_repository_mismatch")
    selected_set = set(selected)
    audit = {sid: {"source_record_id": sid, "repository": row["repository"], "framework": row["framework"],
                   "status": "not_selected_by_representative_budget"} for sid, row in by_id.items()}
    buckets = defaultdict(list)
    for sid in selected:
        row = by_id[sid]
        buckets[(row["framework"], row["api_binding"]["status"])].append(sid)
    for bucket in buckets.values(): bucket.sort(reverse=True)
    ordered = []
    while any(buckets.values()):
        for key in sorted(buckets):
            if buckets[key]: ordered.append(buckets[key].pop())
    jobs, materialized = [], {}
    for sid in ordered:
        row, item = by_id[sid], audit[sid]
        if row["integrity"]["status"] != "verified":
            item["status"] = "blocked_source_integrity"
            continue
        if row["path"].endswith(".ipynb") or row.get("cell") is not None:
            item["status"] = "blocked_notebook_span_schema"
            continue
        if len(jobs) >= config["max_jobs"]:
            item["status"] = "deferred_model_job_budget"
            continue
        try:
            lines, metadata = verifier.source(row, row["path"], row.get("cell"))
            if metadata["file_sha256"] != row["integrity"]["file_sha256"]:
                raise ValueError("frozen_file_hash_mismatch")
            repo = safe_path(root, metadata["destination"])
            raw = safe_path(repo, row["path"]).read_bytes()
            if hashlib.sha256(raw).hexdigest() != metadata["file_sha256"]:
                raise ValueError("source_changed_during_read")
            line = row["line"]
            line_count = len(raw.splitlines())
            if type(line) is not int or not 1 <= line <= line_count:
                raise ValueError("invalid_anchor_line")
            locations = [line]
            imported = row["api_binding"].get("import_line")
            if type(imported) is int and 1 <= imported <= line_count:
                locations.append(imported)
            slices = []
            for location in locations:
                if any(s.span.start_line <= location <= s.span.end_line for s in slices): continue
                slices.append(slice_file(repo, row["path"], max(1, location - config["context_lines"]), min(line_count, location + config["context_lines"]), cloud=True, max_bytes=config["max_slice_bytes"]))
                span = slices[-1].span
                frozen_span = b"".join(raw.splitlines(keepends=True)[span.start_line - 1:span.end_line])
                if hashlib.sha256(frozen_span).hexdigest() != span.sha256:
                    raise ValueError("slice_snapshot_mismatch")
            repository_id = row["repository"] + "@" + row["commit"]
            node = stable_node_id(repository_id, "source_occurrence", row["path"], line, row.get("marker") or "unknown")
            identity = [ROUTER_VERSION, sid, repository_id, [s.span.to_dict() for s in slices]]
            job_id = "job:" + hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
            question = (
                "Review API identity only in the supplied untrusted source. Does the selected occurrence actually refer to the stated framework API, rather than a comment, string, local lookalike, or unresolved name? "
                "Return claim=binding and supported/refuted/unknown with exact supplied source citations. Configuration, runtime activation, object role, effects and risk are separate and must not be inferred from an import. "
                "If definitions or imports are missing, return unknown and request the needed evidence. "
                f"Selected occurrence: framework={row['framework']!r}, path={row['path']!r}, line={line}, marker={row.get('marker')!r}, node={node}."
            )
            job = EvidenceJob(job_id, repository_id, question, (node,), tuple(s.span for s in slices), 65536, config["mode"])
            EvidenceJob.from_dict(job.to_dict())
            prior = materialized.get(row["repository"])
            materialization = {"repository": row["repository"], "commit": row["commit"], "tree": row["tree"], "destination": str(repo), "status": "completed"}
            if prior is not None and prior != materialization:
                raise ValueError("conflicting_repository_materialization")
            materialized[row["repository"]] = materialization
            jobs.append(RoutedJob("api_identity_review", job, tuple(slices), {"source": "relevance_evidence", "source_record_id": sid, "framework": row["framework"], "scope": "api_identity_only"}))
            item.update(status="routed", job_id=job_id, source_file_sha256=metadata["file_sha256"], redactions=sum(s.redactions for s in slices))
        except (ValueError, OSError, KeyError, TypeError, IndexError) as exc:
            item.update(status="blocked_evidence_preparation", error_kind=type(exc).__name__, reason=str(exc)[:300])
        finally:
            verifier.files.clear()
    statuses = Counter(r["status"] for r in audit.values())
    report = {"task_version": ROUTER_VERSION, "execution_health": "partial" if any(r["status"] != "routed" for sid, r in audit.items() if sid in selected_set) else "completed", "scientific_outcome": "unscored",
              "counts": {"input_records": len(rows), "representative_selected": len(selected), "jobs": len(jobs), "statuses": dict(statuses)},
              "redaction_policy": "always_redact_even_for_local_jobs",
              "records": list(audit.values()), "claim_boundary": "Complete routing accounting, not complete semantic coverage. No source record is dropped; notebook spans and budget deferrals remain visible. Jobs address API identity only, not full guard-effect relevance."}
    return jobs, {"repositories": list(materialized.values())}, report
