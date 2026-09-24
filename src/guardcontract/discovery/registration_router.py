"""Route registration candidates into the existing finding/critic pipeline."""
import hashlib
import json
from pathlib import Path

from guardcontract.discovery.registration import discover_registrations
from guardcontract.discovery.registration_v2 import discover_registrations as discover_class_registrations
from guardcontract.discovery.router import RoutedJob, stable_node_id
from guardcontract.core.schemas import EvidenceJob, EvidenceSpan
from guardcontract.evidence.slicing import EvidenceSlice, redact_secrets
from guardcontract.evidence.validation import safe_relative_path
from guardcontract.core.effects import attach_effect_attestations, build_effect_catalog, actionable_effects


def route_registration_repository(root, repository_id, framework, *, mode="cloud", max_jobs=40,
                                  max_total_bytes=65536, max_slice_bytes=32768, context_lines=8,
                                  registration_index="base", effect_attestations_by_id=None,
                                  module_roots=(".",), layout_mode="packaging", include_generic_effect_candidates=False):
    if mode not in {"cloud", "local"} or max_jobs < 1 or max_total_bytes < 1024:
        raise ValueError("invalid_registration_routing_configuration")
    root = Path(root).resolve()
    if not root.is_dir():
        raise ValueError("registration_source_root_missing")
    scanners = {"base": discover_registrations, "class_attributes": discover_class_registrations}
    if registration_index not in scanners:
        raise ValueError("unknown_registration_index")
    if effect_attestations_by_id is not None and not isinstance(effect_attestations_by_id, dict):
        raise ValueError("effect_attestations_mapping")
    if effect_attestations_by_id is not None and any(
            not isinstance(effect_id, str) or not isinstance(attestation, dict)
            for effect_id, attestation in effect_attestations_by_id.items()):
        raise ValueError("effect_attestations_mapping_entry")
    supplied_attestation_ids = set(effect_attestations_by_id or {})
    applied_attestation_ids = set()
    discovery = scanners[registration_index](root, max_groups=max_jobs, module_roots=module_roots, layout_mode=layout_mode)
    generic_unbound = []
    if include_generic_effect_candidates is True:
        from guardcontract.discovery.generic_effect_catalog import inventory as generic_inventory
        generic_unbound = generic_inventory(root, include_non_production=False).get("effects", [])[:200]
    discovery["registration_index"] = registration_index
    source_inventory = {r["path"]: r for r in discovery["files"] if r["status"] == "parsed"}
    source_inventory.update({r["path"]: r for r in discovery["project_layout"]["files"] if r["status"] == "parsed"})
    snapshots = {}

    def snapshot(path):
        if path not in snapshots:
            relative = safe_relative_path(path)
            target = root.joinpath(*relative.parts)
            if target.is_symlink() or not target.resolve().is_relative_to(root) or path not in source_inventory:
                raise ValueError("unregistered_source_path")
            with target.open("rb") as handle:
                raw = handle.read(source_inventory[path]["bytes"] + 1)
            if hashlib.sha256(raw).hexdigest() != source_inventory[path]["source_sha256"]:
                raise ValueError("registration_source_changed")
            snapshots[path] = raw.splitlines(keepends=True)
        return snapshots[path]
    jobs, accounting = [], []
    for index, group in enumerate(discovery["groups"]):
        group_id = hashlib.sha256(json.dumps(group, sort_keys=True).encode()).hexdigest()
        row = {"group_id": group_id, "kind": group["kind"], "registration_path": group["path"],
               "registration_line": group["registration_line"]}
        if group.get("framework") != framework:
            accounting.append({**row, "status": "framework_mismatch", "detected_framework": group.get("framework")})
            continue
        if not group["effects"]:
            accounting.append({**row, "status": "unresolved_effect_no_job",
                               "unresolved_tools": group.get("unresolved_tools", [])})
            continue
        ranges = {}
        preparation_errors = []
        def include(path, start, end):
            try:
                count = len(snapshot(path))
                ranges.setdefault(path, []).append((max(1, start), min(count, end)))
            except (OSError, ValueError) as exc:
                preparation_errors.append({"path": path, "error_kind": type(exc).__name__})
        include(group["path"], 1, 30)
        for declaration in discovery["project_layout"]["declarations"]:
            include(declaration["source"], declaration["start_line"], declaration["end_line"])
        for binding in [*group.get("tool_binding_spans", []), *group.get("guard_binding_spans", []),
                        *group.get("registration_binding_spans", []), *group.get("call_binding_spans", [])]:
            include(binding["path"], binding["start_line"], binding["end_line"])
        include(group["path"], group["registration_line"] - context_lines,
                group.get("registration_end_line", group["registration_line"]) + context_lines)
        catalog, nodes = [], []
        for kind, entries in (("guard_candidate", group["guards"]),
                              ("unresolved_guard", group.get("unresolved_guards", [])),
                              ("tool", group["tools"]), ("helper_candidate", group["helpers"])):
            for entry in entries:
                start_line = entry.get("start_line", entry.get("line"))
                end_line = entry.get("end_line", start_line)
                symbol = entry.get("symbol") or f"<unresolved:{entry.get('parameter', kind)}>"
                include(entry["path"], entry.get("evidence_start_line", start_line) - context_lines, end_line)
                node = stable_node_id(repository_id, kind, entry["path"], start_line, symbol)
                nodes.append(node)
                catalog.append({"node": node, "kind": kind, "start_line": start_line,
                                "end_line": end_line, "symbol": symbol, **entry})
                if kind == "guard_candidate":
                    catalog[-1]["registration_parameters"] = sorted({p["parameter"]
                        for p in group.get("guard_parameters", [])
                        if p["symbol"] == entry["symbol"] and p["definition_line"] == entry["start_line"]})
        for entry in group["effects"]:
            include(entry["path"], entry["line"] - context_lines, entry["line"] + context_lines)
            node = stable_node_id(repository_id, "effect", entry["path"], entry["line"], entry["call"])
            nodes.append(node)
            catalog.append({"node": node, "kind": "effect", **entry})
        for entry in group.get("unresolved_tools", []):
            include(entry["path"], entry["start_line"], entry["end_line"])
            origin = entry.get("origin") or "unknown"
            node = stable_node_id(repository_id, "unresolved_tool", entry["path"], entry["start_line"], origin)
            nodes.append(node)
            # Raw expressions remain in the source slice, where cloud redaction applies.
            catalog.append({"node": node, "kind": "unresolved_tool", "origin": origin,
                            "path": entry["path"], "start_line": entry["start_line"],
                            "end_line": entry["end_line"], "reason": entry["reason"]})
        call_candidates = []
        for edge in group.get("local_call_edges", []):
            def matching_nodes(entry):
                return [n["node"] for n in catalog if n.get("symbol") == entry["symbol"]
                        and n.get("path") == entry["path"] and n.get("start_line") == entry["start_line"]]
            for caller in matching_nodes(edge["caller"]):
                for callee in matching_nodes(edge["callee"]):
                    call_candidates.append({"from": caller, "to": callee, "kind": "calls",
                                            "path": edge["path"], "line": edge["line"],
                                            "status": edge["status"]})
                    include(edge["path"], edge["line"], edge["line"])
        slices = []
        try:
            if preparation_errors:
                raise ValueError("registration_source_unavailable")
            for path, intervals in sorted(ranges.items()):
                merged = []
                for start, end in sorted(intervals):
                    if merged and start <= merged[-1][1] + 1:
                        merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
                    else:
                        merged.append((start, end))
                for start, end in merged:
                    raw = b"".join(snapshot(path)[start - 1:end])
                    if len(raw) > max_slice_bytes:
                        raise ValueError("registration_slice_budget")
                    content = raw.decode("utf-8")
                    content, redactions = redact_secrets(content) if mode == "cloud" else (content, 0)
                    span = EvidenceSpan(path, start, end, hashlib.sha256(raw).hexdigest())
                    slices.append(EvidenceSlice(span, content, redactions))
            if sum(len(s.content.encode()) for s in slices) > max_total_bytes or len(slices) > 16:
                raise ValueError("registration_evidence_budget")
            identity = {"repository": repository_id, "framework": framework, "mode": mode, "group_id": group_id,
                        "evidence": [s.span.to_dict() for s in slices]}
            job_id = "job:" + hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
            question = (
                "These are source registration candidates, not proved execution paths. "
                "Determine actual roles of registered callbacks and helper candidates, including delegated policy decisions and deferred commits. "
                "Recover which supplied guard and protected effect actually share a configured path, "
                "and whether DENY can coexist with that effect. Distinguish staging an intent from committing an effect, "
                "and callback registration from runtime activation. Use unknown where dispatch semantics are missing. "
                "Unresolved tools remain part of the registered scope; missing effect evidence is not evidence of safety. "
                "Declared import roots (analysis assumptions, not runtime proof): "
                + json.dumps(discovery["module_roots"]) + ". "
                + "Framework=" + framework + ". Node catalog: " + json.dumps(catalog, sort_keys=True)
                + ". Lexically resolved local call candidates (not runtime reachability): "
                + json.dumps(call_candidates, sort_keys=True)
            )
            if len(question.encode()) + sum(len(s.content.encode()) for s in slices) > max_total_bytes:
                raise ValueError("registration_total_context_budget")
            job = EvidenceJob(job_id, repository_id, question, tuple(dict.fromkeys(nodes)),
                              tuple(s.span for s in slices), 65536, mode)
            effect_catalog = build_effect_catalog(repository_id, catalog, call_candidates)
            if effect_attestations_by_id:
                known_ids = {row["logical_effect_id"] for row in effect_catalog["logical_effects"]}
                attestations = []
                matched_ids = set()
                for effect_id, attestation in effect_attestations_by_id.items():
                    if effect_id in known_ids:
                        payload = dict(attestation)
                        payload["logical_effect_id"] = effect_id
                        attestations.append(payload)
                        matched_ids.add(effect_id)
                effect_catalog = attach_effect_attestations(effect_catalog, attestations)
                applied_attestation_ids.update(matched_ids)
            effect_partition = actionable_effects(effect_catalog)
            effect_catalog_sha256 = hashlib.sha256(
                json.dumps(effect_catalog, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            jobs.append(RoutedJob("registration_semantic_review", job, tuple(slices), {
                "source": "registration_scout_182", "framework": framework, "decidability": "unknown_dynamic",
                "ast_tool_effect_binding": False, "guard_effect_path_verified": False,
                "registration_kind": group["kind"], "node_catalog": catalog,
                "unresolved_tool_count": len(group.get("unresolved_tools", [])),
                "local_call_candidates": call_candidates,
                "shared_call_gaps": group.get("shared_tool_calls", {}).get("gaps", []),
                "shared_call_truncated": group.get("shared_tool_calls", {}).get("truncated", False),
                "module_roots": discovery["module_roots"],
                "module_root_declarations": discovery["project_layout"]["declarations"],
                "project_layout_gaps": discovery["project_layout"]["gaps"],
                "unbound_effect_candidates": generic_unbound,
                "effect_catalog": effect_catalog,
                "effect_catalog_sha256": effect_catalog_sha256,
                "actionable_effects": effect_partition,
                "effect_evidence_boundary": "Actionable effects require independent resource and runtime binding; all current catalog entries are candidates unless explicitly verified.",
            }))
            accounting.append({**row, "status": "routed", "job_id": job_id, "slice_count": len(slices)})
        except (OSError, ValueError) as exc:
            accounting.append({**row, "status": "evidence_unavailable", "error_kind": type(exc).__name__, "source_errors": preparation_errors})
    unmatched_attestation_ids = sorted(supplied_attestation_ids - applied_attestation_ids)
    return jobs, {"task_version": "182-1", "discovery": discovery, "routing": accounting,
                  "counts": {"groups": len(discovery["groups"]), "routed": len(jobs),
                             "not_routed": len(discovery["groups"]) - len(jobs),
                             "groups_budget_deferred": discovery["groups_budget_deferred"],
                             "effect_attestations_supplied": len(supplied_attestation_ids),
                             "effect_attestations_applied": len(applied_attestation_ids),
                             "effect_attestations_unmatched": len(unmatched_attestation_ids)},
                  "unmatched_effect_attestation_ids": unmatched_attestation_ids,
                  "goal_completion_proven": False}
