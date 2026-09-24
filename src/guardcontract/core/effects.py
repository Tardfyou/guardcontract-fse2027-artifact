"""Separate candidate logical actions from their possible implementation sites."""
from copy import deepcopy
import hashlib
import json
import re


def build_effect_catalog(repository_id, node_catalog, call_candidates=()):
    nodes = {n["node"]: n for n in node_catalog}
    if len(nodes) != len(node_catalog):
        raise ValueError("duplicate_effect_catalog_node")
    tools = [n for n in node_catalog if n["kind"] == "tool"]
    sinks = [n for n in node_catalog if n["kind"] == "effect"]
    logical = []
    for tool in tools:
        direct = [s for s in sinks if s["path"] == tool["path"] and tool["start_line"] <= s["line"] <= tool["end_line"]]
        anchors = [(s["family"], s["node"]) for s in direct]
        if not anchors:
            anchors = [(family, None) for family in sorted({s["family"] for s in sinks})]
        for family, anchor in anchors:
            identity = {"repository_id": repository_id, "tool_node": tool["node"], "family": family, "declaration_anchor": anchor}
            logical.append({"logical_effect_id": "logical:" + hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest(),
                            **identity, "identity_granularity": "declared_operation_candidate" if anchor else "tool_family_unresolved",
                            "candidate_sink_sites": [s["node"] for s in sinks if s["family"] == family],
                            "resource_binding_verified": False, "runtime_participation_verified": False,
                            "binding_status": "candidate_bound_site" if anchor else "unknown_unbound_family",
                            "path_status": "same_file_direct_candidate" if anchor else "unknown_path"})
    raw_edges = list(call_candidates)
    edges = [edge for edge in raw_edges if isinstance(edge, dict)
             and isinstance(edge.get("from"), str) and isinstance(edge.get("to"), str)
             and edge.get("status") == "resolved"]
    non_resolved_edge_count = len(raw_edges) - len(edges)
    adjacency = {}
    for edge in edges:
        adjacency.setdefault(edge["from"], set()).add(edge["to"])
    tool_nodes = {tool["node"] for tool in tools}
    effect_nodes = {sink["node"] for sink in sinks}
    reachable = set(tool_nodes)
    frontier = list(tool_nodes)
    while frontier:
        current = frontier.pop()
        for target in adjacency.get(current, ()):
            if target not in reachable:
                reachable.add(target)
                frontier.append(target)
    for item in logical:
        candidates = set(item["candidate_sink_sites"])
        anchor = item.get("declaration_anchor")
        item["call_path_status"] = (
            "call_graph_incomplete" if non_resolved_edge_count
            else "reached_by_resolved_local_call" if anchor in reachable and anchor in effect_nodes
            else "unbound_family_with_resolved_edges" if anchor is None and edges
            else "not_reached_by_resolved_local_call" if edges
            else "no_resolved_local_call_edges"
        )
    return {"task_version": "192-1", "logical_effects": logical, "sink_sites": sinks,
            "resolved_call_edges": len(edges), "non_resolved_call_edges": non_resolved_edge_count,
            "claim_boundary": "Declaration anchors describe candidate protected operations; they do not assert that their bodies execute. Membership of helper sinks requires independent resource/path evidence."}


def actionable_effects(catalog):
    """Expose only effects with explicit source binding; unresolved candidates stay unknown."""
    if not isinstance(catalog, dict) or not isinstance(catalog.get("logical_effects"), list):
        raise ValueError("effect_catalog_shape")
    base_digest = catalog.get("base_catalog_sha256")
    def attested(item):
        proof = item.get("attestation")
        return (isinstance(base_digest, str)
                and isinstance(proof, dict)
                and proof.get("catalog_sha256") == base_digest
                and proof.get("repository_id") == item.get("repository_id")
                and isinstance(proof.get("validator_id"), str) and bool(proof["validator_id"].strip())
                and isinstance(proof.get("evidence_sha256"), str)
                and re.fullmatch(r"[0-9a-f]{64}", proof["evidence_sha256"]) is not None
                and isinstance(proof.get("oracle_manifest_sha256"), str)
                and re.fullmatch(r"[0-9a-f]{64}", proof["oracle_manifest_sha256"]) is not None)
    selected = [item for item in catalog["logical_effects"]
                if item.get("binding_status") == "candidate_bound_site"
                and item.get("call_path_status") == "reached_by_resolved_local_call"
                and item.get("resource_binding_verified") is True
                and item.get("runtime_participation_verified") is True
                and attested(item)]
    unknown = [item for item in catalog["logical_effects"] if item not in selected]
    return {"actionable": selected, "unknown": unknown,
            "actionable_count": len(selected), "unknown_count": len(unknown),
            "claim_boundary": "Actionable requires a source-bound attestation plus explicit resource and runtime binding flags. This function validates structure and identity but does not certify validator independence."}


def attach_effect_attestations(catalog, attestations):
    """Attach shaped external evidence without authenticating the submitting validator."""
    if not isinstance(catalog, dict) or not isinstance(catalog.get("logical_effects"), list):
        raise ValueError("effect_catalog_shape")
    if not isinstance(attestations, list):
        raise ValueError("effect_attestations_shape")
    result = deepcopy(catalog)
    catalog_digest = hashlib.sha256(json.dumps(catalog, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    repository_id = next((row.get("repository_id") for row in result["logical_effects"] if row.get("repository_id")), None)
    if repository_id is None and result["logical_effects"]:
        raise ValueError("effect_catalog_repository_identity")
    effects = {row.get("logical_effect_id"): row for row in result["logical_effects"]}
    seen = set()
    for row in attestations:
        if not isinstance(row, dict):
            raise ValueError("effect_attestation_shape")
        effect_id = row.get("logical_effect_id")
        if effect_id in seen:
            raise ValueError("duplicate_effect_attestation")
        if effect_id not in effects:
            raise ValueError("unknown_effect_attestation")
        seen.add(effect_id)
        for field in ("resource_binding_verified", "runtime_participation_verified"):
            if type(row.get(field)) is not bool:
                raise ValueError("effect_attestation_boolean")
        digest = row.get("evidence_sha256")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError("effect_attestation_evidence_hash")
        validator_id = row.get("validator_id")
        if not isinstance(validator_id, str) or not validator_id.strip():
            raise ValueError("effect_attestation_validator")
        if row.get("repository_id") != repository_id:
            raise ValueError("effect_attestation_repository_mismatch")
        oracle_manifest = row.get("oracle_manifest_sha256")
        if not isinstance(oracle_manifest, str) or re.fullmatch(r"[0-9a-f]{64}", oracle_manifest) is None:
            raise ValueError("effect_attestation_oracle_manifest_hash")
        if row.get("catalog_sha256") != catalog_digest:
            raise ValueError("effect_attestation_catalog_mismatch")
        target = effects[effect_id]
        target["resource_binding_verified"] = row["resource_binding_verified"]
        target["runtime_participation_verified"] = row["runtime_participation_verified"]
        target["attestation"] = {"validator_id": validator_id, "evidence_sha256": digest,
                                  "oracle_manifest_sha256": oracle_manifest, "catalog_sha256": catalog_digest,
                                  "repository_id": repository_id}
    result["attestation_count"] = len(attestations)
    result["base_catalog_sha256"] = catalog_digest
    result["attestation_boundary"] = (
        "Schema and catalog identity are validated; validator independence and evidence meaning "
        "must be authenticated by the caller before metrics or holdout use."
    )
    return result


def derive_logical_verdict(guard_reports_deny, realizations, expected_sink_ids):
    if guard_reports_deny is not None and type(guard_reports_deny) is not bool:
        raise ValueError("guard_state_must_be_boolean_or_unknown")
    if not isinstance(realizations, list) or any(not isinstance(r, dict) or not isinstance(r.get("sink_site"), str) for r in realizations):
        raise ValueError("realization_list_required")
    ids = [r.get("sink_site") for r in realizations]
    if len(ids) != len(set(ids)) or set(ids) != set(expected_sink_ids):
        raise ValueError("realization_set_mismatch")
    for row in realizations:
        if row.get("relation") not in {"same_logical_effect", "different_effect", "unknown"}:
            raise ValueError("invalid_realization_relation")
        for key in ("allow_effect_occurs", "deny_effect_occurs"):
            if key not in row or row[key] is not None and type(row[key]) is not bool:
                raise ValueError("realization_state_must_be_boolean_or_unknown")
    if guard_reports_deny is not True or not realizations:
        return "unknown"
    same = [r for r in realizations if r["relation"] == "same_logical_effect"]
    # A DENY counterexample is sufficient even if the ALLOW path has no effect.
    if any(r["deny_effect_occurs"] is True for r in same):
        return "present"
    potential = [r for r in realizations if r["relation"] != "different_effect"]
    if (any(r["allow_effect_occurs"] is True for r in same)
            and all(r["deny_effect_occurs"] is False for r in potential)):
        return "blocked"
    return "unknown"
