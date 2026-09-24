"""Assemble complete per-node assertions without choosing a first guard.

This checks assertion consistency, not truth or source reachability. Callers
must authenticate and canonicalize physical function identities before entry;
different catalogue IDs for the same function must not create extra issues.
Occurrence booleans must already refer to the selected request/resource/operation
instance in the named witness. Arbitrary physical-site writes are insufficient;
legacy model rows need validated instance binding before entering this API.
"""
import hashlib
import json

from guardcontract.core.effects import derive_logical_verdict
from guardcontract.protocols.roles import ROLES

POLICY_ROLES = ("reports_policy_outcome", "policy_conditioned_termination", "policy_conditioned_commit_or_abort")


def canonicalize_functions(repository_id, candidates):
    """Merge discovery labels for one source function within an authenticated job."""
    if not isinstance(repository_id, str) or not repository_id:
        raise ValueError("canonical_function_repository")
    if not isinstance(candidates, (list, tuple)) or any(not isinstance(c, dict) for c in candidates):
        raise ValueError("canonical_function_candidate_records")
    groups, node_bindings = {}, {}
    for candidate in candidates:
        fields = ("path", "source_sha256", "symbol")
        if any(not isinstance(candidate.get(k), str) or not candidate[k] for k in (*fields, "node")):
            raise ValueError("canonical_function_fields")
        start, end = candidate.get("start_line"), candidate.get("end_line")
        if type(start) is not int or type(end) is not int or not 1 <= start <= end:
            raise ValueError("canonical_function_span")
        identity = {"repository_id": repository_id, **{k: candidate[k] for k in fields}, "start_line": start, "end_line": end}
        function_id = "function:" + hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        node = candidate["node"]
        if node in node_bindings and node_bindings[node] != function_id:
            raise ValueError("canonical_node_has_conflicting_sources")
        node_bindings[node] = function_id
        group = groups.setdefault(function_id, {"function_id": function_id, **identity, "candidate_ids": set()})
        group["candidate_ids"].add(node)
    return [{**groups[key], "candidate_ids": sorted(groups[key]["candidate_ids"])} for key in sorted(groups)]


def assemble(*, source_revision, scenario_sha256, logical_effect_id, scenario_witnesses,
             guard_candidates, sink_candidates, guards, realizations):
    if any(not isinstance(value, str) or not value for value in (source_revision, scenario_sha256, logical_effect_id)):
        raise ValueError("assembly_scenario_identity")
    if not isinstance(guards, list) or any(not isinstance(g, dict) for g in guards):
        raise ValueError("assembly_guard_rows")
    if not isinstance(scenario_witnesses, dict) or set(scenario_witnesses) != {"ALLOW", "DENY"} or any(not isinstance(v, str) or not v for v in scenario_witnesses.values()) or len(set(scenario_witnesses.values())) != 2:
        raise ValueError("assembly_distinct_scenario_witnesses")
    for candidates in (guard_candidates, sink_candidates):
        if not isinstance(candidates, (list, tuple, set, frozenset)) or any(not isinstance(n, str) or not n for n in candidates) or len(candidates) != len(set(candidates)):
            raise ValueError("assembly_candidate_identity_set")
    guard_ids = [g.get("guard_id") for g in guards]
    if any(not isinstance(g, str) or not g for g in guard_ids) or len(guard_ids) != len(set(guard_ids)) or set(guard_ids) != set(guard_candidates):
        raise ValueError("assembly_complete_guard_set_required")
    # Validate the whole physical-site set even when there is no eligible guard.
    derive_logical_verdict(None, realizations, set(sink_candidates))
    sites = []
    for row in sorted(realizations, key=lambda r: r["sink_site"]):
        scoped = dict(row)
        for decision in ("ALLOW", "DENY"):
            witness_key = decision.lower() + "_witness_id"
            if witness_key not in row or row[witness_key] is not None and (not isinstance(row[witness_key], str) or not row[witness_key]):
                raise ValueError("assembly_site_witness_field")
            if row[witness_key] != scenario_witnesses[decision]:
                scoped[decision.lower() + "_effect_occurs"] = None
        sites.append(scoped)
    assessments = []
    for row in sorted(guards, key=lambda g: g["guard_id"]):
        if set(row) != {"guard_id", "roles", "guard_reports_deny", "deny_witness_id", "effect_scope_relation"} or not isinstance(row["roles"], dict) or set(row["roles"]) != set(ROLES):
            raise ValueError("assembly_guard_fields")
        witness = row["deny_witness_id"]
        if witness is not None and (not isinstance(witness, str) or not witness):
            raise ValueError("assembly_guard_witness_field")
        relation = row["effect_scope_relation"]
        if relation not in {"protects_selected_effect", "unrelated", "unknown"}:
            raise ValueError("assembly_effect_scope_relation")
        if any(v is not None and type(v) is not bool for v in row["roles"].values()):
            raise ValueError("assembly_role_boolean_or_unknown")
        deny = row["guard_reports_deny"]
        if deny is not None and type(deny) is not bool:
            raise ValueError("assembly_deny_boolean_or_unknown")
        policy = [row["roles"][role] for role in POLICY_ROLES]
        eligible = True if any(v is True for v in policy) else False if all(v is False for v in policy) else None
        if eligible is False and deny is True:
            raise ValueError("assembly_deny_without_local_policy_role")
        identity = {"source_revision": source_revision, "scenario_sha256": scenario_sha256,
                    "logical_effect_id": logical_effect_id, "guard_id": row["guard_id"], "scenario_deny_witness_id": scenario_witnesses["DENY"]}
        key = "actor-assessment:" + hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        witness_matches = witness == scenario_witnesses["DENY"]
        qualified = eligible is True and relation == "protects_selected_effect" and witness_matches
        verdict = derive_logical_verdict(deny, sites, set(sink_candidates)) if qualified else "unknown"
        state = "not_policy_actor" if eligible is False else "outside_selected_effect_scope" if relation == "unrelated" else "assessed" if verdict != "unknown" else "unknown"
        assessments.append({**identity, "assessment_key": key, "policy_role_eligible": eligible,
                            "effect_scope_relation": relation, "deny_witness_matches": witness_matches,
                            "guard_reports_deny": deny, "state": state, "verdict": verdict,
                            "deny_witness_site_claims": [r["sink_site"] for r in sites
                                if r["relation"] == "same_logical_effect" and r["deny_effect_occurs"] is True] if verdict == "present" else []})
    return {"schema_version": "203-2", "assessments": assessments,
            "present_assessment_keys": [r["assessment_key"] for r in assessments if r["verdict"] == "present"],
            "unknown_guard_ids": [r["guard_id"] for r in assessments if r["state"] == "unknown"],
            "not_policy_actor_ids": [r["guard_id"] for r in assessments if r["state"] == "not_policy_actor"],
            "no_candidate_guard": not assessments, "source_semantics_verified": False,
            "deduplication_scope": "provided_canonical_guard_ids_only",
            "assessment_count_is_not_vulnerability_count": True,
            "required_occurrence_scope": "selected_request_resource_operation_instance",
            "scope": "deterministic_assembly_of_assertions_not_source_execution_proof"}
