"""Lower registration candidates into a shared effect-aware contract lattice."""
from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

from guardcontract.core.path_consistency import CONTRACT_FIELDS, plan_contract_queries


SCHEMAS = {
    "langchain": {"langchain-sdk-contract-1", "langchain-sdk-contract-2"},
    "google-adk": {"google-adk-sdk-contract-1", "google-adk-sdk-contract-2"},
    "pydantic-ai": {"pydantic-sdk-contract-1"},
    "openai-agents": {"openai-agents-sdk-contract-1"},
    "crewai": {"crewai-sdk-contract-1", "crewai-sdk-contract-2"},
}

# A post-effect callback cannot dominate an effect that the enrolled SDK
# contract proves has already happened. Pre-effect APIs remain unknown until the
# application callback's DENY encoding is checked.
POST_EFFECT_RULES = {
    ("langchain", "after_agent"): "after_agent_deny_occurs_after_successful_handler_effect",
    ("google-adk", "after_tool_callback"): "after_tool_callback_occurs_after_successful_tool",
    ("pydantic-ai", "output_validator"): "registered_tool_executes_before_output_validator",
    ("crewai", "guardrail"): "task_guardrail_runs_after_agent_execute_task",
}

PRE_EFFECT_CAPABILITIES = {
    ("langchain", "wrap_tool_call"): "wrapper_return_without_handler_skips_selected_tool",
    ("langchain", "human_in_the_loop"): "human_reject_removes_selected_tool_before_execution",
    ("google-adk", "before_tool_callback"): "before_tool_non_none_skips_selected_tool",
    ("google-adk", "require_confirmation"): "require_confirmation_reject_skips_function_invocation",
    ("openai-agents", "tool_input_guardrails"): "tool_input_guardrail_raise_prevents_function_invocation",
    ("crewai", "register_before_tool_call_hook"): "before_tool_false_blocks_tool_invocation",
    ("crewai", "before_tool_call"): "decorated_before_tool_false_blocks_tool_invocation",
}


def _canonical_sha256(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def validate_analysis_contract(value: Mapping[str, Any] | None) -> dict[str, Any]:
    if value is None:
        value = {"schema_version": "guardcontract-analysis-contract-1",
                 "registered_tool_selection": "unknown"}
    version = value.get("schema_version") if isinstance(value, Mapping) else None
    expected = {"schema_version", "registered_tool_selection"}
    if version == "guardcontract-analysis-contract-2":
        expected.add("policy_obligations")
    if (not isinstance(value, Mapping)
            or version not in {"guardcontract-analysis-contract-1", "guardcontract-analysis-contract-2"}
            or value.get("registered_tool_selection") not in {"possible", "unknown"}
            or set(value) != expected):
        raise ValueError("analysis_contract_shape")
    normalized = dict(value)
    if version == "guardcontract-analysis-contract-2":
        from guardcontract.core.schemas import EvidenceSpan
        obligations = value["policy_obligations"]
        if not isinstance(obligations, list) or len(obligations) > 100:
            raise ValueError("policy_obligation_inventory")
        checked, ids = [], set()
        for row in obligations:
            if not isinstance(row, Mapping) or set(row) != {"id", "guard_node", "logical_effect_id", "operation", "resource", "source"}:
                raise ValueError("policy_obligation_shape")
            if any(not isinstance(row[k], str) or not row[k].strip() for k in ("id", "guard_node", "logical_effect_id", "operation", "resource")) or row["id"] in ids:
                raise ValueError("policy_obligation_identity")
            ids.add(row["id"])
            source = EvidenceSpan.from_dict(row["source"]).to_dict()
            checked.append({**row, "source": source})
        normalized["policy_obligations"] = checked
    normalized["contract_sha256"] = _canonical_sha256(normalized)
    return normalized


def _parameter_key(value: str) -> str:
    return value.rsplit(".", 1)[-1].lower()


def distribute_analysis_contract(value, contexts):
    """Partition declared obligations by exact guard/effect pair before calls."""
    normalized = validate_analysis_contract(value)
    base = {k: v for k, v in normalized.items() if k != 'contract_sha256'}
    if 'policy_obligations' not in base:
        return [dict(base) for _ in contexts]
    scoped = [{**base, 'policy_obligations': []} for _ in contexts]
    targets = []
    for context in contexts:
        guards = {n['node'] for n in context['node_catalog'] if n.get('kind') == 'guard_candidate'}
        effects = {e['logical_effect_id'] for e in context['effect_catalog']['logical_effects']}
        targets.append((guards, effects))
    for obligation in base['policy_obligations']:
        matches = [i for i, (guards, effects) in enumerate(targets)
                   if obligation['guard_node'] in guards and obligation['logical_effect_id'] in effects]
        if not matches:
            raise ValueError('policy_obligation_target_not_in_routed_jobs:' + obligation['id'])
        for index in matches:
            scoped[index]['policy_obligations'].append(dict(obligation))
    return scoped


def _sdk_fact(framework: str, sdk_contract: Mapping[str, Any] | None, fact: str) -> bool:
    return bool(
        isinstance(sdk_contract, Mapping)
        and sdk_contract.get("schema_version") in SCHEMAS.get(framework, set())
        and isinstance(sdk_contract.get("contract_sha256"), str)
        and sdk_contract.get("facts", {}).get(fact) is True
    )


def _guard_lifecycle(framework: str, parameters: list[str], sdk_contract: Mapping[str, Any] | None):
    rows = []
    for parameter in parameters:
        key = _parameter_key(parameter)
        post_fact = POST_EFFECT_RULES.get((framework, key))
        pre_fact = PRE_EFFECT_CAPABILITIES.get((framework, key))
        if post_fact:
            verified = _sdk_fact(framework, sdk_contract, post_fact)
            rows.append({"parameter": parameter, "position": "post_effect" if verified else "unknown",
                         "required_sdk_fact": post_fact, "sdk_fact_verified": verified})
        elif pre_fact:
            verified = _sdk_fact(framework, sdk_contract, pre_fact)
            rows.append({"parameter": parameter, "position": "pre_effect_capable" if verified else "unknown",
                         "required_sdk_fact": pre_fact,
                         "sdk_fact_verified": verified})
        else:
            rows.append({"parameter": parameter, "position": "unknown",
                         "required_sdk_fact": None, "sdk_fact_verified": False})
    return rows


def plan_registration_contracts(context: Mapping[str, Any], *, framework: str,
                                sdk_contract: Mapping[str, Any] | None = None,
                                analysis_contract: Mapping[str, Any] | None = None,
                                max_candidates: int = 200) -> dict[str, Any]:
    """Build per guard/effect query plans without promoting model hypotheses."""
    contract = validate_analysis_contract(analysis_contract)
    catalog = context.get("node_catalog")
    effect_catalog = context.get("effect_catalog")
    if not isinstance(catalog, list) or not isinstance(effect_catalog, Mapping):
        raise ValueError("registration_contract_context")
    guards = [node for node in catalog if node.get("kind") == "guard_candidate"]
    effects = effect_catalog.get("logical_effects")
    if not isinstance(effects, list):
        raise ValueError("registration_contract_effects")
    if len(guards) * len(effects) > max_candidates:
        raise ValueError("registration_contract_candidate_budget")
    rows = []
    for guard in guards:
        parameters = guard.get("registration_parameters", [])
        if not isinstance(parameters, list) or any(not isinstance(item, str) for item in parameters):
            raise ValueError("registration_contract_guard_parameters")
        lifecycle = _guard_lifecycle(framework, parameters, sdk_contract)
        for effect in effects:
            facts = dict.fromkeys(CONTRACT_FIELDS, "unknown")
            if contract["registered_tool_selection"] == "possible":
                facts["request_selects_operation"] = "true"
            facts["guard_registered"] = "true"
            # Lifecycle position cannot prove application joint reachability,
            # especially when a tool stages an effect for a later guarded commit.
            identity = {
                "framework": framework,
                "guard_node": guard.get("node"),
                "logical_effect_id": effect.get("logical_effect_id"),
                "analysis_contract_sha256": contract["contract_sha256"],
            }
            rows.append({
                "candidate_id": "contract:" + _canonical_sha256(identity),
                **identity,
                "facts": facts,
                "guard_source": {key: guard[key] for key in ("path", "start_line", "end_line", "symbol") if key in guard},
                "effect_source": {key: effect[key] for key in ("tool_node", "family", "declaration_anchor", "candidate_sink_sites") if key in effect},
                "source_nodes": [{key: node[key] for key in ("node", "kind", "path", "start_line", "end_line", "line", "symbol", "call", "family") if key in node} for node in catalog],
                "fact_sources": {
                    "request_selects_operation": "analysis_contract" if facts["request_selects_operation"] == "true" else None,
                    "guard_registered": "registration_index",
                    "guard_applies_to_operation": None,
                    "deny_reachable": None,
                    "effect_reachable": None,
                    "deny_effect_joint_reachable": None,
                },
                "lifecycle": lifecycle,
                "query_plan": plan_contract_queries(facts),
            })
    return {
        "schema_version": "registration-contract-plan-1",
        "framework": framework,
        "analysis_contract": contract,
        "sdk_contract_sha256": sdk_contract.get("contract_sha256") if isinstance(sdk_contract, Mapping) else None,
        "sdk_semantics": {
            "schema_version": sdk_contract.get("schema_version"),
            "contract_sha256": sdk_contract.get("contract_sha256"),
            "framework_versions": dict(sdk_contract.get("framework_versions", {})),
            "limits": list(sdk_contract.get("limits", [])),
            "facts": {fact: sdk_contract["facts"][fact]
                      for (owner, _), fact in {**POST_EFFECT_RULES, **PRE_EFFECT_CAPABILITIES}.items()
                      if owner == framework and type(sdk_contract.get("facts", {}).get(fact)) is bool},
            "application_path_or_effect_verified": False,
        } if isinstance(sdk_contract, Mapping) and sdk_contract.get("schema_version") in SCHEMAS.get(framework, set()) else None,
        "candidates": rows,
        "counts": {
            "guards": len(guards),
            "logical_effects": len(effects),
            "contract_candidates": len(rows),
            "pivotal_unknown_predicates": sum(row["query_plan"]["query_count"] for row in rows),
            "known_predictions": sum(row["query_plan"]["assessment"]["issue_prediction"] is not None for row in rows),
        },
        "claim_boundary": (
            "SDK facts establish framework ordering only. Registration establishes attachment only. "
            "Policy scope, DENY reachability, and application effect paths remain unknown unless separately evidenced. "
            "Independent behavior-oracle attestations are excluded from prediction facts to prevent label leakage."
        ),
    }
