#!/usr/bin/env python3
"""Framework-neutral GuardContract trace audit and repair planning."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class EffectContract:
    contract_id: str
    protected_effect: str
    deny_verdict: str = "DENY"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EffectContract":
        required = {"contract_id", "protected_effect"}
        missing = sorted(required - data.keys())
        if missing:
            raise ValueError(f"missing contract fields: {', '.join(missing)}")
        return cls(
            contract_id=str(data["contract_id"]),
            protected_effect=str(data["protected_effect"]),
            deny_verdict=str(data.get("deny_verdict", "DENY")),
        )


def audit_trace(contract: EffectContract, row: dict[str, Any]) -> dict[str, Any]:
    """Score the safety invariant and retain an executable counterexample."""
    events = row.get("events", [])
    deny_seen = any(
        event.get("kind") == "guard_verdict"
        and event.get("verdict") == contract.deny_verdict
        for event in events
    )
    effect_seen = any(
        event.get("kind") == "protected_effect"
        and event.get("effect") == contract.protected_effect
        for event in events
    )
    violation = deny_seen and effect_seen
    return {
        "contract_id": contract.contract_id,
        "deny_seen": deny_seen,
        "effect_seen": effect_seen,
        "conforms": not violation,
        "counterexample": events if violation else None,
        "invariant": f"{contract.deny_verdict} => not {contract.protected_effect}",
    }


def classify_observation(contract: EffectContract, row: dict[str, Any]) -> dict[str, Any]:
    """Normalize guard, effect-attempt, and committed-resource evidence.

    Logs are retained as attempts; only independently observed markers count as
    committed effects. Missing correlation or unexpected execution is unknown.
    """
    events = row.get("events", [])
    if row.get("execution_health") != "completed":
        return {"status": "error", "reason": "execution_incomplete", "semantic_proof": False}
    guards = [e for e in events if e.get("kind") == "guard_verdict"
              and e.get("verdict") == contract.deny_verdict]
    attempts = [e for e in events if e.get("kind") in {"protected_effect", "effect_attempt"}
                and e.get("effect") == contract.protected_effect]
    markers = row.get("independent_markers")
    if not isinstance(markers, list):
        return {"status": "unknown", "reason": "marker_observation_missing", "semantic_proof": False}
    invocation_ids = {value.get("invocation_id") for value in events if isinstance(value, dict) and value.get("invocation_id")}
    marker_ids = {value.get("invocation_id") for value in markers if isinstance(value, dict) and value.get("invocation_id")}
    skipped = [event for event in events if event.get("kind") == "effect_skipped"
               and event.get("effect") == contract.protected_effect]
    skipped_ids = {event.get("invocation_id") for event in skipped if event.get("invocation_id")}
    explicit_skip = (not markers and not attempts and len(skipped) == 1
                     and invocation_ids and skipped_ids == invocation_ids)
    correlation = ("verified" if (invocation_ids and marker_ids and invocation_ids == marker_ids)
                   or explicit_skip else "unverified")
    committed = len(markers)
    return {"status": "scored", "guard_deny_count": len(guards),
            "effect_attempt_count": len(attempts), "committed_effect_count": committed,
            "deny_effect_violation": bool(guards and committed),
            "effect_skipped_count": len(skipped),
            "correlation": correlation, "semantic_proof": False,
            "claim_boundary": "Marker count is a committed-resource observation only when its independent identity and request/attempt binding are separately verified."}


def validate_effect_observation(value: Any) -> dict[str, Any]:
    """Validate normalized runner output without treating it as semantic proof."""
    if not isinstance(value, dict):
        raise ValueError("effect_observation_object")
    events, marker_count, marker_status = value.get("attempt_events"), value.get("marker_count"), value.get("marker_observation")
    if not isinstance(events, list) or marker_status not in {"collected", "not_collected_by_runner", "unknown"}:
        raise ValueError("effect_observation_schema")
    if marker_count is not None and (type(marker_count) is not int or marker_count < 0):
        raise ValueError("effect_observation_marker_count")
    if marker_status == "collected" and marker_count is None:
        raise ValueError("effect_observation_collected_count")
    return {"valid": True, "attempt_event_count": len(events), "marker_count": marker_count,
            "marker_observation": marker_status, "semantic_proof": False}


def synthesize_repair(framework: str, guard_mode: str) -> dict[str, Any]:
    """Select the smallest public pre-effect adapter for a known lifecycle gap."""
    catalog = {
        ("openai-agents", "parallel-input"): {
            "repair_id": "openai-function-tool-input-guardrail",
            "public_api": "function_tool(tool_input_guardrails=[...])",
            "placement": "immediate pre-dispatch gate on the protected function tool",
        },
        ("crewai", "task-output"): {
            "repair_id": "crewai-before-tool-call-hook",
            "public_api": "register_before_tool_call_hook(...) ",
            "placement": "framework pre-tool hook on the protected tool",
        },
    }
    try:
        selected = catalog[(framework, guard_mode)]
    except KeyError as exc:
        raise ValueError(f"no repair adapter for {framework}/{guard_mode}") from exc
    return {
        **selected,
        "selection_rule": "nearest public interception point that dominates the protected effect",
        "proof_obligations": [
            "deny verdict prevents the protected effect",
            "allow verdict preserves the protected effect",
        ],
    }
