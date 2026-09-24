"""Label-blind eligibility states for guard/effect behavior evaluation."""
from __future__ import annotations

from collections.abc import Mapping


INFRASTRUCTURE_COVERAGE = {"budget_deferred", "source_unavailable", "error", "partial"}
UNKNOWN_GUARDS = {None, "", "<unknown-guard>"}


def classify_unit(row: Mapping) -> dict:
    """Classify evaluation readiness without reading or inventing behavior labels."""
    if row.get("behavior_label") is not None or row.get("issue_label") is not None:
        raise ValueError("eligibility_requires_label_blind_unit")
    coverage = row.get("coverage_status", "unknown")
    if coverage in INFRASTRUCTURE_COVERAGE:
        return {
            "eligibility_status": "infrastructure_deferred",
            "behavior_candidate": False,
            "oracle_readiness": "deferred",
            "reasons": [f"coverage:{coverage}"],
        }
    deny_proof = row.get("deny_reachability_evidence")
    if (isinstance(deny_proof, Mapping)
            and deny_proof.get("verified") is True
            and deny_proof.get("deny_reachability") == "unreachable"):
        return {
            "eligibility_status": "target_ineligible_no_reachable_deny",
            "behavior_candidate": False,
            "oracle_readiness": "not_applicable",
            "reasons": ["independently_verified_no_reachable_deny"],
        }
    guard = row.get("guard")
    effect = row.get("effect")
    if effect is None:
        if guard in UNKNOWN_GUARDS:
            return {
                "eligibility_status": "unresolved_joint_registration",
                "behavior_candidate": False,
                "oracle_readiness": "unresolved",
                "reasons": ["no_joint_guard_registration_proved"],
            }
        return {
            "eligibility_status": "unresolved_effect_binding",
            "behavior_candidate": False,
            "oracle_readiness": "unresolved",
            "reasons": ["no_protected_effect_bound"],
        }
    reasons = []
    if guard in UNKNOWN_GUARDS:
        reasons.append("guard_identity_unresolved")
    if row.get("deny_capability") != "present":
        reasons.append("deny_capability_unresolved")
    if row.get("lifecycle_position") not in {"pre", "post"}:
        reasons.append("lifecycle_position_unresolved")
    if not isinstance(effect, Mapping) or not all(effect.get(key) is not None
                                                  for key in ("path", "line", "family", "call")):
        reasons.append("effect_identity_incomplete")
    return {
        "eligibility_status": "behavior_candidate",
        "behavior_candidate": True,
        "oracle_readiness": "ready" if not reasons else "predicate_resolution_required",
        "reasons": reasons,
    }
