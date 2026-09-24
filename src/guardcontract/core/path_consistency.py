"""Check scoped path claims without treating consistency as semantic proof."""
from itertools import product


FIELDS = {"request_selects_operation", "guard_registered", "guard_applies_to_operation",
          "deny_reachable", "deny_effect_joint_reachable"}
DOMAIN = {"true", "false", "unknown"}

CONTRACT_FIELDS = (
    "request_selects_operation",
    "guard_registered",
    "guard_applies_to_operation",
    "deny_reachable",
    "effect_reachable",
    "deny_effect_joint_reachable",
)


def _validate_contract_facts(facts):
    if (not isinstance(facts, dict) or set(facts) != set(CONTRACT_FIELDS)
            or any(value not in DOMAIN for value in facts.values())):
        raise ValueError("guard_contract_fields")


def assess_contract(facts):
    """Derive a tri-state issue result from local, independently sourced facts.

    ``effect_reachable`` is reachability when the registered operation is
    selected. Joint reachability requires one feasible execution containing both
    the applicable DENY and the selected committed effect. Separate existential
    reachability and non-dominance are insufficient (branches may be exclusive).
    """
    _validate_contract_facts(facts)
    prerequisites = CONTRACT_FIELDS[:-1]
    false_fields = [field for field in prerequisites if facts[field] == "false"]
    joint = facts["deny_effect_joint_reachable"]
    if false_fields and joint == "true":
        classification, prediction, reason = "unknown", None, "contradictory_joint_prerequisites"
    elif false_fields:
        classification = "absent"
        prediction = False
        reason = "definite_false_prerequisite"
    elif any(facts[field] == "unknown" for field in prerequisites):
        classification = "unknown"
        prediction = None
        reason = "unresolved_prerequisite"
    elif joint == "false":
        classification = "blocked"
        prediction = False
        reason = "no_joint_execution_in_declared_scope"
    elif joint == "true":
        classification = "present"
        prediction = True
        reason = "joint_execution_supported"
    else:
        classification = "unknown"
        prediction = None
        reason = "unresolved_joint_execution"
    return {
        "classification": classification,
        "issue_prediction": prediction,
        "reason": reason,
        "false_prerequisites": false_fields,
        "semantic_proof": False,
    }


def plan_contract_queries(facts):
    """Return only unknown predicates that can change the derived result."""
    _validate_contract_facts(facts)
    unknown = [field for field in CONTRACT_FIELDS if facts[field] == "unknown"]
    if assess_contract(facts)["classification"] == "absent":
        unknown = []
    completions = []
    for values in product(("false", "true"), repeat=len(unknown)):
        completed = dict(facts)
        completed.update(zip(unknown, values, strict=True))
        result = assess_contract(completed)["classification"]
        completions.append((dict(zip(unknown, values, strict=True)), result))
    possible = sorted({result for _, result in completions}) or [assess_contract(facts)["classification"]]
    pivotal = []
    for field in unknown:
        others = [item for item in unknown if item != field]
        changes = False
        for values in product(("false", "true"), repeat=len(others)):
            base = dict(facts)
            base.update(zip(others, values, strict=True))
            left, right = dict(base), dict(base)
            left[field], right[field] = "false", "true"
            if assess_contract(left)["classification"] != assess_contract(right)["classification"]:
                changes = True
                break
        if changes:
            pivotal.append(field)
    return {
        "assessment": assess_contract(facts),
        "possible_classifications": possible,
        "pivotal_unknowns": pivotal,
        "query_fields": pivotal,
        "query_count": len(pivotal),
        "semantic_proof": False,
        "claim_boundary": (
            "The planner removes irrelevant questions from a fixed Boolean contract. "
            "It does not validate the semantic truth of supplied facts."
        ),
    }


def check(facts):
    if set(facts) != FIELDS or any(not isinstance(v, str) or v not in DOMAIN for v in facts.values()):
        raise ValueError("scoped_path_fields")
    joint = facts["deny_effect_joint_reachable"]
    prerequisites = FIELDS - {"deny_effect_joint_reachable"}
    conflicts = sorted(key for key in prerequisites if joint == "true" and facts[key] == "false")
    if conflicts:
        return {"consistent": False, "contradictions": conflicts,
                "derived_claim": "unknown", "semantic_proof": False}
    if not all(facts[key] == "true" for key in prerequisites):
        claim = "unknown"
    else:
        claim = {"true": "present", "false": "absent", "unknown": "unknown"}[joint]
    return {"consistent": True, "contradictions": [], "derived_claim": claim,
            "semantic_proof": False}
