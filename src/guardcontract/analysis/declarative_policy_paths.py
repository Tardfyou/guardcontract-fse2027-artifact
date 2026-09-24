"""Shared pre-effect dominance proof for declarative policy/effect bindings."""
from guardcontract.discovery.framework_declarations import PRE_EFFECT_POLICY_FACTS


def predict(rows, sdk_contracts, pre_effect_policy_facts=None):
    policy_facts = dict(PRE_EFFECT_POLICY_FACTS)
    if pre_effect_policy_facts is not None:
        if not isinstance(pre_effect_policy_facts, dict):
            raise ValueError("pre_effect_policy_facts")
        for key, value in pre_effect_policy_facts.items():
            if (not isinstance(key, tuple) or len(key) != 2
                    or not all(isinstance(item, str) and item for item in key)
                    or not isinstance(value, str) or not value):
                raise ValueError("pre_effect_policy_fact")
        policy_facts.update(pre_effect_policy_facts)
    predictions=[]
    for row in rows:
        matches=row.get("matching_policies",[])
        parameters={match.get("parameter") for match in matches}
        facts={policy_facts.get((row.get("framework"),parameter))
               for parameter in parameters}
        facts.discard(None)
        contract=sdk_contracts.get(row.get("framework"),{})
        verified=sorted(fact for fact in facts if contract.get("facts",{}).get(fact) is True)
        gates={"family_passed":row.get("family_status")=="passed",
               "policy_scope_bound":row.get("policy_scope_status")=="bound",
               "matching_policy_can_deny":row.get("matching_policy_deny_capability")=="present",
               "pre_effect_sdk_fact_verified":bool(verified)}
        prediction="absent" if all(gates.values()) else "unknown"
        predictions.append({"candidate_id":row["candidate_id"],"repository":row.get("repository"),
            "framework":row.get("framework"),"lifecycle":row.get("lifecycle"),
            "tool_symbol":row.get("tool_symbol"),"effect_path":row.get("effect_path"),
            "effect_line":row.get("effect_line"),"prediction":prediction,"gates":gates,
            "verified_sdk_facts":verified,
            "reason":"verified_pre_effect_policy_dominates_tool_invocation" if prediction=="absent"
                     else "pre_effect_dominance_unproven"})
    return predictions
