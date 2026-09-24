"""Deterministically finalize analyst/critic reviews into source certificates."""
import hashlib
import json


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def finalize(plan, result, critic_inputs):
    records = {(row["cell_id"].rsplit("-", 1)[0], row["role"]): row for row in result["records"]}
    expected_keys = {(cell["sample_id"], role) for cell in plan["cells"] for role in ("analyst", "critic")}
    if set(records) != expected_keys or len(records) != len(result["records"]):
        raise ValueError("reviewed226_record_inventory")
    outputs = []
    for cell in plan["cells"]:
        sid = cell["sample_id"]
        analyst, critic = records[(sid, "analyst")], records[(sid, "critic")]
        base = {"sample_id": sid, "repository_id": cell["repository_id"], "status": "unknown",
                "issue_prediction": None, "sites": [], "review_gate_passed": False,
                "execution_verified": False, "runtime_assembly_ready": False}
        if analyst["execution_state"] != "completed" or critic["execution_state"] != "completed":
            outputs.append({**base, "reason": "incomplete_analyst_or_critic"})
            continue
        critic_input = critic_inputs[sid]
        if (critic_input.get("role") != "critic" or critic_input.get("repository_id") != cell["repository_id"]
                or critic_input.get("previous_review") != analyst["review"]):
            raise ValueError("reviewed226_critic_handoff")
        for review, role in ((analyst["review"], "analyst"), (critic["review"], "critic")):
            if review["role"] != role or review["repository_id"] != cell["repository_id"] or not review["deterministic_evidence_attachment_verified"]:
                raise ValueError("reviewed226_review_identity")
        expected = {claim["claim_id"]: "contradicted" if claim["claim_id"].startswith("control-opposite-") else "supported"
                    for claim in critic_input["claims"]}
        analyst_verdicts = {row["claim_id"]: row["verdict"] for row in analyst["review"]["claims"]}
        critic_verdicts = {row["claim_id"]: row["verdict"] for row in critic["review"]["claims"]}
        if set(analyst_verdicts) != set(expected) or set(critic_verdicts) != set(expected):
            raise ValueError("reviewed226_claim_inventory")
        gate = all(critic_verdicts[key] == value for key, value in expected.items())
        corrections = [key for key in expected if analyst_verdicts[key] != expected[key] and critic_verdicts[key] == expected[key]]
        unresolved = [key for key in expected if critic_verdicts[key] != expected[key]]
        certificate = cell["certificate"]
        output = {**base, "status": "accepted" if gate else "rejected", "review_gate_passed": gate,
            "issue_prediction": certificate["issue_prediction"] if gate else None,
            "sites": certificate["sites"] if gate else [], "analyst_errors_corrected_by_critic": corrections,
            "critic_unresolved_claims": unresolved, "source_certificate_sha256": digest(certificate),
            "review_chain_sha256": digest({"analyst": analyst["review"], "critic": critic["review"]}),
            "execution_verified": False, "runtime_assembly_ready": False,
            "claim_boundary": "Accepted conditional source certificate after negative-control critic gate; independent runtime evaluation remains separate."}
        outputs.append(output)
    return {"schema_version": "reviewed-source-certificates-1", "records": outputs,
            "accepted": sum(row["status"] == "accepted" for row in outputs),
            "model_calls": result["actual_calls"], "model_tokens": result["actual_total_tokens"],
            "goal_completion_proven": False}
