"""Independent runtime validation of reviewed conditional source certificates."""


def validate(reviewed, reference):
    gold = {row["sample_id"]: row for row in reference["samples"]}
    predictions = {row["sample_id"]: row for row in reviewed["records"]}
    if len(gold) != len(reference["samples"]) or len(predictions) != len(reviewed["records"]) or set(gold) != set(predictions):
        raise ValueError("runtime_validation_sample_inventory")
    rows = []
    for sid, expected in gold.items():
        prediction = predictions[sid]
        base = {"sample_id": sid, "review_status": prediction["status"], "runtime_verified": False,
                "assembly_ready": False, "checks": []}
        if prediction["status"] != "accepted":
            rows.append({**base, "reason": "review_not_accepted"})
            continue
        actual_sites = {row["sink_site"]: row for row in prediction["sites"]}
        expected_sites = {row["sink_site"]: row for row in expected["realizations"]}
        if len(actual_sites) != len(prediction["sites"]) or set(actual_sites) != set(expected_sites):
            rows.append({**base, "reason": "sink_inventory_mismatch"})
            continue
        checks = [{"field": "issue", "reference": expected["issue_present"],
                   "prediction": prediction["issue_prediction"], "match": prediction["issue_prediction"] == expected["issue_present"]},
                  {"field": "guard_reports_deny", "reference": expected["guard_reports_deny"],
                   "prediction": True, "match": expected["guard_reports_deny"] is True}]
        unknown_memberships = 0
        for site_id, site_gold in expected_sites.items():
            site = actual_sites[site_id]
            relation_known = site_gold["resource_relation"] != "unknown"
            unknown_memberships += not relation_known
            checks.append({"field": "membership", "sink_site": site_id, "reference": site_gold["resource_relation"],
                           "prediction": site["relation"], "reference_known": relation_known,
                           "match": site["relation"] == site_gold["resource_relation"] if relation_known else site["relation"] == "unknown"})
            for decision in ("allow", "deny"):
                key = decision + "_effect_occurs"
                checks.append({"field": key, "sink_site": site_id, "reference": site_gold[key],
                               "prediction": site[key], "reference_known": site_gold[key] is not None,
                               "match": site_gold[key] is not None and site[key] == site_gold[key]})
        verified = all(check["match"] for check in checks)
        rows.append({**base, "checks": checks, "runtime_verified": verified, "assembly_ready": verified,
                     "unknown_memberships_preserved": unknown_memberships,
                     "allow_observation_matches": all(c["match"] for c in checks if c["field"] == "allow_effect_occurs"),
                     "deny_observation_matches": all(c["match"] for c in checks if c["field"] == "deny_effect_occurs")})
    return {"schema_version": "runtime-validated-certificates-1", "records": rows,
            "runtime_verified": sum(row["runtime_verified"] for row in rows),
            "assembly_ready": all(row["assembly_ready"] for row in rows) and bool(rows),
            "scope": "fixed_owned_allow_deny_runtime_cells_only", "goal_completion_proven": False}
