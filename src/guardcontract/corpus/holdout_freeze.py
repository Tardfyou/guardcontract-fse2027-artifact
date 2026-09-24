"""Create a reproducible prospective holdout freeze plan without labels."""
import hashlib
import json


def freeze_candidates(candidates, *, seed, per_framework=20):
    if not isinstance(seed, str) or not seed:
        raise ValueError("holdout_freeze_seed_required")
    if type(per_framework) is not int or per_framework < 1:
        raise ValueError("holdout_freeze_budget")
    rows = sorted({row["repository"]: row for row in candidates}.values(), key=lambda row: row["repository"])
    if any(not isinstance(row, dict) or not isinstance(row.get("repository"), str) or
           not isinstance(row.get("framework"), str) for row in rows):
        raise ValueError("holdout_candidate_identity")
    selected = []
    by_framework = {}
    for row in rows:
        framework = row["framework"]
        by_framework.setdefault(framework, [])
        if len(by_framework[framework]) >= per_framework:
            continue
        digest = hashlib.sha256((seed + "\0" + row["repository"]).encode()).hexdigest()
        by_framework[framework].append({**row, "selection_digest": digest, "source_opened": False,
                                        "behavior_label": None, "holdout_eligible": False})
    for framework in sorted(by_framework):
        selected.extend(sorted(by_framework[framework], key=lambda row: row["selection_digest"]))
    return {"schema_version": "prospective-holdout-freeze-plan-1", "seed": seed,
            "per_framework_cap": per_framework, "selected": selected,
            "selection_only": True, "holdout_admission_authorized": False,
            "claim_boundary": "Selection is a reproducible candidate freeze only; source, labels, family independence and behavior oracle are not established."}
