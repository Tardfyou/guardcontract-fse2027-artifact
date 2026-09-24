"""Fail-closed admission audit for prospective holdout candidates."""


REQUIRED = ("repository", "framework", "pinned_commit", "source_family", "source_sha256")

def enrich_from_frozen_records(candidates, frame, families):
    selected = {row["repository"]["full_name"]: row for row in frame.get("selected", [])
                if isinstance(row, dict) and isinstance(row.get("repository"), dict)}
    family_by_repo = {}
    for family in families:
        family_id = family.get("family_id") or family.get("id")
        for repository in family.get("repositories", []):
            family_by_repo[repository] = family_id
    return [{**candidate,
             "framework": candidate.get("framework") or selected.get(candidate.get("repository"), {}).get("framework"),
             "pinned_commit": candidate.get("pinned_commit") or selected.get(candidate.get("repository"), {}).get("pinned_commit"),
             "source_family": candidate.get("source_family") or family_by_repo.get(candidate.get("repository"))}
            for candidate in candidates]


def audit_candidates(candidates):
    if not isinstance(candidates, list) or any(not isinstance(item, dict) for item in candidates):
        raise ValueError("holdout_candidates_list_required")
    rows, eligible = [], []
    for index, candidate in enumerate(candidates):
        if not isinstance(candidate, dict):
            rows.append({"index": index, "status": "invalid_candidate", "missing": list(REQUIRED)})
            continue
        missing = [field for field in REQUIRED if not isinstance(candidate.get(field), str) or not candidate[field].strip()]
        status = "eligible_for_source_review" if not missing else "missing_identity_evidence"
        row = {"repository": candidate.get("repository"), "status": status, "missing": missing,
               "source_opened": False, "behavior_label": None, "holdout_eligible": False}
        rows.append(row)
        if not missing:
            eligible.append(candidate["repository"])
    return {"schema_version": "holdout-admission-audit-1", "rows": rows,
            "counts": {"candidates": len(rows), "eligible_for_source_review": len(eligible),
                       "holdout_eligible": 0}, "eligible_for_source_review": sorted(set(eligible)),
            "holdout_admission_authorized": False,
            "claim_boundary": "Identity completeness only; no source, family independence, behavior oracle or issue label is established."}
