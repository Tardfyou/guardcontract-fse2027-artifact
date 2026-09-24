"""Compare frozen frame identity with materialization without semantic execution."""
from collections import Counter, defaultdict


def audit_identity(frame_rows, materialized_rows, family_by_repo=None):
    frozen = {row["repository"]["full_name"]: row for row in frame_rows
              if isinstance(row, dict) and isinstance(row.get("repository"), dict)}
    material = {row.get("repository"): row for row in materialized_rows if isinstance(row, dict)}
    family_by_repo = family_by_repo or {}
    rows = []
    for repo, row in sorted(frozen.items()):
        mat = material.get(repo)
        reasons = []
        if mat is None or mat.get("status") != "completed": reasons.append("materialization_unavailable")
        elif mat.get("commit") != row.get("pinned_commit"): reasons.append("commit_mismatch")
        elif not isinstance(mat.get("source_inventory_sha256"), str): reasons.append("source_inventory_hash_missing")
        if repo not in family_by_repo: reasons.append("source_family_unassigned")
        status = "identity_ready_for_semantic_review" if not reasons else "identity_not_ready"
        rows.append({"repository": repo, "framework": row.get("framework"), "pinned_commit": row.get("pinned_commit"),
                     "source_family": family_by_repo.get(repo), "status": status, "reasons": reasons,
                     "source_opened": False, "behavior_label": None, "holdout_eligible": False})
    return {"schema_version":"holdout-identity-audit-1", "rows":rows,
            "counts":dict(Counter(row["status"] for row in rows)),
            "holdout_admission_authorized":False,
            "claim_boundary":"Revision and inventory identity only; no source semantics, execution or behavior labels."}
