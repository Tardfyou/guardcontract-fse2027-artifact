"""Propagate conservative session exposure over existing source families."""
from collections import Counter
def build(ledger,session):
    if session.get("mention_interpretation") == "review_candidates_only":
        raise ValueError("session_mentions_require_source_exposure_adjudication")
    mentioned=set(session["mentioned_repositories"]);family_by_repo={repo:family for family in ledger["families"] for repo in family["repositories"]};tainted=set()
    for repo in mentioned:
        family=family_by_repo.get(repo)
        if family:tainted.update(family["repositories"])
    rows=[]
    for row in ledger["rows"]:
        repo=row["repository"];prior=row["status"]
        if prior!="pending_global_exposure_audit":status=prior
        elif repo in tainted:status="exclude_session_mention_family"
        else:status="candidate_prospective_identity_freeze"
        rows.append({"repository":repo,"prior_status":prior,"status":status,"holdout_eligible":False})
    counts=Counter(r["status"] for r in rows);candidates=sorted(r["repository"] for r in rows if r["status"]=="candidate_prospective_identity_freeze")
    return {"schema_version":"session-aware-holdout-eligibility-1","rows":rows,"counts":dict(counts),"session_mentioned_repositories":len(mentioned),
        "session_family_tainted_repositories":len(tainted),"prospective_freeze_candidates":candidates,"holdout_eligible_repositories":0,"holdout_admission_authorized":False,
        "blocking_gaps":["prospective_identity_pool_not_frozen","source_integrity_and_framework_strata_not_checked","behavior_oracle_labels_not_collected","direct_related_positive_negative_oracle_coverage_not_established"],
        "claim_boundary":"Any exact repository mention in scanned session prefixes taints its exact/near-copy family. Remaining identities are candidates only; source has not been opened under the frozen evaluation protocol."}
