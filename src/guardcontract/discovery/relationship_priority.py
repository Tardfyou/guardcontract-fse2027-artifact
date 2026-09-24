"""Planning-only prioritization for generic relationship candidates."""
import re


def rank_candidates(candidates):
    if not isinstance(candidates, list) or any(not isinstance(row, dict) for row in candidates):
        raise ValueError("relationship_candidates_list")
    rows = []
    for row in candidates:
        relevance = row.get("evaluation_relevance")
        binding = row.get("binding_status")
        reasons = []
        production = relevance == "production_candidate"
        if production: reasons.append("production_path")
        if binding == "co_domain_only": reasons.append("same_function")
        elif binding == "cross_function_co_domain": reasons.append("local_helper_edge")
        if (isinstance(row.get("source_sha256"), str)
                and re.fullmatch(r"[0-9a-f]{64}", row["source_sha256"])):
            reasons.append("source_hash_bound")
        # Ranking is only a review queue: it creates no semantic or safety fact.
        key = (0 if production else 1, 0 if binding == "co_domain_only" else 1,
               row.get("path", ""), row.get("function_line", 0), row.get("guard_marker", ""))
        rows.append({**row, "review_priority_key": key, "review_priority_reasons": reasons,
                     "planning_only": True})
    rows.sort(key=lambda row: row["review_priority_key"])
    for rank, row in enumerate(rows, 1):
        row["review_priority_rank"] = rank
    return {"schema_version": "generic-relationship-priority-1", "candidates": rows,
            "claim_boundary": "Planning order only; no registration, policy, path, runtime, label or holdout claim."}
