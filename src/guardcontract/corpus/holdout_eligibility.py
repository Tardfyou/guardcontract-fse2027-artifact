"""Conservative repository-family eligibility without admitting a holdout."""
from collections import defaultdict,Counter


def build(exact,nearcopy):
    repositories={repo for component in exact["components"] for repo in component["repositories"]}
    graph=defaultdict(set)
    for repo in repositories:graph[repo]
    for component in exact["components"]:
        members=component["repositories"]
        for repo in members:graph[repo].update(set(members)-{repo})
    for pair in nearcopy["pairs"]:
        left,right=pair["left_repository"],pair["right_repository"]
        # Unselected repositories can bridge a candidate to exposed source.
        graph[left].add(right);graph[right].add(left)
    known={repo for component in exact["components"] if component["status"]=="exclude_known_exposure" for repo in component["repositories"]}
    quarantine={repo for component in exact["components"] if component["status"]=="quarantine_source_integrity" for repo in component["repositories"]}
    potential=set(nearcopy["potential_exposure_review_queue"])
    unavailable={row["repository"] for row in nearcopy["files"] if row["status"]!="fingerprinted"}
    unverified_ids=set(nearcopy["unverified_input_record_ids"])
    unverified={row["repository"] for row in nearcopy["files"] if unverified_ids.intersection(row.get("source_record_ids",[]))}
    exposed_seeds=known|potential;propagated=set();families=[];seen=set()
    for start in sorted(graph):
        if start in seen:continue
        stack=[start];members=set()
        while stack:
            node=stack.pop()
            if node in members:continue
            members.add(node);stack.extend(graph[node]-members)
        seen|=members;tainted=bool(members&exposed_seeds)
        if tainted:propagated|=members
        if members&repositories:
            families.append({"repositories":sorted(members),"repository_count":len(members),"candidate_repositories":sorted(members&repositories),"exposure_tainted":tainted})
    rows=[]
    for repo in sorted(repositories):
        if repo in known:status="exclude_known_exposure"
        elif repo in quarantine or repo in unverified:status="exclude_source_integrity"
        elif repo in propagated:status="exclude_conservative_nearcopy_exposure"
        elif repo in unavailable:status="exclude_unavailable_source"
        else:status="pending_global_exposure_audit"
        rows.append({"repository":repo,"status":status,"holdout_eligible":False})
    counts=Counter(row["status"] for row in rows)
    return {"schema_version":"holdout-eligibility-2","rows":rows,"families":families,"counts":dict(counts),
        "graph_repositories":len(graph),"bridge_repositories":len(set(graph)-repositories),
        "repositories":len(rows),"nearcopy_pairs_treated_as_family_edges":len(nearcopy["pairs"]),
        "known_exposure_seeds":len(known),"potential_exposure_seeds":len(potential&repositories),
        "unavailable_source_repositories":len(unavailable&repositories),"unverified_source_repositories":len(unverified&repositories),
        "provisionally_clean_pending_audit":counts["pending_global_exposure_audit"],"holdout_eligible_repositories":0,
        "holdout_admission_authorized":False,"blocking_gaps":["global_historical_exposure_inventory_incomplete","nearcopy_candidates_conservatively_unadjudicated","source_gaps_excluded"],
        "claim_boundary":"Conservative exclusion ledger only; no repository admitted and no risk labels propagated.","goal_completion_proven":False}
