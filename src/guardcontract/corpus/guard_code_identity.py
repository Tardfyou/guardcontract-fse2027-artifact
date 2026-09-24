"""Freeze a balanced identity pool from public guard API code-search metadata."""
import hashlib,json
def rank(seed,framework,row):return hashlib.sha256(f"{seed}\0{framework}\0{row['repository']['id']}\0{row['repository']['full_name']}".encode()).hexdigest()
def select(raw,excluded,official,*,frameworks,per_framework,seed):
    if raw["execution_health"]!="completed" or not raw.get("public_scope_enforced") or raw["counts"]["queries_with_errors"]:raise ValueError("guard_identity_source_incomplete")
    buckets={f:[] for f in frameworks};reasons={"previous_or_first_pool":0,"official_framework_repository":0,"ambiguous_framework":0}
    for row in raw["candidates"]:
        name=row["repository"]["full_name"]
        if name in excluded:reasons["previous_or_first_pool"]+=1;continue
        if name.lower() in official:reasons["official_framework_repository"]+=1;continue
        matches=[f for f in row["matched_frameworks"] if f in buckets]
        if len(matches)!=1:reasons["ambiguous_framework"]+=1;continue
        buckets[matches[0]].append(row)
    if any(len(v)<per_framework for v in buckets.values()):raise ValueError("guard_identity_insufficient_stratum")
    selected=[]
    for framework in frameworks:
        for row in sorted(buckets[framework],key=lambda r:rank(seed,framework,r))[:per_framework]:selected.append({"framework":framework,"repository_id":row["repository"]["id"],"full_name":row["repository"]["full_name"],"locations":row["locations"],"rank_sha256":rank(seed,framework,row),"source_state":"public_code_search_identity_and_paths_only"})
    identity=[[r["framework"],r["repository_id"],r["full_name"]] for r in selected]
    return {"schema_version":"prospective-guard-code-identity-freeze-1","frameworks":frameworks,"per_framework":per_framework,"selection_seed":seed,"selected":selected,"counts":{"selected":len(selected),"selected_by_framework":{f:sum(r["framework"]==f for r in selected) for f in frameworks},"eligible_before_sampling":{f:len(buckets[f]) for f in frameworks},"exclusions":reasons},"identity_sha256":hashlib.sha256(json.dumps(identity,separators=(",",":"),sort_keys=True).encode()).hexdigest(),"matched_source_content_read":False,"holdout_admission_authorized":False,"claim_boundary":"Guard-API-enriched identity pool from truncated first-page code-search results. Paths and blob identities are stored, source content and labels are not read. Not a probability sample."}
