"""Freeze lifecycle-stratified identities from guard/effect code-search metadata."""
import hashlib,json
def rank(seed,stratum,row):return hashlib.sha256(f"{seed}\0{stratum}\0{row['repository']['id']}\0{row['repository']['full_name']}".encode()).hexdigest()
def select(raw,excluded,official,*,strata,target,seed):
    if raw["execution_health"]!="completed" or not raw.get("public_scope_enforced") or raw["counts"]["queries_with_errors"]:raise ValueError("guard_effect_identity_source")
    buckets={s:[] for s in strata};reasons={"previous_pool":0,"official":0,"ambiguous_stratum":0}
    for row in raw["candidates"]:
        name=row["repository"]["full_name"]
        if name in excluded:reasons["previous_pool"]+=1;continue
        if name.lower() in official:reasons["official"]+=1;continue
        matches=[s for s in row["matched_frameworks"] if s in buckets]
        if len(matches)!=1:reasons["ambiguous_stratum"]+=1;continue
        buckets[matches[0]].append(row)
    selected=[]
    for stratum in strata:
        framework,polarity=stratum.rsplit("-",1)
        for row in sorted(buckets[stratum],key=lambda r:rank(seed,stratum,r))[:target]:selected.append({"framework":framework,"query_polarity":polarity,"query_stratum":stratum,"repository_id":row["repository"]["id"],"full_name":row["repository"]["full_name"],"locations":row["locations"],"rank_sha256":rank(seed,stratum,row),"source_state":"guard_effect_identity_and_paths_only"})
    identity=[[r["query_stratum"],r["repository_id"],r["full_name"]] for r in selected];available={s:len(buckets[s]) for s in strata};selected_counts={s:sum(r["query_stratum"]==s for r in selected) for s in strata}
    return {"schema_version":"prospective-guard-effect-identity-freeze-1","strata":strata,"target_per_stratum":target,"selection_seed":seed,"selected":selected,"counts":{"selected":len(selected),"available":available,"selected_by_stratum":selected_counts,"shortfall_by_stratum":{s:max(0,target-selected_counts[s]) for s in strata},"exclusions":reasons},"identity_sha256":hashlib.sha256(json.dumps(identity,separators=(",",":"),sort_keys=True).encode()).hexdigest(),"query_polarity_is_label":False,"source_content_read":False,"holdout_admission_authorized":False}
