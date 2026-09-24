"""Deterministically freeze a balanced metadata-only prospective identity pool."""
import hashlib,json
def rank(seed,framework,row):return hashlib.sha256(f"{seed}\0{framework}\0{row['repository']['id']}\0{row['repository']['full_name']}".encode()).hexdigest()
def select(raw,excluded,*,frameworks,per_framework,seed):
    if raw["execution_health"]!="completed" or raw["counts"]["queries_with_errors"]:raise ValueError("prospective_identity_source_incomplete")
    buckets={f:[] for f in frameworks};reasons={"previous_corpus":0,"fork":0,"archived":0,"missing_default_branch":0,"ambiguous_framework":0}
    for row in raw["candidates"]:
        repo=row["repository"]
        if repo["full_name"] in excluded:reasons["previous_corpus"]+=1;continue
        if repo["fork"]:reasons["fork"]+=1;continue
        if repo["archived"]:reasons["archived"]+=1;continue
        if not repo["default_branch"]:reasons["missing_default_branch"]+=1;continue
        matches=[f for f in row["matched_frameworks"] if f in buckets]
        if len(matches)!=1:reasons["ambiguous_framework"]+=1;continue
        buckets[matches[0]].append(row)
    if any(len(rows)<per_framework for rows in buckets.values()):raise ValueError("prospective_identity_insufficient_stratum")
    selected=[]
    for framework in frameworks:
        for row in sorted(buckets[framework],key=lambda r:rank(seed,framework,r))[:per_framework]:
            selected.append({"framework":framework,"repository":row["repository"],"rank_sha256":rank(seed,framework,row),"source_state":"metadata_only_unpinned"})
    identity=[[r["framework"],r["repository"]["id"],r["repository"]["full_name"]] for r in selected]
    return {"schema_version":"prospective-identity-freeze-1","selection_seed":seed,"per_framework":per_framework,"frameworks":frameworks,"selected":selected,
        "counts":{"selected_repositories":len(selected),"selected_by_framework":{f:sum(r["framework"]==f for r in selected) for f in frameworks},"eligible_before_sampling":{f:len(buckets[f]) for f in frameworks},"exclusions":reasons},
        "identity_sha256":hashlib.sha256(json.dumps(identity,separators=(",",":"),sort_keys=True).encode()).hexdigest(),"source_content_read":False,"holdout_admission_authorized":False,
        "claim_boundary":"Balanced enriched tool-validation identity pool from the first 200 results of each frozen lexical query. It is not a probability sample and cannot estimate ecosystem prevalence."}
