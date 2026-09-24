"""Select prospective identities only after exact matched-blob family exclusion."""
import hashlib,json
def rank(seed,stratum,row):return hashlib.sha256(f"{seed}\0{stratum}\0{row['repository']['id']}\0{row['repository']['full_name']}".encode()).hexdigest()
def select(raw,excluded_repositories,excluded_blobs,official,*,strata,target,seed):
    buckets={s:[] for s in strata};reasons={"excluded_repository":0,"official":0,"ambiguous_stratum":0,"historically_or_pilot_exposed_blob":0,"within_pool_duplicate_blob_family":0};seen_blobs=set();selected=[]
    candidates=[]
    for row in raw["candidates"]:
        name=row["repository"]["full_name"];blobs={loc["blob_sha"] for loc in row["locations"] if loc.get("blob_sha")}
        if name in excluded_repositories:reasons["excluded_repository"]+=1;continue
        if name.lower() in official:reasons["official"]+=1;continue
        matches=[s for s in row["matched_frameworks"] if s in buckets]
        if len(matches)!=1:reasons["ambiguous_stratum"]+=1;continue
        if blobs&excluded_blobs:reasons["historically_or_pilot_exposed_blob"]+=1;continue
        candidates.append((matches[0],row,blobs))
    for stratum in strata:
        ordered=sorted((x for x in candidates if x[0]==stratum),key=lambda x:rank(seed,stratum,x[1]))
        for _,row,blobs in ordered:
            if len(buckets[stratum])>=target:break
            if blobs&seen_blobs:reasons["within_pool_duplicate_blob_family"]+=1;continue
            framework,polarity=stratum.rsplit("-",1);item={"framework":framework,"query_polarity":polarity,"query_stratum":stratum,"repository_id":row["repository"]["id"],"full_name":row["repository"]["full_name"],"locations":row["locations"],"rank_sha256":rank(seed,stratum,row),"source_state":"family_first_identity_and_paths_only"};buckets[stratum].append(item);selected.append(item);seen_blobs.update(blobs)
    counts={s:len(buckets[s]) for s in strata};identity=[[r["query_stratum"],r["repository_id"],r["full_name"]] for r in selected]
    return {"schema_version":"prospective-family-first-identity-freeze-1","strata":strata,"target_per_stratum":target,"selection_seed":seed,"selected":selected,"counts":{"selected":len(selected),"selected_by_stratum":counts,"shortfall_by_stratum":{s:max(0,target-counts[s]) for s in strata},"excluded_blob_identities":len(excluded_blobs),"exclusions":reasons},"identity_sha256":hashlib.sha256(json.dumps(identity,separators=(",",":"),sort_keys=True).encode()).hexdigest(),"family_unit_required":True,"source_content_read":False,"holdout_admission_authorized":False}
