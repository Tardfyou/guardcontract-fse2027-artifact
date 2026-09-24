"""Freeze stratified development and unread confirmation family identities."""
import hashlib,json,math
def split(selected,pinned,*,seed,development_fraction=0.2,min_development=2):
    if not 0<development_fraction<1:raise ValueError("family_split_fraction")
    pin_by_name={r["full_name"]:r for r in pinned if r["status"]=="pinned"};by={}
    for row in selected:
        if row["full_name"] not in pin_by_name:raise ValueError("family_split_missing_pin")
        by.setdefault(row["query_stratum"],[]).append(row)
    development=[];confirmation=[]
    for stratum,rows in sorted(by.items()):
        ordered=sorted(rows,key=lambda r:hashlib.sha256(f"{seed}\0{stratum}\0{r['full_name']}".encode()).hexdigest());count=min(len(rows)-1,max(min_development,math.floor(len(rows)*development_fraction))) if len(rows)>1 else 0
        for index,row in enumerate(ordered):
            pin=pin_by_name[row["full_name"]];item={**row,"repository":pin["repository"],"pinned_commit":pin["pinned_commit"],"matched_files":[{"path":x["path"],"blob_sha":x["blob_sha"],"query_id":x["query_id"]} for x in row["locations"]]};item.pop("locations",None);(development if index<count else confirmation).append(item)
    if {r["full_name"] for r in development}&{r["full_name"] for r in confirmation}:raise ValueError("family_split_overlap")
    identity=lambda rows:hashlib.sha256(json.dumps([[r["query_stratum"],r["repository_id"],r["full_name"],r["pinned_commit"]] for r in rows],sort_keys=True,separators=(",",":")).encode()).hexdigest()
    strata=sorted(by);return {"schema_version":"prospective-family-split-1","seed":seed,"development_fraction":development_fraction,"development":development,"confirmation":confirmation,"counts":{"families":len(selected),"development":len(development),"confirmation":len(confirmation),"development_by_stratum":{s:sum(r["query_stratum"]==s for r in development) for s in strata},"confirmation_by_stratum":{s:sum(r["query_stratum"]==s for r in confirmation) for s in strata}},"development_identity_sha256":identity(development),"confirmation_identity_sha256":identity(confirmation),"confirmation_source_read":False,"holdout_admission_authorized":False}
