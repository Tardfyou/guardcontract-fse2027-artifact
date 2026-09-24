"""Pin frozen public repository identities to default-branch commit OIDs."""
import json,re
HEX40=re.compile(r"^[0-9a-f]{40}$")
def graphql(selected):
    fields=[]
    for index,row in enumerate(selected):
        owner,name=row["repository"]["full_name"].split("/",1);fields.append(f"r{index}:repository(owner:{json.dumps(owner)},name:{json.dumps(name)}){{nameWithOwner isPrivate isArchived defaultBranchRef{{name target{{oid}}}}}}")
    return "query{"+" ".join(fields)+"}"
def pin(selected,requester,batch_size=50):
    if not 1<=batch_size<=100:raise ValueError("pin_batch_size")
    rows=[];requests=0
    for offset in range(0,len(selected),batch_size):
        batch=selected[offset:offset+batch_size]
        try:response=requester(graphql(batch));requests+=1;data=response["data"]
        except Exception as exc:
            rows.extend({"framework":r["framework"],"repository":r["repository"],"status":"error","error_kind":type(exc).__name__} for r in batch);continue
        for index,row in enumerate(batch):
            value=data.get(f"r{index}");expected=row["repository"];base={"framework":row["framework"],"repository":expected}
            if not isinstance(value,dict):rows.append({**base,"status":"error","error_kind":"missing_repository"});continue
            branch=value.get("defaultBranchRef") or {};target=branch.get("target") or {};oid=target.get("oid")
            valid=(value.get("nameWithOwner")==expected["full_name"] and value.get("isPrivate") is False and value.get("isArchived") is False and branch.get("name")==expected["default_branch"] and isinstance(oid,str) and HEX40.fullmatch(oid))
            rows.append({**base,"status":"pinned" if valid else "error",**({"pinned_commit":oid,"source_state":"metadata_identity_and_commit_frozen"} if valid else {"error_kind":"identity_visibility_branch_or_oid_mismatch"})})
    return {"schema_version":"prospective-commit-freeze-1","records":rows,"counts":{"planned":len(selected),"pinned":sum(r["status"]=="pinned" for r in rows),"errors":sum(r["status"]=="error" for r in rows),"requests":requests,"pinned_by_framework":{f:sum(r["status"]=="pinned" and r["framework"]==f for r in rows) for f in sorted({r["framework"] for r in selected})}},"source_content_read":False,"repository_code_executed":False,"holdout_admission_authorized":False}
