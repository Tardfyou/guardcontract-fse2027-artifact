"""Validate and pin code-search identities using GitHub repository metadata."""
import json,re
HEX40=re.compile(r"^[0-9a-f]{40}$")
def query(rows):
    fields=[]
    for i,row in enumerate(rows):
        owner,name=row["full_name"].split("/",1);fields.append(f"r{i}:repository(owner:{json.dumps(owner)},name:{json.dumps(name)}){{databaseId nameWithOwner isPrivate isFork isArchived url defaultBranchRef{{name target{{oid}}}}}}")
    return "query{"+" ".join(fields)+"}"
def pin(selected,requester,batch_size=50):
    records=[];requests=0
    for offset in range(0,len(selected),batch_size):
        batch=selected[offset:offset+batch_size]
        try:data=requester(query(batch))["data"];requests+=1
        except Exception as exc:records.extend({**r,"status":"error","error_kind":type(exc).__name__} for r in batch);continue
        for i,row in enumerate(batch):
            value=data.get(f"r{i}");branch=(value or {}).get("defaultBranchRef") or {};oid=(branch.get("target") or {}).get("oid");valid=isinstance(value,dict) and value.get("databaseId")==row["repository_id"] and value.get("nameWithOwner")==row["full_name"] and value.get("isPrivate") is False and value.get("isFork") is False and value.get("isArchived") is False and isinstance(branch.get("name"),str) and HEX40.fullmatch(oid or "")
            if valid:records.append({**row,"status":"pinned","pinned_commit":oid,"repository":{"id":row["repository_id"],"full_name":row["full_name"],"default_branch":branch["name"],"clone_url":value["url"]+".git","fork":False,"archived":False},"source_state":"public_identity_path_and_commit_frozen"})
            else:records.append({**row,"status":"error","error_kind":"identity_visibility_fork_archive_branch_or_oid_mismatch"})
    frameworks=sorted({r["framework"] for r in selected});return {"schema_version":"prospective-guard-code-commit-freeze-1","records":records,"counts":{"planned":len(selected),"pinned":sum(r["status"]=="pinned" for r in records),"errors":sum(r["status"]=="error" for r in records),"requests":requests,"pinned_by_framework":{f:sum(r["status"]=="pinned" and r["framework"]==f for r in records) for f in frameworks}},"source_content_read":False,"repository_code_executed":False,"holdout_admission_authorized":False}
