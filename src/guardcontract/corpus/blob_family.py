"""Build exact source-family components from matched Git blob identities."""
import hashlib,json
from collections import defaultdict,Counter
def build(selected):
    parent={r["full_name"]:r["full_name"] for r in selected}
    def find(x):
        while parent[x]!=x:parent[x]=parent[parent[x]];x=parent[x]
        return x
    def union(a,b):
        a,b=find(a),find(b)
        if a!=b:parent[max(a,b)]=min(a,b)
    by_blob=defaultdict(set)
    for row in selected:
        for loc in row["locations"]:
            blob=loc.get("blob_sha")
            if isinstance(blob,str) and len(blob)==40:by_blob[blob].add(row["full_name"])
    for names in by_blob.values():
        names=sorted(names)
        for name in names[1:]:union(names[0],name)
    groups=defaultdict(list)
    for row in selected:groups[find(row["full_name"])].append(row)
    components=[];representatives=[]
    for rows in sorted(groups.values(),key=lambda rs:min(r["full_name"] for r in rs)):
        ordered=sorted(rows,key=lambda r:(r["rank_sha256"],r["full_name"]));strata=sorted({r["query_stratum"] for r in rows});names=sorted(r["full_name"] for r in rows);cid="blob-family:"+hashlib.sha256(json.dumps(names,separators=(",",":")).encode()).hexdigest();components.append({"family_id":cid,"repositories":names,"repository_count":len(names),"query_strata":strata,"representative":ordered[0]["full_name"]});representatives.append(ordered[0])
    return {"schema_version":"matched-blob-family-1","components":components,"representatives":representatives,"counts":{"repositories":len(selected),"families":len(components),"duplicate_repositories":len(selected)-len(components),"multi_repository_families":sum(c["repository_count"]>1 for c in components),"cross_stratum_families":sum(len(c["query_strata"])>1 for c in components),"representatives_by_stratum":dict(Counter(r["query_stratum"] for r in representatives))},"family_unit_required":True,"claim_boundary":"Exact equality of any matched Git blob joins repository identities. Formatting/renaming near copies remain unmerged until source materialization."}
