"""Atomic analyst/critic claims for Pydantic AI path certificates."""
import hashlib,json

from guardcontract.protocols.certificate_review_atomic import SYSTEM,decode

def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":")).encode()).hexdigest()

def task(certificate,source,helper_source,sdk_contract,*,repository_id,role="analyst",previous=None):
    if certificate.get("status")!="supported" or certificate.get("sdk_contract_sha256")!=sdk_contract.get("contract_sha256"):raise ValueError("pydantic245_certificate")
    if role not in {"analyst","critic"} or (role=="critic")!=(previous is not None):raise ValueError("pydantic245_role")
    paths={row["decision"]:row for row in certificate["paths"]};request=certificate["review_evidence"]["request_binding"]
    guard=certificate["guard"];sink=certificate["sink"]
    tool=next(row for row in paths["ALLOW"]["events"] if row["kind"]=="registered_tool")
    claims=[];raw={}
    def add(cid,statement,evidence,sdk=False):claims.append({"claim_id":cid,"statement":statement});raw[cid]=(evidence,sdk)
    add("request-binding","The fixed originating request selects the registered tool and payload.",request)
    if certificate["mode"]=="direct_write":
        mode="The registered tool directly performs the selected write; it does not merely stage that write for later commit."
        opposite_mode="The registered tool only stages the selected write, which is committed or aborted by the output validator."
    else:
        mode="The registered tool stages the selected write, which the output validator later commits on ALLOW or aborts on DENY."
        opposite_mode="The registered tool directly performs the selected write before output validation."
    add("tool-effect-mode",mode,[tool,sink],sdk=True)
    add("output-validator-ordering","The registered tool runs before the applicable output-validator policy decision.",[tool,guard],sdk=True)
    site=next(row for row in certificate["sites"] if row["relation"]=="same_logical_effect")
    add("site-membership",f"Physical sink {site['path']}:{site['line']} is the selected logical effect.",[tool,sink])
    add("site-occurrence",f"At the selected sink, occurrence is ALLOW=true, DENY={str(site['deny_effect_occurs']).lower()}.",[tool,sink,guard],sdk=True)
    issue="DENY still permits the selected effect." if certificate["issue_prediction"] else "DENY blocks the selected effect while ALLOW preserves it."
    opposite_issue="DENY blocks the selected effect while ALLOW preserves it." if certificate["issue_prediction"] else "DENY still permits the selected effect."
    add("issue",issue,[tool,sink,guard],sdk=True);add("control-opposite-issue",opposite_issue,[tool,sink,guard],sdk=True)
    add("control-opposite-mode",opposite_mode,[tool,sink],sdk=True)
    source_by_path={"app.py":source,certificate["helper_path"]:helper_source};spans=sorted({(row["path"],row["start_line"],row["end_line"]) for evidence,_ in raw.values() for row in evidence})
    evidence={};by_span={}
    for number,(path,start,end) in enumerate(spans):
        body=source_by_path.get(path);lines=body.splitlines(keepends=True) if body is not None else []
        if not 1<=start<=end<=len(lines):raise ValueError("pydantic245_source_span")
        content="".join(lines[start-1:end]);alias=f"e{number}";by_span[(path,start,end)]=alias
        evidence[alias]={"path":path,"start_line":start,"end_line":end,"content":content,"source_sha256":hashlib.sha256(body.encode()).hexdigest(),"content_sha256":hashlib.sha256(content.encode()).hexdigest()}
    evidence["sdk"]={"kind":"sdk_contract","contract_sha256":sdk_contract["contract_sha256"],"facts":sdk_contract["facts"],"limits":sdk_contract["limits"],"framework_versions":sdk_contract["framework_versions"]}
    requirements={cid:sorted({by_span[(row["path"],row["start_line"],row["end_line"])] for row in rows}|({"sdk"} if sdk else set())) for cid,(rows,sdk) in raw.items()}
    payload={"role":role,"repository_id":repository_id,"claims":claims,"evidence":evidence}
    if previous is not None:payload["previous_review"]=previous
    payload["input_id"]="pydantic-review:"+digest({"system":SYSTEM,"payload":payload})[:24]
    spec={"input_id":payload["input_id"],"role":role,"repository_id":repository_id,"claim_ids":[r["claim_id"] for r in claims],"requirements":requirements,
        "evidence":evidence,"model_input_sha256":digest(payload),"negative_control_claim_ids":["control-opposite-issue","control-opposite-mode"],
        "model_citation_responsibility":False,"deterministic_evidence_attachment":True}
    return payload,spec
