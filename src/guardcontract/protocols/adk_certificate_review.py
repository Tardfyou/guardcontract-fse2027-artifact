"""Atomic analyst/critic claims for Google ADK path certificates."""
import hashlib,json

from guardcontract.protocols.certificate_review_atomic import SYSTEM,decode


def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":")).encode()).hexdigest()


def task(certificate,source,_unused,sdk_contract,*,repository_id,role="analyst",previous=None):
    if certificate.get("status")!="supported" or certificate.get("sdk_contract_sha256")!=sdk_contract.get("contract_sha256"):
        raise ValueError("adk_review234_certificate")
    if role not in {"analyst","critic"} or (role=="critic")!=(previous is not None):raise ValueError("adk_review234_role")
    paths={row["decision"]:row for row in certificate["paths"]}
    def event(decision,kind):return next(row for row in paths[decision]["events"] if row["kind"]==kind)
    request_evidence=certificate["review_evidence"]["request_binding"]
    before=event("ALLOW","before_tool_callback");after=event("ALLOW","after_tool_callback")
    decision=certificate["guard"];sink=certificate["sink"]
    claims=[];raw_requirements={}
    def add(cid,statement,evidence,sdk=False):
        claims.append({"claim_id":cid,"statement":statement});raw_requirements[cid]=(evidence,sdk)
    add("request-binding","The fixed originating request selects the registered publication tool and payload.",request_evidence)
    if certificate["mode"]=="after_tool":
        placement="The applicable policy decision is in after_tool_callback, after the selected tool effect."
    else:
        placement="The applicable policy decision is in before_tool_callback and can skip the selected tool under DENY."
    add("callback-placement",placement,[before,after,decision,sink],sdk=True)
    add("deny-order","The supported DENY path reports an applicable policy DENY and has the certificate's stated ordering relative to the selected effect.",
        [before,after,decision,sink],sdk=True)
    site=certificate["sites"][0]
    add("site-membership",f"Physical sink {site['path']}:{site['line']} is the selected logical effect.",
        [next(row for row in request_evidence if row["kind"]=="registered_tool"),sink])
    add("site-occurrence",f"At the selected sink, occurrence is ALLOW=true, DENY={str(site['deny_effect_occurs']).lower()}.",
        [before,after,decision,sink],sdk=True)
    issue="DENY still permits the selected effect." if certificate["issue_prediction"] else "DENY blocks the selected effect while ALLOW preserves it."
    opposite="DENY blocks the selected effect while ALLOW preserves it." if certificate["issue_prediction"] else "DENY still permits the selected effect."
    add("issue",issue,[before,after,decision,sink],sdk=True)
    add("control-opposite-issue",opposite,[before,after,decision,sink],sdk=True)
    opposite_placement=("The applicable policy decision is in before_tool_callback and skips the selected tool under DENY."
                        if certificate["mode"]=="after_tool" else
                        "The applicable policy decision is only in after_tool_callback, after the selected tool effect.")
    add("control-opposite-placement",opposite_placement,[before,after,decision,sink],sdk=True)
    spans=sorted({(row["path"],row["start_line"],row["end_line"]) for evidence,_ in raw_requirements.values() for row in evidence})
    lines=source.splitlines(keepends=True);evidence={};by_span={}
    for number,(path,start,end) in enumerate(spans):
        if path!="app.py" or not 1<=start<=end<=len(lines):raise ValueError("adk_review234_source_span")
        content="".join(lines[start-1:end]);alias=f"e{number}";by_span[(path,start,end)]=alias
        evidence[alias]={"path":path,"start_line":start,"end_line":end,"content":content,
            "source_sha256":hashlib.sha256(source.encode()).hexdigest(),"content_sha256":hashlib.sha256(content.encode()).hexdigest()}
    evidence["sdk"]={"kind":"sdk_contract","contract_sha256":sdk_contract["contract_sha256"],"facts":sdk_contract["facts"],
        "limits":sdk_contract["limits"],"framework_versions":sdk_contract["framework_versions"]}
    requirements={cid:sorted({by_span[(row["path"],row["start_line"],row["end_line"])] for row in rows}|({"sdk"} if sdk else set()))
                  for cid,(rows,sdk) in raw_requirements.items()}
    payload={"role":role,"repository_id":repository_id,"claims":claims,"evidence":evidence}
    if previous is not None:payload["previous_review"]=previous
    payload["input_id"]="adk-review:"+digest({"system":SYSTEM,"payload":payload})[:24]
    spec={"input_id":payload["input_id"],"role":role,"repository_id":repository_id,"claim_ids":[row["claim_id"] for row in claims],
        "requirements":requirements,"evidence":evidence,"model_input_sha256":digest(payload),"negative_control_claim_ids":["control-opposite-issue","control-opposite-placement"],
        "model_citation_responsibility":False,"deterministic_evidence_attachment":True}
    return payload,spec
