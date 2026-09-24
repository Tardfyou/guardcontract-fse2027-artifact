"""Pydantic review with single-predicate issue and opposite-control claims."""
from guardcontract.protocols.certificate_review_atomic import SYSTEM,decode
from guardcontract.protocols.pydantic_certificate_review import digest,task as compound_task

def task(certificate,source,helper_source,sdk_contract,*,repository_id,role="analyst",previous=None):
    payload,spec=compound_task(certificate,source,helper_source,sdk_contract,repository_id=repository_id,role=role,previous=previous)
    occurs=certificate["issue_prediction"] is True
    statements={"issue":f"The selected effect {'occurs' if occurs else 'does not occur'} on DENY.",
        "control-opposite-issue":f"The selected effect {'does not occur' if occurs else 'occurs'} on DENY."}
    for claim in payload["claims"]:
        if claim["claim_id"] in statements:claim["statement"]=statements[claim["claim_id"]]
    payload["input_id"]="pydantic-review-v2:"+digest({"system":SYSTEM,"payload":{k:v for k,v in payload.items() if k!="input_id"}})[:24]
    spec={**spec,"input_id":payload["input_id"],"model_input_sha256":digest(payload)}
    return payload,spec
