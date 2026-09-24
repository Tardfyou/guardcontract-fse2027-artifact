"""Shared execution and exact scoring for blind typed analyst/critic reviews."""
import json
from collections import Counter
from guardcontract.pipeline.review_execution import call_model,write_new

def execute(plan,frozen,output,key,*,system,decoder,transport_factory):
    if (output/"runs").exists():raise ValueError("blind_typed_existing_run")
    records=[];tokens=0;usage_known=True
    for cell in plan["cells"]:
        for role in ("analyst","critic"):
            directory=output/"runs"/f"{cell['sample_id']}-{role}";payload=json.loads(frozen[cell["role_inputs"][role]]);spec=json.loads(frozen[cell["role_specs"][role]])
            if not usage_known or tokens>=plan["max_total_tokens_stop_before_next_call"] or len(records)>=plan["max_calls"]:
                directory.mkdir(parents=True);row={"cell_id":directory.name,"role":role,"execution_state":"missing","review":None,"calls":[],"fault_domain":"budget","error_code":"unknown_usage_or_budget_stop"}
                write_new(directory/"ACTUAL_INPUT.json",payload);write_new(directory/"ACTUAL_SPEC.json",spec);write_new(directory/"RESULT.json",row)
            else:
                row,used,known=call_model(payload,spec,role,directory,plan,key,system=system,decoder=decoder,transport_factory=transport_factory);tokens+=used;usage_known&=known
            records.append(row)
    result={"schema_version":plan["result_schema_version"],"records":records,"actual_calls":sum(len(r["calls"]) for r in records),"actual_total_tokens":tokens if usage_known else None,
        "known_accounted_tokens":tokens,"usage_known":usage_known,"goal_completion_proven":False};write_new(output/"RESULT.json",result);return result

def score(evaluation,result,invariants):
    expected={r["sample_id"]:r["expected_fields"] for r in evaluation["cells"]};states=Counter(r["execution_state"] for r in result["records"]);rows=[];correct=known=0;sample_gates={}
    infrastructure=any(r["execution_state"] in {"error","missing"} for r in result["records"]);by={(r["cell_id"].rsplit("-",1)[0],r["role"]):r for r in result["records"]}
    for sid,target in expected.items():
        role_gates=[]
        for role in ("analyst","critic"):
            record=by[(sid,role)];fields=record["review"]["fields"] if record["execution_state"]=="completed" else {}
            for name,want in target.items():
                got=fields.get(name);rows.append({"sample_id":sid,"role":role,"field":name,"reference":want,"prediction":got,"correct":got==want});known+=record["execution_state"] not in {"error","missing"};correct+=record["execution_state"] not in {"error","missing"} and got==want
            checks=invariants(fields) if fields else {};role_gates.append(record["execution_state"]=="completed" and all(checks.values()) and fields==target and record["review"]["deterministic_evidence_attachment_verified"])
        sample_gates[sid]=all(role_gates)
    ratio=lambda n,d:{"numerator":n,"denominator":d,"value":None if infrastructure or not d else n/d}
    return {"execution_states":dict(states),"rows":rows,"typed_field_accuracy":ratio(correct,known),"sample_gates":sample_gates,
        "complete_blind_role_pairs":{"numerator":sum(sample_gates.values()),"denominator":len(sample_gates),"value":None if infrastructure else sum(sample_gates.values())/len(sample_gates)},
        "scientific_status":"undetermined_infrastructure_or_missing" if infrastructure else "scored_typed_path_review","goal_completion_proven":False}
