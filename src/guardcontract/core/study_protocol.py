"""Structural checks for the prospective multi-frame study protocol."""


def validate(protocol):
    if protocol.get("schema_version")!="guardcontract-prospective-study-1" or set(protocol.get("frames",{}))!={"tool_validation_holdout","ecosystem_measurement","mechanism_experiment"}:raise ValueError("study241_frames")
    holdout=protocol["frames"]["tool_validation_holdout"]
    if holdout["minimum_known_positive"]<100 or holdout["minimum_known_negative"]<100 or len(holdout["framework_strata"])<5:raise ValueError("study241_holdout_size")
    if holdout["point_gate"]!={"issue_precision":0.95,"issue_recall":0.95}:raise ValueError("study241_primary_gate")
    if "prevalence" not in holdout["purpose"].lower() or "prohibited" not in protocol["frames"]["ecosystem_measurement"]:raise ValueError("study241_estimand_separation")
    if protocol["leakage_controls"]["current_eligibility"]!=0 or len(protocol["freeze_gate"])<6:raise ValueError("study241_freeze_gate")
    if protocol["external_vulnerability_hunting"]!="paused" or protocol["goal_completion_proven"] is not False:raise ValueError("study241_boundary")
    return {"schema_version":"study-protocol-validation-1","valid":True,"frames":3,"holdout_currently_admitted":False,"goal_completion_proven":False}
