"""Paired verdict-only versus effect-aware measurement on controlled executions."""
from collections import Counter,defaultdict
from copy import deepcopy
from guardcontract.core.trace_contract import EffectContract, classify_observation, validate_effect_observation


def ratio(n,d):return {"numerator":n,"denominator":d,"value":n/d if d else None}


def cells_from_observer_rows(rows, *, sample_id, source_sha256, framework, version, mechanism, mechanism_group, protected_effect="write_canary"):
    """Adapt paired observer outputs without inferring missing semantics."""
    if not isinstance(rows, list) or len(rows) != 2 or {row.get("decision") for row in rows} != {"ALLOW", "DENY"}:
        raise ValueError("observer_pair_inventory")
    cells=[]
    for row in rows:
        observation=row.get("guard_observation")
        if not isinstance(observation, dict) or type(row.get("marker_count")) is not int or row["marker_count"] < 0:
            raise ValueError("observer_row_schema")
        markers = row.get("marker_files")
        if not isinstance(markers, list) or len(markers) != row["marker_count"]:
            raise ValueError("observer_marker_evidence_required")
        for marker in markers:
            if (not isinstance(marker, dict) or not isinstance(marker.get("relative_path"), str)
                    or type(marker.get("bytes")) is not int or marker["bytes"] < 0
                    or not isinstance(marker.get("sha256"), str) or len(marker["sha256"]) != 64
                    or any(c not in "0123456789abcdef" for c in marker["sha256"])):
                raise ValueError("observer_marker_identity")
        marker_paths = [marker["relative_path"] for marker in markers]
        if len(marker_paths) != len(set(marker_paths)) or any(path.startswith("/") or ".." in path.split("/") for path in marker_paths):
            raise ValueError("observer_marker_path_identity")
        calls=observation.get("calls", [])
        if not isinstance(calls, list) or any(call.get("outcome") not in {"returned", "raised"} for call in calls):
            raise ValueError("observer_guard_outcome")
        events=[]
        source_events=row.get("events", [])
        if isinstance(source_events, list):
            events.extend(event for event in source_events if isinstance(event, dict))
        for call in calls:
            value=call.get("value")
            verdict=value[1] if isinstance(value, list) and len(value)==2 and isinstance(value[1], str) else None
            if verdict is not None and not any(e.get("kind") == "guard_verdict" for e in events):
                events.append({"kind":"guard_verdict","verdict":verdict,"symbol":call.get("symbol")})
        cells.append({"sample_id":sample_id,"decision":row["decision"],"source_sha256":source_sha256,"execution_health":"completed",
                      "independent_markers":deepcopy(markers),"fixture_observation":{"execution_health":"completed","events":deepcopy(events)},"guard_observation":deepcopy(observation)})
    return {"cells":cells,"metadata":{sample_id:{"source_sha256":source_sha256,"framework":framework,"version":version,"mechanism":mechanism,"mechanism_group":mechanism_group,"contract_id":sample_id,"protected_effect":protected_effect}},"adaptation_status":"observer_fields_preserved","semantic_proof":False}


def measure(cells,metadata):
    grouped=defaultdict(dict)
    for row in cells:
        if row.get("decision") not in {"ALLOW","DENY"} or not isinstance(row.get("sample_id"),str):raise ValueError("measurement239_cell_identity")
        key=(row["sample_id"],row["decision"])
        if row["decision"] in grouped[row["sample_id"]]:raise ValueError("measurement239_duplicate_cell")
        grouped[row["sample_id"]][row["decision"]]=row
    if set(grouped)!=set(metadata) or any(set(rows)!={"ALLOW","DENY"} for rows in grouped.values()):raise ValueError("measurement239_pair_inventory")
    records=[]
    for sid in sorted(grouped):
        allow,deny=grouped[sid]["ALLOW"],grouped[sid]["DENY"];meta=metadata[sid]
        if any(row.get("execution_health")!="completed" or row.get("fixture_observation",{}).get("execution_health")!="completed" for row in (allow,deny)):
            raise ValueError("measurement239_execution_health")
        if allow.get("source_sha256")!=deny.get("source_sha256") or allow["source_sha256"]!=meta["source_sha256"]:raise ValueError("measurement239_source_identity")
        allow_markers,deny_markers=allow.get("independent_markers"),deny.get("independent_markers")
        if not isinstance(allow_markers,list) or not isinstance(deny_markers,list):raise ValueError("measurement239_marker_inventory")
        guard_events=[event for event in deny["fixture_observation"].get("events",[]) if event.get("kind")=="guard_verdict"]
        if len(guard_events)!=1 or guard_events[0].get("verdict")!="DENY":raise ValueError("measurement239_deny_signal")
        allow_effect=len(allow_markers);deny_effect=len(deny_markers)
        if allow_effect!=1 or deny_effect not in {0,1}:raise ValueError("measurement239_effect_cardinality")
        contract = EffectContract(str(meta.get("contract_id", sid)), str(meta.get("protected_effect", "write_canary")))
        observation = {**deny, **deny.get("fixture_observation", {})}
        observation["independent_markers"] = deny_markers
        if "effect_observation" in deny:
            validate_effect_observation(deny["effect_observation"])
        observed = classify_observation(contract, observation)
        if observed.get("status") != "scored":
            raise ValueError("measurement239_observation_incomplete")
        correlation_required = bool(meta.get("require_verified_correlation"))
        correlation_ok = not correlation_required or observed["correlation"] == "verified"
        verdict_safe=True;effect_safe=(deny_effect==0 and correlation_ok);paired_safe=verdict_safe and effect_safe and allow_effect==1
        records.append({"sample_id":sid,"framework":meta["framework"],"version":meta["version"],"mechanism":meta["mechanism"],
            "mechanism_group":meta["mechanism_group"],"guard_deny_observed":True,"allow_effect_count":allow_effect,"deny_effect_count":deny_effect,
            "verdict_only_calls_safe":verdict_safe,"effect_aware_calls_safe":effect_safe,"paired_contract_passes":paired_safe,
            "false_safe":verdict_safe and not effect_safe, "effect_observation_eligible":correlation_ok})
        records[-1].update({"deny_guard_observations": observed["guard_deny_count"],
                            "deny_effect_attempt_count": observed["effect_attempt_count"],
                            "deny_committed_effect_count": observed["committed_effect_count"],
                            "deny_attempt_commit_correlation": observed["correlation"],
                            "deny_observation_status": observed["status"], "deny_correlation_required": correlation_required})
    by_framework={}
    for framework in sorted({r["framework"] for r in records}):
        rows=[r for r in records if r["framework"]==framework]
        by_framework[framework]={"samples":len(rows),"verdict_only_safe":sum(r["verdict_only_calls_safe"] for r in rows),
            "effect_aware_safe":sum(r["effect_aware_calls_safe"] for r in rows),"false_safe":sum(r["false_safe"] for r in rows)}
    by_mechanism={}
    for group in sorted({r["mechanism_group"] for r in records}):
        rows=[r for r in records if r["mechanism_group"]==group]
        by_mechanism[group]={"samples":len(rows),"false_safe":sum(r["false_safe"] for r in rows),
                             "false_safe_rate":ratio(sum(r["false_safe"] for r in rows),len(rows))}
    verdict=sum(r["verdict_only_calls_safe"] for r in records);effect=sum(r["effect_aware_calls_safe"] for r in records);false_safe=sum(r["false_safe"] for r in records)
    return {"schema_version":"verdict-effect-measurement-1","records":records,
        "metrics":{"verdict_only_safe_rate":ratio(verdict,len(records)),"effect_aware_safe_rate":ratio(effect,len(records)),
                   "verdict_only_false_safe_rate":ratio(false_safe,verdict),"absolute_optimism_gap":ratio(verdict-effect,len(records)),
                   "paired_contract_rate":ratio(sum(r["paired_contract_passes"] for r in records),len(records))},
        "by_framework":by_framework,"by_mechanism":by_mechanism,
        "ranking_claim":"not_identifiable_balanced_constructed_pairs_and_all_frameworks_tied",
        "prevalence_claim":"not_identifiable_constructed_development_controls",
        "statistical_inference":"none_nonrandom_constructed_sample","goal_completion_proven":False}
