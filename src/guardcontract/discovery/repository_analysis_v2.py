"""Fail-closed multi-framework repository analyzer."""
import argparse
import hashlib,json,tempfile
import re
from collections import Counter
from pathlib import Path
from guardcontract.discovery.repository_analysis import analyze as analyze_supported
from guardcontract.discovery.langchain_adapter import scan as scan_langchain
from guardcontract.discovery.registration_v2 import discover_registrations as scan_pydantic
from guardcontract.discovery.registration_v2 import discover_registrations as scan_adk
from guardcontract.discovery.registration_v2 import discover_registrations as scan_crewai
from guardcontract.discovery.generic_effect_catalog import inventory as generic_effect_inventory
SUPPORTED={"openai-agents","crewai"}
def _registration_site_semantics(group, framework):
    parameters={row.get("parameter") for row in group.get("guard_parameters",[]) if isinstance(row,dict)}
    if framework=="google-adk":
        if "require_confirmation" in parameters:return "google-adk-tool-confirmation","pre_effect_decidable"
        if "before_tool_callback" in parameters:return "google-adk-before-tool","pre_effect_decidable"
        if "after_tool_callback" in parameters:return "google-adk-after-tool","post_effect_dependent"
        return "google-adk-agent","unknown"
    if framework=="pydantic-ai":
        if "output_validator" in parameters:return "pydantic-ai-output-validator","post_effect_dependent"
        return "pydantic-ai-agent","unknown"
    if framework=="crewai":
        if parameters & {"crewai.hooks.register_before_tool_call_hook","before_tool_call"}:
            return "crewai-before-tool","pre_effect_decidable"
        if parameters & {"crewai.hooks.register_after_tool_call_hook","after_tool_call"}:
            return "crewai-after-tool","post_effect_dependent"
        return "crewai-agent","unknown"
    if framework=="langchain":
        if "human_in_the_loop" in parameters:return "langchain-tool-approval","pre_effect_decidable"
        return "langchain-middleware","unknown"
    return framework+"-agent","unknown"

def _registration_site(group, framework):
    lifecycle,decidability=_registration_site_semantics(group,framework)
    selected_symbols={row.get("symbol") for row in group.get("guard_parameters",[]) if isinstance(row,dict)}
    semantics=[row for row in group.get("guard_semantics",[]) if row.get("symbol") in selected_symbols]
    capabilities={row.get("deny_capability","unknown") for row in semantics}
    deny_capability="present" if "present" in capabilities else ("absent" if capabilities=={"absent"} else "unknown")
    return {"path":group["path"],"line":group["registration_line"],"construct":group["kind"],"lifecycle":lifecycle,
            "guard":group["guards"][0]["symbol"] if group["guards"] else "<unknown-guard>","decidability":decidability,
            "deny_capability":deny_capability,"deny_capability_evidence":semantics,
            "path_status":group.get("path_status","path_unverified"),"call_graph_edges":len(group.get("local_call_edges",[])),
            "call_graph_unresolved":sum(e.get("status")!="resolved" for e in group.get("local_call_edges",[]) if isinstance(e,dict)),
            "tool_evidence":{"explicit_effects":group.get("effects",[]),"effect_status":"unknown",
                             "unresolved_tools":group.get("unresolved_tools",[])},
            "repair_class":"unknown","registration_evidence":group}

def _registration_sites(group, framework):
    parameters=[row for row in group.get("guard_parameters",[]) if isinstance(row,dict)]
    if not parameters:return [_registration_site(group,framework)]
    partitions={}
    for parameter in parameters:
        lifecycle,decidability=_registration_site_semantics({"guard_parameters":[parameter]},framework)
        partitions.setdefault((lifecycle,decidability),[]).append(parameter)
    sites=[]
    for entries in partitions.values():
        symbols={entry.get("symbol") for entry in entries if entry.get("symbol")}
        guards=[guard for guard in group.get("guards",[]) if guard.get("symbol") in symbols]
        subgroup={**group,"guard_parameters":entries,"guards":guards or group.get("guards",[])}
        sites.append(_registration_site(subgroup,framework))
    return sites
def _source_inventory_digest(repo):
    records=[]
    for path in sorted(Path(repo).rglob("*")):
        if not path.is_file() or path.is_symlink() or ".git" in path.parts: continue
        records.append({"path":path.relative_to(repo).as_posix(),"bytes":path.stat().st_size,"sha256":hashlib.sha256(path.read_bytes()).hexdigest()})
    return hashlib.sha256(json.dumps(records,sort_keys=True,separators=(",",":")).encode()).hexdigest()
def analyze(config):
    frame=json.loads(Path(config["frame"]).read_text());field=config.get("repository_list_field","selected");selected=frame[field]
    materialization=json.loads(Path(config["materialization"]).read_text());available={r["repository"] for r in materialization["repositories"] if r["status"]=="completed"}
    supported_all=[r for r in selected if r["framework"] in SUPPORTED]
    supported=[r for r in supported_all if r["repository"]["full_name"] in available]
    unavailable_supported=[r for r in supported_all if r["repository"]["full_name"] not in available]
    unsupported=[r for r in selected if r["framework"] not in SUPPORTED and (r["framework"] != "langchain" or not config.get("enable_langchain_adapter", False)) and r["framework"] not in {"pydantic-ai","google-adk"}]
    if supported:
        with tempfile.TemporaryDirectory(prefix="guardcontract-repository-router-") as temporary:
            routed=Path(temporary)/"frame.json";routed.write_text(json.dumps({**frame,field:supported}));result=analyze_supported({**config,"frame":str(routed)})
    else:
        result={"schema_version":4,"task_version":config["task_version"],"split":config["split"],"repositories":[],"counts":{},"analysis_scope":"no supported framework routed","effect_model_boundary":"all requested frameworks unsupported"}
    for item in unavailable_supported:
        result["repositories"].append({"framework":item["framework"],"repository":item["repository"]["full_name"],"commit":item["pinned_commit"],"matched_files":len(item.get("matched_files",[])),"excluded_matched_files":[],"scanned_files":0,"source_scan_truncated":False,"parse_errors":[],"role":"source_unavailable","sites":[],"status":"source_unavailable","execution_health":"source_unavailable","gaps":["materialization_unavailable"]})
    for item in selected:
        if item["framework"] != "crewai": continue
        name=item["repository"]["full_name"]
        material=next((r for r in materialization["repositories"] if r.get("repository")==name and r.get("status")=="completed"),None)
        row=next((r for r in result["repositories"] if r.get("repository")==name and r.get("framework")=="crewai"),None)
        if material is None or row is None or material.get("commit") != item["pinned_commit"] or not Path(material.get("destination", "")).is_dir(): continue
        candidate=scan_crewai(Path(material["destination"]), max_files=int(config.get("max_repository_python_files", 5000)), max_file_bytes=int(config.get("max_python_file_bytes", 1048576)), max_groups=int(config.get("max_groups_per_repository", 40)))
        hooks=[g for g in candidate["groups"] if g.get("framework")=="crewai" and g.get("kind") in {"same_scope_global_hook","decorated_global_hook"}]
        existing={(site.get("path"),site.get("line"),site.get("construct")) for site in row.get("sites",[])}
        for group in hooks:
            key=(group["path"],group["registration_line"],group["kind"])
            if key in existing: continue
            row.setdefault("sites",[]).extend(_registration_sites(group,"crewai"))
        if hooks:
            row["role"]="crewai-global-hook-registration-candidate"
            row["status"]="partial"
            row["registration_v2_overlay"]={"groups":len(hooks),"execution_health":candidate["execution_health"],"groups_budget_deferred":candidate["groups_budget_deferred"]}
    for item in selected:
        if not config.get("enable_langchain_adapter", False) or item["framework"] != "langchain": continue
        if item["repository"]["full_name"] not in available:
            result["repositories"].append({"framework":"langchain", "repository":item["repository"]["full_name"],
                "commit":item["pinned_commit"], "sites":[], "status":"source_unavailable",
                "execution_health":"source_unavailable", "gaps":["materialization_unavailable"]})
            continue
        material=next(r for r in materialization["repositories"] if r["repository"]==item["repository"]["full_name"])
        if material.get("commit") != item["pinned_commit"]:
            result["repositories"].append({"framework":"langchain","repository":item["repository"]["full_name"],"commit":item["pinned_commit"],"sites":[],"status":"source_unavailable","execution_health":"source_unavailable","gaps":["materialization_identity_mismatch"]}); continue
        if not Path(material.get("destination", "")).is_dir():
            result["repositories"].append({"framework":"langchain","repository":item["repository"]["full_name"],"commit":item["pinned_commit"],"sites":[],"status":"source_unavailable","execution_health":"source_unavailable","gaps":["materialization_destination_missing"]}); continue
        inventory_digest=material.get("source_inventory_sha256")
        if inventory_digest is not None and re.fullmatch(r"[0-9a-f]{64}", inventory_digest) is None:
            result["repositories"].append({"framework":"langchain","repository":item["repository"]["full_name"],"commit":item["pinned_commit"],"sites":[],"status":"source_unavailable","execution_health":"source_unavailable","gaps":["materialization_inventory_digest_invalid"]}); continue
        tree_digest=material.get("tree")
        if tree_digest is not None and re.fullmatch(r"[0-9a-f]{40}", tree_digest) is None:
            result["repositories"].append({"framework":"langchain","repository":item["repository"]["full_name"],"commit":item["pinned_commit"],"sites":[],"status":"source_unavailable","execution_health":"source_unavailable","gaps":["materialization_tree_digest_invalid"]}); continue
        if config.get("verify_materialization_inventory") and inventory_digest is not None and _source_inventory_digest(material["destination"]) != inventory_digest:
            result["repositories"].append({"framework":"langchain","repository":item["repository"]["full_name"],"commit":item["pinned_commit"],"sites":[],"status":"source_unavailable","execution_health":"source_unavailable","gaps":["materialization_inventory_mismatch"]}); continue
        candidate=scan_langchain(Path(material["destination"]), int(config.get("max_repository_python_files", 5000)), int(config.get("max_python_file_bytes", 1048576)))
        result["repositories"].append({"framework":"langchain","repository":item["repository"]["full_name"],"commit":item["pinned_commit"],"matched_files":len(item.get("matched_files",[])),"excluded_matched_files":[],"scanned_files":0,"source_scan_truncated":False,"parse_errors":[],"role":"langchain_registration_candidate","sites":[_registration_site(g,"langchain") for g in candidate["groups"]],"status":"partial" if candidate["groups"] else "unsupported","gaps":candidate["unresolved_registrations"]})
        row = result["repositories"][-1]
        files = candidate["files"]
        row.update(scanned_files=sum(f["status"] == "parsed" for f in files),
                   source_scan_truncated=not candidate["source_enumeration_complete"],
                   parse_errors=[f for f in files if f.get("error_kind") == "SyntaxError"],
                   source_errors=[f for f in files if f["status"] == "unavailable"],
                   groups_budget_deferred=candidate["groups_budget_deferred"],
                   materialization_source_inventory_sha256=inventory_digest,
                   materialization_tree=tree_digest,
                   execution_health=candidate["execution_health"], source_file_ledger=files)
        if candidate["execution_health"] != "completed":
            row["status"] = "partial"
    for item in selected:
        if item["framework"] != "pydantic-ai": continue
        name=item["repository"]["full_name"]
        if name not in available:
            result["repositories"].append({"framework":"pydantic-ai","repository":name,"commit":item["pinned_commit"],"sites":[],"status":"source_unavailable","execution_health":"source_unavailable","gaps":["materialization_unavailable"]}); continue
        material=next(r for r in materialization["repositories"] if r["repository"]==name)
        if material.get("commit") != item["pinned_commit"]:
            result["repositories"].append({"framework":"pydantic-ai","repository":name,"commit":item["pinned_commit"],"sites":[],"status":"source_unavailable","execution_health":"source_unavailable","gaps":["materialization_identity_mismatch"]}); continue
        if not Path(material.get("destination", "")).is_dir():
            result["repositories"].append({"framework":"pydantic-ai","repository":name,"commit":item["pinned_commit"],"sites":[],"status":"source_unavailable","execution_health":"source_unavailable","gaps":["materialization_destination_missing"]}); continue
        inventory_digest=material.get("source_inventory_sha256")
        if inventory_digest is not None and re.fullmatch(r"[0-9a-f]{64}", inventory_digest) is None:
            result["repositories"].append({"framework":"pydantic-ai","repository":name,"commit":item["pinned_commit"],"sites":[],"status":"source_unavailable","execution_health":"source_unavailable","gaps":["materialization_inventory_digest_invalid"]}); continue
        tree_digest=material.get("tree")
        if tree_digest is not None and re.fullmatch(r"[0-9a-f]{40}", tree_digest) is None:
            result["repositories"].append({"framework":"pydantic-ai","repository":name,"commit":item["pinned_commit"],"sites":[],"status":"source_unavailable","execution_health":"source_unavailable","gaps":["materialization_tree_digest_invalid"]}); continue
        if config.get("verify_materialization_inventory") and inventory_digest is not None and _source_inventory_digest(material["destination"]) != inventory_digest:
            result["repositories"].append({"framework":"pydantic-ai","repository":name,"commit":item["pinned_commit"],"sites":[],"status":"source_unavailable","execution_health":"source_unavailable","gaps":["materialization_inventory_mismatch"]}); continue
        candidate=scan_pydantic(Path(material["destination"]), max_files=int(config.get("max_repository_python_files", 5000)), max_file_bytes=int(config.get("max_python_file_bytes", 1048576)), max_groups=int(config.get("max_groups_per_repository", 40)))
        groups=[g for g in candidate["groups"] if g.get("framework")=="pydantic-ai"]
        sites=[site for group in groups for site in _registration_sites(group,"pydantic-ai")]
        files=candidate["files"]
        result["repositories"].append({"framework":"pydantic-ai","repository":name,"commit":item["pinned_commit"],"matched_files":len(item.get("matched_files",[])),"excluded_matched_files":[],"scanned_files":sum(f["status"]=="parsed" for f in files),"source_scan_truncated":not candidate["source_enumeration_complete"],"parse_errors":[f for f in files if f.get("error_kind")=="SyntaxError"],"source_errors":[f for f in files if f["status"]=="unavailable"],"groups_budget_deferred":candidate["groups_budget_deferred"],"discovered_groups_total":len(candidate["groups"]),"framework_groups":len(groups),"framework_mismatch_groups":len(candidate["groups"])-len(groups),"materialization_source_inventory_sha256":inventory_digest,"materialization_tree":tree_digest,"role":"pydantic-ai-registration-candidate","sites":sites,"status":"partial" if sites else "unsupported","gaps":candidate["unresolved_registrations"],"execution_health":candidate["execution_health"],"source_file_ledger":files})
    for item in selected:
        if item["framework"] != "google-adk": continue
        name=item["repository"]["full_name"]
        if name not in available:
            result["repositories"].append({"framework":"google-adk","repository":name,"commit":item["pinned_commit"],"sites":[],"status":"source_unavailable","execution_health":"source_unavailable","gaps":["materialization_unavailable"]}); continue
        material=next(r for r in materialization["repositories"] if r["repository"]==name)
        if material.get("commit") != item["pinned_commit"]:
            result["repositories"].append({"framework":"google-adk","repository":name,"commit":item["pinned_commit"],"sites":[],"status":"source_unavailable","execution_health":"source_unavailable","gaps":["materialization_identity_mismatch"]}); continue
        if not Path(material.get("destination", "")).is_dir():
            result["repositories"].append({"framework":"google-adk","repository":name,"commit":item["pinned_commit"],"sites":[],"status":"source_unavailable","execution_health":"source_unavailable","gaps":["materialization_destination_missing"]}); continue
        inventory_digest=material.get("source_inventory_sha256")
        if inventory_digest is not None and re.fullmatch(r"[0-9a-f]{64}", inventory_digest) is None:
            result["repositories"].append({"framework":"google-adk","repository":name,"commit":item["pinned_commit"],"sites":[],"status":"source_unavailable","execution_health":"source_unavailable","gaps":["materialization_inventory_digest_invalid"]}); continue
        tree_digest=material.get("tree")
        if tree_digest is not None and re.fullmatch(r"[0-9a-f]{40}", tree_digest) is None:
            result["repositories"].append({"framework":"google-adk","repository":name,"commit":item["pinned_commit"],"sites":[],"status":"source_unavailable","execution_health":"source_unavailable","gaps":["materialization_tree_digest_invalid"]}); continue
        if config.get("verify_materialization_inventory") and inventory_digest is not None and _source_inventory_digest(material["destination"]) != inventory_digest:
            result["repositories"].append({"framework":"google-adk","repository":name,"commit":item["pinned_commit"],"sites":[],"status":"source_unavailable","execution_health":"source_unavailable","gaps":["materialization_inventory_mismatch"]}); continue
        candidate=scan_adk(Path(material["destination"]), max_files=int(config.get("max_repository_python_files", 5000)), max_file_bytes=int(config.get("max_python_file_bytes", 1048576)), max_groups=int(config.get("max_groups_per_repository", 40)))
        groups=[g for g in candidate["groups"] if g.get("framework")=="google-adk"]
        sites=[site for group in groups for site in _registration_sites(group,"google-adk")]
        files=candidate["files"]
        result["repositories"].append({"framework":"google-adk","repository":name,"commit":item["pinned_commit"],"matched_files":len(item.get("matched_files",[])),"excluded_matched_files":[],"scanned_files":sum(f["status"]=="parsed" for f in files),"source_scan_truncated":not candidate["source_enumeration_complete"],"parse_errors":[f for f in files if f.get("error_kind")=="SyntaxError"],"source_errors":[f for f in files if f["status"]=="unavailable"],"groups_budget_deferred":candidate["groups_budget_deferred"],"discovered_groups_total":len(candidate["groups"]),"framework_groups":len(groups),"framework_mismatch_groups":len(candidate["groups"])-len(groups),"materialization_source_inventory_sha256":inventory_digest,"materialization_tree":tree_digest,"role":"google-adk-registration-candidate","sites":sites,"status":"partial" if sites else "unsupported","gaps":candidate["unresolved_registrations"],"execution_health":candidate["execution_health"],"source_file_ledger":files})
    for r in unsupported:
        name=r["repository"]["full_name"]; material=next((x for x in materialization["repositories"] if x.get("repository")==name and x.get("status")=="completed"),None)
        generic = generic_effect_inventory(material["destination"]) if config.get("enable_generic_effect_catalog") and material else None
        result["repositories"].append({"framework":r["framework"],"repository":name,"commit":r["pinned_commit"],"matched_files":len(r.get("matched_files",[])),"excluded_matched_files":[],"scanned_files":generic["scanned_files"] if generic else 0,"source_scan_truncated":False,"parse_errors":[],"role":"unsupported_framework","sites":[],"generic_effect_catalog":generic,"status":"unsupported" if name in available else "source_unavailable","gaps":["repository_analyzer_framework_not_implemented"]})
    result["repositories"].sort(key=lambda r:(r["framework"],r["repository"]))
    rows = result["repositories"]
    sites = [s for r in rows for s in r["sites"]]
    incomplete = [r for r in rows if
        r.get("execution_health", "completed") != "completed"
        or r.get("status") in {"source_unavailable", "error"}
        or r.get("parse_errors") or r.get("source_errors")
        or r.get("source_scan_truncated") or r.get("configuration_scan_truncated")
        or r.get("configuration_parse_errors") or r.get("groups_budget_deferred")]
    prior_health = result.get("execution_health", "completed")
    health = "partial" if incomplete or len(rows) != len(selected) else "completed"
    if prior_health != "completed":
        health = prior_health
    pydantic_count=sum(r["framework"]=="pydantic-ai" for r in selected)
    adk_count=sum(r["framework"]=="google-adk" for r in selected)
    result["counts"].update(
        planned_repositories=len(selected),
        completed_repositories=len({r.get("repository") for r in rows if r.get("repository")}),
        planned_repository_framework_pairs=len(selected),
        completed_repository_framework_pairs=len(rows),
        completed_repository_rows=len(rows),
        execution_incomplete_repository_rows=len(incomplete),
        supported_framework_repositories=len(supported_all)+pydantic_count+adk_count,
        legacy_analyzer_framework_repositories=len(supported_all),
        registration_v2_framework_repositories=pydantic_count+adk_count,
        repository_detection_implemented_repositories=sum(
            r.get("framework") in {"openai-agents", "crewai", "langchain", "pydantic-ai", "google-adk"}
            and r.get("status") in {"partial", "completed"} for r in rows),
        unsupported_framework_repositories=len(unsupported),
        unsupported_frameworks=dict(Counter(r["framework"] for r in unsupported)),
        roles=dict(Counter(r.get("role", "unknown") for r in rows)),
        lifecycles=dict(Counter(s.get("lifecycle", "unknown") for s in sites)),
        decidability=dict(Counter(s.get("decidability", "unknown") for s in sites)),
        deny_capability=dict(Counter(s.get("deny_capability", "unknown") for s in sites)),
        deny_effect_candidates=dict(Counter(s.get("deny_capability", "unknown") for s in sites
                                            if s.get("tool_evidence", {}).get("explicit_effects"))),
        repair_classes=dict(Counter(s.get("repair_class", "unknown") for s in sites)),
        effect_families=dict(Counter(effect.get("family", "unknown") for s in sites
                                     for effect in s.get("tool_evidence", {}).get("explicit_effects", []))),
        explicit_effect_sites=sum(bool(s.get("tool_evidence", {}).get("explicit_effects")) for s in sites),
        repositories_with_explicit_effect_site=sum(any(site.get("tool_evidence", {}).get("explicit_effects")
                                                   for site in r.get("sites", [])) for r in rows),
        guard_sites=len(sites), repositories_with_sites=sum(bool(r["sites"]) for r in rows))
    result.update(task_version=config["task_version"], split=config["split"],
                  execution_health=health, unsupported_preserved=True, goal_completion_proven=False)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config",type=Path,required=True)
    parser.add_argument("--result",type=Path,required=True)
    args=parser.parse_args();result=analyze(json.loads(args.config.read_text(encoding="utf-8")))
    args.result.parent.mkdir(parents=True,exist_ok=True)
    args.result.write_text(json.dumps(result,ensure_ascii=False,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps(result.get("counts",{}),sort_keys=True))
    return 0


if __name__=="__main__":raise SystemExit(main())
