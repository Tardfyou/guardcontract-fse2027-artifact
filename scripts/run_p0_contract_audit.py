"""Audit a frozen admission set with source-only policy-condition hypotheses."""
import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from guardcontract.protocols.protection_obligation_v3 import SYSTEM, spec_for, decode, merge, summarize, digest
from guardcontract.pipeline.review_execution import call_model, write_new
from guardcontract.pipeline.shared_review_budget import SharedReviewBudget
from guardcontract.backends.scoped_review_transport import ScopedReviewTransport
from guardcontract.evidence.python_redaction_v3 import redact_python
from run_p0_source_recovery import redact_data

GIT = ROOT / "experiments/p0-complete-git-source-round125-n1823"
CONTEXTS = ROOT / "experiments/p0-source-contexts-v2-round131-n1829"
SDK_REFERENCE = ROOT / "experiments/p0-sdk-source-references-round130-n1828/SDK_REFERENCES_V2.json"
SDK_REVIEW = ROOT / "experiments/p0-contract-admission-pilot-round132-n1830/SDK_COMPATIBILITY_REVIEW.json"
MODEL_ID = ROOT / "config/paratera-current-model-id.txt"
MODEL_POLICY = ROOT / "config/research-model-policy.json"
CALL_STATE = ROOT / "config/external-model-call-state.json"
ANALYSIS_ASSUMPTIONS = {
    "version": "source-feasible-path-assumptions-2",
    "observations_required": False,
    "rules": [
        "Determine source-permitted feasible paths, not whether a deployment run, model completion or file artifact has been observed.",
        "For model/provider credentials, services and local IO that the source permits configuring, consider an ordinary successful execution under a legal configuration; actual secrets and live observation are not required.",
        "Do not bypass hard-coded failure, missing implementation, type/parse restrictions, binding uncertainty, or unresolved SDK compatibility.",
        "Business-model candidate outputs and tool plans may disobey natural-language instructions, but must satisfy the program's actual structural constraints. Do not fabricate observed executions.",
        "Do not assume a decision model misclassifies: establish its reachable result domain, parsing, error handling and downstream use from the supplied implementation.",
        "Keep missing runtime observations separate from missing source facts. An unobserved event alone is not a critical path gap.",
    ],
}
SDK_FILES = {
    "langchain": [".venv-langchain/lib/python3.12/site-packages/langchain/agents/middleware/human_in_the_loop.py",
                  ".venv-langchain/lib/python3.12/site-packages/langchain/agents/factory.py",
                  ".venv-langchain/lib/python3.12/site-packages/langgraph/prebuilt/tool_node.py"],
    "google-adk": [".venv-google-adk-270/lib/python3.12/site-packages/google/adk/flows/llm_flows/functions.py",
                   ".venv-google-adk-270/lib/python3.12/site-packages/google/adk/flows/llm_flows/base_llm_flow.py",
                   ".venv-google-adk-270/lib/python3.12/site-packages/google/adk/tools/function_tool.py"],
    "pydantic-ai": [".venv-pydantic-ai/lib/python3.12/site-packages/pydantic_ai/_agent_graph.py",
                    ".venv-pydantic-ai/lib/python3.12/site-packages/pydantic_ai/_output.py"],
    "crewai": [".venv-crewai/lib/python3.12/site-packages/crewai/crew.py",
               ".venv-crewai/lib/python3.12/site-packages/crewai/task.py",
               ".venv-crewai/lib/python3.12/site-packages/crewai/crews/utils.py",
               ".venv-crewai/lib/python3.12/site-packages/crewai/project/annotations.py"],
    "openai-agents": ["experiments/p0-sdk-source-references-round130-n1828/openai-agents-0.4.0/sources/agents/run.py",
                      "experiments/p0-sdk-source-references-round130-n1828/openai-agents-0.4.0/sources/agents/_run_impl.py",
                      "experiments/p0-sdk-source-references-round130-n1828/openai-agents-0.4.0/sources/agents/guardrail.py"],
}


def read(path): return json.loads(Path(path).read_bytes())
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify_admission(admission):
    ids = [p["sample_id"] for p in admission["ledger"]]
    contracts = admission["contracts"]
    cids = [c["contract_id"] for c in contracts]
    if len(ids) != 772 or len(set(ids)) != 772 or len(set(cids)) != len(cids):
        raise ValueError("admission_inventory")
    by_id = {c["contract_id"]: c for c in contracts}
    for c in contracts:
        if c["admission_status"] != "applicable" or c["prediction_read_for_admission"] or c["behavior_label"] is not None:
            raise ValueError("admission_label_boundary")
        if not c["parent_sample_ids"] or not set(c["parent_sample_ids"]) <= set(ids):
            raise ValueError("admission_parent_identity")
    for p in admission["ledger"]:
        expected = {c["contract_id"] for c in contracts if p["sample_id"] in c["parent_sample_ids"]}
        if set(p["contract_ids"]) != expected or bool(expected) != p["admitted_contract_found"]:
            raise ValueError("admission_bidirectional_mapping")


def parent_summary(admission, rows, exclusions=None):
    excluded = {cid for item in (exclusions or []) for cid in item["contract_ids"]}
    parents = []
    for parent in admission["ledger"]:
        matches = [r for r in rows if parent["sample_id"] in r["parent_sample_ids"]]
        classes = {r["contract_audit_prediction"] for r in matches}
        prediction = "present" if "present" in classes else "absent" if classes == {"absent"} else "unknown"
        unresolved = sum(r["contract_audit_prediction"] == "unknown" for r in matches)
        parents.append({**parent, "contract_audit_prediction": prediction if matches else None,
                        "all_contracts_resolved": bool(matches) and unresolved == 0,
                        "unknown_contract_count": unresolved, "eligible_contract_count": len(matches),
                        "eligible_contract_found": bool(matches),
                        "excluded_contract_ids": sorted(set(parent.get("contract_ids", [])) & excluded)})
    selected = [p for p in parents if p["eligible_contract_found"]]
    counts = Counter(p["contract_audit_prediction"] for p in selected)
    unresolved = sum(p["unknown_contract_count"] > 0 for p in selected)
    return parents, {"parents": len(selected), "existential_prediction_counts": dict(counts),
                     "all_contracts_resolved": len(selected) - unresolved,
                     "parents_with_any_unknown": unresolved,
                     "unknown_rate": unresolved / len(selected) if selected else None,
                     "below_twenty_percent": bool(selected) and 5 * unresolved < len(selected)}


def source_view(path, alias, include_symbols=None):
    raw = path.read_bytes()
    if path.suffix == ".py":
        import io, tokenize
        try: text = raw.decode(tokenize.detect_encoding(io.BytesIO(raw).readline)[0])
        except (UnicodeError, SyntaxError): text = "\0"
        clean = redact_python(text)
    else:
        try: clean = redact_data(raw)
        except UnicodeError: clean = {"source": "SOURCE_WITHHELD", "status": "withheld"}
    lines = clean["source"].splitlines()
    result = {"path": alias, "source_sha256": hashlib.sha256(raw).hexdigest(), "status": clean["status"],
              "start_line": 1, "end_line": len(lines), "content": "\n".join(f"{i}|{line}" for i, line in enumerate(lines, 1))}
    if include_symbols:
        import ast
        tree = ast.parse(clean["source"]); found = set(); selected = set()
        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)) or getattr(node, "name", None) in include_symbols:
                found.add(getattr(node, "name", None))
                start = min([node.lineno] + [d.lineno for d in getattr(node, "decorator_list", [])])
                selected.update(range(start, node.end_lineno + 1))
        if not set(include_symbols) <= found: raise ValueError("sdk_excerpt_symbol_missing")
        ranges = []
        for number in sorted(selected):
            if ranges and number == ranges[-1][1] + 1: ranges[-1][1] = number
            else: ranges.append([number, number])
        result.update(line_ranges=ranges, excerpt_only=True, excerpt_symbols=include_symbols,
                      content="\n".join(f"{i}|{lines[i-1]}" for i in sorted(selected)))
    return result


def sdk_context(selection, refs, inputs):
    framework = selection["audit_framework"]
    version = selection["source_selected_reference_version"]
    if version:
        base = SDK_REFERENCE.parent / (framework + "-" + version)
        manifest_path = base / "MANIFEST.json"; manifest = read(manifest_path)
        if manifest["package"] != framework or manifest["version"] != version:
            raise ValueError("sdk_wheel_version_identity")
        inputs[str(manifest_path.relative_to(ROOT))] = sha(manifest_path)
        expected = {r["path"]: r["sha256"] for r in manifest["files"]}
        source_base = base / "sources"
    else:
        source_base = ROOT / SDK_FILES[framework][0].split("/site-packages/")[0] / "site-packages"
        expected = None
    views, missing = [], []
    modules = list(selection["minimum_relevant_sdk_modules"])
    if framework == "crewai":
        modules.extend(("crewai/tasks/llm_guardrail.py", "crewai/utilities/guardrail.py", "crewai/utilities/guardrail_types.py"))
    # Newer OpenAI releases split the old monolithic implementation.
    # Select the replacement modules by authenticated file availability.
    if (framework == "openai-agents" and "agents/_run_impl.py" in modules and
            not (source_base / "agents/_run_impl.py").is_file() and
            (source_base / "agents/run_internal/run_loop.py").is_file()):
        modules.remove("agents/_run_impl.py")
        modules.extend("agents/run_internal/" + name + ".py" for name in
                       ("run_loop", "guardrails", "tool_execution", "agent_runner_helpers"))
    for module in modules:
        path = source_base / module
        if not path.is_file(): missing.append(module); continue
        actual = sha(path)
        if expected is not None and actual != expected.get(module): raise ValueError("sdk_wheel_source_drift")
        inputs[str(path.relative_to(ROOT))] = actual
        views.append(source_view(path, f"__sdk__/{framework}/{version or 'unresolved-reference'}/{module}"))
    reference = refs["contracts"][framework]
    reference_versions = set(reference.get("framework_versions", {}).values())
    if version and version not in reference_versions:
        reference = {"facts": [], "reason": "existing probe/source fact version differs from selected application dependency"}
    return {"source_views": views, "reference_contract": reference,
            "audit_framework": framework, "original_framework": selection["original_framework"],
            "source_selected_reference_version": version,
            "version_resolution_status": selection["version_resolution_status"],
            "missing_sdk_modules": missing, "exact_runtime_observed": False,
            "version_evidence": {k: selection[k] for k in ("dependency_declarations", "lock_evidence", "notes")},
            "source_reference_note": "Frozen SDK source and bounded owned probes, not application behavior. Exact dependency pin is a source declaration, not observed runtime. When the application version is unresolved, reference snapshots are illustrative only; a version-dependent witness/exclusion requires a justified compatibility argument, otherwise record a critical gap. Do not transfer facts from incompatible versions."}


def prepare(admission_path, out, supplement_path=None, eligibility_path=None):
    admission = read(admission_path)
    verify_admission(admission)
    if not admission["contracts"]: raise ValueError("nonempty_frozen_admission_required")
    if eligibility_path is None: raise ValueError("fixed_scope_eligibility_freeze_required")
    eligibility = read(eligibility_path)
    if eligibility["admission_sha256"] != sha(admission_path): raise ValueError("eligibility_admission_drift")
    eligible_ids = set(eligibility["eligible_contract_ids"])
    excluded_ids = {cid for row in eligibility["exclusions"] for cid in row["contract_ids"]}
    if eligible_ids & excluded_ids or eligible_ids | excluded_ids != {c["contract_id"] for c in admission["contracts"]}:
        raise ValueError("eligibility_partition")
    out.mkdir(parents=True, exist_ok=False)
    grouped = defaultdict(list)
    for c in admission["contracts"]:
        if c["contract_id"] in eligible_ids: grouped[c["repository"]].append(c)
    refs = read(SDK_REFERENCE)
    supplement = read(supplement_path) if supplement_path else {"repositories": {}, "inputs": {}}
    sdk_review = read(SDK_REVIEW)
    if sdk_review["admission_sha256"] != sha(admission_path): raise ValueError("sdk_review_admission_drift")
    selections = {r["repository"]: r for r in sdk_review["repositories"]}
    selected_model = MODEL_ID.read_text().strip()
    policy = read(MODEL_POLICY)
    if selected_model != "GLM-5.3-Flash" or policy["allowed_external_model_ids"] != [selected_model]:
        raise ValueError("external_model_policy_requires_GLM-5.3-Flash")
    inputs = {str(admission_path.relative_to(ROOT)): sha(admission_path), str(SDK_REFERENCE.relative_to(ROOT)): sha(SDK_REFERENCE),
              str(SDK_REVIEW.relative_to(ROOT)): sha(SDK_REVIEW), str(eligibility_path.relative_to(ROOT)): sha(eligibility_path)}
    inputs[str(MODEL_ID.relative_to(ROOT))] = sha(MODEL_ID)
    inputs[str(MODEL_POLICY.relative_to(ROOT))] = sha(MODEL_POLICY)
    inputs[str(CALL_STATE.relative_to(ROOT))] = sha(CALL_STATE)
    for path, expected in eligibility["inputs"].items():
        if sha(ROOT / path) != expected: raise ValueError("eligibility_input_drift")
        inputs[path] = expected
    if supplement_path:
        inputs[str(supplement_path.relative_to(ROOT))] = sha(supplement_path)
        for path, expected in supplement["inputs"].items():
            if sha(ROOT / path) != expected: raise ValueError("context_supplement_input_drift")
            inputs[path] = expected
    for path, expected in sdk_review["inputs_sha256"].items():
        # Review-time implementation hashes describe the pre-fix runner.
        # Source/admission identities remain mandatory; current code is frozen below.
        if not path.startswith("experiments/"): continue
        if sha(ROOT / path) != expected: raise ValueError("sdk_review_input_drift")
        inputs[path] = expected
    jobs = []
    for name, contracts in sorted(grouped.items()):
        key = hashlib.sha256(name.encode()).hexdigest()[:24]
        inventory_path = GIT / "repositories" / key / "RESULT.json"
        inventory = read(inventory_path); inputs[str(inventory_path.relative_to(ROOT))] = sha(inventory_path)
        selection = selections[name]
        extra = supplement["repositories"].get(name, {})
        if selection["source_commit"] != inventory["commit"] or not {c["contract_id"] for c in contracts} <= set(selection["contract_ids"]):
            raise ValueError("sdk_review_scope_mismatch")
        exported = {f["path"]: f for f in inventory["exported"]}
        for contract in contracts:
            if contract["source_commit"] != inventory["commit"]:
                raise ValueError("admission_commit_mismatch")
            for evidence in contract["admission_evidence"]:
                if evidence["source_sha256"] != exported.get(evidence["path"], {}).get("sha256"):
                    raise ValueError("admission_source_sha_mismatch")
        context_path = CONTEXTS / "repositories" / (key + ".json")
        context = read(context_path); inputs[str(context_path.relative_to(ROOT))] = sha(context_path)
        required = {e["path"] for c in contracts for e in c["admission_evidence"]}
        for evidence in selection["dependency_declarations"] + selection["lock_evidence"] + selection["import_evidence"]:
            if evidence["source_sha256"] != exported.get(evidence["path"], {}).get("sha256"):
                raise ValueError("sdk_selection_evidence_drift")
            required.add(evidence["path"])
        selected = set(required)
        selected.update(extra.get("application_paths", []))
        for component in context.get("components", []):
            if set(component) & required: selected.update(component)
        if not any(p.endswith(".py") for p in selected): selected.update(context["selected_python"])
        for file in inventory["exported"]:
            p = Path(file["path"])
            scope_root = Path(selection["source_scope_root"])
            in_scope = scope_root == Path(".") or p.is_relative_to(scope_root)
            if in_scope and (p.name in {"pyproject.toml", "requirements.txt", "setup.cfg", "uv.lock", "poetry.lock", "Pipfile.lock"} or p.suffix in {".yaml", ".yml"}):
                selected.add(file["path"])
        views = []
        for file in inventory["exported"]:
            if file["path"] not in selected: continue
            path = GIT / file["destination"]
            if sha(path) != file["sha256"]: raise ValueError("contract_source_identity_drift")
            inputs[str(path.relative_to(ROOT))] = file["sha256"]
            views.append(source_view(path, file["path"]))
        if not required <= {v["path"] for v in views}: raise ValueError("admitted_evidence_not_supplied")
        framework = selection["audit_framework"]
        sdk = sdk_context(selection, refs, inputs)
        if extra.get("replace_sdk_reference", False):
            sdk.update(source_views=[], reference_contract={"facts": [], "reason": "Original reference conflicts with source dependencies."},
                       source_selected_reference_version=None, version_resolution_status="compatible_candidate_not_declared_pin")
        for file in extra.get("additional_sources", []):
            path = ROOT / file["source_file"]
            if sha(path) != file["sha256"]: raise ValueError("context_supplement_source_drift")
            inputs[file["source_file"]] = file["sha256"]
            views.append(source_view(path, file["alias"], file.get("include_symbols")))
        if extra.get("environment_notes"):
            sdk["supplemental_environment_notes"] = extra["environment_notes"]
        sdk["source_reference_note"] = (
            "This task fixes the explicitly selected source/API-compatible SDK profile as its analysis environment. "
            "It does not identify the deployed installation or claim results across all allowed versions. "
            "Verify critical constructor, dependency and path bindings within this profile; a real missing implementation or incompatibility remains unknown. "
            "Owned SDK facts remain limited to their stated versions and scenarios.")
        reference_version = extra.get("selected_reference_sdk") or selection["source_selected_reference_version"] or selection["existing_source_view_version"]
        environment = {"scope": "fixed_compatible_reference", "framework": framework,
            "selected_reference_sdk": reference_version, "selection_origin": "project_declared" if selection["source_selected_reference_version"] else "source_api_compatible_reference",
            "actual_deployment_verified": False, "range_wide_conclusion": False,
            "source_constraint_note": "Respect explicit source dependency constraints; unresolved critical API compatibility stays unknown. Configuration and ordinary IO assumptions are explicit analysis conditions."}
        payload = {"analysis_environment": environment, "analysis_assumptions": ANALYSIS_ASSUMPTIONS, "framework_reference": sdk, "repositories": [{"repository": name,
            "commit": inventory["commit"], "tree": inventory["tree"], "contracts": contracts,
            "sources": views + sdk["source_views"], "source_inventory": [f["path"] for f in inventory["tree_inventory"]],
            "unread_paths": [f["path"] for f in inventory["tree_inventory"] if f["path"] not in selected],
            "context_selection": "complete local import components containing frozen policy/operation evidence; version/config files retained",
            "dependency_closure_proven": False}], "role": "analyst"}
        # SDK text is supplied once in sources; the independent reference keeps
        # its small identities, limits and facts without duplicating every byte.
        payload["framework_reference"] = {k: v for k, v in sdk.items() if k != "source_views"}
        job_id = "repository-" + key
        path = out / "tasks" / (job_id + ".json"); write_new(path, payload)
        jobs.append({"job_id": job_id, "task": str(path.relative_to(out)), "sha256": sha(path),
                     "repository": name, "audit_framework": framework, "bytes": path.stat().st_size,
                     "sdk_version_status": selection["version_resolution_status"],
                     "contract_ids": [c["contract_id"] for c in contracts]})
    code = sorted({Path(__file__).resolve(), ROOT / "tools/run_p0_source_recovery.py", *sorted((ROOT / "src/guardcontract").rglob("*.py")),
                   *(ROOT / p for p in inputs if p.startswith(("tools/", "src/")) and p.endswith(".py"))})
    for path in code:
        relative = str(path.relative_to(ROOT)); inputs[relative] = sha(path)
        target = out / "code" / relative; target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(path, target)
    plan = {"schema_version": "p0-protection-obligation-audit-plan-4", "admission_path": str(admission_path.relative_to(ROOT)),
            "admission_sha256": sha(admission_path), "jobs": jobs, "inputs": inputs,
            "model": selected_model, "max_tokens": 16000, "max_total_tokens_stop_before_next_call": 400000,
            "maximum_task_bytes": 1800000,
            "timeout_seconds": 300, "roles": ["analyst", "critic"], "max_calls": 2 * len(jobs),
            "run_tokens_stop_before_next_call": min(12000000, 800000 * len(jobs)),
            "token_budget_scope": "shared_run_gate_plus_legacy_per_call_transport_threshold",
            "payload_ensure_ascii": False, "analysis_assumptions": ANALYSIS_ASSUMPTIONS,
            "environment_quantifier_version": 3, "analysis_scope": "fixed_compatible_reference",
            "eligibility_path": str(eligibility_path.relative_to(ROOT)), "eligibility_sha256": sha(eligibility_path),
            "eligible_contract_ids": sorted(eligible_ids), "exclusions": eligibility["exclusions"],
            "source_admitted_contracts": len(admission["contracts"]),
            "applicable_contracts": len(eligible_ids), "original_ledger_units": 772,
            "full_772_admission_complete": admission["full_772_admission_complete"],
            "sdk_review_pre_fix_code_sha256": {p: h for p, h in sdk_review["inputs_sha256"].items() if not p.startswith("experiments/")},
            "assumptions": ["untrusted well-formed model/tool plans", "ordinary successful IO is feasible when source/config permit it", "frozen SDK references used only within compatible versions"],
            "application_behavior_labels_read": False, "owned_sdk_probe_facts_used": True,
            "formal_independent_evaluation": False, "legacy_actual_deny_head_redefined": False}
    plan["external_model_calls_enabled_at_prepare"] = read(CALL_STATE).get("enabled") is True
    write_new(out / "RUN_PLAN.json", plan)
    print(json.dumps({"source_contracts": len(admission["contracts"]), "eligible": len(eligible_ids), "excluded": len(excluded_ids), "jobs": len(jobs), "max_calls": plan["max_calls"]}), flush=True)


def verify(plan):
    for path, expected in plan["inputs"].items():
        if sha(ROOT / path) != expected: raise ValueError("obligation_input_drift:" + path)


def execute(out, workers):
    plan = read(out / "RUN_PLAN.json"); verify(plan)
    if "run_tokens_stop_before_next_call" not in plan:
        raise ValueError("explicit_run_token_budget_required_for_new_execution")
    budget = SharedReviewBudget(max_calls=plan["max_calls"], stop_before_tokens=plan["run_tokens_stop_before_next_call"])
    plan_sha256 = sha(out / "RUN_PLAN.json")
    run = out / "runs"; run.mkdir(exist_ok=False)
    key = (Path.home() / ".config/guardcontract/paratera.key").read_text().strip()
    def job(item):
        path = out / item["task"]
        if sha(path) != item["sha256"]: raise ValueError("obligation_task_drift")
        if path.stat().st_size > plan.get("maximum_task_bytes", 1800000):
            raise ValueError("obligation_context_budget")
        payload = read(path); reviews = []; total = 0; known = True
        for role in plan["roles"]:
            value = {**payload, "role": role}
            directory = run / item["job_id"] / role
            spec = spec_for(value)
            if not budget.start():
                row = {"cell_id": directory.name, "role": role, "execution_state": "missing", "review": None,
                       "calls": [], "fault_domain": "budget", "error_code": "shared_run_budget_or_unknown_usage"}
                used, usage_known = 0, True
                write_new(directory / "ACTUAL_INPUT.json", value); write_new(directory / "ACTUAL_SPEC.json", spec)
                write_new(directory / "RESULT.json", row)
            else:
                used, usage_known = 0, False
                try:
                    row, used, usage_known = call_model(value, spec, role, directory, plan, key,
                        system=SYSTEM, decoder=decode, transport_factory=ScopedReviewTransport,
                        payload_ensure_ascii=plan.get("payload_ensure_ascii", True))
                finally:
                    budget.finish(used, usage_known)
            reviews.append(row); total += used; known &= usage_known
        result = {"job_id": item["job_id"], "reviews": reviews, "calls": sum(len(r["calls"]) for r in reviews),
                  "tokens": total if known else None, "usage_known": known}
        write_new(run / item["job_id"] / "RESULT.json", result)
        print(json.dumps({"job_id": item["job_id"], "states": [r["execution_state"] for r in reviews], "tokens": result["tokens"]}), flush=True)
        return result
    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(job, item): item for item in plan["jobs"]}
        for future in as_completed(futures):
            try: results.append(future.result())
            except Exception as exc:
                item = futures[future]; directory = run / item["job_id"]
                reviews = [read(p) for p in directory.glob("*/RESULT.json")]
                failure = {"job_id": item["job_id"], "reviews": reviews,
                           "calls": sum(len(r.get("calls", [])) for r in reviews), "tokens": None,
                           "usage_known": False, "error_code": type(exc).__name__}
                if not (directory / "RESULT.json").exists(): write_new(directory / "RESULT.json", failure)
                results.append(failure)
    integrity_errors = []
    if sha(out / "RUN_PLAN.json") != plan_sha256: integrity_errors.append("obligation_plan_changed_during_run")
    try: verify(plan)
    except (OSError, ValueError) as exc: integrity_errors.append(str(exc))
    states = Counter(r["execution_state"] for job in results for r in job["reviews"])
    roles_complete = states["completed"] == len(plan["roles"]) * len(plan["jobs"])
    write_new(out / "RUN_MANIFEST.json", {"plan_sha256": plan_sha256,
        "jobs": {r["job_id"]: sha(run / r["job_id"] / "RESULT.json") for r in results},
        "artifacts": {str(p.relative_to(out)): sha(p) for p in sorted(run.rglob("*.json"))},
        "actual_model_calls": sum(r["calls"] for r in results),
        "total_tokens": sum(r["tokens"] for r in results) if all(r["usage_known"] for r in results) else None,
        "execution_health": "error" if integrity_errors else "completed" if roles_complete else "partial",
        "role_execution_states": dict(states),
        "shared_run_budget": budget.snapshot(),
        "scientific_outcome": "unscored" if integrity_errors else "development_source_hypotheses",
        "integrity_errors": integrity_errors,
        "application_behavior_labels_read": False})


def collect(out):
    plan = read(out / "RUN_PLAN.json")
    manifest = read(out / "RUN_MANIFEST.json"); admission = read(ROOT / plan["admission_path"])
    if manifest["plan_sha256"] != sha(out / "RUN_PLAN.json"):
        raise ValueError("obligation_manifest_plan_drift")
    if plan["admission_sha256"] != sha(ROOT / plan["admission_path"]):
        raise ValueError("obligation_admission_drift")
    verify_admission(admission)
    for path, expected in manifest["artifacts"].items():
        if sha(out / path) != expected: raise ValueError("obligation_artifact_drift")
    integrity_errors = list(manifest["integrity_errors"])
    try: verify(plan)
    except (OSError, ValueError) as exc: integrity_errors.append(str(exc))
    reviews = {}
    for job in plan["jobs"]:
        if sha(out / job["task"]) != job["sha256"]: raise ValueError("obligation_task_drift")
        payload = read(out / job["task"])
        path = out / "runs" / job["job_id"] / "RESULT.json"
        if sha(path) != manifest["jobs"][job["job_id"]]: raise ValueError("obligation_result_drift")
        for row in read(path)["reviews"]:
            if row["role"] not in plan["roles"]: raise ValueError("obligation_result_role")
            expected = spec_for({**payload, "role": row["role"]})
            if row["execution_state"] == "completed" and not integrity_errors:
                if row["review"]["payload_sha256"] != expected["payload_sha256"] or row["review"]["role"] != row["role"]:
                    raise ValueError("obligation_review_context_drift")
                if set(row["review"]["contracts"]) != set(job["contract_ids"]): raise ValueError("obligation_review_inventory")
                for cid, value in row["review"]["contracts"].items():
                    if (cid, row["role"]) in reviews: raise ValueError("obligation_duplicate_review")
                    reviews[(cid, row["role"])] = value
    selected_contracts = [c for c in admission["contracts"] if c["contract_id"] in plan["eligible_contract_ids"]]
    rows = [merge(c, reviews.get((c["contract_id"], "analyst")), reviews.get((c["contract_id"], "critic"))) for c in selected_contracts]
    counts = summarize(rows, [c["contract_id"] for c in selected_contracts])
    parent_rows, parent_counts = parent_summary(admission, rows, plan["exclusions"])
    by_contract = {c["contract_id"]: c for c in admission["contracts"]}
    strata = {}
    audit_frameworks = {cid: job["audit_framework"] for job in plan["jobs"] for cid in job["contract_ids"]}
    for field in ("framework", "audit_framework", "effect_stratum", "source_family", "denial_basis"):
        groups = defaultdict(list)
        for row in rows:
            if field == "denial_basis":
                bases = {r.get("denial_basis", "unknown") for r in row["reviews"].values() if r}
                name = next(iter(bases)) if len(bases) == 1 else "unresolved_or_disagreed"
            elif field == "audit_framework": name = audit_frameworks[row["contract_id"]]
            else: name = by_contract[row["contract_id"]][field]
            groups[name].append(row)
        strata[field] = {name: summarize(group, [r["contract_id"] for r in group]) for name, group in groups.items()}
    result = {"schema_version": "p0-protection-obligation-audit-result-4", "counts": counts,
              "analysis_scope": plan["analysis_scope"], "source_admitted_contracts": plan["source_admitted_contracts"],
              "exclusions": plan["exclusions"], "excluded_contracts": sum(len(r["contract_ids"]) for r in plan["exclusions"]),
              "eligible_parent_counts": parent_counts, "strata": strata, "integrity_errors": integrity_errors,
              "rows": rows, "ledger": parent_rows, "model_calls": manifest["actual_model_calls"], "total_tokens": manifest["total_tokens"],
              "p0_complete": False, "full_772_admission_complete": plan["full_772_admission_complete"],
              "legacy_actual_deny_head_redefined": False, "application_behavior_labels_read": False,
              "claim_boundary": "Development source hypotheses on independently admitted pilot contracts. No behavior GT, P/R, complete-corpus coverage or strong-acceptance claim."}
    write_new(out / "RESULT.json", result)
    print(json.dumps({"counts": counts, "eligible_parent_counts": result["eligible_parent_counts"], "model_calls": result["model_calls"], "tokens": result["total_tokens"]}), flush=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__); p.add_argument("stage", choices=["prepare", "run", "collect"])
    p.add_argument("--out", type=Path, required=True); p.add_argument("--admission", type=Path)
    p.add_argument("--supplement", type=Path)
    p.add_argument("--eligibility", type=Path)
    p.add_argument("--workers", type=int, choices=[1, 2, 3, 4], default=2); a = p.parse_args()
    if a.stage == "prepare": prepare(a.admission.resolve(), a.out.resolve(), a.supplement.resolve() if a.supplement else None, a.eligibility.resolve() if a.eligibility else None)
    elif a.stage == "run": execute(a.out.resolve(), a.workers)
    else: collect(a.out.resolve())
