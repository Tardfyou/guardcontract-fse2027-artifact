"""Reusable certificate pair review over the frozen review executor."""
from guardcontract.pipeline.review_execution import call_model, write_new
from guardcontract.backends.recorded import RecordedTransport
import hashlib
import json
import ast


def enclosing_callable_context(payload, spec, source, helper, system):
    """Preserve lexical conditions surrounding snippets; do not infer reachability."""
    sources = {"app.py": source, "deferred_effects.py": helper}
    scopes = {}
    for path, body in sources.items():
        if body is not None:
            scopes[path] = [(min([node.lineno, *(d.lineno for d in node.decorator_list)]), node.end_lineno)
                            for node in ast.walk(ast.parse(body))
                            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    evidence, aliases, by_span = {}, {}, {}
    for alias, item in payload["evidence"].items():
        if item.get("path") not in sources:
            evidence[alias] = item
            aliases[alias] = alias
            continue
        path, start, end = item["path"], item["start_line"], item["end_line"]
        enclosing = [(a, b) for a, b in scopes[path] if a <= start <= end <= b]
        if enclosing:
            start, end = max(enclosing, key=lambda span: span[1] - span[0])
        key = (path, start, end)
        if key in by_span:
            aliases[alias] = by_span[key]
            continue
        content = "".join(sources[path].splitlines(keepends=True)[start - 1:end])
        evidence[alias] = {**item, "start_line": start, "end_line": end, "content": content,
                           "content_sha256": hashlib.sha256(content.encode()).hexdigest()}
        aliases[alias] = alias
        by_span[key] = alias
    payload = {**payload, "evidence": evidence}
    material = {key: value for key, value in payload.items() if key != "input_id"}
    payload["input_id"] = "context-review:" + hashlib.sha256(json.dumps(
        {"system": system, "payload": material}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:24]
    spec = {**spec, "input_id": payload["input_id"], "evidence": evidence,
            "requirements": {cid: sorted({aliases[alias] for alias in required}) for cid, required in spec["requirements"].items()},
            "model_input_sha256": hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            "enclosing_callable_context": True, "semantic_completeness_proven": False}
    return payload, spec


def verify_certificate_sources(certificate, source, helper, sdk_contract):
    """Bind a certificate to supplied bytes before allocating a model call."""
    sha = lambda text: hashlib.sha256(text.encode()).hexdigest()
    source_hash = sha(source)
    expected = [certificate[key] for key in ("source_sha256", "app_source_sha256") if key in certificate]
    if not expected or any(value != source_hash for value in expected):
        raise ValueError("certificate_application_source_mismatch")
    if "helper_source_sha256" in certificate and certificate["helper_source_sha256"] != sha(helper):
        raise ValueError("certificate_helper_source_mismatch")
    sdk_hash = hashlib.sha256(json.dumps({k: v for k, v in sdk_contract.items() if k != "contract_sha256"},
                                         sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if sdk_contract.get("contract_sha256") != sdk_hash or certificate.get("sdk_contract_sha256") != sdk_hash:
        raise ValueError("certificate_sdk_contract_mismatch")
    sources = {"app.py": source, certificate.get("helper_path", "deferred_effects.py"): helper}
    def visit(value):
        if isinstance(value, dict):
            if {"path", "source_sha256", "start_line", "end_line"} <= value.keys():
                body = sources.get(value["path"])
                start, end = value["start_line"], value["end_line"]
                if (body is None or value["source_sha256"] != sha(body)
                        or type(start) is not int or type(end) is not int
                        or not 1 <= start <= end <= len(body.splitlines())):
                    raise ValueError("certificate_source_reference_mismatch")
            for item in value.values():
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)
    visit(certificate)
    return {"application_sha256": source_hash, "sdk_contract_sha256": sdk_hash,
            "source_binding_verified": True, "claim_semantics_verified": False}


def prepare_review_input(certificate, source, helper, sdk_contract, payload, spec, system, *, include_context=True):
    """Authenticate and contextualize either atomic claims or typed fields."""
    binding = verify_certificate_sources(certificate, source, helper, sdk_contract)
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if (spec.get("model_input_sha256") != digest or spec.get("input_id") != payload.get("input_id")
            or spec.get("evidence") != payload.get("evidence")
            or spec.get("role") != payload.get("role")
            or spec.get("repository_id") != payload.get("repository_id")):
        raise ValueError("review_input_identity_mismatch")
    sources = {"app.py": source, certificate.get("helper_path", "deferred_effects.py"): helper}
    for item in payload["evidence"].values():
        if item.get("kind") == "sdk_contract":
            fields = ("contract_sha256", "facts", "limits", "framework_versions")
            if any(item.get(field) != sdk_contract.get(field) for field in fields):
                raise ValueError("review_sdk_evidence_mismatch")
            continue
        body = sources.get(item.get("path"))
        start, end = item.get("start_line"), item.get("end_line")
        if (body is None or type(start) is not int or type(end) is not int
                or not 1 <= start <= end <= len(body.splitlines())):
            raise ValueError("review_source_evidence_range")
        content = "".join(body.splitlines(keepends=True)[start - 1:end])
        if (item.get("source_sha256") != hashlib.sha256(body.encode()).hexdigest()
                or item.get("content") != content
                or item.get("content_sha256") != hashlib.sha256(content.encode()).hexdigest()):
            raise ValueError("review_source_evidence_mismatch")
    if any(any(alias not in payload["evidence"] for alias in required)
           for required in spec["requirements"].values()):
        raise ValueError("review_evidence_requirement_mismatch")
    uncovered = sorted(name for name, required in spec["requirements"].items() if not required)
    if include_context:
        payload, spec = enclosing_callable_context(payload, spec, source, helper, system)
    return payload, {**spec, "source_binding": binding, "evidence_identity_verified": True,
                     "uncovered_requirements": uncovered, "evidence_requirements_complete": not uncovered,
                     "semantic_completeness_proven": False}


def scoped_unit_from_certificate(certificate, source, helper, sdk_contract):
    """Name the callback separately from its policy helper, without issue labels."""
    from guardcontract.evidence.source_references import function_spans

    verify_certificate_sources(certificate, source, helper, sdk_contract)
    sources = {"app.py": source, certificate.get("helper_path", "deferred_effects.py"): helper}
    indexes = {path: function_spans(body) for path, body in sources.items() if body is not None}
    def reference(row):
        result = {key: row[key] for key in ("path", "start_line", "end_line", "source_sha256")}
        candidates = [(end - start, symbol) for symbol, spans in indexes[row["path"]].items()
                      for start, end in spans if start <= row["start_line"] <= row["end_line"] <= end]
        if candidates:
            width = min(size for size, _ in candidates)
            symbols = {symbol for size, symbol in candidates if size == width}
            if len(symbols) != 1:
                raise ValueError("ambiguous_reference_symbol")
            result["enclosing_symbol"] = next(iter(symbols))
        return result
    callbacks = {}
    for path in certificate["paths"]:
        for event in path["events"]:
            if event["kind"] == "applicable_policy_guard":
                ref = reference(event)
                callbacks[json.dumps(ref, sort_keys=True)] = ref
    if len(callbacks) > 1:
        raise ValueError("multiple_guard_instances_require_explicit_unit")
    decision = reference(certificate["guard"])
    return {
        "invocation_scope": "The single-request invocation represented by the supplied source and bounded SDK facts; consider feasible ALLOW and DENY executions.",
        "guard_reference": next(iter(callbacks.values())) if callbacks else decision,
        "guard_reference_origin": "explicit_callback_event" if callbacks else "policy_decision_reference",
        "policy_decision_reference": decision,
        "effect_reference": reference(certificate["sink"]),
        "request_references": [reference(row) for row in certificate["review_evidence"]["request_binding"]],
        "resource_scope": "The resource used at effect_reference for the originating request; use unknown if the source does not bind it.",
        "operation": "The protected write at effect_reference",
        "identity_boundary": "Symbols identify source code, not registration or policy applicability. A policy helper and its calling callback are distinct code entities.",
    }


def certificate_agreement(review, spec):
    controls = set(spec.get("negative_control_claim_ids", []))
    observed = {c["claim_id"]: c["verdict"] for c in (review or {}).get("claims", [])}
    rows = [{"claim_id": cid, "expected_from_certificate": "contradicted" if cid in controls else "supported",
             "observed": observed.get(cid, "missing"), "negative_control": cid in controls}
            for cid in spec["claim_ids"]]
    for row in rows:
        row["agrees"] = row["observed"] == row["expected_from_certificate"]
    return {"claims": rows, "agreement": sum(r["agrees"] for r in rows), "denominator": len(rows),
            "negative_controls_agree": sum(r["agrees"] for r in rows if r["negative_control"]),
            "negative_controls": len(controls), "independent_semantic_verification": False}


def configured_thinking_transport(factory, thinking):
    """Record the actual request after applying an explicit experimental option."""
    if thinking not in {"enabled", "disabled"}:
        raise ValueError("invalid_certificate_thinking_mode")
    class Transport:
        def __init__(self, *args, **kwargs):
            self.inner = factory(*args, **kwargs)
        def __getattr__(self, name):
            return getattr(self.inner, name)
        def __call__(self, url, headers, body, timeout):
            request = json.loads(body)
            request["thinking"] = {"type": thinking}
            return self.inner(url, headers, json.dumps(request, separators=(",", ":")).encode(), timeout)
    return Transport


def blind_claim_ids(payload, spec, system):
    def digest(value):
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    aliases = {cid: "c" + digest([spec["repository_id"], cid])[:16] for cid in spec["claim_ids"]}
    claims = sorted(({**row, "claim_id": aliases[row["claim_id"]]} for row in payload["claims"]),
                    key=lambda row: row["claim_id"])
    payload = {k: v for k, v in payload.items() if k != "input_id"}
    payload["claims"] = claims
    payload["input_id"] = "blind-review:" + digest({"system": system, "payload": payload})[:24]
    spec = {**spec, "input_id": payload["input_id"], "model_input_sha256": digest(payload),
            "claim_ids": [row["claim_id"] for row in claims],
            "requirements": {aliases[cid]: value for cid, value in spec["requirements"].items()},
            "negative_control_claim_ids": [aliases[cid] for cid in spec.get("negative_control_claim_ids", [])],
            "private_claim_id_map": {alias: cid for cid, alias in aliases.items()}}
    return payload, spec


def explicit_event_claims(payload, spec, certificate, system):
    """Disambiguate co-occurrence from the temporal order of the verdict."""
    occurs = certificate.get("issue_prediction")
    if type(occurs) is not bool:
        raise ValueError("event_claims_require_boolean_issue_prediction")
    statements = {
        "issue": ("In the configured DENY scenario, the applicable guard reports DENY and the selected protected effect executes at least once in the same run; the effect may occur before or after the verdict."
                  if occurs else "In the configured DENY scenario, the applicable guard reports DENY and the selected protected effect does not execute in that run."),
        "control-opposite-issue": ("In the configured DENY scenario, the applicable guard reports DENY and the selected protected effect does not execute in that run."
                                   if occurs else "In the configured DENY scenario, the applicable guard reports DENY and the selected protected effect executes at least once in the same run; the effect may occur before or after the verdict."),
    }
    deny = next(p for p in certificate["paths"] if p["decision"] == "DENY")
    statements["deny-order"] = "The configured DENY path has the following event order: " + " -> ".join(e["kind"] for e in deny["events"]) + "."
    claims = [{**c, "statement": statements.get(c["claim_id"], c["statement"])} for c in payload["claims"]]
    payload = {**payload, "claims": claims}
    material = {k: v for k, v in payload.items() if k != "input_id"}
    payload["input_id"] = "event-review:" + hashlib.sha256(json.dumps({"system": system, "payload": material}, sort_keys=True).encode()).hexdigest()[:24]
    spec = {**spec, "input_id": payload["input_id"], "model_input_sha256": hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
    return payload, spec

def review_certificate_pair(certificate, source, helper, sdk_contract, *, repository_id,
                            output, plan, key, task_builder, decoder, system,
                            transport_factory=RecordedTransport):
    """Review fixed certificate assertions with the existing recorded transport."""
    if output.exists():
        raise ValueError("certificate_review_output_exists")
    source_binding = verify_certificate_sources(certificate, source, helper, sdk_contract)
    plan = {"enclosing_callable_context": True, **plan}
    if "thinking" in plan:
        transport_factory = configured_thinking_transport(transport_factory, plan["thinking"])
    if plan.get("max_calls") != 2 or type(plan.get("max_total_tokens_stop_before_next_call")) is not int or plan["max_total_tokens_stop_before_next_call"] < 1:
        raise ValueError("certificate_pair_budget")
    output.mkdir(parents=True)
    write_new(output / "PLAN.json", {**plan, "repository_id": repository_id,
              "certificate": certificate, "sdk_contract": sdk_contract, "source_binding": source_binding})
    records, total, known, previous = [], 0, True, None
    for role in ("analyst", "critic"):
        if not known or total >= plan["max_total_tokens_stop_before_next_call"] or (role == "critic" and previous is None):
            records.append({"role": role, "execution_state": "missing", "review": None,
                            "calls": [], "error_code": "prior_failure_or_budget_stop"})
            break
        payload, spec = task_builder(certificate, source, helper, sdk_contract,
                                     repository_id=repository_id, role=role, previous=previous)
        payload, spec = prepare_review_input(certificate, source, helper, sdk_contract,
            payload, spec, system, include_context=plan["enclosing_callable_context"])
        if plan.get("explicit_event_claims", False):
            payload, spec = explicit_event_claims(payload, spec, certificate, system)
        if plan.get("blind_claim_ids", False):
            payload, spec = blind_claim_ids(payload, spec, system)
        remaining_plan = {**plan, "max_total_tokens_stop_before_next_call": plan["max_total_tokens_stop_before_next_call"] - total}
        row, used, usage_known = call_model(payload, spec, role, output / role,
            remaining_plan, key, system=system, decoder=decoder, transport_factory=transport_factory)
        row["certificate_agreement"] = certificate_agreement(row.get("review"), spec)
        records.append(row)
        total += used
        known = known and usage_known
        previous = row.get("review")
    result = {"records": records, "actual_calls": sum(len(r["calls"]) for r in records),
              "actual_total_tokens": total if known else None, "usage_known": known,
              "goal_completion_proven": False,
              "claim_boundary": "Certificate assertion review only; not issue accuracy or independent runtime verification."}
    write_new(output / "RESULT.json", result)
    return result
