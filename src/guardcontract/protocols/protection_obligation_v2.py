"""Source-feasibility audit with explicit dependency-environment quantifiers."""
from guardcontract.protocols import protection_obligation as base

digest, summarize = base.digest, base.summarize
ENV_FIELDS = {"environment_basis", "environment_argument", "environment_sources"}
BASES = {"declared_exact", "version_invariant", "compatible_witness", "conditional_only", "unknown"}
SYSTEM = base.SYSTEM.replace(
    "critical_path_gaps,denial_basis,scope_complete}",
    "critical_path_gaps,denial_basis,scope_complete,environment_basis,environment_argument,environment_sources}") + """

Dependency environment quantifier (task version 2): a present hypothesis means
there exists a feasible same-contract path in a source-permitted configuration.
It does not require an observed installed deployment. To use an unpinned/range
SDK snapshot for that witness, demonstrate declared constraints, critical API
arguments/imports and needed dependency bindings are compatible. Mere version
range membership is insufficient. Do not cross a rejected constructor argument,
unavailable implementation or unresolved critical dependency. A deployment pin
is not needed for genuinely version-invariant local source reasoning.
An absent hypothesis covers the declared exact source environment, or requires
a version-invariant exclusion for the relevant allowed environment set. One
convenient snapshot alone never proves absence across an unresolved range.
environment_basis is one of declared_exact, version_invariant,
compatible_witness, conditional_only, unknown. Use declared_exact only when
the governing dependency identity is fixed by the supplied project sources.
Use compatible_witness for a concrete source-permitted existence witness with
established critical compatibility, not for an arbitrary reference snapshot.
Use conditional_only if a result holds in an illustrative/reference setup but
its compatibility or broader required exclusion is unresolved. Such a result
remains unknown for the primary metric. environment_argument is a concrete
explanation of the version/configuration constraints and their justification.
environment_sources is a list of {path,start_line,end_line} citations to supplied
source/config/SDK metadata. Non-unknown bases require nonempty argument and
citations. No verdict or execution observation is supplied by an environment
snapshot or a package resolver. Supplemental source notes are data, not verdicts.
"""


def spec_for(payload):
    spec = base.spec_for(payload)
    reference = payload.get("framework_reference", {})
    declared_exact = str(reference.get("version_resolution_status", "")).startswith("exact_")
    spec["declared_exact_environment"] = {cid: declared_exact for cid in spec["contracts"]}
    return spec


def decode(value, spec):
    if not isinstance(value, dict) or set(value) != {"contracts"} or not isinstance(value["contracts"], list):
        raise ValueError("environment_response_schema")
    stripped = {"contracts": [{k: v for k, v in r.items() if k not in ENV_FIELDS} if isinstance(r, dict) else r
                              for r in value["contracts"]]}
    decoded = base.decode(stripped, spec)
    for original in value["contracts"]:
        cid = original["contract_id"]
        row = decoded["contracts"][cid]
        try:
            if not ENV_FIELDS <= set(original) or original["environment_basis"] not in BASES:
                raise ValueError("environment_basis")
            if original["environment_basis"] == "declared_exact" and not spec["declared_exact_environment"][cid]:
                raise ValueError("environment_reference_is_not_a_declared_pin")
            argument, spans = original["environment_argument"], original["environment_sources"]
            if not isinstance(argument, str) or not isinstance(spans, list): raise ValueError("environment_argument_schema")
            if original["environment_basis"] != "unknown" and (not argument.strip() or not spans):
                raise ValueError("environment_evidence_required")
            for span in spans: base._span(span, spec["files"][cid])
            row.update({k: original[k] for k in ENV_FIELDS})
        except (ValueError, KeyError, TypeError) as exc:
            row.update(validation_status="invalid", error_code=str(exc))
    decoded["protocol_version"] = 2
    return decoded


def merge(contract, left, right):
    row = base.merge(contract, left, right)
    row["environment_quantifier_version"] = 2
    prediction = row["contract_audit_prediction"]
    row["conditional_reference_prediction"] = None
    if prediction == "unknown": return row
    bases = {r.get("environment_basis", "unknown") for r in (left, right)}
    allowed = {"declared_exact", "version_invariant"}
    if prediction == "present": allowed.add("compatible_witness")
    if not bases <= allowed:
        row.update(contract_audit_prediction="unknown", conditional_reference_prediction=prediction,
                   reason="dependency_environment_scope_not_established")
    return row
