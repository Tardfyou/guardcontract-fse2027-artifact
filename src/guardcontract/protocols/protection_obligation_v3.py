"""User-selected audit of unchanged source in a frozen compatible SDK profile."""
from guardcontract.protocols import protection_obligation as base
from guardcontract.protocols import protection_obligation_v2 as env_protocol

digest, summarize = base.digest, base.summarize
SYSTEM = base.SYSTEM.replace(
    "critical_path_gaps,denial_basis,scope_complete}",
    "critical_path_gaps,denial_basis,scope_complete,environment_basis,environment_argument,environment_sources}") + """

Task version 3: audit the unchanged application source in the explicitly fixed
reference environment described by analysis_environment and supplied SDK source.
The user selected this reproducible scope. A project lock is respected; when no
lock exists, the explicitly selected source/API-compatible reference is the
analysis scope. Do not require evidence of the actual deployed installation or
exclude every other SDK version before deciding this bounded question. A result
does not claim safety or failure across an open dependency-version range.
Still verify critical imports, constructor arguments, types, parsing and binding
in the selected profile. A fixed reference is not itself proof of compatibility.
An actual API mismatch, missing critical implementation or binding stays unknown.
Do not change application code or assume the missing implementation works.

Use the exact frozen obligation and protected operation/resource. Do not replace
a broader delivery obligation with the narrower algorithm of its input checker.
Prefer source-explicit forbidden terms/states; avoid unsupported interpretations
of synonyms. A same-attempt rejection differs from a later accepted retry.
Before accepting any proposed path, check the actual executable entry, object
bindings after decorators, and fixed versus configurable inputs. A decorator
can replace a function name with a non-callable SDK tool object; calling that
object directly is not the SDK's tool-dispatch route. Do not introduce a new
entry argument where the shown driver hard-codes its input. Legal model outputs
remain variable under the declared source assumption. A quoted trigger phrase
is not, by itself, the semantic action forbidden by the contract. A refusal or
denied-status notification is not successful processing of the denied object.
The trace must link the actual SDK invocation route to the same protected commit.
Guard-signal reasoning is conditional on well-formed signals allowed by the
declared interface (such as reject/False/HTTP400); do not claim an external service
actually produced that signal. No live provider observation or real credential
is needed for source-counterfactual analysis under the stated legal IO assumption.
Do not assume a decision-model error solely to manufacture a witness: establish
the relevant source-permitted result domain and downstream behavior.

environment_basis is declared_exact, version_invariant, compatible_witness,
conditional_only, or unknown. declared_exact is
reserved for a governing project dependency lock/pin, as explicitly indicated
by framework_reference.version_resolution_status starting with exact_. A fixed
reference selected for this audit is not itself a project pin. For ordinary
Python-only reasoning without a project SDK lock, use version_invariant when
justified or compatible_witness for the explicitly fixed profile.
compatible_witness means the selected fixed
profile's critical source/API compatibility is established; it can support either
a witness or an exclusion WITHIN THAT PROFILE. conditional_only means a critical
compatibility/binding fact remains an assumption and does not count as known.
environment_argument explains the selected version/configuration and concrete
source justification; environment_sources is a list of {path,start_line,end_line}
citations to supplied code/config/SDK metadata. Known bases require nonempty
argument and citations. The actual deployed environment is not asserted.
"""


def spec_for(payload):
    spec = env_protocol.spec_for(payload)
    profile = payload.get("analysis_environment")
    if not isinstance(profile, dict) or profile.get("scope") != "fixed_compatible_reference":
        raise ValueError("fixed_analysis_environment_required")
    spec["analysis_environment"] = profile
    return spec


def decode(value, spec):
    result = env_protocol.decode(value, spec)
    for row in result["contracts"].values():
        row["analysis_environment"] = spec["analysis_environment"]
        row["analysis_environment_sha256"] = digest(spec["analysis_environment"])
    result["protocol_version"] = 3
    return result


def merge(contract, left, right):
    row = base.merge(contract, left, right)
    row.update(environment_quantifier_version=3, analysis_scope="fixed_compatible_reference",
               actual_deployment_verified=False, range_wide_conclusion=False,
               conditional_reference_prediction=None)
    predicted = row["contract_audit_prediction"]
    if predicted == "unknown": return row
    bases = {r.get("environment_basis", "unknown") for r in (left, right)}
    identities = {r.get("analysis_environment_sha256") for r in (left, right)}
    if (not bases <= {"declared_exact", "version_invariant", "compatible_witness"} or
            len(identities) != 1 or None in identities):
        row.update(contract_audit_prediction="unknown", conditional_reference_prediction=predicted,
                   reason="fixed_reference_critical_compatibility_or_identity_unresolved")
    else:
        row["analysis_environment"] = left["analysis_environment"]
    return row
