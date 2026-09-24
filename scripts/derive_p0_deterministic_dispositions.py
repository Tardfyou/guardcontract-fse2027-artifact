"""Disposition layer over recorded reviews, probe facts, and source anchors.

Computes contract dispositions from three evidence kinds, in this authority
order (Round156 release-gate design):

1. Deterministic probe facts (pinned-environment installability, repository
   entry importability, symbol existence) override everything: an
   uninstallable pinned environment or an entry that cannot import under the
   pinned references yields incompatibility_evidenced with the recorded
   error -- an environment disposition, not a safety or detection claim.
2. Two-role consensus facts from recorded reviews feed the semantic
   predicates; a role that degenerated (empty facts) simply contributes no
   consensus, it never blocks a deterministic fact.
3. Legacy mode can release labels from review facts. In ``--strict-witness``
   mode, review consensus and source ordering are candidates only: this legacy
   CLI has no complete mechanical path-witness or scoped-proof input, so they
   cannot release VP/CWS labels.

Everything reads recorded artifacts; no model calls; every disposition
carries its derivation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from run_p0_contract_audit import read, merge  # noqa: E402

FIELDS = ("same_contract_scope", "forbidden_condition_reachable",
          "protected_operation_reachable", "forbidden_commit_joint_reachable")

ENTRY_BREAKING = ("ImportError", "AttributeError", "NameError", "ModuleNotFoundError")


def probe_facts(row: dict) -> dict:
    facts = {"install_returncode": row.get("install_returncode")}
    entry = next((p for p in row.get("probes", []) if p["kind"] == "repo_entry_import"), None)
    if entry and entry.get("outcomes"):
        outcomes = entry["outcomes"]
        facts["entry_total"] = len(outcomes)
        facts["entry_ok"] = sum(1 for o in outcomes if o.get("ok"))
        facts["entry_errors"] = [o.get("error", "") for o in outcomes if not o.get("ok")]
    return facts


def disposition_for(row: dict, reviews: dict, contract: dict, wiring_fact: dict | None = None,
                    strict_witness: bool = False) -> dict:
    facts = probe_facts(row)
    facts_probe = facts
    derivation = []
    if facts.get("install_returncode") not in (0, None):
        derivation.append("pinned environment uninstallable on analysis host (recorded pip resolution failure)")
        return {"disposition": "incompatibility_evidenced",
                "kind": "environment_uninstallable",
                "derivation": derivation, "probe": facts}
    entry_errors = facts.get("entry_errors") or []
    entry_ok, entry_total = facts.get("entry_ok", 0), facts.get("entry_total", 0)
    pinned_names = {part.split("==")[0].strip().lower().replace("-", "_")
                    for part in row.get("sdk", "").split(";") if part.strip()}
    pinned_roots = pinned_names | {n.removeprefix("pydantic_ai").strip("_") for n in ()} | {"pydantic_ai" if "pydantic_ai" in pinned_names else ""}
    def missing_root(error: str) -> str:
        import re
        # "cannot import name 'X' from 'Y'": the failing root is Y (pinned pkg)
        m = re.search(r"from '([a-zA-Z0-9_.]+)'", error)
        if m:
            return m.group(1).split(".")[0]
        m = re.search(r"No module named '([a-zA-Z0-9_.]+)'", error)
        if m:
            return m.group(1).split(".")[0]
        for piece in error.split("'"):
            if piece and not piece.startswith("probe_mod"):
                return piece.split(".")[0]
        return ""
    if entry_total and entry_ok == 0 and all(any(k in e for k in ENTRY_BREAKING) for e in entry_errors):
        roots = {missing_root(e) for e in entry_errors}
        pinned_failures = sorted(r for r in roots
                                 if r in pinned_names or (r == "pydantic_ai" and "pydantic_ai_slim" in pinned_names)
                                 or (r == "agents" and "openai_agents" in pinned_names)
                                 or (r == "google" and "google_adk" in pinned_names))
        if pinned_failures:
            derivation.append("repository entry fails to import modules that ARE part of the pinned reference set: "
                              + ", ".join(pinned_failures))
            derivation.extend(entry_errors[:3])
            return {"disposition": "incompatibility_evidenced",
                    "kind": "entry_broken_under_pinned",
                    "derivation": derivation, "probe": facts}
        if pinned_failures:
            derivation.append("entry failures mix pinned-set breakage with unprofiled/intra-repo imports: "
                              + ", ".join(sorted(roots)))
        else:
            derivation.append("entry import failures reference modules outside the pinned set (probe profile "
                              "incomplete or intra-repo packages): " + ", ".join(sorted(roots)))
    # consensus facts from recorded reviews
    values = {role: (reviews.get(role) or {}).get("value") for role in ("analyst", "critic")}
    complete = all(values.get(r) and values[r].get("facts") for r in ("analyst", "critic"))
    if wiring_fact and wiring_fact.get("positions") in (["before"], ["after"]):
        # Release rule v2 (user-approved 2026-09-17): a decisive deterministic
        # ordering fact plus ONE complete substantive role review releases the
        # label when the role's facts agree with the ordering. The degenerate
        # role contributes nothing; it never blocks a code-anchored fact.
        # Prefer agreed consensus facts; fall back to the most complete single role.
        agreed = {}
        if complete:
            f1, f2 = values["analyst"]["facts"], values["critic"]["facts"]
            agreed = {k: v for k, v in ((k, f1.get(k) if f1.get(k) == f2.get(k) else None) for k in f1) if v is not None}
        if agreed:
            single = {"facts": agreed}
        else:
            single = next((values[r] for r in ("critic", "analyst")
                           if values.get(r) and values[r].get("facts")), None)
        if single and single.get("facts"):
            facts = single["facts"]
            semantics_ok = (facts.get("same_contract_scope") == "true"
                            and facts.get("protected_operation_reachable") == "true")
            if wiring_fact["positions"] == ["after"] and semantics_ok and facts.get("forbidden_condition_reachable") == "true":
                if strict_witness:
                    derivation.append("candidate: AFTER source ordering + model semantic facts; no mechanical shared-path witness")
                else:
                    derivation.append("release rule v2: deterministic AFTER ordering + complete single-role facts")
                    return {"disposition": "present", "kind": "verifier_anchored_release",
                            "derivation": derivation, "probe": facts_probe, "facts": facts, "wiring": wiring_fact}
            elif wiring_fact["positions"] == ["before"] and semantics_ok and facts.get("forbidden_commit_joint_reachable") == "false":
                if strict_witness:
                    derivation.append("candidate: BEFORE source ordering + model semantic facts; no scoped all-path proof")
                else:
                    derivation.append("release rule v2: deterministic BEFORE ordering + complete single-role facts, joint unreachable")
                    return {"disposition": "absent", "kind": "verifier_anchored_release",
                            "derivation": derivation, "probe": facts_probe, "facts": facts, "wiring": wiring_fact}
            else:
                derivation.append("release rule v2 evaluated but available facts do not match the deterministic ordering")
    # Single-role substantive review: under strict-witness (v3) this is a
    # candidate signal only -- a model review, however substantive, cannot
    # grant a label without a mechanical witness.
    for role in ("analyst", "critic"):
        value = values.get(role)
        if value and value.get("facts"):
            solo = merge(contract, value, value)
            if solo["contract_audit_prediction"] != "unknown":
                if strict_witness:
                    derivation.append(f"candidate ({role}): substantive review {solo['contract_audit_prediction']} "
                                      "awaiting mechanical witness; not released without one")
                    semantic_candidate = solo["contract_audit_prediction"]
                    break
                derivation.append(f"single-role substantive release ({role}): " + str(solo.get("reason", "")))
                return {"disposition": solo["contract_audit_prediction"],
                        "kind": "single_role_substantive_release",
                        "derivation": derivation, "probe": facts_probe, "facts": solo.get("facts"),
                        "wiring": wiring_fact}
    if complete:
        merged = merge(contract, values["analyst"], values["critic"])
        if merged["contract_audit_prediction"] != "unknown":
            if strict_witness:
                derivation.append("candidate: two-role consensus complete but model agreement is not a mechanical witness or proof")
                derivation.append(str(merged.get("reason", "")))
            else:
                derivation.append("two-role consensus facts complete; substantive gate passed")
                return {"disposition": merged["contract_audit_prediction"],
                        "kind": "consensus_release",
                        "derivation": derivation + [merged.get("reason", "")],
                        "probe": facts, "facts": merged.get("facts")}
        derivation.append("consensus facts complete but substantive gate unresolved: " + str(merged.get("reason", "")))
    else:
        missing_roles = [r for r in ("analyst", "critic") if not (values.get(r) and values[r].get("facts"))]
        derivation.append(f"no consensus facts (degenerate/missing roles: {missing_roles})")
    if facts.get("entry_total"):
        derivation.append(f"probe: environment viable, entry {facts.get('entry_ok')}/{facts['entry_total']} importable")
    return {"disposition": "unknown", "kind": "deterministic_layer_unknown",
            "derivation": derivation, "probe": facts}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True, help="run dir with recorded reviews (tasks/ + runs/)")
    parser.add_argument("--probes", type=Path, required=True, help="PROBE_RESULT.json")
    parser.add_argument("--aggregation", type=Path, required=True, help="label aggregation for contract set context")
    parser.add_argument("--wiring", type=Path, default=None, help="WIRING.json from the static verifier")
    parser.add_argument("--strict-witness", action="store_true",
                        help="v3 taxonomy: recorded reviews and source ordering remain candidates; this CLI releases no VP/CWS without an explicit mechanical witness/proof input")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run = args.run.resolve()
    probes = json.loads(args.probes.read_text(encoding="utf-8"))
    agg = json.loads(args.aggregation.read_text(encoding="utf-8"))
    probe_rows = {r["job_id"]: r for r in probes["rows"]}
    wiring_rows = {}
    if args.wiring:
        wiring = json.loads(args.wiring.read_text(encoding="utf-8"))
        for row in wiring["rows"]:
            positions = sorted({o["guard_position"] for o in row["wiring"]["orderings"]
                                if o["guard_position"] not in ("unknown",)})
            wiring_rows[row["sample_id"]] = {
                "positions": positions,
                "guards": len(row["wiring"]["guards"]),
                "tools_with_effects": len(row["wiring"]["tools_with_effects"]),
            }
    plan = read(run / "RUN_PLAN.json")

    rows = []
    for r in agg["rows"]:
        job_id = r["job_id"]
        payload = read(run / next(j["task"] for j in plan["jobs"] if j["job_id"] == job_id))
        contract = payload["repositories"][0]["contracts"][0]
        cid = r["contract_id"]
        reviews = {}
        for role in plan["roles"]:
            result_path = run / "runs" / job_id / role / "RESULT.json"
            if result_path.is_file():
                row = read(result_path)
                reviews[role] = {"value": (row.get("review") or {}).get("contracts", {}).get(cid),
                                 "state": row.get("execution_state")}
        wiring_fact = wiring_rows.get(job_id)
        if wiring_fact and wiring_fact["positions"] == ["after"]:
            rows_note = "static wiring: guard ordering AFTER effect (deterministic AST fact)"
        elif wiring_fact and wiring_fact["positions"] == ["before"]:
            rows_note = "static wiring: guard ordering BEFORE effect (deterministic AST fact)"
        elif wiring_fact and wiring_fact["positions"]:
            rows_note = "static wiring: mixed/ambiguous ordering " + "+".join(wiring_fact["positions"])
        else:
            rows_note = None
        # Absent probes only skip the incompatibility/witness branches; the
        # semantic release rules still apply.
        probe_row = probe_rows.get(job_id) or {"sdk": "", "probes": [], "install_returncode": None}
        outcome = disposition_for(probe_row, reviews, contract, wiring_fact, args.strict_witness)
        if wiring_fact is not None:
            outcome["wiring"] = wiring_fact
        if rows_note:
            outcome.setdefault("derivation", []).append(rows_note)
        rows.append({**{k: r[k] for k in ("job_id", "contract_id", "repository", "bucket",
                                          "environment_status", "label")}, **outcome})

    if args.strict_witness:
        rename = {"present": "VIOLATION-PRESENT", "absent": "CONFORMANT-WITHIN-SCOPE",
                  "incompatibility_evidenced": "EXCLUDED", "unknown": "UNKNOWN"}
        for x in rows:
            x["disposition"] = rename.get(x["disposition"], x["disposition"])
    counts = Counter(x["disposition"] for x in rows)
    result = {
        "schema_version": "p0-deterministic-disposition-2" if args.strict_witness else "p0-deterministic-disposition-1",
        "run": str(run.relative_to(ROOT)),
        "probes_sha256": hashlib.sha256(args.probes.read_bytes()).hexdigest(),
        "aggregation_sha256": hashlib.sha256(args.aggregation.read_bytes()).hexdigest(),
        "counts": {"contracts": len(rows), **dict(counts)},
        "authority_order": ("probe-based exclusions > mechanical witness/proof > unknown; this legacy CLI has no mechanical path-witness/proof input, so review/wiring candidates cannot release VP/CWS"
                            if args.strict_witness else
                            "probe facts > two-role consensus > unknown; labels are source-level dispositions, not behavior ground truth"),
        "claim_boundary": ("Strict-witness migration audit only. Review consensus and AST ordering are candidate facts; no VP/CWS is released without a separate mechanical witness or scoped proof."
                           if args.strict_witness else
                           "Historical development disposition semantics; model consensus may release labels and must not be used as witness-only DEC ground truth."),
        "rows": rows,
        "created_time_ns": time.time_ns(),
    }
    args.out.mkdir(parents=True, exist_ok=False)
    (args.out / "DISPOSITIONS.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["counts"], sort_keys=True))


if __name__ == "__main__":
    main()
