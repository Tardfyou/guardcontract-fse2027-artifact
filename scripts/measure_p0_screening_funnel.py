"""Measure source-screening coverage on its own frame, never DEC prevalence.

The 745-repository API census and the 695-repository intake ledger are kept
separate. Normal UNKNOWN/disagreement remains in every intake denominator.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return json.loads(path.read_bytes())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def measure(screening, census, source_units):
    if screening.get("full_772_screening_execution_complete") is not True or screening.get("input_drift"):
        raise ValueError("screening_execution_not_complete")
    rows = screening["rows"]
    identifiers = [row["unit"] for row in rows]
    if len(identifiers) != len(set(identifiers)) or set(identifiers) != {row["sample_id"] for row in source_units}:
        raise ValueError("intake_frame_inventory")
    source_by_id = {row["sample_id"]: row for row in source_units}
    by_framework, by_protocol, by_repo, by_family = defaultdict(Counter), defaultdict(Counter), defaultdict(list), defaultdict(list)
    output_rows = []
    for row in rows:
        unit = source_by_id[row["unit"]]
        if row["execution_health"] != "completed" or row["status"] not in {"applicable", "not_applicable", "unresolved_contract"}:
            raise ValueError("incomplete_or_invalid_source_review")
        if unit["repository"].lower() != row["repository"].lower():
            raise ValueError("repository_identity_mismatch")
        family = unit.get("source_family")
        if not isinstance(family, str) or not family:
            raise ValueError("source_family_required")
        protocol = "inherited_source_admission" if row.get("inherited_not_new_GLM_result") else "source_bound_GLM_screening"
        by_framework[unit["framework"]][row["status"]] += 1
        by_protocol[protocol][row["status"]] += 1
        by_repo[row["repository"].lower()].append(row["status"])
        by_family[family].append(row["status"])
        output_rows.append({"unit": row["unit"], "repository": row["repository"], "framework": unit["framework"],
                            "source_family": family, "status": row["status"], "protocol_group": protocol})
    api_repos = {row["repository"].lower() for row in census["admitted_repositories"]}
    intake_repos = set(by_repo)
    counts = Counter(row["status"] for row in rows)
    def summaries(groups):
        return {"total": len(groups), "with_applicable_candidate": sum("applicable" in values for values in groups.values()),
                "with_unresolved_unit": sum("unresolved_contract" in values for values in groups.values()),
                "all_sampled_units_not_applicable": sum(set(values) == {"not_applicable"} for values in groups.values())}
    return {"schema_version": "source-screening-ecological-funnel-1", "source_intake": {"units": len(rows),
            "repositories": len(intake_repos), "source_families": len(by_family),
            "source_family_status": "Candidate identifiers from the fixed source plan, not audited independent implementation lineages.", "unit_statuses": dict(counts),
            "repository_statuses": summaries(by_repo), "family_statuses": summaries(by_family),
            "by_framework": {key: dict(value) for key, value in sorted(by_framework.items())},
            "by_protocol_group": {key: dict(value) for key, value in sorted(by_protocol.items())}},
            "api_census": {"repositories": len(api_repos), "counts": census["counts"]},
            "population_join": {"repository_overlap": len(api_repos & intake_repos), "api_census_only": len(api_repos - intake_repos),
                                "source_intake_only": len(intake_repos - api_repos), "identity_normalization": "case-insensitive owner/repository"},
            "rows": output_rows, "DEC_prevalence_available": False, "behavior_labels_read": False,
            "claim_boundary": "Complete recorded source-screening opinions on a fixed discovery frame only. Applicable is a candidate, not a mechanically verified operational contract or DEC violation. Unresolved stays in denominators. Inherited and GLM protocols are reported separately. No population sampling weights or prevalence confidence intervals are invented."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--screening", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--census", type=Path, default=ROOT / "experiments/large-scale-direct-census-post-v11-n502/CENSUS.json")
    parser.add_argument("--source-plan", type=Path, default=ROOT / "experiments/p0-source-recovery-v4-round129-n1827/RUN_PLAN.json")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    manifest = read(args.manifest)
    if manifest.get("execution_health") != "completed" or manifest["result_sha256"] != sha(args.screening):
        raise ValueError("screening_manifest_binding")
    if (ROOT / manifest["result"]).resolve() != args.screening.resolve():
        raise ValueError("screening_manifest_result_path")
    for relative, expected in manifest["results"].items():
        path = (ROOT / relative).resolve()
        if not path.is_relative_to(ROOT) or sha(path) != expected:
            raise ValueError("screening_job_result_drift")
    value = measure(read(args.screening), read(args.census), read(args.source_plan)["units"])
    value["inputs"] = {str(path.resolve().relative_to(ROOT)): sha(path) for path in
                       (args.screening, args.manifest, args.census, args.source_plan, Path(__file__))}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("x") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps({"source_intake": value["source_intake"], "population_join": value["population_join"]}), flush=True)


if __name__ == "__main__":
    main()
