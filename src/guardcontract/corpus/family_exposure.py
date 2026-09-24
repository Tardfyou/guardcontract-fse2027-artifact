"""Audit exact observed-file reuse and known review exposure, without source reads."""
if __package__ in (None, ""):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path


def mentioned_repositories(document, universe):
    found = set()
    def visit(value, key=None):
        if isinstance(value, dict):
            for name, child in value.items(): visit(child, name)
        elif isinstance(value, list):
            for child in value: visit(child, key)
        elif isinstance(value, str) and key in {"repository", "repository_id", "repositories", "eligible_repositories"}:
            name = value.rsplit("@", 1)[0]
            if name in universe: found.add(name)
    visit(document)
    return found


def build(evidence, exposure_inputs):
    rows = evidence["records"]
    ids = [r["source_record_id"] for r in rows]
    if len(ids) != len(set(ids)): raise ValueError("duplicate_record_id")
    universe = {r["repository"] for r in rows}
    parent = {repo: repo for repo in universe}
    def find(repo):
        while parent[repo] != repo:
            parent[repo] = parent[parent[repo]]
            repo = parent[repo]
        return repo
    def union(left, right):
        a, b = find(left), find(right)
        parent[max(a, b)] = min(a, b)
    by_digest, by_repo, unavailable = defaultdict(set), defaultdict(list), []
    for row in rows:
        by_repo[row["repository"]].append(row)
        if row["integrity"]["status"] != "verified":
            unavailable.append(row["source_record_id"])
            continue
        digest = row["integrity"].get("file_sha256")
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("invalid_verified_file_digest")
        by_digest[digest].add(row["repository"])
    shared = []
    for digest, repos in sorted(by_digest.items()):
        names = sorted(repos)
        if len(names) > 1:
            shared.append({"file_sha256": digest, "repositories": names})
            for name in names[1:]: union(names[0], name)
    exposures = {path: sorted(mentioned_repositories(doc, universe)) for path, doc in exposure_inputs.items()}
    exposed = set().union(*(set(names) for names in exposures.values()))
    groups = defaultdict(list)
    for repo in sorted(universe): groups[find(repo)].append(repo)
    components = []
    for names in sorted(groups.values()):
        known = sorted(set(names) & exposed)
        bad = [r["source_record_id"] for name in names for r in by_repo[name] if r["integrity"]["status"] != "verified"]
        component_id = "family:" + hashlib.sha256(json.dumps(names, separators=(",", ":")).encode()).hexdigest()
        components.append({"family_id": component_id, "repositories": names, "known_exposed_repositories": known,
                           "propagated_exposure_repositories": sorted(set(names) - exposed) if known else [],
                           "unverified_record_ids": bad, "observation_count": sum(len(by_repo[n]) for n in names),
                           "status": "exclude_known_exposure" if known else "quarantine_source_integrity" if bad else "candidate_pending_nearcopy_and_exposure_audit",
                           "holdout_eligible": False})
    return {"task_version": "163-1", "execution_health": "completed", "scientific_outcome": "unscored",
            "counts": {"input_records": len(rows), "repositories": len(universe), "exact_observed_file_components": len(components),
                       "cross_repository_shared_files": len(shared), "known_exposed_repositories": len(exposed),
                       "additional_exposure_linked_repositories": sum(len(c["propagated_exposure_repositories"]) for c in components),
                       "excluded_exposure_repositories": sum(len(c["repositories"]) for c in components if c["status"] == "exclude_known_exposure"),
                       "quarantined_repositories": sum(len(c["repositories"]) for c in components if c["status"] == "quarantine_source_integrity"),
                       "candidate_repositories": sum(len(c["repositories"]) for c in components if c["status"] == "candidate_pending_nearcopy_and_exposure_audit"),
                       "unverified_records": len(unavailable), "holdout_eligible_repositories": 0},
            "components": components, "shared_files": shared, "known_exposure_by_input": exposures,
            "exposure_inventory_complete": False, "nearcopy_audit_complete": False,
            "claim_boundary": "Exact hashes cover observed source files only, not entire repositories or near copies. Shared utility files may overmerge. Listed prior reviews are a partial exposure inventory. No component is yet eligible as an independent holdout; no risk labels or model outputs are propagated."}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--config", required=True, type=Path)
    p.add_argument("--result", required=True, type=Path)
    a = p.parse_args()
    raw = a.config.read_bytes(); config = json.loads(raw)
    inputs = {}
    def read(path):
        content = Path(path).read_bytes(); inputs[path] = hashlib.sha256(content).hexdigest()
        return json.loads(content)
    result = build(read(config["evidence"]), {path: read(path) for path in config["exposure_inputs"]})
    result["inputs_sha256"] = inputs
    result["config_sha256"] = hashlib.sha256(raw).hexdigest()
    with a.result.open("x") as output:
        json.dump(result, output, ensure_ascii=False, indent=2, sort_keys=True); output.write("\n")
    print(json.dumps(result["counts"]))


if __name__ == "__main__": main()
