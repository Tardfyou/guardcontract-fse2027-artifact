"""Versioned source-integrity and lexical-evidence layer over existing candidates.

All candidate observations are retained. This instrument verifies local pinned
bytes and Python symbol bindings; object roles, effect paths and risk remain
separate unknowns. It does not import target modules or contact any service.
"""
from __future__ import annotations
if __package__ in (None, ""):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from guardcontract.paths import project_root

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = project_root()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from guardcontract.analysis.dependencies.relevance_binding import PythonBindings


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(value):
    return sha(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def safe_path(root, relative):
    if not isinstance(relative, str) or Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise ValueError("invalid_relative_path")
    path = root / relative
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("path_escape")
    # Symlink ancestors are also rejected; do not follow alternate source trees.
    if any(parent.is_symlink() for parent in [path, *path.parents] if parent != root.parent):
        raise ValueError("symlink_path")
    return path


def git_tree(repo, commit, tree):
    if not all(isinstance(v, str) and re.fullmatch(r"[0-9a-f]{40}", v) for v in (commit, tree)):
        raise ValueError("missing_or_invalid_version")
    def git(*args):
        return subprocess.run(["git", "--no-optional-locks", "--no-replace-objects", "-c", "core.hooksPath=/dev/null", "-c", "maintenance.auto=false",
                               "-c", "gc.auto=0", "-C", str(repo), *args], check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
                              env={**os.environ, "GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0"}).stdout
    observed = git("rev-parse", "HEAD", "HEAD^{tree}").decode().splitlines()
    if observed != [commit, tree]:
        raise ValueError("checkout_version_mismatch")
    blobs = {}
    for record in git("ls-tree", "-r", "-z", commit).split(b"\0"):
        if not record:
            continue
        meta, name = record.split(b"\t", 1)
        mode, kind, digest = meta.decode().split()
        if kind == "blob" and mode in {"100644", "100755"}:
            blobs[name.decode("utf-8", errors="strict")] = digest
    return blobs


def unit_source(raw, path, cell):
    if path.endswith(".py"):
        if cell is not None:
            raise ValueError("cell_on_non_notebook")
        return raw.decode("utf-8-sig")
    if path.endswith(".ipynb"):
        nb = json.loads(raw.decode("utf-8-sig"))
        if not isinstance(nb, dict) or not isinstance(nb.get("cells"), list):
            raise ValueError("invalid_notebook_schema")
        if type(cell) is not int or cell < 0:
            raise ValueError("missing_notebook_cell")
        value = nb["cells"][cell]
        if not isinstance(value, dict):
            raise ValueError("invalid_notebook_cell")
        if value.get("cell_type") != "code":
            raise ValueError("not_code_cell")
        source = value["source"]
        if isinstance(source, list) and all(isinstance(x, str) for x in source):
            return "".join(source)
        if isinstance(source, str):
            return source
        raise ValueError("invalid_cell_source")
    return None


def run(config, root):
    inputs = {}
    def read(name):
        raw = safe_path(root, name).read_bytes()
        inputs[name] = sha(raw)
        return json.loads(raw)
    ledger = read(config["ledger"])
    prior = read(config["previous_frame"])
    by_id = {r["record_id"]: r["direct_relevance_status"] for r in prior["audit_records"]}
    contracts = {}
    for name in config["contract_inputs"]:
        for fw, definition in read(name)["frameworks"].items():
            if fw in contracts and contracts[fw] != definition:
                raise ValueError("conflicting_framework_definitions")
            contracts[fw] = definition
    observations = list(ledger["records"])
    for layer in config.get("additional_scans", []):
        scan = read(layer["scan"])
        mats = {r["repository"]: r for r in read(layer["materialization"])["repositories"] if r.get("status") == "completed"}
        for i, site in enumerate(scan["sites"]):
            mat = mats[site["repository"]]
            observations.append({"record_id": identity([layer["name"], i, site]), "observation": site,
                                 "source_layer": layer["name"], "source_input": layer["scan"], "source_pointer": f"/sites/{i}",
                                 "commit": mat["commit"], "tree": mat["tree"], "destination": mat["destination"],
                                 "source_file_sha256": None})
    if len({r["record_id"] for r in observations}) != len(observations):
        raise ValueError("duplicate_input_record_id")
    if len(observations) != config["expected_observations"]:
        raise ValueError("input_count_mismatch")
    source_observation_count = len(observations)
    if config.get("selection_record_ids") is not None:
        wanted = config["selection_record_ids"]
        if not isinstance(wanted, list) or not wanted or len(set(wanted)) != len(wanted):
            raise ValueError("invalid_smoke_selection")
        observations = [r for r in observations if r["record_id"] in set(wanted)]
        if len(observations) != len(wanted):
            raise ValueError("missing_smoke_selection")
    trees, files, parsers = {}, {}, {}
    rows = []
    for entry in observations:
        s = entry["observation"]
        key = [s["repository"], entry.get("commit"), s["path"], s.get("cell"), s["line"], s["framework"],
               s.get("marker", s.get("guard")), s.get("lifecycle")]
        flags = list(entry.get("source_path_framework_candidates", []))
        path_parts = {p.casefold() for p in Path(s["path"]).parts}
        policy_exclusions = []
        if s["repository"].split("/")[0].casefold() in config["official_owners"]:
            policy_exclusions.append("official_owner")
        if path_parts & set(config["auxiliary_path_parts"]):
            policy_exclusions.append("auxiliary_path")
        if s.get("source_copy_path"):
            flags.append("historical_source_path_heuristic")
        row = {"schema_version": 1, "evidence_id": identity(key), "source_record_id": entry["record_id"],
               "repository": s["repository"], "commit": entry.get("commit"), "tree": entry.get("tree"),
               "path": s["path"], "cell": s.get("cell"), "line": s["line"], "framework": s["framework"],
               "marker": s.get("marker", s.get("guard")), "lifecycle": s.get("lifecycle"),
               "source_layer": entry["source_layer"], "source_input": entry["source_input"], "source_pointer": entry["source_pointer"],
               "previous_inclusion": by_id.get(entry["record_id"], "not_in_previous_frame"),
               "integrity": {"status": "unknown"}, "api_binding": {"status": "unknown", "reason": "not_evaluated"},
               "object_role": {"status": "unknown", "source_path_hints": sorted(set(flags)), "policy_exclusions": policy_exclusions},
               "measurement_applicability": {"status": "unknown", "reason": "guard_effect_path_not_evaluated"},
               "risk": {"status": "unknown", "reason": "no_independent_path_or_runtime_evidence"},
               "primary_measurement_eligible": False}
        repo_key = (entry.get("destination"), entry.get("commit"), entry.get("tree"))
        try:
            repo = safe_path(root, entry["destination"])
            if repo_key not in trees:
                try:
                    trees[repo_key] = git_tree(repo, entry.get("commit"), entry.get("tree"))
                except (OSError, ValueError, subprocess.SubprocessError) as exc:
                    trees[repo_key] = {"__error__": str(exc) if isinstance(exc, ValueError) else type(exc).__name__}
            if "__error__" in trees[repo_key]:
                raise ValueError(trees[repo_key]["__error__"])
            file_key = (*repo_key, s["path"])
            if file_key not in files:
                try:
                    target = safe_path(repo, s["path"])
                    if target.stat().st_size > config["max_file_bytes"]:
                        raise ValueError("oversize_source")
                    raw = target.read_bytes()
                    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
                    if trees[repo_key].get(s["path"]) != blob:
                        raise ValueError("source_blob_mismatch")
                    files[file_key] = {"bytes": raw, "sha256": sha(raw), "git_blob": blob}
                except (OSError, ValueError) as exc:
                    files[file_key] = {"error": str(exc) if isinstance(exc, ValueError) else type(exc).__name__}
            f = files[file_key]
            if f.get("error"):
                raise ValueError(f["error"])
            if entry.get("source_file_sha256") and entry["source_file_sha256"] != f["sha256"]:
                raise ValueError("historical_file_hash_mismatch")
            row["integrity"] = {"status": "verified", "file_sha256": f["sha256"], "git_blob": f["git_blob"], "git_commit_tree_checked": True}
            if not s["path"].endswith((".py", ".ipynb")):
                row["api_binding"] = {"status": "unknown", "reason": "language_binding_backend_not_implemented"}
            elif s["framework"] not in contracts:
                row["api_binding"] = {"status": "unknown", "reason": "framework_contract_not_available"}
            else:
                parse_key = (*file_key, s.get("cell"))
                if parse_key not in parsers:
                    try:
                        source = unit_source(f["bytes"], s["path"], s.get("cell"))
                        parsers[parse_key] = (PythonBindings(source), len(source.splitlines()))
                    except (ValueError, TypeError, KeyError, IndexError, SyntaxError, UnicodeError, RecursionError) as exc:
                        parsers[parse_key] = {"error": type(exc).__name__}
                parsed = parsers[parse_key]
                if isinstance(parsed, dict):
                    row["api_binding"] = {"status": "unknown", "reason": "source_parse_error", "error_kind": parsed["error"]}
                elif type(s["line"]) is not int or not 1 <= s["line"] <= parsed[1]:
                    row["api_binding"] = {"status": "unknown", "reason": "invalid_source_line"}
                else:
                    row["api_binding"] = parsed[0].check(s, contracts[s["framework"]])
        except (KeyError, ValueError, OSError) as exc:
            row["integrity"] = {"status": "unavailable", "reason": str(exc) if isinstance(exc, ValueError) else type(exc).__name__}
            row["api_binding"] = {"status": "unknown", "reason": "source_integrity_unavailable"}
        rows.append(row)
    duplicate_counts = Counter(r["evidence_id"] for r in rows)
    for row in rows:
        row["semantic_observation_count"] = duplicate_counts[row["evidence_id"]]
    groups = defaultdict(list)
    for r in rows:
        groups[r["repository"]].append(r)
    repositories = [{"repository": name, "observations": len(values),
                     "api_binding_counts": dict(Counter(r["api_binding"]["status"] for r in values)),
                     "primary_measurement_eligible": False, "object_role": "unknown"}
                    for name, values in sorted(groups.items())]
    unsupported_reasons = {"language_binding_backend_not_implemented", "framework_contract_not_available"}
    errors = sum(r["integrity"]["status"] != "verified" or r["api_binding"]["reason"] in {"source_parse_error", "invalid_source_line"} for r in rows)
    return {"schema_version": 1, "task_version": config["task_version"], "captured_at": datetime.now(timezone.utc).isoformat(),
            "execution_health": "partial" if errors else "completed", "scientific_outcome": "unscored",
            "instrument_scope": "pinned_source_integrity_and_conservative_python_lexical_binding",
            "source_observation_count": source_observation_count,
            "selection_record_ids": config.get("selection_record_ids"),
            "counts": {"planned_observations": len(observations), "processed_observations": len(rows), "repositories": len(repositories),
                       "integrity_verified": sum(r["integrity"]["status"] == "verified" for r in rows), "source_or_parse_errors": errors,
                       "api_binding": dict(Counter(r["api_binding"]["status"] for r in rows)),
                       "unique_semantic_sites": len(duplicate_counts),
                       "duplicate_semantic_groups": sum(n > 1 for n in duplicate_counts.values()),
                       "unsupported_backend_observations": sum(r["api_binding"]["reason"] in unsupported_reasons for r in rows),
                       "primary_measurement_eligible": 0},
            "api_binding_reasons": dict(Counter(r["api_binding"]["reason"] for r in rows)),
            "inputs_sha256": inputs, "config_sha256": identity(config),
            "code_sha256": {name: sha((ROOT / name).read_bytes()) for name in ('src/guardcontract/evidence/repository_evidence.py', 'src/guardcontract/analysis/dependencies/relevance_binding.py')},
            "records": rows, "repositories": repositories,
            "claim_boundary": "Supported means lexical API binding, not application role, control activation, runtime reachability, guard-effect applicability or vulnerability. Unknown/unsupported/errors are retained. Previous inclusion does not confer evidence. No target modules are executed; no network requests."}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--config", type=Path, required=True)
    p.add_argument("--result", type=Path, required=True)
    a = p.parse_args()
    if a.result.exists():
        raise FileExistsError(a.result)
    result = run(json.loads(a.config.read_text()), Path.cwd().resolve())
    with a.result.open("x") as stream:
        json.dump(result, stream, ensure_ascii=False, sort_keys=True, indent=2)
        stream.write("\n")
    print(json.dumps(result["counts"]))
    return 2 if result["execution_health"] == "partial" else 0


if __name__ == "__main__":
    raise SystemExit(main())
