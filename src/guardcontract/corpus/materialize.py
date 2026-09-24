from __future__ import annotations
if __package__ in (None, ""):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from guardcontract.paths import project_root

import argparse
import json
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any


PROJECT_DIR = project_root()
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from guardcontract.corpus.dependencies import materialize_github_sample_i2 as base
from guardcontract.corpus.dependencies.materialize_github_sample_i3 import SPARSE_PATTERNS


def normalize_repository_row(row: dict[str, Any]) -> dict[str, Any]:
    """Normalize identity-freeze rows without coupling to a specific round."""
    normalized = dict(row)
    repository = normalized.get("repository")
    if isinstance(repository, str):
        normalized["repository"] = {
            "full_name": repository,
            "clone_url": f"https://github.com/{repository}.git",
            "default_branch": normalized.get("default_branch"),
        }
    elif not isinstance(repository, dict):
        raise ValueError("repository identity must be a full-name string or object")
    if not normalized.get("framework"):
        stratum = normalized.get("stratum")
        if not isinstance(stratum, str) or not stratum:
            raise ValueError("framework or stratum is required")
        normalized["framework"] = stratum
    if "matched_files" not in normalized and isinstance(normalized.get("matched_paths"), list):
        normalized["matched_files"] = [{"path": path} for path in normalized["matched_paths"]]
    return normalized


def unique_repositories(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_name: dict[str, dict[str, Any]] = {}
    frameworks: dict[str, set[str]] = {}
    for raw_row in rows:
        row = normalize_repository_row(raw_row)
        name = row["repository"]["full_name"]
        existing = by_name.get(name)
        if existing is not None and existing["pinned_commit"] != row["pinned_commit"]:
            raise ValueError(f"repository {name} has conflicting pinned commits")
        by_name.setdefault(name, row)
        declared = row.get("frameworks", [row["framework"]])
        frameworks.setdefault(name, set()).update(declared)
    result = []
    for name in sorted(by_name):
        row = dict(by_name[name])
        row["frameworks"] = sorted(frameworks[name])
        result.append(row)
    return result


def materialize(config: dict[str, Any], frame: dict[str, Any]) -> dict[str, Any]:
    rows = unique_repositories(frame[config.get("repository_list_field", "selected")])
    corpus_dir = Path(config["corpus_dir"])
    corpus_dir.mkdir(parents=True, exist_ok=False)
    workers = int(config.get("workers", 8))
    if workers < 1 or workers > 32:
        raise ValueError("workers must be between 1 and 32")

    original_patterns = base.SPARSE_PATTERNS
    base.SPARSE_PATTERNS = SPARSE_PATTERNS
    completed_rows = []
    try:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            pending = {
                executor.submit(base.materialize_one, corpus_dir, item): item
                for item in rows
            }
            for future in as_completed(pending):
                item = pending[future]
                try:
                    result = future.result()
                    result["frameworks"] = item["frameworks"]
                    completed_rows.append(result)
                except Exception as exc:
                    completed_rows.append(
                        {
                            "framework": item["framework"],
                            "frameworks": item["frameworks"],
                            "repository": item["repository"]["full_name"],
                            "destination": (
                                corpus_dir
                                / base.destination_name(item["repository"]["full_name"])
                            ).as_posix(),
                            "status": "error",
                            "error_type": type(exc).__name__,
                            "error": str(exc)[:500],
                        }
                    )
    finally:
        base.SPARSE_PATTERNS = original_patterns

    completed_rows.sort(key=lambda row: row["repository"])
    planned_by_framework = Counter(
        framework for item in rows for framework in item["frameworks"]
    )
    completed_by_framework = Counter(
        framework
        for row in completed_rows
        if row["status"] == "completed"
        for framework in row["frameworks"]
    )
    result = {
        "schema_version": 1,
        "frame": config["frame"],
        "policy": {
            "repository_code_executed": False,
            "dependencies_installed": False,
            "symlinks_hashed": False,
            "sparse_patterns": SPARSE_PATTERNS,
            "configuration_included": True,
            "deduplicated_by_repository": True,
            "workers": workers,
        },
        "counts": {
            "planned_unique_repositories": len(rows),
            "completed_unique_repositories": sum(
                row["status"] == "completed" for row in completed_rows
            ),
            "errors": sum(row["status"] == "error" for row in completed_rows),
            "planned_repository_framework_pairs": sum(planned_by_framework.values()),
            "completed_repository_framework_pairs": sum(completed_by_framework.values()),
            "planned_by_framework": dict(sorted(planned_by_framework.items())),
            "completed_by_framework": dict(sorted(completed_by_framework.items())),
        },
        "repositories": completed_rows,
        "gate_passed": all(row["status"] == "completed" for row in completed_rows),
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Concurrent sparse materialization with repository deduplication"
    )
    parser.add_argument("--frame", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args()
    frame = json.loads(args.frame.read_text(encoding="utf-8"))
    config = json.loads(args.config.read_text(encoding="utf-8"))
    result = materialize(config, frame)
    args.result.parent.mkdir(parents=True, exist_ok=True)
    args.result.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result["counts"], sort_keys=True))
    return 0 if result["gate_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
