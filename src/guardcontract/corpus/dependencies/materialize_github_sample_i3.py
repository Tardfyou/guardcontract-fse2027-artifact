from __future__ import annotations
if __package__ in (None, ""):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from guardcontract.paths import project_root

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


PROJECT_DIR = project_root()
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from guardcontract.corpus.dependencies import materialize_github_sample_i2 as base


SPARSE_PATTERNS = [
    *base.SPARSE_PATTERNS,
    "*.yaml",
    "**/*.yaml",
    "*.yml",
    "**/*.yml",
    "*.json",
    "**/*.json",
    "*.toml",
    "**/*.toml",
    "!**/.venv/**",
    "!**/venv/**",
    "!**/env/**",
    "!**/site-packages/**",
    "!**/node_modules/**",
    "!**/__pycache__/**",
]


def materialize_one(root: Path, item: dict[str, Any]) -> dict[str, Any]:
    original = base.SPARSE_PATTERNS
    base.SPARSE_PATTERNS = SPARSE_PATTERNS
    try:
        return base.materialize_one(root, item)
    finally:
        base.SPARSE_PATTERNS = original


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sparse materialize pinned Python repositories and declarative configuration"
    )
    parser.add_argument("--frame", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args()
    frame = json.loads(args.frame.read_text(encoding="utf-8"))
    config = json.loads(args.config.read_text(encoding="utf-8"))
    corpus_dir = Path(config["corpus_dir"])
    corpus_dir.mkdir(parents=True, exist_ok=False)
    rows = []
    for item in frame["selected"]:
        try:
            rows.append(materialize_one(corpus_dir, item))
        except Exception as exc:
            rows.append(
                {
                    "framework": item["framework"],
                    "repository": item["repository"]["full_name"],
                    "destination": (
                        corpus_dir / base.destination_name(item["repository"]["full_name"])
                    ).as_posix(),
                    "status": "error",
                    "error_type": type(exc).__name__,
                    "error": str(exc)[:500],
                }
            )
    completed = Counter(row["framework"] for row in rows if row["status"] == "completed")
    planned = Counter(item["framework"] for item in frame["selected"])
    result = {
        "schema_version": 1,
        "frame": args.frame.as_posix(),
        "policy": {
            "repository_code_executed": False,
            "dependencies_installed": False,
            "symlinks_hashed": False,
            "sparse_patterns": SPARSE_PATTERNS,
            "configuration_included": True,
        },
        "counts": {
            "planned": len(rows),
            "completed": sum(row["status"] == "completed" for row in rows),
            "errors": sum(row["status"] == "error" for row in rows),
            "planned_by_framework": dict(sorted(planned.items())),
            "completed_by_framework": dict(sorted(completed.items())),
        },
        "repositories": rows,
        "gate_passed": all(row["status"] == "completed" for row in rows),
    }
    args.result.parent.mkdir(parents=True, exist_ok=True)
    args.result.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result["counts"], sort_keys=True))
    return 0 if result["gate_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
