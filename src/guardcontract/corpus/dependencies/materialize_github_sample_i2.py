from __future__ import annotations
if __package__ in (None, ""):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import argparse
import hashlib
import json
import os
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any


SPARSE_PATTERNS = [
    "*.py",
    "**/*.py",
    "README*",
    "**/README*",
    "pyproject.toml",
    "**/pyproject.toml",
    "requirements*.txt",
    "**/requirements*.txt",
]


def destination_name(full_name: str) -> str:
    safe = full_name.replace("/", "__")
    if not safe or safe.startswith(".") or any(part in {"", ".", ".."} for part in safe.split("__")):
        raise ValueError(f"unsafe repository name: {full_name!r}")
    return safe


def run_git(args: list[str], cwd: Path | None = None) -> str:
    env = dict(os.environ)
    env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_LFS_SKIP_SMUDGE": "1",
        }
    )
    command = [
        "git",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "filter.lfs.smudge=",
        "-c",
        "filter.lfs.required=false",
        *args,
    ]
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=1800,
    )
    return completed.stdout.strip()


def source_inventory(repo_dir: Path) -> tuple[int, int, str]:
    records = []
    for path in sorted(repo_dir.rglob("*")):
        if not path.is_file() or path.is_symlink() or ".git" in path.parts:
            continue
        relative = path.relative_to(repo_dir).as_posix()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        records.append({"path": relative, "bytes": path.stat().st_size, "sha256": digest})
    raw = json.dumps(records, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return len(records), sum(record["bytes"] for record in records), hashlib.sha256(raw).hexdigest()


def materialize_one(root: Path, item: dict[str, Any]) -> dict[str, Any]:
    full_name = item["repository"]["full_name"]
    destination = root / destination_name(full_name)
    if destination.exists():
        raise FileExistsError(f"destination already exists: {destination}")
    run_git(
        [
            "clone",
            "--filter=blob:none",
            "--no-checkout",
            "--no-tags",
            "--depth=1",
            "--branch",
            item["repository"]["default_branch"],
            item["repository"]["clone_url"],
            str(destination),
        ]
    )
    expected = item["pinned_commit"]
    current = run_git(["rev-parse", "HEAD"], cwd=destination)
    if current != expected:
        run_git(["fetch", "--depth=1", "origin", expected], cwd=destination)
    run_git(["sparse-checkout", "init", "--no-cone"], cwd=destination)
    run_git(["sparse-checkout", "set", *SPARSE_PATTERNS], cwd=destination)
    run_git(["checkout", "--detach", expected], cwd=destination)
    head = run_git(["rev-parse", "HEAD"], cwd=destination)
    tree = run_git(["rev-parse", "HEAD^{tree}"], cwd=destination)
    expected_tree = item.get("pinned_tree")
    if head != expected or (expected_tree is not None and tree != expected_tree):
        raise RuntimeError(f"pin mismatch for {full_name}: {head}/{tree}")
    file_count, source_bytes, source_digest = source_inventory(destination)
    return {
        "framework": item["framework"],
        "repository": full_name,
        "destination": destination.as_posix(),
        "commit": head,
        "tree": tree,
        "source_file_count": file_count,
        "source_bytes": source_bytes,
        "source_inventory_sha256": source_digest,
        "status": "completed",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Sparse materialize pinned public repositories without executing them")
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
                    "destination": (corpus_dir / destination_name(item["repository"]["full_name"])).as_posix(),
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
    args.result.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["counts"], sort_keys=True))
    return 0 if result["gate_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
