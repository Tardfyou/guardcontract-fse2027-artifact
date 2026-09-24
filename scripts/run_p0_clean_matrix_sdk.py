"""Run the clean-matrix queue in isolated per-framework containers.

Mirrors the p0 isolation profile: network none, read-only mounts, dropped
capabilities, non-root, pinned image digest, framework venv site-packages
mounted read-only. One container per framework executes every admitted
program of that framework; nothing outside the mounted venv and sources is
reachable and no model calls occur.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
ENVIRONMENTS = {
    "langchain": ".venv-langchain",
    "google-adk": ".venv-google-adk-270",
    "pydantic-ai": ".venv-pydantic-ai",
    "openai-agents": ".venv-openai",
    "crewai": ".venv-crewai",
}
IMAGE = "sha256:afc139a0a640942491ec481ad8dda10f2c5b753f5c969393b12480155fe15a63"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_new(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", type=Path, required=True, help="generation output dir holding QUEUE.json + sources/")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--image-id", default=IMAGE)
    args = parser.parse_args()
    if os.getuid() == 0 or not args.image_id.startswith("sha256:"):
        raise ValueError("clean_matrix_isolation_identity")
    matrix = args.matrix.resolve()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    queue = json.loads((matrix / "QUEUE.json").read_text(encoding="utf-8"))
    frameworks = sorted({r["framework"] for r in queue["rows"]})
    inputs = {str(p.relative_to(ROOT)): sha(p) for p in
              [Path(__file__).resolve(), ROOT / "tools/p0_clean_matrix_cell_driver.py",
               ROOT / "tools/p0_clean_matrix_effects.py",
               ROOT / "tools/generate_p0_clean_matrix_v1.py",
               matrix / "QUEUE.json"]}
    write_new(out / "RUN_PLAN.json", {
        "schema_version": "p0-clean-matrix-sdk-plan-1",
        "frameworks": frameworks,
        "programs": len(queue["rows"]),
        "planned_cells": 2 * len(queue["rows"]),
        "inputs": inputs,
        "image_id": args.image_id,
        "network": "none", "model_calls": 0, "real_model_calls": 0,
        "matrix_sha256": sha(matrix / "QUEUE.json"),
        "claim_boundary": "Owned deterministic clean-matrix execution; not public repository coverage.",
    })
    rows = []
    commands = []
    for framework in frameworks:
        dependencies = ROOT / ENVIRONMENTS[framework] / "lib/python3.12/site-packages"
        target = out / framework
        target.mkdir()
        command = [
            "docker", "run", "--rm", "--pull", "never", "--network", "none",
            "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--user", f"{os.getuid()}:{os.getgid()}",
            "--pids-limit", "256", "--memory", "2g", "--cpus", "4",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=128m",
            "--tmpfs", "/.local:rw,noexec,nosuid,size=64m",
            "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "PYTHONPATH=/sdk:/matrix:/workdir",
            "-e", "OTEL_SDK_DISABLED=true", "-e", "LANGSMITH_TRACING=false",
            "-e", "LANGCHAIN_TRACING_V2=false", "-e", "OPENAI_AGENTS_DISABLE_TRACING=1",
            "-e", "XDG_DATA_HOME=/tmp/xdg-data", "-e", "XDG_CACHE_HOME=/tmp/xdg-cache",
            "-e", "CREWAI_STORAGE_DIR=/tmp/crewai",
            "-v", f"{dependencies}:/sdk:ro", "-v", f"{matrix}:/matrix:ro",
            "-v", f"{ROOT / 'tools/p0_clean_matrix_cell_driver.py'}:/driver.py:ro",
            "-v", f"{target}:/out:rw",
            "--workdir", "/workdir", args.image_id, "python", "/driver.py",
            "--matrix-root", "/matrix", "--out", "/out", "--framework", framework,
        ]
        commands.append(command)
        started = time.monotonic()
        result = subprocess.run(command, capture_output=True, text=True, timeout=1800)
        (target / "stdout.txt").write_text(result.stdout)
        (target / "stderr.txt").write_text(result.stderr)
        summary = target / "SUMMARY.json"
        rows.append({
            "framework": framework, "returncode": result.returncode,
            "elapsed_seconds": round(time.monotonic() - started, 6),
            "programs": json.loads(summary.read_text())["programs"] if summary.is_file() else None,
            "completed": json.loads(summary.read_text())["completed"] if summary.is_file() else None,
            "status": "completed" if result.returncode == 0 and summary.is_file() else "error",
        })
    execution_health = "completed" if all(r["status"] == "completed" for r in rows) else "partial"
    write_new(out / "RESULT.json", {
        "schema_version": "p0-clean-matrix-sdk-result-1",
        "rows": rows, "frameworks": len(rows),
        "programs": sum(r["programs"] or 0 for r in rows),
        "planned_cells": 2 * len(queue["rows"]),
        "completed_programs": sum(r["completed"] or 0 for r in rows),
        "execution_health": execution_health,
        "model_calls": 0, "network": "none",
        "claim_boundary": "Owned deterministic clean-matrix execution in isolated containers; not public repository coverage.",
    })
    write_new(out / "RUN_MANIFEST.json", {
        "schema_version": "p0-clean-matrix-sdk-manifest-1",
        "execution_health": execution_health,
        "commands": commands,
        "matrix_sha256": sha(matrix / "QUEUE.json"),
        "created_time_ns": time.time_ns(),
        "artifacts": {str(p.relative_to(out)): sha(p) for p in out.rglob("*") if p.is_file()},
    })
    print(json.dumps({"programs": sum(r["programs"] or 0 for r in rows),
                      "completed": sum(r["completed"] or 0 for r in rows),
                      "health": execution_health}, sort_keys=True))
    raise SystemExit(0 if execution_health == "completed" else 2)


if __name__ == "__main__":
    main()
