"""Build and attest a constrained container command for source-oracle runs."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


IMAGE_ID_PREFIX = "sha256:"


def _inside(root: Path, path: Path) -> Path:
    root = root.resolve()
    path = path.resolve()
    try:
        return path.relative_to(root)
    except ValueError as exc:
        raise ValueError("container_oracle_path_outside_project") from exc


def build_command(*, root: Path, scratch: Path, image_id: str, mode: str,
                  config: Path, queue: Path | None = None, runtime_user: str = "65534:65534") -> list[str]:
    root = root.resolve()
    scratch = scratch.resolve()
    config_rel = _inside(root, config)
    if not image_id.startswith(IMAGE_ID_PREFIX) or len(image_id) != 71:
        raise ValueError("container_oracle_image_id")
    if mode not in {"smoke", "prediction-blind"}:
        raise ValueError("container_oracle_mode")
    if mode == "prediction-blind" and queue is None:
        raise ValueError("container_oracle_queue_required")
    parts = runtime_user.split(":")
    if len(parts) != 2 or not all(part.isdigit() for part in parts) or any(int(part) == 0 for part in parts):
        raise ValueError("container_oracle_runtime_user")
    runner = ("tools/run_source_oracle_adapter_smoke.py" if mode == "smoke"
              else "tools/run_prediction_blind_source_oracle.py")
    command = [
        "docker", "run", "--rm", "--pull", "never",
        "--user", runtime_user, "--network", "none", "--read-only",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "64", "--memory", "256m", "--cpus", "1",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
        "--env", "HOME=/tmp", "--env", "PYTHONDONTWRITEBYTECODE=1",
        "--env", "PYTHONPATH=/workspace/src",
        "--volume", f"{root}:/workspace:ro",
        "--volume", f"{scratch}:/out:rw",
        "--workdir", "/workspace", "--entrypoint", "python3", image_id,
        f"/workspace/{runner}", "--config", f"/workspace/{config_rel.as_posix()}",
    ]
    if queue is not None:
        queue_rel = _inside(root, queue)
        command.extend(["--queue", f"/workspace/{queue_rel.as_posix()}"])
    command.extend(["--output", "/out/RESULT.json"])
    return command


def attest_output(scratch: Path, *, image_id: str, mode: str, runtime_user: str) -> dict:
    result_path = scratch / "RESULT.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    records = []
    total_bytes = 0
    for path in sorted(scratch.rglob("*")):
        if not path.is_file() or path == result_path:
            continue
        data = path.read_bytes()
        total_bytes += len(data)
        records.append({
            "path": path.relative_to(scratch).as_posix(),
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "content_hex": data.hex() if len(data) <= 64 else None,
        })
    result["container_isolation"] = {
        "image_id": image_id,
        "mode": mode,
        "network": "none",
        "root_filesystem": "read_only",
        "user": runtime_user,
        "capabilities": "all_dropped",
        "no_new_privileges": True,
        "pids_limit": 64,
        "memory_limit_bytes": 256 * 1024 * 1024,
        "raw_result_sha256": hashlib.sha256(result_path.read_bytes()).hexdigest(),
        "sidecar_files": records,
        "sidecar_total_bytes": total_bytes,
    }
    return result
