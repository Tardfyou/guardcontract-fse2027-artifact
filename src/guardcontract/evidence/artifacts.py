from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from guardcontract.core.schemas import PatchEnvelope, RepairJob
from guardcontract.evidence.validation import validate_patch


def _atomic_new(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise FileExistsError(f"refusing to overwrite artifact: {path}")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def write_patch_bundle(repo: Path, output_root: Path, job: RepairJob, patch: PatchEnvelope, *, backend_fingerprint: str) -> dict[str, Any]:
    source_root = repo.resolve()
    artifact_root = output_root.resolve()
    if artifact_root == source_root or artifact_root.is_relative_to(source_root):
        raise ValueError("patch output directory must be outside the source repository")
    validation = validate_patch(job, patch)
    if not validation.accepted:
        raise ValueError("patch failed policy validation: " + "; ".join(validation.errors))
    safe_id = hashlib.sha256(job.job_id.encode()).hexdigest()[:20]
    bundle = artifact_root / safe_id
    diff_bytes = patch.unified_diff.encode("utf-8")
    manifest = {
        "schema_version": patch.schema_version,
        "job_id": job.job_id,
        "repository_id": job.repository_id,
        "base_revision": job.base_revision,
        "backend_fingerprint": backend_fingerprint,
        "patch_sha256": hashlib.sha256(diff_bytes).hexdigest(),
        "touched_paths": list(patch.touched_paths),
        "residual_risks": list(patch.residual_risks),
        "applied_to_source": False,
        "policy_validation": "supported",
        "independent_verification": "unscored",
    }
    _atomic_new(bundle / "candidate.patch", diff_bytes)
    try:
        _atomic_new(bundle / "manifest.json", (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode())
    except BaseException:
        (bundle / "candidate.patch").unlink(missing_ok=True)
        raise
    return {"bundle": bundle.as_posix(), "manifest": manifest}
