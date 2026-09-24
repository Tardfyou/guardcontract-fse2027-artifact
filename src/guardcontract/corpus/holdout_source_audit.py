"""Hash-only source audit for already materialized, revision-pinned candidates."""
import hashlib
from pathlib import Path


def audit_materialized(candidates, materialized):
    locations = {row.get("repository"): row for row in materialized if isinstance(row, dict)}
    rows = []
    for candidate in candidates:
        repository = candidate.get("repository")
        location = locations.get(repository)
        if not location or location.get("status") != "completed":
            rows.append({"repository": repository, "status": "unavailable_materialization", "source_sha256": None})
            continue
        path = Path(location.get("destination", ""))
        if not path.is_dir() or path.is_symlink():
            rows.append({"repository": repository, "status": "unsafe_materialization", "source_sha256": None})
            continue
        digest = hashlib.sha256()
        files = 0
        for source in sorted(path.rglob("*.py")):
            if source.is_symlink() or not source.is_file() or not source.resolve().is_relative_to(path):
                continue
            digest.update(source.relative_to(path).as_posix().encode() + b"\0" + source.read_bytes())
            files += 1
        rows.append({"repository": repository, "status": "hashed_source_inventory",
                     "source_sha256": digest.hexdigest(), "source_files": files,
                     "source_opened": True, "behavior_label": None, "holdout_eligible": False})
    return {"schema_version": "holdout-source-audit-1", "rows": rows,
            "holdout_admission_authorized": False,
            "claim_boundary": "Hash-only inventory; no execution, semantic label or behavior oracle."}
