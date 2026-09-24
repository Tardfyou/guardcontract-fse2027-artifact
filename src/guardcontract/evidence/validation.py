from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable

from guardcontract.core.schemas import EvidenceJob, EvidenceSpan, FindingEnvelope, PatchEnvelope, RepairJob


@dataclass(frozen=True)
class ValidationResult:
    accepted: bool
    confidence: str
    errors: tuple[str, ...]


def safe_relative_path(value: str) -> PurePosixPath:
    if not value or "\\" in value or "\x00" in value:
        raise ValueError("path must be a non-empty POSIX repository-relative path")
    raw_parts = value.split("/")
    if any(part in {"", ".", ".."} for part in raw_parts):
        raise ValueError(f"unsafe repository path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute():
        raise ValueError(f"unsafe repository path: {value!r}")
    if path.parts[0].endswith(":"):
        raise ValueError(f"unsafe repository path: {value!r}")
    return path


def span_bytes(repo: Path, span: EvidenceSpan) -> bytes:
    relative = safe_relative_path(span.path)
    root = repo.resolve()
    target = root.joinpath(*relative.parts)
    if target.is_symlink() or not target.is_file() or not target.resolve().is_relative_to(root):
        raise ValueError(f"evidence path is not a regular in-repository file: {span.path}")
    lines = target.read_bytes().splitlines(keepends=True)
    if span.end_line > len(lines):
        raise ValueError(f"evidence span exceeds file length: {span.path}")
    return b"".join(lines[span.start_line - 1 : span.end_line])


def digest_span(repo: Path, path: str, start_line: int, end_line: int) -> str:
    provisional = EvidenceSpan(path, start_line, end_line, "0" * 64)
    return hashlib.sha256(span_bytes(repo, provisional)).hexdigest()


def verify_span(repo: Path, span: EvidenceSpan) -> None:
    actual = hashlib.sha256(span_bytes(repo, span)).hexdigest()
    if actual != span.sha256:
        raise ValueError(f"evidence hash mismatch: {span.path}:{span.start_line}-{span.end_line}")


def validate_finding(repo: Path, job: EvidenceJob, finding: FindingEnvelope) -> ValidationResult:
    errors: list[str] = []
    if finding.job_id != job.job_id:
        errors.append("finding job_id does not match job")
    allowed_spans = {(item.path, item.start_line, item.end_line, item.sha256) for item in job.evidence}
    cited: list[EvidenceSpan] = list(finding.source_spans)
    for edge in finding.path_edges:
        if edge.source not in job.allowed_nodes or edge.target not in job.allowed_nodes:
            errors.append(f"edge references unknown node: {edge.source}->{edge.target}")
        cited.extend(edge.evidence)
    if finding.effect:
        cited.extend(finding.effect.evidence)
    for span in cited:
        if (span.path, span.start_line, span.end_line, span.sha256) not in allowed_spans:
            errors.append(f"citation was not supplied to model: {span.path}:{span.start_line}-{span.end_line}")
            continue
        try:
            verify_span(repo, span)
        except ValueError as exc:
            errors.append(str(exc))
    if finding.claim == "ordering" and finding.verdict == "supported":
        if not any(edge.kind in {"precedes", "dominates"} for edge in finding.path_edges):
            errors.append("supported ordering claim lacks a definite ordering edge")
    if finding.claim == "effect" and finding.verdict == "supported" and finding.effect is None:
        errors.append("supported effect claim lacks effect evidence")
    return ValidationResult(not errors, finding.verdict if not errors else "unknown", tuple(dict.fromkeys(errors)))


_DIFF_HEADER = re.compile(r"^diff --git a/(\S+) b/(\S+)$")


def validate_patch(job: RepairJob, patch: PatchEnvelope) -> ValidationResult:
    errors: list[str] = []
    if patch.job_id != job.job_id or patch.base_revision != job.base_revision:
        errors.append("patch identity does not match repair job")
    allowed = set(job.allowed_paths)
    headers: list[str] = []
    changed_lines = 0
    for line in patch.unified_diff.splitlines():
        match = _DIFF_HEADER.match(line)
        if match:
            left, right = match.groups()
            if left != right:
                errors.append("renames and cross-path diffs are not allowed")
            try:
                safe_relative_path(right)
            except ValueError as exc:
                errors.append(str(exc))
            headers.append(right)
        elif (line.startswith("+") and not line.startswith("+++")) or (line.startswith("-") and not line.startswith("---")):
            changed_lines += 1
    if not headers:
        errors.append("patch has no file diff headers")
    if len(set(headers)) > job.max_files:
        errors.append("patch exceeds file-count budget")
    if changed_lines > job.max_changed_lines:
        errors.append("patch exceeds changed-line budget")
    if set(headers) != set(patch.touched_paths):
        errors.append("touched_paths does not match diff headers")
    forbidden = set(headers) - allowed
    if forbidden:
        errors.append(f"patch touches unapproved paths: {sorted(forbidden)}")
    return ValidationResult(not errors, "supported" if not errors else "unknown", tuple(dict.fromkeys(errors)))
