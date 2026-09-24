from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from guardcontract.core.schemas import EvidenceSpan
from guardcontract.evidence.validation import safe_relative_path


EXCLUDED_PARTS = {".git", ".env", ".venv", "venv", "node_modules", "vendor", "site-packages", "__pycache__"}
SECRET_NAME = re.compile(r"(?i)(api[_-]?key|access[_-]?token|password|passwd|secret|authorization)\s*[:=]\s*(['\"]?)([^\s,'\"}]+)\2")
BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")
HIGH_ENTROPY = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9+/=_-]{32,}(?![A-Za-z0-9])")


@dataclass(frozen=True)
class EvidenceSlice:
    span: EvidenceSpan
    content: str
    redactions: int
    untrusted: bool = True

    def to_dict(self) -> dict[str, object]:
        return {"span": self.span.to_dict(), "content": self.content, "redactions": self.redactions, "untrusted": self.untrusted}


def redact_secrets(text: str) -> tuple[str, int]:
    count = 0

    def named(match: re.Match[str]) -> str:
        nonlocal count
        count += 1
        return f"{match.group(1)}=<REDACTED>"

    text = SECRET_NAME.sub(named, text)
    for pattern in (BEARER,):
        text, replaced = pattern.subn("<REDACTED>", text)
        count += replaced
    def entropy(match: re.Match[str]) -> str:
        nonlocal count
        value = match.group(0)
        left, separator, right = value.partition("=")
        if separator and left == right and left.isidentifier():
            return value
        count += 1
        return "<REDACTED>"
    text = HIGH_ENTROPY.sub(entropy, text)
    return text, count


def slice_file(repo: Path, relative_path: str, start_line: int, end_line: int, *, cloud: bool, max_bytes: int = 32_768) -> EvidenceSlice:
    relative = safe_relative_path(relative_path)
    if any(part in EXCLUDED_PARTS or part.lower().startswith(".env") for part in relative.parts):
        raise ValueError(f"excluded evidence path: {relative_path}")
    root = repo.resolve()
    target = root.joinpath(*relative.parts)
    if target.is_symlink() or not target.is_file() or not target.resolve().is_relative_to(root):
        raise ValueError("evidence must be a regular in-repository file")
    raw_lines = target.read_bytes().splitlines(keepends=True)
    if start_line < 1 or end_line < start_line or end_line > len(raw_lines):
        raise ValueError("invalid evidence line range")
    raw = b"".join(raw_lines[start_line - 1 : end_line])
    if len(raw) > max_bytes:
        raise ValueError("evidence slice exceeds byte budget")
    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("evidence is not UTF-8 source text") from exc
    redactions = 0
    if cloud:
        content, redactions = redact_secrets(content)
    span = EvidenceSpan(relative.as_posix(), start_line, end_line, hashlib.sha256(raw).hexdigest())
    return EvidenceSlice(span, content, redactions)
