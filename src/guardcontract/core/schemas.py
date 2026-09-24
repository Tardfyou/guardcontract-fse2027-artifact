from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar, Mapping


SCHEMA_VERSION = "57-1"


class SchemaError(ValueError):
    pass


def _object(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SchemaError(f"{label} must be an object")
    return value


def _closed(data: Mapping[str, Any], required: set[str], optional: set[str], label: str) -> None:
    missing = required - data.keys()
    unknown = data.keys() - required - optional
    if missing:
        raise SchemaError(f"{label} missing fields: {sorted(missing)}")
    if unknown:
        raise SchemaError(f"{label} has unknown fields: {sorted(unknown)}")


def _text(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        raise SchemaError(f"{label} must be a non-empty string")
    return value


def _enum(value: Any, allowed: set[str], label: str) -> str:
    value = _text(value, label)
    if value not in allowed:
        raise SchemaError(f"{label} must be one of {sorted(allowed)}")
    return value


def _strings(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise SchemaError(f"{label} must be a string array")
    return tuple(value)


@dataclass(frozen=True)
class EvidenceSpan:
    path: str
    start_line: int
    end_line: int
    sha256: str

    @classmethod
    def from_dict(cls, value: Any) -> "EvidenceSpan":
        data = _object(value, "evidence span")
        _closed(data, {"path", "start_line", "end_line", "sha256"}, set(), "evidence span")
        start, end = data["start_line"], data["end_line"]
        if not isinstance(start, int) or isinstance(start, bool) or start < 1:
            raise SchemaError("start_line must be a positive integer")
        if not isinstance(end, int) or isinstance(end, bool) or end < start:
            raise SchemaError("end_line must be at least start_line")
        digest = _text(data["sha256"], "sha256")
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise SchemaError("sha256 must be 64 lowercase hexadecimal characters")
        return cls(_text(data["path"], "path"), start, end, digest)

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "start_line": self.start_line, "end_line": self.end_line, "sha256": self.sha256}


@dataclass(frozen=True)
class PathEdge:
    source: str
    target: str
    kind: str
    evidence: tuple[EvidenceSpan, ...]

    KINDS: ClassVar[set[str]] = {
        "binds", "calls", "dispatches", "hands_off_to", "reads_config",
        "precedes", "may_precede", "dominates", "produces_effect",
    }

    @classmethod
    def from_dict(cls, value: Any) -> "PathEdge":
        data = _object(value, "path edge")
        _closed(data, {"from", "to", "kind", "evidence"}, set(), "path edge")
        evidence = data["evidence"]
        if not isinstance(evidence, list) or not evidence:
            raise SchemaError("path edge evidence must be a non-empty array")
        return cls(
            _text(data["from"], "from"), _text(data["to"], "to"),
            _enum(data["kind"], cls.KINDS, "edge kind"),
            tuple(EvidenceSpan.from_dict(item) for item in evidence),
        )

    def to_dict(self) -> dict[str, Any]:
        return {"from": self.source, "to": self.target, "kind": self.kind, "evidence": [item.to_dict() for item in self.evidence]}


@dataclass(frozen=True)
class EffectClaim:
    family: str
    retractability: str
    evidence: tuple[EvidenceSpan, ...]

    FAMILIES: ClassVar[set[str]] = {"filesystem", "network", "database", "subprocess", "browser", "message", "unknown"}
    RETRACTABILITY: ClassVar[set[str]] = {"none", "transactional", "compensatable", "unknown"}

    @classmethod
    def from_dict(cls, value: Any) -> "EffectClaim":
        data = _object(value, "effect")
        _closed(data, {"family", "retractability", "evidence"}, set(), "effect")
        evidence = data["evidence"]
        if not isinstance(evidence, list) or not evidence:
            raise SchemaError("effect evidence must be a non-empty array")
        return cls(_enum(data["family"], cls.FAMILIES, "effect family"), _enum(data["retractability"], cls.RETRACTABILITY, "retractability"), tuple(EvidenceSpan.from_dict(item) for item in evidence))

    def to_dict(self) -> dict[str, Any]:
        return {"family": self.family, "retractability": self.retractability, "evidence": [item.to_dict() for item in self.evidence]}


@dataclass(frozen=True)
class EvidenceJob:
    job_id: str
    repository_id: str
    question: str
    allowed_nodes: tuple[str, ...]
    evidence: tuple[EvidenceSpan, ...]
    max_response_bytes: int
    mode: str
    schema_version: str = SCHEMA_VERSION

    @classmethod
    def from_dict(cls, value: Any) -> "EvidenceJob":
        data = _object(value, "evidence job")
        required = {"schema_version", "job_id", "repository_id", "question", "allowed_nodes", "evidence", "max_response_bytes", "mode"}
        _closed(data, required, set(), "evidence job")
        if data["schema_version"] != SCHEMA_VERSION:
            raise SchemaError("unsupported schema_version")
        evidence = data["evidence"]
        if not isinstance(evidence, list) or not evidence:
            raise SchemaError("job evidence must be a non-empty array")
        limit = data["max_response_bytes"]
        if not isinstance(limit, int) or isinstance(limit, bool) or not 256 <= limit <= 1_000_000:
            raise SchemaError("max_response_bytes must be between 256 and 1000000")
        allowed_nodes = _strings(data["allowed_nodes"], "allowed_nodes")
        if not allowed_nodes or len(set(allowed_nodes)) != len(allowed_nodes):
            raise SchemaError("allowed_nodes must be non-empty and unique")
        return cls(_text(data["job_id"], "job_id"), _text(data["repository_id"], "repository_id"), _text(data["question"], "question"), allowed_nodes, tuple(EvidenceSpan.from_dict(item) for item in evidence), limit, _enum(data["mode"], {"local", "cloud"}, "mode"))

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": self.schema_version, "job_id": self.job_id, "repository_id": self.repository_id, "question": self.question, "allowed_nodes": list(self.allowed_nodes), "evidence": [item.to_dict() for item in self.evidence], "max_response_bytes": self.max_response_bytes, "mode": self.mode}


@dataclass(frozen=True)
class FindingEnvelope:
    job_id: str
    finding_id: str
    claim: str
    verdict: str
    source_spans: tuple[EvidenceSpan, ...]
    path_edges: tuple[PathEdge, ...]
    effect: EffectClaim | None
    assumptions: tuple[str, ...]
    validation_requests: tuple[str, ...]
    schema_version: str = SCHEMA_VERSION

    @classmethod
    def from_dict(cls, value: Any) -> "FindingEnvelope":
        data = _object(value, "finding")
        required = {"schema_version", "job_id", "finding_id", "claim", "verdict", "source_spans", "path_edges", "effect", "assumptions", "validation_requests"}
        _closed(data, required, set(), "finding")
        if data["schema_version"] != SCHEMA_VERSION:
            raise SchemaError("unsupported schema_version")
        spans, edges = data["source_spans"], data["path_edges"]
        if not isinstance(spans, list) or not isinstance(edges, list):
            raise SchemaError("source_spans and path_edges must be arrays")
        verdict = _enum(data["verdict"], {"supported", "refuted", "unknown"}, "verdict")
        if verdict == "supported" and not spans:
            raise SchemaError("supported findings require source_spans")
        effect = None if data["effect"] is None else EffectClaim.from_dict(data["effect"])
        return cls(_text(data["job_id"], "job_id"), _text(data["finding_id"], "finding_id"), _enum(data["claim"], {"binding", "effect", "ordering", "repair"}, "claim"), verdict, tuple(EvidenceSpan.from_dict(item) for item in spans), tuple(PathEdge.from_dict(item) for item in edges), effect, _strings(data["assumptions"], "assumptions"), _strings(data["validation_requests"], "validation_requests"))

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": self.schema_version, "job_id": self.job_id, "finding_id": self.finding_id, "claim": self.claim, "verdict": self.verdict, "source_spans": [item.to_dict() for item in self.source_spans], "path_edges": [item.to_dict() for item in self.path_edges], "effect": self.effect.to_dict() if self.effect else None, "assumptions": list(self.assumptions), "validation_requests": list(self.validation_requests)}


@dataclass(frozen=True)
class RepairJob:
    job_id: str
    repository_id: str
    base_revision: str
    repair_plan: Mapping[str, Any]
    allowed_paths: tuple[str, ...]
    max_files: int
    max_changed_lines: int
    evidence: tuple[EvidenceSpan, ...]
    mode: str
    schema_version: str = SCHEMA_VERSION

    @classmethod
    def from_dict(cls, value: Any) -> "RepairJob":
        data = _object(value, "repair job")
        required = {"schema_version", "job_id", "repository_id", "base_revision", "repair_plan", "allowed_paths", "max_files", "max_changed_lines", "evidence", "mode"}
        _closed(data, required, set(), "repair job")
        if data["schema_version"] != SCHEMA_VERSION:
            raise SchemaError("unsupported schema_version")
        if not isinstance(data["repair_plan"], Mapping):
            raise SchemaError("repair_plan must be an object")
        max_files, max_lines = data["max_files"], data["max_changed_lines"]
        if not isinstance(max_files, int) or isinstance(max_files, bool) or not 1 <= max_files <= 20:
            raise SchemaError("max_files must be between 1 and 20")
        if not isinstance(max_lines, int) or isinstance(max_lines, bool) or not 1 <= max_lines <= 5000:
            raise SchemaError("max_changed_lines must be between 1 and 5000")
        evidence = data["evidence"]
        if not isinstance(evidence, list) or not evidence:
            raise SchemaError("repair evidence must be a non-empty array")
        return cls(_text(data["job_id"], "job_id"), _text(data["repository_id"], "repository_id"), _text(data["base_revision"], "base_revision"), dict(data["repair_plan"]), _strings(data["allowed_paths"], "allowed_paths"), max_files, max_lines, tuple(EvidenceSpan.from_dict(item) for item in evidence), _enum(data["mode"], {"local", "cloud"}, "mode"))

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": self.schema_version, "job_id": self.job_id, "repository_id": self.repository_id, "base_revision": self.base_revision, "repair_plan": dict(self.repair_plan), "allowed_paths": list(self.allowed_paths), "max_files": self.max_files, "max_changed_lines": self.max_changed_lines, "evidence": [item.to_dict() for item in self.evidence], "mode": self.mode}


@dataclass(frozen=True)
class PatchEnvelope:
    job_id: str
    base_revision: str
    unified_diff: str
    touched_paths: tuple[str, ...]
    residual_risks: tuple[str, ...]
    schema_version: str = SCHEMA_VERSION

    @classmethod
    def from_dict(cls, value: Any) -> "PatchEnvelope":
        data = _object(value, "patch")
        required = {"schema_version", "job_id", "base_revision", "unified_diff", "touched_paths", "residual_risks"}
        _closed(data, required, set(), "patch")
        if data["schema_version"] != SCHEMA_VERSION:
            raise SchemaError("unsupported schema_version")
        diff = _text(data["unified_diff"], "unified_diff")
        if not diff.startswith("diff --git "):
            raise SchemaError("unified_diff must start with a git diff header")
        return cls(_text(data["job_id"], "job_id"), _text(data["base_revision"], "base_revision"), diff, _strings(data["touched_paths"], "touched_paths"), _strings(data["residual_risks"], "residual_risks"))

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": self.schema_version, "job_id": self.job_id, "base_revision": self.base_revision, "unified_diff": self.unified_diff, "touched_paths": list(self.touched_paths), "residual_risks": list(self.residual_risks)}
