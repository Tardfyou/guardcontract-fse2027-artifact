"""Bounded LLM augmentation for GuardContract auditing and patch proposals."""

from guardcontract.backends.base import BackendError, DeterministicUnknownBackend, FakeBackend, OpenAICompatibleBackend
from guardcontract.core.schemas import EvidenceJob, FindingEnvelope, PatchEnvelope, RepairJob, SchemaError
from guardcontract.evidence.artifacts import write_patch_bundle
from guardcontract.pipeline.merge import hypothesis_record

__all__ = [
    "BackendError",
    "DeterministicUnknownBackend",
    "EvidenceJob",
    "FakeBackend",
    "FindingEnvelope",
    "OpenAICompatibleBackend",
    "PatchEnvelope",
    "RepairJob",
    "SchemaError",
    "hypothesis_record",
    "write_patch_bundle",
]
