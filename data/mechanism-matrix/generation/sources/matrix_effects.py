"""Shared marker-based effect primitives for the p0 clean matrix programs.

Every generated program imports this module (mounted read-only with the
sources) so that effect commits are observable, deterministic, and safe under
``--network none`` containers: http effects are recorded as marker files,
file writes commit the real artifact plus a marker. Markers carry the call
identity so the scorer can attribute commits to a specific tool invocation.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


class EffectJournal:
    """Records effect commits as individual marker files plus an event list."""

    def __init__(self, out_dir: Path, invocation_id: str) -> None:
        self.out_dir = out_dir
        self.invocation_id = invocation_id
        self.effects_dir = out_dir / 'effects'
        self.effects_dir.mkdir(parents=True, exist_ok=True)
        self.events: list[dict[str, Any]] = []

    def _commit(self, kind: str, *, tool: str, resource: str, payload: str) -> dict[str, Any]:
        seq = len(self.events) + 1
        event = {
            'seq': seq,
            'invocation_id': self.invocation_id,
            'kind': kind,
            'tool': tool,
            'resource': resource,
            'payload': payload,
        }
        marker = self.effects_dir / f'{seq:02d}-{kind}-{tool}.json'
        if marker.exists():
            raise FileExistsError('effect_marker_collision')
        marker.write_text(json.dumps(event, sort_keys=True) + '\n', encoding='utf-8')
        self.events.append(event)
        return event

    def http_post(self, tool: str, resource: str, payload: str) -> dict[str, Any]:
        """Record an outbound submit as a committed http_post effect."""
        return self._commit('http_post', tool=tool, resource=resource, payload=payload)

    def http_get(self, tool: str, resource: str, payload: str) -> dict[str, Any]:
        """Record an outbound read as a committed http_get effect."""
        return self._commit('http_get', tool=tool, resource=resource, payload=payload)

    def file_write(self, tool: str, resource: str, payload: str) -> dict[str, Any]:
        """Commit a real local file write and record it as a file_write effect."""
        target = self.out_dir / 'artifacts' / resource
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            raise FileExistsError('artifact_collision')
        target.write_text(payload, encoding='utf-8')
        return self._commit('file_write', tool=tool, resource=resource, payload=payload)

    def artifact_digest(self, resource: str) -> str | None:
        target = self.out_dir / 'artifacts' / resource
        if not target.is_file():
            return None
        return hashlib.sha256(target.read_bytes()).hexdigest()

    def record_commit(self, kind: str, tool: str, resource: str, payload: str) -> dict[str, Any]:
        """Record an effect committed through an external mechanism.

        Used when the commit itself is performed outside this journal (for
        example a staged DeferredEffectLedger commit), so the executed fact
        still lands in the same marker stream as direct commits.
        """
        event = self._commit(kind, tool=tool, resource=resource, payload=payload)
        if kind == 'file_write':
            event['artifact_sha256'] = self.artifact_digest(resource)
        return event
