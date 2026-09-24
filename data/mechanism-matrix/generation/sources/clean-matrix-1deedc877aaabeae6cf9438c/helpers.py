"""Indirected helpers: the effect commit lives one import hop away."""
from __future__ import annotations


def commit_protected(journal) -> None:
    journal.http_post('emit_log_entry', 'https://internal.example/api/records', 'clean-matrix-inert-payload')


def commit_unprotected(journal) -> None:
    journal.http_post('mirror_notes', 'https://internal.example/api/notes', 'clean-matrix-inert-payload')
