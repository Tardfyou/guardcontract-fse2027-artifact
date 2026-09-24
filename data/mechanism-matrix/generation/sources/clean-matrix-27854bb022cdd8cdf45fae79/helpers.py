"""Indirected helpers: the effect commit lives one import hop away."""
from __future__ import annotations


def commit_protected(journal) -> None:
    journal.file_write('emit_log_entry', 'records/primary-record.json', 'clean-matrix-inert-payload')


def commit_unprotected(journal) -> None:
    journal.file_write('mirror_notes', 'records/scratch-notes.txt', 'clean-matrix-inert-payload')
