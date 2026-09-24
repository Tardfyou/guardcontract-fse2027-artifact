from __future__ import annotations

import functools
import os
import secrets
from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable


@dataclass(frozen=True)
class PendingTextWrite:
    path: Path
    data: str
    encoding: str | None = None
    errors: str | None = None
    newline: str | None = None


@dataclass(frozen=True)
class PendingMakeDirectory:
    path: Path
    mode: int = 0o777
    parents: bool = False
    exist_ok: bool = False


@dataclass(frozen=True)
class PendingBytesWrite:
    path: Path
    data: bytes


@dataclass
class _EffectTransaction:
    pending_effects: list[PendingTextWrite | PendingMakeDirectory | PendingBytesWrite] = field(default_factory=list)
    applied_count: int = 0
    state: str = "open"


class DeferredEffectLedger:
    """Stage supported effects until the enclosing guard contract accepts."""

    def __init__(self, *, allowed_roots: tuple[str | Path, ...] | None = None,
                 max_pending_effects: int = 256, max_pending_bytes: int = 64 * 1024 * 1024) -> None:
        if max_pending_effects < 1 or max_pending_bytes < 1:
            raise ValueError("deferred effect budgets must be positive")
        self._allowed_roots = (tuple(Path(root).resolve() for root in allowed_roots)
                               if allowed_roots is not None else None)
        if self._allowed_roots is not None and not self._allowed_roots:
            raise ValueError("allowed_roots cannot be empty")
        self._max_pending_effects = max_pending_effects
        self._max_pending_bytes = max_pending_bytes
        self._legacy = _EffectTransaction()
        self._active: ContextVar[_EffectTransaction | None] = ContextVar(
            f"guardcontract_deferred_effects_{id(self)}", default=None
        )

    @property
    def capabilities(self) -> dict[str, bool]:
        return {
            "async_scope_isolation": True,
            "nested_scope_single_commit": True,
            "duplicate_commit_idempotence": True,
            "ordered_filesystem_effects": True,
            "binary_write_staging": True,
            "strict_resource_boundary": self._allowed_roots is not None,
            "bounded_pending_memory": True,
            "filesystem_application_failure_rollback": True,
            "process_crash_recovery": False,
            "cross_backend_atomicity": False,
        }

    def _current(self) -> _EffectTransaction:
        return self._active.get() or self._legacy

    def _path(self, value: str | Path) -> Path:
        path = Path(value)
        if self._allowed_roots is None:
            return path
        resolved = path.resolve(strict=False)
        matching = [root for root in self._allowed_roots
                    if resolved == root or resolved.is_relative_to(root)]
        if not matching:
            raise ValueError("deferred effect target is outside allowed roots")
        root = max(matching, key=lambda item: len(item.parts))
        cursor = resolved
        while cursor != root:
            if cursor.exists() and cursor.is_symlink():
                raise ValueError("deferred effect target traverses a symlink")
            cursor = cursor.parent
        return resolved

    @staticmethod
    def _effect_bytes(effect: PendingTextWrite | PendingMakeDirectory | PendingBytesWrite) -> int:
        if isinstance(effect, PendingBytesWrite):
            return len(effect.data)
        if isinstance(effect, PendingTextWrite):
            return len(effect.data.encode(effect.encoding or "utf-8", effect.errors or "strict"))
        return 0

    def _append(self, transaction: _EffectTransaction,
                effect: PendingTextWrite | PendingMakeDirectory | PendingBytesWrite) -> None:
        if len(transaction.pending_effects) >= self._max_pending_effects:
            raise ValueError("deferred effect count budget exceeded")
        pending_bytes = sum(self._effect_bytes(item) for item in transaction.pending_effects)
        if pending_bytes + self._effect_bytes(effect) > self._max_pending_bytes:
            raise ValueError("deferred effect byte budget exceeded")
        transaction.pending_effects.append(effect)

    def stage_text_write(
        self,
        path: str | Path,
        data: str,
        *,
        encoding: str | None = None,
        errors: str | None = None,
        newline: str | None = None,
    ) -> None:
        transaction = self._current()
        if transaction is self._legacy and transaction.state in {"committed", "aborted"}:
            self._legacy = _EffectTransaction()
            transaction = self._legacy
        if transaction.state != "open":
            raise RuntimeError(f"cannot stage an effect in a {transaction.state} transaction")
        self._append(transaction, PendingTextWrite(self._path(path), data, encoding, errors, newline))

    def stage_bytes_write(self, path: str | Path, data: bytes | bytearray | memoryview) -> None:
        transaction = self._current()
        if transaction is self._legacy and transaction.state in {"committed", "aborted"}:
            self._legacy = _EffectTransaction(); transaction = self._legacy
        if transaction.state != "open":
            raise RuntimeError(f"cannot stage an effect in a {transaction.state} transaction")
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("binary deferred effect data must be bytes-like")
        self._append(transaction, PendingBytesWrite(self._path(path), bytes(data)))

    def stage_mkdir(
        self,
        path: str | Path,
        mode: int = 0o777,
        parents: bool = False,
        exist_ok: bool = False,
    ) -> None:
        transaction = self._current()
        if transaction is self._legacy and transaction.state in {"committed", "aborted"}:
            self._legacy = _EffectTransaction()
            transaction = self._legacy
        if transaction.state != "open":
            raise RuntimeError(f"cannot stage an effect in a {transaction.state} transaction")
        self._append(transaction, PendingMakeDirectory(self._path(path), mode, parents, exist_ok))

    @property
    def pending_count(self) -> int:
        transaction = self._current()
        return len(transaction.pending_effects) - transaction.applied_count

    @property
    def pending_bytes(self) -> int:
        transaction = self._current()
        return sum(self._effect_bytes(effect)
                   for effect in transaction.pending_effects[transaction.applied_count:])

    def _commit(self, transaction: _EffectTransaction) -> int:
        if transaction.state == "committed":
            return 0
        if transaction.state == "aborted":
            return 0
        if transaction.state not in {"open", "failed"}:
            raise RuntimeError(f"cannot commit a {transaction.state} transaction")
        started_at = transaction.applied_count
        transaction.state = "committing"
        applied: list[tuple[str, Path, Path | None] | tuple[str, list[Path], None]] = []
        temporary_paths: list[Path] = []

        def temporary(target: Path, role: str) -> Path:
            for _ in range(32):
                candidate = target.parent / (
                    f".{target.name}.guardcontract-{role}-{secrets.token_hex(8)}")
                if not candidate.exists() and not candidate.is_symlink():
                    temporary_paths.append(candidate)
                    return candidate
            raise RuntimeError("cannot allocate deferred effect temporary path")

        def apply_write(effect: PendingTextWrite | PendingBytesWrite) -> None:
            target = effect.path
            if not target.parent.is_dir():
                raise FileNotFoundError(f"deferred effect parent does not exist: {target.parent}")
            if target.is_symlink() or target.exists() and not target.is_file():
                raise ValueError("deferred effect write target is not a regular file")
            staged = temporary(target, "staged")
            if isinstance(effect, PendingBytesWrite):
                staged.write_bytes(effect.data)
            else:
                staged.write_text(effect.data, encoding=effect.encoding,
                                  errors=effect.errors, newline=effect.newline)
            backup = None
            if target.exists():
                backup = temporary(target, "backup")
                os.replace(target, backup)
            try:
                os.replace(staged, target)
            except BaseException:
                if backup is not None and backup.exists():
                    os.replace(backup, target)
                raise
            applied.append(("write", target, backup))

        def apply_directory(effect: PendingMakeDirectory) -> None:
            missing = []
            cursor = effect.path
            while not cursor.exists():
                missing.append(cursor)
                if not effect.parents:
                    break
                cursor = cursor.parent
            effect.path.mkdir(mode=effect.mode, parents=effect.parents,
                              exist_ok=effect.exist_ok)
            created = [path for path in reversed(missing) if path.exists()]
            applied.append(("directories", created, None))

        def rollback() -> list[BaseException]:
            errors = []
            for path in temporary_paths:
                if "guardcontract-staged" not in path.name:
                    continue
                try:
                    path.unlink(missing_ok=True)
                except BaseException as exc:
                    errors.append(exc)
            for kind, target, backup in reversed(applied):
                try:
                    if kind == "write":
                        target.unlink(missing_ok=True)
                        if backup is not None and backup.exists():
                            os.replace(backup, target)
                    else:
                        for directory in reversed(target):
                            directory.rmdir()
                except BaseException as exc:
                    errors.append(exc)
            for path in temporary_paths:
                try:
                    path.unlink(missing_ok=True)
                except BaseException as exc:
                    errors.append(exc)
            return errors

        try:
            while transaction.applied_count < len(transaction.pending_effects):
                effect = transaction.pending_effects[transaction.applied_count]
                self._path(effect.path)
                if isinstance(effect, PendingMakeDirectory):
                    apply_directory(effect)
                else:
                    apply_write(effect)
                transaction.applied_count += 1
        except BaseException as exc:
            rollback_errors = rollback()
            transaction.applied_count = started_at
            transaction.state = "failed"
            if rollback_errors:
                raise ExceptionGroup("deferred effect commit and rollback failed",
                                     [exc, *rollback_errors]) from exc
            raise
        transaction.state = "committed"
        for kind, _target, backup in applied:
            if kind == "write" and backup is not None:
                backup.unlink(missing_ok=True)
        return transaction.applied_count - started_at

    def commit(self) -> int:
        if self._active.get() is not None:
            raise RuntimeError("an active deferred-effect scope can only be committed by its owner")
        return self._commit(self._legacy)

    def _abort(self, transaction: _EffectTransaction) -> int:
        if transaction.state == "committed":
            return 0
        remaining = len(transaction.pending_effects) - transaction.applied_count
        transaction.pending_effects.clear()
        transaction.applied_count = 0
        transaction.state = "aborted"
        return remaining

    def abort(self) -> int:
        if self._active.get() is not None:
            raise RuntimeError("an active deferred-effect scope can only be aborted by its owner")
        count = self._abort(self._legacy)
        self._legacy = _EffectTransaction()
        return count

    def _begin_scope(
        self,
    ) -> tuple[_EffectTransaction, Token[_EffectTransaction | None] | None, bool]:
        current = self._active.get()
        if current is not None:
            if current.state != "open":
                raise RuntimeError(f"cannot nest inside a {current.state} transaction")
            return current, None, False
        transaction = _EffectTransaction()
        token = self._active.set(transaction)
        return transaction, token, True

    def _end_scope(self, token: Token[_EffectTransaction | None] | None) -> None:
        if token is not None:
            self._active.reset(token)


def deferred_effect_scope(function: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
    @functools.wraps(function)
    async def wrapped(owner: Any, *args: Any, **kwargs: Any) -> Any:
        ledger = owner.context.deferred_effects
        transaction, token, is_root = ledger._begin_scope()
        try:
            result = await function(owner, *args, **kwargs)
            if is_root:
                ledger._commit(transaction)
            return result
        except BaseException:
            if is_root and transaction.state in {"open", "failed"}:
                ledger._abort(transaction)
            raise
        finally:
            if is_root:
                ledger._end_scope(token)

    return wrapped
