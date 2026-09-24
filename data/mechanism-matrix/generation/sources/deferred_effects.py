from __future__ import annotations

import functools
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


@dataclass
class _EffectTransaction:
    pending_effects: list[PendingTextWrite | PendingMakeDirectory] = field(default_factory=list)
    applied_count: int = 0
    state: str = "open"


class DeferredEffectLedger:
    """Stage supported effects until the enclosing guard contract accepts."""

    def __init__(self) -> None:
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
            "process_crash_recovery": False,
            "cross_backend_atomicity": False,
        }

    def _current(self) -> _EffectTransaction:
        return self._active.get() or self._legacy

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
        transaction.pending_effects.append(PendingTextWrite(Path(path), data, encoding, errors, newline))

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
        transaction.pending_effects.append(PendingMakeDirectory(Path(path), mode, parents, exist_ok))

    @property
    def pending_count(self) -> int:
        transaction = self._current()
        return len(transaction.pending_effects) - transaction.applied_count

    def _commit(self, transaction: _EffectTransaction) -> int:
        if transaction.state == "committed":
            return 0
        if transaction.state == "aborted":
            return 0
        if transaction.state not in {"open", "failed"}:
            raise RuntimeError(f"cannot commit a {transaction.state} transaction")
        started_at = transaction.applied_count
        transaction.state = "committing"
        try:
            while transaction.applied_count < len(transaction.pending_effects):
                effect = transaction.pending_effects[transaction.applied_count]
                if isinstance(effect, PendingMakeDirectory):
                    effect.path.mkdir(mode=effect.mode, parents=effect.parents, exist_ok=effect.exist_ok)
                else:
                    effect.path.write_text(
                        effect.data,
                        encoding=effect.encoding,
                        errors=effect.errors,
                        newline=effect.newline,
                    )
                transaction.applied_count += 1
        except BaseException:
            transaction.state = "failed"
            raise
        transaction.state = "committed"
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
