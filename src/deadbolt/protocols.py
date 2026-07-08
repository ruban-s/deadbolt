"""Structural interfaces for deadbolt's pluggable backends.

Implementers conform by shape (``typing.Protocol``); they need not inherit from
these. See ``docs/ARCHITECTURE.md`` for the semantics each method must uphold.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Sequence

    from .db.types import AdapterConfig, Row, SortBy, TableSpec, Where


@runtime_checkable
class AsyncDatabaseAdapter(Protocol):
    config: AdapterConfig

    async def create(
        self, *, model: str, data: Row, select: Sequence[str] | None = None
    ) -> Row: ...

    async def find_one(
        self, *, model: str, where: Sequence[Where], select: Sequence[str] | None = None
    ) -> Row | None: ...

    async def find_many(
        self,
        *,
        model: str,
        where: Sequence[Where] = (),
        limit: int | None = None,
        offset: int | None = None,
        sort_by: SortBy | None = None,
        select: Sequence[str] | None = None,
    ) -> list[Row]: ...

    async def update(self, *, model: str, where: Sequence[Where], update: Row) -> Row | None: ...

    async def update_many(self, *, model: str, where: Sequence[Where], update: Row) -> int: ...

    async def delete(self, *, model: str, where: Sequence[Where]) -> None: ...

    async def delete_many(self, *, model: str, where: Sequence[Where]) -> int: ...

    async def count(self, *, model: str, where: Sequence[Where] = ()) -> int: ...

    async def create_schema(
        self, *, tables: Sequence[TableSpec], file: str | None = None
    ) -> str: ...


@runtime_checkable
class Hasher(Protocol):
    """Password hashing with a rehash-on-verify upgrade path."""

    async def hash(self, password: str) -> str: ...

    async def verify(self, hashed: str, password: str) -> bool: ...

    def needs_rehash(self, hashed: str) -> bool: ...


@runtime_checkable
class SessionStore(Protocol):
    """Optional secondary store for cached sessions (e.g. Redis)."""

    async def get(self, key: str) -> bytes | None: ...

    async def set(self, key: str, value: bytes, ttl: int) -> None: ...

    async def delete(self, key: str) -> None: ...


@runtime_checkable
class EmailSender(Protocol):
    """Delivers verification and password-reset messages."""

    async def send(self, *, to: str, subject: str, body: str) -> None: ...


@runtime_checkable
class SmsSender(Protocol):
    """Delivers SMS one-time codes (used by the phone-number plugin)."""

    async def send_sms(self, *, to: str, body: str) -> None: ...
