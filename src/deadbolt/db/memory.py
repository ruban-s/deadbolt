"""In-memory adapter for tests and local development. Implemented in Phase 1."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .types import AdapterConfig

if TYPE_CHECKING:
    from collections.abc import Sequence

    from .types import Row, SortBy, TableSpec, Where


class MemoryAdapter:
    """A dict-backed :class:`~deadbolt.protocols.AsyncDatabaseAdapter`."""

    def __init__(self) -> None:
        self.config = AdapterConfig(adapter_id="memory", adapter_name="Memory")

    async def create(self, *, model: str, data: Row, select: Sequence[str] | None = None) -> Row:
        raise NotImplementedError

    async def find_one(
        self, *, model: str, where: Sequence[Where], select: Sequence[str] | None = None
    ) -> Row | None:
        raise NotImplementedError

    async def find_many(
        self,
        *,
        model: str,
        where: Sequence[Where] = (),
        limit: int | None = None,
        offset: int | None = None,
        sort_by: SortBy | None = None,
        select: Sequence[str] | None = None,
    ) -> list[Row]:
        raise NotImplementedError

    async def update(self, *, model: str, where: Sequence[Where], update: Row) -> Row | None:
        raise NotImplementedError

    async def update_many(self, *, model: str, where: Sequence[Where], update: Row) -> int:
        raise NotImplementedError

    async def delete(self, *, model: str, where: Sequence[Where]) -> None:
        raise NotImplementedError

    async def delete_many(self, *, model: str, where: Sequence[Where]) -> int:
        raise NotImplementedError

    async def count(self, *, model: str, where: Sequence[Where] = ()) -> int:
        raise NotImplementedError

    async def create_schema(self, *, tables: Sequence[TableSpec], file: str | None = None) -> str:
        raise NotImplementedError
