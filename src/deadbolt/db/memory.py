"""In-memory adapter for tests and local development."""

from __future__ import annotations

import copy
from typing import TYPE_CHECKING, Any

from .types import AdapterConfig

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from .types import Row, SortBy, TableSpec, Where

_COMPARATORS: dict[str, Callable[[Any, Any], bool]] = {
    "eq": lambda a, e: bool(a == e),
    "ne": lambda a, e: bool(a != e),
    "in": lambda a, e: a in e,
    "lt": lambda a, e: bool(a < e),
    "lte": lambda a, e: bool(a <= e),
    "gt": lambda a, e: bool(a > e),
    "gte": lambda a, e: bool(a >= e),
    "contains": lambda a, e: e in a,
    "starts_with": lambda a, e: str(a).startswith(str(e)),
    "ends_with": lambda a, e: str(a).endswith(str(e)),
}
_NULL_SAFE = frozenset({"eq", "ne", "in"})


def _matches(row: Row, condition: Where) -> bool:
    actual = row.get(condition.field)
    if actual is None and condition.operator not in _NULL_SAFE:
        return False
    try:
        comparator = _COMPARATORS[condition.operator]
    except KeyError as error:  # pragma: no cover - guards runtime misuse of the Operator type
        raise ValueError(f"unsupported operator: {condition.operator}") from error
    return comparator(actual, condition.value)


def _row_matches(row: Row, where: Sequence[Where]) -> bool:
    ands = [c for c in where if c.connector == "AND"]
    ors = [c for c in where if c.connector == "OR"]
    if not all(_matches(row, c) for c in ands):
        return False
    return not ors or any(_matches(row, c) for c in ors)


def _project(row: Row, select: Sequence[str] | None) -> Row:
    if select is None:
        return copy.deepcopy(row)
    return {k: copy.deepcopy(v) for k, v in row.items() if k in select}


class MemoryAdapter:
    """A dict-backed :class:`~deadbolt.protocols.AsyncDatabaseAdapter`."""

    def __init__(self) -> None:
        self.config = AdapterConfig(
            adapter_id="memory",
            adapter_name="Memory",
            supports_json=True,
            supports_dates=True,
            supports_booleans=True,
        )
        self._tables: dict[str, list[Row]] = {}

    def _rows(self, model: str) -> list[Row]:
        return self._tables.setdefault(model, [])

    async def create(self, *, model: str, data: Row, select: Sequence[str] | None = None) -> Row:
        stored = copy.deepcopy(data)
        self._rows(model).append(stored)
        return _project(stored, select)

    async def find_one(
        self, *, model: str, where: Sequence[Where], select: Sequence[str] | None = None
    ) -> Row | None:
        for row in self._rows(model):
            if _row_matches(row, where):
                return _project(row, select)
        return None

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
        rows = [r for r in self._rows(model) if _row_matches(r, where)]
        if sort_by is not None:
            rows.sort(
                key=lambda r: _sort_key(r.get(sort_by.field)),
                reverse=sort_by.direction == "desc",
            )
        if offset:
            rows = rows[offset:]
        if limit is not None:
            rows = rows[:limit]
        return [_project(r, select) for r in rows]

    async def update(self, *, model: str, where: Sequence[Where], update: Row) -> Row | None:
        for row in self._rows(model):
            if _row_matches(row, where):
                row.update(copy.deepcopy(update))
                return copy.deepcopy(row)
        return None

    async def update_many(self, *, model: str, where: Sequence[Where], update: Row) -> int:
        count = 0
        for row in self._rows(model):
            if _row_matches(row, where):
                row.update(copy.deepcopy(update))
                count += 1
        return count

    async def delete(self, *, model: str, where: Sequence[Where]) -> None:
        rows = self._rows(model)
        for i, row in enumerate(rows):
            if _row_matches(row, where):
                del rows[i]
                return

    async def delete_many(self, *, model: str, where: Sequence[Where]) -> int:
        rows = self._rows(model)
        kept = [r for r in rows if not _row_matches(r, where)]
        removed = len(rows) - len(kept)
        self._tables[model] = kept
        return removed

    async def count(self, *, model: str, where: Sequence[Where] = ()) -> int:
        return sum(1 for r in self._rows(model) if _row_matches(r, where))

    async def create_schema(self, *, tables: Sequence[TableSpec], file: str | None = None) -> str:
        return ""


def _sort_key(value: object) -> tuple[int, object]:
    return (0, value) if value is not None else (-1, "")
