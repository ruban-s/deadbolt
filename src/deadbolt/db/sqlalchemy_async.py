"""SQLAlchemy 2.0 Core async adapter. Requires ``deadbolt[sqlalchemy]``.

Importing this module requires SQLAlchemy; the top-level ``deadbolt`` package
never imports it eagerly.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    Integer,
    MetaData,
    Table,
    Text,
    and_,
    func,
    or_,
    true,
)
from sqlalchemy import delete as sql_delete
from sqlalchemy import insert as sql_insert
from sqlalchemy import select as sql_select
from sqlalchemy import update as sql_update

from ..models import CORE_TABLES
from .types import AdapterConfig

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from sqlalchemy import ColumnElement
    from sqlalchemy.ext.asyncio import AsyncEngine
    from sqlalchemy.sql import Select

    from .types import Row, SortBy, TableSpec, Where

_COLUMN_TYPES = {
    "string": Text,
    "number": Integer,
    "boolean": Boolean,
    "date": Text,
    "json": JSON,
}


class SQLAlchemyAdapter:
    """A SQLAlchemy Core-backed async adapter over Postgres/MySQL/SQLite.

    Dates are stored as ISO-8601 strings so timezone-aware values round-trip
    identically across every dialect.
    """

    def __init__(self, engine: AsyncEngine, *, schema: Sequence[TableSpec] = CORE_TABLES) -> None:
        self.config = AdapterConfig(
            adapter_id="sqlalchemy",
            adapter_name="SQLAlchemy",
            supports_json=True,
            supports_dates=False,
            supports_booleans=True,
        )
        self._engine = engine
        self._metadata = MetaData()
        self._tables = {spec.model: self._build_table(spec) for spec in schema}
        self._date_fields = {
            spec.model: {name for name, field in spec.fields.items() if field.type == "date"}
            for spec in schema
        }

    def _build_table(self, spec: TableSpec) -> Table:
        columns: list[Column[Any]] = [
            Column(
                field.field_name or name,
                _COLUMN_TYPES[field.type],
                primary_key=name == "id",
                unique=field.unique and name != "id",
                nullable=not field.required,
            )
            for name, field in spec.fields.items()
        ]
        return Table(spec.model, self._metadata, *columns)

    def _table(self, model: str) -> Table:
        return self._tables[model]

    async def create_schema(self, *, tables: Sequence[TableSpec], file: str | None = None) -> str:
        async with self._engine.begin() as conn:
            await conn.run_sync(self._metadata.create_all)
        return ""

    async def create(self, *, model: str, data: Row, select: Sequence[str] | None = None) -> Row:
        table = self._table(model)
        async with self._engine.begin() as conn:
            await conn.execute(sql_insert(table).values(self._encode(model, data)))
        return dict(data)

    async def find_one(
        self, *, model: str, where: Sequence[Where], select: Sequence[str] | None = None
    ) -> Row | None:
        stmt = self._select(model, where).limit(1)
        async with self._engine.connect() as conn:
            row = (await conn.execute(stmt)).mappings().first()
        return self._decode(model, dict(row)) if row is not None else None

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
        stmt = self._select(model, where)
        if sort_by is not None:
            column = self._table(model).c[sort_by.field]
            stmt = stmt.order_by(column.desc() if sort_by.direction == "desc" else column.asc())
        if offset:
            stmt = stmt.offset(offset)
        if limit is not None:
            stmt = stmt.limit(limit)
        async with self._engine.connect() as conn:
            rows = (await conn.execute(stmt)).mappings().all()
        return [self._decode(model, dict(row)) for row in rows]

    async def update(self, *, model: str, where: Sequence[Where], update: Row) -> Row | None:
        values = self._encode(model, update)
        if not values:
            return await self.find_one(model=model, where=where)
        stmt = sql_update(self._table(model)).where(self._clause(model, where)).values(values)
        async with self._engine.begin() as conn:
            if (await conn.execute(stmt)).rowcount == 0:
                return None
        return await self.find_one(model=model, where=where)

    async def update_many(self, *, model: str, where: Sequence[Where], update: Row) -> int:
        values = self._encode(model, update)
        if not values:
            return await self.count(model=model, where=where)
        stmt = sql_update(self._table(model)).where(self._clause(model, where)).values(values)
        async with self._engine.begin() as conn:
            return (await conn.execute(stmt)).rowcount

    async def delete(self, *, model: str, where: Sequence[Where]) -> None:
        table = self._table(model)
        async with self._engine.begin() as conn:
            await conn.execute(sql_delete(table).where(self._clause(model, where)))

    async def delete_many(self, *, model: str, where: Sequence[Where]) -> int:
        table = self._table(model)
        async with self._engine.begin() as conn:
            result = await conn.execute(sql_delete(table).where(self._clause(model, where)))
            return result.rowcount

    async def count(self, *, model: str, where: Sequence[Where] = ()) -> int:
        table = self._table(model)
        stmt = sql_select(func.count()).select_from(table).where(self._clause(model, where))
        async with self._engine.connect() as conn:
            return (await conn.execute(stmt)).scalar_one()

    def _select(self, model: str, where: Sequence[Where]) -> Select[Any]:
        return sql_select(self._table(model)).where(self._clause(model, where))

    def _clause(self, model: str, where: Sequence[Where]) -> ColumnElement[bool]:
        table = self._table(model)
        dates = self._date_fields[model]
        ands = [self._condition(table, c, dates) for c in where if c.connector == "AND"]
        ors = [self._condition(table, c, dates) for c in where if c.connector == "OR"]
        clause: ColumnElement[bool] = and_(true(), *ands)
        if ors:
            clause = and_(clause, or_(*ors))
        return clause

    @staticmethod
    def _condition(table: Table, condition: Where, dates: set[str]) -> ColumnElement[bool]:
        column = table.c[condition.field]
        value = condition.value
        if condition.field in dates and isinstance(value, datetime):
            value = value.isoformat()
        builders: dict[str, Callable[[], ColumnElement[bool]]] = {
            "eq": lambda: column == value,
            "ne": lambda: column != value,
            "lt": lambda: column < value,
            "lte": lambda: column <= value,
            "gt": lambda: column > value,
            "gte": lambda: column >= value,
            "in": lambda: column.in_(value),
            "contains": lambda: column.like(f"%{value}%"),
            "starts_with": lambda: column.like(f"{value}%"),
            "ends_with": lambda: column.like(f"%{value}"),
        }
        return builders[condition.operator]()

    def _encode(self, model: str, data: Row) -> Row:
        dates = self._date_fields[model]
        return {
            k: v.isoformat() if k in dates and isinstance(v, datetime) else v
            for k, v in data.items()
        }

    def _decode(self, model: str, row: Row) -> Row:
        dates = self._date_fields[model]
        return {
            k: datetime.fromisoformat(v) if k in dates and isinstance(v, str) else v
            for k, v in row.items()
        }
