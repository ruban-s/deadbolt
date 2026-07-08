"""Database adapters and the portable query/schema primitives."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .memory import MemoryAdapter
from .types import (
    AdapterConfig,
    Connector,
    FieldSpec,
    FieldType,
    Operator,
    Row,
    SortBy,
    TableSpec,
    Where,
)

if TYPE_CHECKING:
    from .sqlalchemy_async import SQLAlchemyAdapter

__all__ = [
    "AdapterConfig",
    "Connector",
    "FieldSpec",
    "FieldType",
    "MemoryAdapter",
    "Operator",
    "Row",
    "SQLAlchemyAdapter",
    "SortBy",
    "TableSpec",
    "Where",
]


def __getattr__(name: str) -> Any:
    if name == "SQLAlchemyAdapter":
        from .sqlalchemy_async import SQLAlchemyAdapter  # noqa: PLC0415

        return SQLAlchemyAdapter
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
