"""Portable query and schema primitives shared by every database adapter."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Operator = Literal[
    "eq", "ne", "lt", "lte", "gt", "gte", "in", "contains", "starts_with", "ends_with"
]
Connector = Literal["AND", "OR"]
FieldType = Literal["string", "number", "boolean", "date", "json"]

Row = dict[str, Any]


@dataclass(frozen=True)
class Where:
    """A single filter condition, combined with others by ``connector``."""

    field: str
    value: Any
    operator: Operator = "eq"
    connector: Connector = "AND"


@dataclass(frozen=True)
class SortBy:
    field: str
    direction: Literal["asc", "desc"] = "asc"


@dataclass(frozen=True)
class FieldSpec:
    """A column definition, including deadbolt's custom-field attributes."""

    type: FieldType
    required: bool = False
    unique: bool = False
    default_value: Any = None
    input: bool = True
    references: str | None = None
    field_name: str | None = None


@dataclass(frozen=True)
class TableSpec:
    """A logical table assembled from core, plugin, and user fields."""

    model: str
    fields: dict[str, FieldSpec] = field(default_factory=dict)


@dataclass(frozen=True)
class AdapterConfig:
    """Capability flags the shared adapter factory reads to shape transforms."""

    adapter_id: str
    adapter_name: str
    supports_json: bool = False
    supports_dates: bool = True
    supports_booleans: bool = True
    supports_numeric_ids: bool = True
    use_plural: bool = False
    supports_transactions: bool = True
