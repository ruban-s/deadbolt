"""The plugin primitive: extend deadbolt with endpoints and schema."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..db.types import TableSpec
    from ..endpoints.registry import Endpoint
    from ..hooks import Hook


@dataclass(frozen=True)
class Plugin:
    """A unit of extension contributing endpoints, hooks, and, optionally, tables."""

    id: str
    endpoints: tuple[Endpoint, ...] = ()
    schema: tuple[TableSpec, ...] = field(default_factory=tuple)
    before: tuple[Hook, ...] = ()
    after: tuple[Hook, ...] = ()


__all__ = ["Plugin"]
