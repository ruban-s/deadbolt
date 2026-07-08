"""SQLAlchemy 2.0 Core async adapter. Requires ``deadbolt[sqlalchemy]``.

Implemented in Phase 1. Importing this module requires SQLAlchemy; the top-level
``deadbolt`` package never imports it eagerly.
"""

from __future__ import annotations

from typing import Any


class SQLAlchemyAdapter:
    """A SQLAlchemy Core-backed async adapter over Postgres/MySQL/SQLite."""

    def __init__(self, engine: Any) -> None:
        self.engine = engine
        raise NotImplementedError("SQLAlchemy adapter lands in Phase 1.")
