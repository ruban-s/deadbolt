from __future__ import annotations

import uuid
from datetime import UTC, datetime


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id() -> str:
    return uuid.uuid4().hex
