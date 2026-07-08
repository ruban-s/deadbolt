from __future__ import annotations

from typing import Any

from argon2 import PasswordHasher

import deadbolt as db
from deadbolt.crypto import Argon2Hasher
from deadbolt.db import MemoryAdapter


def fast_hasher() -> Argon2Hasher:
    """A low-memory Argon2 hasher for tests, so the suite stays fast and light."""
    return Argon2Hasher(PasswordHasher(time_cost=1, memory_cost=8, parallelism=1))


def build_auth(**kw: Any) -> db.Auth:
    kw.setdefault("email_and_password", db.EmailPassword(enabled=True))
    kw.setdefault("hasher", fast_hasher())
    return db.Auth(adapter=MemoryAdapter(), secret="x" * 32, **kw)
