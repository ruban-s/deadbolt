"""Argon2id password hashing with a rehash-on-verify upgrade path."""

from __future__ import annotations

import anyio
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError


class Argon2Hasher:
    """A :class:`~deadbolt.protocols.Hasher` backed by ``argon2-cffi``.

    Hashing runs in a worker thread so it never blocks the event loop.
    """

    def __init__(self, hasher: PasswordHasher | None = None) -> None:
        self._ph = hasher or PasswordHasher()

    async def hash(self, password: str) -> str:
        return await anyio.to_thread.run_sync(self._ph.hash, password)

    async def verify(self, hashed: str, password: str) -> bool:
        try:
            return await anyio.to_thread.run_sync(self._ph.verify, hashed, password)
        except (VerificationError, InvalidHashError):
            return False

    def needs_rehash(self, hashed: str) -> bool:
        return self._ph.check_needs_rehash(hashed)
