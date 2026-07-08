from __future__ import annotations

import json

import pytest

import deadbolt as db
from _helpers import fast_hasher
from deadbolt.crypto import hash_token
from deadbolt.db import Where
from deadbolt.plugins.magic_link import magic_link

pytestmark = pytest.mark.anyio


class CountingHasher:
    def __init__(self) -> None:
        self.inner = fast_hasher()
        self.verify_calls = 0

    async def hash(self, password: str) -> str:
        return await self.inner.hash(password)

    async def verify(self, hashed: str, password: str) -> bool:
        self.verify_calls += 1
        return await self.inner.verify(hashed, password)

    def needs_rehash(self, hashed: str) -> bool:
        return False


class CapturingEmail:
    def __init__(self) -> None:
        self.token: str | None = None

    async def send(self, *, to: str, subject: str, body: str) -> None:
        self.token = body.rsplit(":", 1)[1].strip()


def post(path: str, body: object) -> db.AuthRequest:
    return db.AuthRequest(method="POST", path=path, body=json.dumps(body).encode())


async def test_sign_in_hashes_even_for_unknown_user() -> None:
    hasher = CountingHasher()
    auth = db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=hasher,
    )
    resp = await auth.handle(
        post("/sign-in/email", {"email": "ghost@b.com", "password": "whatever1"})
    )
    assert resp.status == 401
    assert hasher.verify_calls == 1


async def test_reset_token_is_hashed_at_rest() -> None:
    email = CapturingEmail()
    auth = db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=fast_hasher(),
        email_sender=email,
    )
    await auth.handle(post("/sign-up/email", {"email": "a@b.com", "password": "hunter2pw"}))
    await auth.handle(post("/request-password-reset", {"email": "a@b.com"}))

    assert email.token is not None
    record = await auth.adapter.find_one(
        model="verification", where=[Where("value", hash_token(email.token))]
    )
    assert record is not None
    assert record["value"] != email.token
    reset = await auth.handle(
        post("/reset-password", {"token": email.token, "new_password": "newpass99"})
    )
    assert reset.status == 200


async def test_magic_token_is_hashed_at_rest() -> None:
    email = CapturingEmail()
    auth = db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=fast_hasher(),
        email_sender=email,
        plugins=[magic_link()],
    )
    await auth.handle(post("/magic-link/send", {"email": "a@b.com"}))
    assert email.token is not None
    record = await auth.adapter.find_one(
        model="verification", where=[Where("value", hash_token(email.token))]
    )
    assert record is not None
    assert record["value"] != email.token
