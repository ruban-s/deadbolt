from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Sequence

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


def _basic_auth(trusted_origins: Sequence[str] = ()) -> db.Auth:
    return db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=fast_hasher(),
        trusted_origins=trusted_origins,
    )


def _signup(origin: str | None = None, base_url: str | None = None) -> db.AuthRequest:
    headers = db.http.MultiDict([("origin", origin)]) if origin else db.http.MultiDict()
    return db.AuthRequest(
        method="POST",
        path="/sign-up/email",
        headers=headers,
        body=json.dumps({"email": "a@b.com", "password": "hunter2pw"}).encode(),
        base_url=base_url,
    )


async def test_untrusted_origin_rejected() -> None:
    auth = _basic_auth()
    resp = await auth.handle(_signup(origin="https://evil.com", base_url="https://app.com"))
    assert resp.status == 403
    assert json.loads(resp.body)["error"]["code"] == "untrusted_origin"


async def test_same_origin_allowed() -> None:
    auth = _basic_auth()
    resp = await auth.handle(_signup(origin="https://app.com", base_url="https://app.com/api"))
    assert resp.status == 200


async def test_configured_trusted_origin_allowed() -> None:
    auth = _basic_auth(trusted_origins=["https://trusted.com"])
    resp = await auth.handle(_signup(origin="https://trusted.com", base_url="https://app.com"))
    assert resp.status == 200


async def test_wildcard_trusted_origin() -> None:
    auth = _basic_auth(trusted_origins=["chrome-extension://*"])
    resp = await auth.handle(
        _signup(origin="chrome-extension://abc123", base_url="https://app.com")
    )
    assert resp.status == 200


async def test_missing_origin_allowed() -> None:
    auth = _basic_auth()
    resp = await auth.handle(_signup(base_url="https://app.com"))
    assert resp.status == 200


def _signin(ip: str | None) -> db.AuthRequest:
    return db.AuthRequest(
        method="POST",
        path="/sign-in/email",
        body=json.dumps({"email": "a@b.com", "password": "hunter2pw"}).encode(),
        client_ip=ip,
    )


def _limited_auth(ip_rules: db.RateLimit) -> db.Auth:
    return db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=fast_hasher(),
        rate_limit=ip_rules,
    )


async def test_rate_limit_blocks_after_max() -> None:
    rule = db.RateLimitRule("/sign-in/email", max=2, window=60)
    auth = _limited_auth(db.RateLimit(rules=(rule,)))
    assert (await auth.handle(_signin("1.2.3.4"))).status == 401
    assert (await auth.handle(_signin("1.2.3.4"))).status == 401
    blocked = await auth.handle(_signin("1.2.3.4"))
    assert blocked.status == 429
    assert json.loads(blocked.body)["error"]["code"] == "rate_limited"


async def test_rate_limit_is_per_client() -> None:
    rule = db.RateLimitRule("/sign-in/email", max=1, window=60)
    auth = _limited_auth(db.RateLimit(rules=(rule,)))
    assert (await auth.handle(_signin("1.1.1.1"))).status == 401
    assert (await auth.handle(_signin("1.1.1.1"))).status == 429
    assert (await auth.handle(_signin("2.2.2.2"))).status == 401


async def test_rate_limit_can_be_disabled() -> None:
    auth = _limited_auth(db.RateLimit(enabled=False))
    for _ in range(5):
        assert (await auth.handle(_signin("1.2.3.4"))).status == 401


async def test_rate_limit_window_resets() -> None:
    from deadbolt.ratelimit import MemoryRateLimitStore  # noqa: PLC0415

    clock = {"t": 0.0}
    store = MemoryRateLimitStore(now=lambda: clock["t"])
    assert await store.increment("k", window=60) == 1
    assert await store.increment("k", window=60) == 2
    clock["t"] = 61.0
    assert await store.increment("k", window=60) == 1


async def test_body_size_limit() -> None:
    auth = db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=fast_hasher(),
        max_body_bytes=50,
    )
    oversized = db.AuthRequest(method="POST", path="/sign-in/email", body=b"x" * 100)
    resp = await auth.handle(oversized)
    assert resp.status == 413
    assert json.loads(resp.body)["error"]["code"] == "payload_too_large"


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
