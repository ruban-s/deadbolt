from __future__ import annotations

import hashlib
import json

import pytest

import deadbolt as db
from _helpers import fast_hasher
from deadbolt.plugins.haveibeenpwned import haveibeenpwned

pytestmark = pytest.mark.anyio


def fake_hibp(breached: set[str], *, count: str = "42"):
    """A stub HIBP range endpoint that reports ``breached`` passwords as pwned."""

    async def fetch(prefix: str) -> str:
        lines = ["FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:1"]  # decoy, never matches
        for password in breached:
            digest = hashlib.sha1(password.encode()).hexdigest().upper()  # noqa: S324
            if digest[:5] == prefix:
                lines.append(f"{digest[5:]}:{count}")
        return "\r\n".join(lines)

    return fetch


def build_auth(fetch) -> db.Auth:
    return db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=fast_hasher(),
        plugins=[haveibeenpwned(fetch=fetch)],
    )


def post(path: str, body: object, cookies: dict[str, str] | None = None) -> db.AuthRequest:
    return db.AuthRequest(
        method="POST", path=path, body=json.dumps(body).encode(), cookies=cookies or {}
    )


async def test_breached_password_rejected_on_signup() -> None:
    auth = build_auth(fake_hibp({"hunter2pw"}))
    resp = await auth.handle(post("/sign-up/email", {"email": "a@b.com", "password": "hunter2pw"}))
    assert resp.status == 400
    assert json.loads(resp.body)["error"]["code"] == "pwned_password"


async def test_safe_password_allowed() -> None:
    auth = build_auth(fake_hibp({"hunter2pw"}))
    resp = await auth.handle(
        post("/sign-up/email", {"email": "a@b.com", "password": "a-long-unique-passphrase"})
    )
    assert resp.status == 200


async def test_padding_entries_with_zero_count_not_treated_as_breach() -> None:
    # HIBP padding rows carry count 0 — they must not count as a hit.
    auth = build_auth(fake_hibp({"a-long-unique-passphrase"}, count="0"))
    resp = await auth.handle(
        post("/sign-up/email", {"email": "a@b.com", "password": "a-long-unique-passphrase"})
    )
    assert resp.status == 200


async def test_breached_password_rejected_on_change_password() -> None:
    auth = build_auth(fake_hibp({"breached-new-pw"}))
    signup = await auth.handle(
        post("/sign-up/email", {"email": "a@b.com", "password": "a-long-unique-passphrase"})
    )
    cookies = {c.name: c.value for c in signup.cookies if c.value}
    resp = await auth.handle(
        post(
            "/change-password",
            {"current_password": "a-long-unique-passphrase", "new_password": "breached-new-pw"},
            cookies,
        )
    )
    assert resp.status == 400
    assert json.loads(resp.body)["error"]["code"] == "pwned_password"
