from __future__ import annotations

import json
from typing import Any

import pytest

import deadbolt as db
from deadbolt.core.config import CookieConfig, SessionConfig
from deadbolt.crypto import CookieSigner
from deadbolt.db import MemoryAdapter, Where
from deadbolt.session import SessionManager

pytestmark = pytest.mark.anyio


class RehashHasher:
    async def hash(self, password: str) -> str:
        return f"h:{password}"

    async def verify(self, hashed: str, password: str) -> bool:
        return hashed == f"h:{password}"

    def needs_rehash(self, hashed: str) -> bool:
        return True


def build_auth(**kw: Any) -> db.Auth:
    return db.Auth(
        adapter=MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        **kw,
    )


def req(
    method: str,
    path: str,
    *,
    body: dict[str, Any] | None = None,
    cookies: dict[str, str] | None = None,
) -> db.AuthRequest:
    return db.AuthRequest(
        method=method,
        path=path,
        body=json.dumps(body).encode() if body is not None else None,
        cookies=cookies or {},
    )


async def test_non_host_cookie_name_and_domain() -> None:
    sm = SessionManager(
        adapter=MemoryAdapter(),
        signer=CookieSigner("s" * 32),
        config=SessionConfig(),
        cookie=CookieConfig(host_prefix=False, secure=False, domain="example.com"),
    )
    assert sm.cookie_name == "session"
    cookie = sm.build_cookie("tok")
    assert cookie.domain == "example.com"


async def test_clear_cookie_expires_immediately() -> None:
    sm = SessionManager(
        adapter=MemoryAdapter(),
        signer=CookieSigner("s" * 32),
        config=SessionConfig(),
        cookie=CookieConfig(),
    )
    cleared = sm.clear_cookie()
    assert cleared.value == ""
    assert cleared.max_age == 0


async def test_rehash_on_sign_in_updates_stored_hash() -> None:
    auth = build_auth(hasher=RehashHasher())
    await auth.handle(
        req("POST", "/sign-up/email", body={"email": "a@b.com", "password": "hunter2pw"})
    )
    account_before = await auth.adapter.find_one(
        model="account", where=[Where("account_id", "a@b.com")]
    )
    assert account_before is not None
    updated_at_before = account_before["updated_at"]

    resp = await auth.handle(
        req("POST", "/sign-in/email", body={"email": "a@b.com", "password": "hunter2pw"})
    )
    assert resp.status == 200
    account_after = await auth.adapter.find_one(
        model="account", where=[Where("account_id", "a@b.com")]
    )
    assert account_after is not None
    assert account_after["updated_at"] >= updated_at_before


async def test_change_password_revokes_other_sessions() -> None:
    auth = build_auth()
    first = await auth.handle(
        req("POST", "/sign-up/email", body={"email": "a@b.com", "password": "hunter2pw"})
    )
    cookie_a = {c.name: c.value for c in first.cookies}
    second = await auth.handle(
        req("POST", "/sign-in/email", body={"email": "a@b.com", "password": "hunter2pw"})
    )
    cookie_b = {c.name: c.value for c in second.cookies}

    changed = await auth.handle(
        req(
            "POST",
            "/change-password",
            cookies=cookie_a,
            body={
                "current_password": "hunter2pw",
                "new_password": "newpass99",
                "revoke_other_sessions": True,
            },
        )
    )
    assert changed.status == 200
    assert changed.cookies

    stale = await auth.handle(req("GET", "/get-session", cookies=cookie_b))
    assert json.loads(stale.body)["user"] is None


async def test_get_session_when_user_deleted() -> None:
    auth = build_auth()
    signed_up = await auth.handle(
        req("POST", "/sign-up/email", body={"email": "a@b.com", "password": "hunter2pw"})
    )
    cookies = {c.name: c.value for c in signed_up.cookies}
    await auth.adapter.delete(model="user", where=[Where("email", "a@b.com")])

    resp = await auth.handle(req("GET", "/get-session", cookies=cookies))
    assert json.loads(resp.body) == {"session": None, "user": None}


async def test_memory_update_many_and_no_match() -> None:
    adapter = MemoryAdapter()
    for i in range(3):
        await adapter.create(model="t", data={"id": str(i), "flag": False})
    changed = await adapter.update_many(model="t", where=[], update={"flag": True})
    assert changed == 3
    assert await adapter.update(model="t", where=[Where("id", "missing")], update={}) is None
    assert await adapter.delete_many(model="t", where=[Where("id", "missing")]) == 0
    assert await adapter.find_one(model="t", where=[Where("id", "0")], select=["id"]) == {"id": "0"}


async def test_memory_delete_no_match_is_noop() -> None:
    adapter = MemoryAdapter()
    await adapter.create(model="t", data={"id": "1"})
    await adapter.delete(model="t", where=[Where("id", "nope")])
    assert await adapter.count(model="t") == 1
