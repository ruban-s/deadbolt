from __future__ import annotations

import json

import pytest

import deadbolt as db
from _helpers import fast_hasher
from deadbolt.plugins.one_time_token import one_time_token

pytestmark = pytest.mark.anyio


def build_auth(*, expires_in: int = 60) -> db.Auth:
    return db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=fast_hasher(),
        plugins=[one_time_token(expires_in=expires_in)],
    )


def post(path: str, body: object, cookies: dict[str, str] | None = None) -> db.AuthRequest:
    return db.AuthRequest(
        method="POST", path=path, body=json.dumps(body).encode(), cookies=cookies or {}
    )


async def sign_up(auth: db.Auth) -> dict[str, str]:
    resp = await auth.handle(post("/sign-up/email", {"email": "a@b.com", "password": "hunter2pw"}))
    return {c.name: c.value for c in resp.cookies if c.value}


async def generate(auth: db.Auth, cookies: dict[str, str]) -> str:
    resp = await auth.handle(post("/one-time-token/generate", {}, cookies))
    assert resp.status == 200
    return str(json.loads(resp.body)["token"])


async def test_generate_then_verify_yields_session() -> None:
    auth = build_auth()
    cookies = await sign_up(auth)
    token = await generate(auth, cookies)

    verified = await auth.handle(post("/one-time-token/verify", {"token": token}))
    assert verified.status == 200
    assert json.loads(verified.body)["user"]["email"] == "a@b.com"
    new_session = next(c for c in verified.cookies if c.value)

    # The minted session actually works.
    who = await auth.handle(
        db.AuthRequest(
            method="GET", path="/get-session", cookies={new_session.name: new_session.value}
        )
    )
    assert json.loads(who.body)["user"]["email"] == "a@b.com"


async def test_token_is_single_use() -> None:
    auth = build_auth()
    token = await generate(auth, await sign_up(auth))
    first = await auth.handle(post("/one-time-token/verify", {"token": token}))
    assert first.status == 200
    second = await auth.handle(post("/one-time-token/verify", {"token": token}))
    assert second.status == 401
    assert json.loads(second.body)["error"]["code"] == "invalid_token"


async def test_expired_token_rejected() -> None:
    auth = build_auth(expires_in=-1)
    token = await generate(auth, await sign_up(auth))
    resp = await auth.handle(post("/one-time-token/verify", {"token": token}))
    assert resp.status == 401


async def test_generate_requires_session() -> None:
    auth = build_auth()
    resp = await auth.handle(post("/one-time-token/generate", {}))
    assert resp.status == 401


async def test_unknown_token_rejected() -> None:
    auth = build_auth()
    resp = await auth.handle(post("/one-time-token/verify", {"token": "nope"}))
    assert resp.status == 401
