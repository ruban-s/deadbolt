from __future__ import annotations

import json

import pytest

import deadbolt as db
from _helpers import fast_hasher
from deadbolt.plugins.jwt import jwt

pytestmark = pytest.mark.anyio


def build_auth(*, expires_in: int = 900) -> db.Auth:
    return db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=fast_hasher(),
        plugins=[jwt(expires_in=expires_in)],
    )


def post(path: str, body: object, cookies: dict[str, str] | None = None) -> db.AuthRequest:
    return db.AuthRequest(
        method="POST", path=path, body=json.dumps(body).encode(), cookies=cookies or {}
    )


async def signup(auth: db.Auth) -> dict[str, str]:
    resp = await auth.handle(post("/sign-up/email", {"email": "a@b.com", "password": "hunter2pw"}))
    return {c.name: c.value for c in resp.cookies if c.value}


async def test_issue_and_verify() -> None:
    auth = build_auth()
    cookies = await signup(auth)
    issued = await auth.handle(db.AuthRequest(method="GET", path="/token", cookies=cookies))
    assert issued.status == 200
    token = json.loads(issued.body)["token"]
    assert token.count(".") == 2

    verified = await auth.handle(post("/token/verify", {"token": token}))
    assert verified.status == 200
    body = json.loads(verified.body)
    assert body["valid"] is True
    assert body["claims"]["email"] == "a@b.com"


async def test_issue_requires_session() -> None:
    auth = build_auth()
    resp = await auth.handle(db.AuthRequest(method="GET", path="/token"))
    assert resp.status == 401


async def test_verify_rejects_garbage() -> None:
    auth = build_auth()
    resp = await auth.handle(post("/token/verify", {"token": "not.a.jwt"}))
    assert resp.status == 401
    assert json.loads(resp.body)["error"]["code"] == "invalid_token"


async def test_verify_rejects_expired() -> None:
    auth = build_auth(expires_in=-1)
    cookies = await signup(auth)
    issued = await auth.handle(db.AuthRequest(method="GET", path="/token", cookies=cookies))
    token = json.loads(issued.body)["token"]
    verified = await auth.handle(post("/token/verify", {"token": token}))
    assert verified.status == 401


async def test_token_from_other_secret_rejected() -> None:
    auth = build_auth()
    cookies = await signup(auth)
    token = json.loads(
        (await auth.handle(db.AuthRequest(method="GET", path="/token", cookies=cookies))).body
    )["token"]

    other = db.Auth(
        adapter=db.MemoryAdapter(),
        secret="y" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=fast_hasher(),
        plugins=[jwt()],
    )
    resp = await other.handle(post("/token/verify", {"token": token}))
    assert resp.status == 401
