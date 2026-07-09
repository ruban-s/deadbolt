from __future__ import annotations

import json

import pytest

import deadbolt as db
from _helpers import fast_hasher
from deadbolt.http import MultiDict
from deadbolt.plugins.bearer import bearer

pytestmark = pytest.mark.anyio


def build_auth() -> db.Auth:
    return db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=fast_hasher(),
        plugins=[bearer()],
    )


def post(path: str, body: object) -> db.AuthRequest:
    return db.AuthRequest(method="POST", path=path, body=json.dumps(body).encode())


def with_bearer(method: str, path: str, token: str) -> db.AuthRequest:
    return db.AuthRequest(
        method=method, path=path, headers=MultiDict([("authorization", f"Bearer {token}")])
    )


async def sign_up(auth: db.Auth) -> db.AuthResponse:
    return await auth.handle(post("/sign-up/email", {"email": "a@b.com", "password": "hunter2pw"}))


async def test_sign_up_exposes_token_header() -> None:
    auth = build_auth()
    resp = await sign_up(auth)
    assert resp.status == 200
    token = resp.headers.get("set-auth-token")
    assert token is not None and token != ""


async def test_bearer_token_authenticates_without_cookie() -> None:
    auth = build_auth()
    token = (await sign_up(auth)).headers.get("set-auth-token")
    assert token is not None

    session = await auth.handle(with_bearer("GET", "/get-session", token))
    assert session.status == 200
    assert json.loads(session.body)["user"]["email"] == "a@b.com"


async def test_missing_token_is_unauthorized() -> None:
    auth = build_auth()
    await sign_up(auth)
    resp = await auth.handle(db.AuthRequest(method="GET", path="/get-session"))
    assert json.loads(resp.body) == {"session": None, "user": None}


async def test_tampered_token_is_rejected() -> None:
    auth = build_auth()
    token = (await sign_up(auth)).headers.get("set-auth-token")
    assert token is not None

    forged = await auth.handle(with_bearer("GET", "/get-session", token + "tamper"))
    assert json.loads(forged.body) == {"session": None, "user": None}


async def test_revoked_token_stops_working() -> None:
    auth = build_auth()
    token = (await sign_up(auth)).headers.get("set-auth-token")
    assert token is not None

    signout = await auth.handle(with_bearer("POST", "/sign-out", token))
    assert signout.status == 200

    after = await auth.handle(with_bearer("GET", "/get-session", token))
    assert json.loads(after.body) == {"session": None, "user": None}


async def test_cookie_takes_precedence_over_bearer() -> None:
    auth = build_auth()
    resp = await sign_up(auth)
    cookie = next(c for c in resp.cookies if c.value)

    request = db.AuthRequest(
        method="GET",
        path="/get-session",
        cookies={cookie.name: cookie.value},
        headers=MultiDict([("authorization", "Bearer garbage")]),
    )
    session = await auth.handle(request)
    assert json.loads(session.body)["user"]["email"] == "a@b.com"
