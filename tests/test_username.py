from __future__ import annotations

import json

import pytest

import deadbolt as db
from _helpers import fast_hasher
from deadbolt.plugins.username import username

pytestmark = pytest.mark.anyio


def build_auth() -> db.Auth:
    return db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=fast_hasher(),
        plugins=[username()],
    )


def post(path: str, body: object, cookies: dict[str, str] | None = None) -> db.AuthRequest:
    return db.AuthRequest(
        method="POST", path=path, body=json.dumps(body).encode(), cookies=cookies or {}
    )


async def signup(auth: db.Auth, email: str = "a@b.com") -> dict[str, str]:
    resp = await auth.handle(post("/sign-up/email", {"email": email, "password": "hunter2pw"}))
    return {c.name: c.value for c in resp.cookies if c.value}


async def test_set_and_sign_in() -> None:
    auth = build_auth()
    cookies = await signup(auth)
    set_resp = await auth.handle(post("/username/set", {"username": "Alice_01"}, cookies))
    assert json.loads(set_resp.body)["username"] == "Alice_01"

    ok = await auth.handle(
        post("/sign-in/username", {"username": "alice_01", "password": "hunter2pw"})
    )
    assert ok.status == 200
    assert json.loads(ok.body)["user"]["email"] == "a@b.com"


async def test_wrong_password_rejected() -> None:
    auth = build_auth()
    cookies = await signup(auth)
    await auth.handle(post("/username/set", {"username": "alice"}, cookies))
    bad = await auth.handle(
        post("/sign-in/username", {"username": "alice", "password": "wrongpass"})
    )
    assert bad.status == 401


async def test_unknown_username_rejected() -> None:
    auth = build_auth()
    resp = await auth.handle(
        post("/sign-in/username", {"username": "ghost", "password": "hunter2pw"})
    )
    assert resp.status == 401
    assert json.loads(resp.body)["error"]["code"] == "invalid_credentials"


async def test_invalid_username_format() -> None:
    auth = build_auth()
    cookies = await signup(auth)
    resp = await auth.handle(post("/username/set", {"username": "no"}, cookies))
    assert resp.status == 400
    assert json.loads(resp.body)["error"]["code"] == "invalid_username"


async def test_username_taken() -> None:
    auth = build_auth()
    a = await signup(auth, "a@b.com")
    b = await signup(auth, "b@b.com")
    await auth.handle(post("/username/set", {"username": "shared"}, a))
    resp = await auth.handle(post("/username/set", {"username": "SHARED"}, b))
    assert resp.status == 409


async def test_availability() -> None:
    auth = build_auth()
    cookies = await signup(auth)
    await auth.handle(post("/username/set", {"username": "taken"}, cookies))

    taken = await auth.handle(
        db.AuthRequest(
            method="GET",
            path="/username/available",
            query=db.http.MultiDict([("username", "taken")]),
        )
    )
    assert json.loads(taken.body)["available"] is False
    free = await auth.handle(
        db.AuthRequest(
            method="GET",
            path="/username/available",
            query=db.http.MultiDict([("username", "free_name")]),
        )
    )
    assert json.loads(free.body)["available"] is True


async def test_change_username() -> None:
    auth = build_auth()
    cookies = await signup(auth)
    await auth.handle(post("/username/set", {"username": "first"}, cookies))
    await auth.handle(post("/username/set", {"username": "second"}, cookies))
    old = await auth.handle(
        post("/sign-in/username", {"username": "first", "password": "hunter2pw"})
    )
    assert old.status == 401
    new = await auth.handle(
        post("/sign-in/username", {"username": "second", "password": "hunter2pw"})
    )
    assert new.status == 200


async def test_set_requires_session() -> None:
    auth = build_auth()
    resp = await auth.handle(post("/username/set", {"username": "x"}))
    assert resp.status == 401
