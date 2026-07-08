from __future__ import annotations

import json

import pytest

import deadbolt as db
from _helpers import fast_hasher
from deadbolt.plugins.api_keys import api_keys

pytestmark = pytest.mark.anyio


def build_auth() -> db.Auth:
    return db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=fast_hasher(),
        plugins=[api_keys()],
    )


def post(path: str, body: object, cookies: dict[str, str] | None = None) -> db.AuthRequest:
    return db.AuthRequest(
        method="POST", path=path, body=json.dumps(body).encode(), cookies=cookies or {}
    )


async def signup(auth: db.Auth) -> dict[str, str]:
    resp = await auth.handle(post("/sign-up/email", {"email": "a@b.com", "password": "hunter2pw"}))
    return {c.name: c.value for c in resp.cookies if c.value}


async def create_key(auth: db.Auth, cookies: dict[str, str]) -> tuple[str, str]:
    resp = await auth.handle(post("/api-key/create", {"name": "ci"}, cookies))
    body = json.loads(resp.body)
    return body["key"], body["api_key"]["id"]


async def test_create_and_verify() -> None:
    auth = build_auth()
    cookies = await signup(auth)
    key, _ = await create_key(auth, cookies)
    assert key.startswith("dbk_")

    resp = await auth.handle(post("/api-key/verify", {"key": key}))
    assert resp.status == 200
    assert json.loads(resp.body)["valid"] is True


async def test_key_is_hashed_at_rest() -> None:
    auth = build_auth()
    cookies = await signup(auth)
    key, _ = await create_key(auth, cookies)
    stored = (await auth.adapter.find_many(model="api_key"))[0]["key"]
    assert stored != key


async def test_list_hides_secret() -> None:
    auth = build_auth()
    cookies = await signup(auth)
    await create_key(auth, cookies)
    listed = await auth.handle(db.AuthRequest(method="GET", path="/api-key/list", cookies=cookies))
    keys = json.loads(listed.body)["api_keys"]
    assert len(keys) == 1
    assert "key" not in keys[0]
    assert keys[0]["start"].startswith("dbk_")


async def test_revoke() -> None:
    auth = build_auth()
    cookies = await signup(auth)
    key, key_id = await create_key(auth, cookies)
    revoked = await auth.handle(post("/api-key/revoke", {"id": key_id}, cookies))
    assert revoked.status == 200
    check = await auth.handle(post("/api-key/verify", {"key": key}))
    assert check.status == 401


async def test_verify_invalid_key() -> None:
    auth = build_auth()
    resp = await auth.handle(post("/api-key/verify", {"key": "dbk_nope"}))
    assert resp.status == 401
    assert json.loads(resp.body)["error"]["code"] == "invalid_key"


async def test_expired_key_rejected() -> None:
    auth = build_auth()
    cookies = await signup(auth)
    resp = await auth.handle(post("/api-key/create", {"name": "temp", "expires_in": -1}, cookies))
    key = json.loads(resp.body)["key"]
    check = await auth.handle(post("/api-key/verify", {"key": key}))
    assert check.status == 401


async def test_create_requires_session() -> None:
    auth = build_auth()
    resp = await auth.handle(post("/api-key/create", {"name": "x"}))
    assert resp.status == 401


async def test_revoke_unknown() -> None:
    auth = build_auth()
    cookies = await signup(auth)
    resp = await auth.handle(post("/api-key/revoke", {"id": "ghost"}, cookies))
    assert resp.status == 404
