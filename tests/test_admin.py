from __future__ import annotations

import json

import pytest

import deadbolt as db
from _helpers import fast_hasher
from deadbolt.plugins.admin import admin

pytestmark = pytest.mark.anyio


def build_auth() -> db.Auth:
    return db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=fast_hasher(),
        plugins=[admin(admin_emails=["boss@b.com"])],
    )


def post(path: str, body: object, cookies: dict[str, str] | None = None) -> db.AuthRequest:
    return db.AuthRequest(
        method="POST", path=path, body=json.dumps(body).encode(), cookies=cookies or {}
    )


async def signup(auth: db.Auth, email: str) -> dict[str, str]:
    resp = await auth.handle(post("/sign-up/email", {"email": email, "password": "hunter2pw"}))
    return {c.name: c.value for c in resp.cookies if c.value}


async def signin(auth: db.Auth, email: str) -> db.AuthResponse:
    return await auth.handle(post("/sign-in/email", {"email": email, "password": "hunter2pw"}))


async def _user_id(auth: db.Auth, email: str) -> str:
    user = await auth.adapter.find_one(model="user", where=[db.Where("email", email)])
    assert user is not None
    return str(user["id"])


async def test_non_admin_forbidden() -> None:
    auth = build_auth()
    cookies = await signup(auth, "user@b.com")
    resp = await auth.handle(
        db.AuthRequest(method="GET", path="/admin/list-users", cookies=cookies)
    )
    assert resp.status == 403


async def test_bootstrap_admin_can_list_users() -> None:
    auth = build_auth()
    boss = await signup(auth, "boss@b.com")
    await signup(auth, "user@b.com")
    resp = await auth.handle(db.AuthRequest(method="GET", path="/admin/list-users", cookies=boss))
    users = json.loads(resp.body)["users"]
    assert {u["email"] for u in users} == {"boss@b.com", "user@b.com"}


async def test_set_role_promotes_admin() -> None:
    auth = build_auth()
    boss = await signup(auth, "boss@b.com")
    promoted_cookies = await signup(auth, "new@b.com")
    new_id = await _user_id(auth, "new@b.com")

    await auth.handle(post("/admin/set-role", {"user_id": new_id, "role": "admin"}, boss))
    # the promoted user can now use admin endpoints
    resp = await auth.handle(
        db.AuthRequest(method="GET", path="/admin/list-users", cookies=promoted_cookies)
    )
    assert resp.status == 200


async def test_ban_blocks_sign_in() -> None:
    auth = build_auth()
    boss = await signup(auth, "boss@b.com")
    await signup(auth, "bad@b.com")
    bad_id = await _user_id(auth, "bad@b.com")

    banned = await auth.handle(post("/admin/ban-user", {"user_id": bad_id, "reason": "spam"}, boss))
    assert banned.status == 200

    resp = await signin(auth, "bad@b.com")
    assert resp.status == 403
    assert json.loads(resp.body)["error"]["code"] == "banned"
    assert all(not c.value for c in resp.cookies)


async def test_unban_restores_sign_in() -> None:
    auth = build_auth()
    boss = await signup(auth, "boss@b.com")
    await signup(auth, "bad@b.com")
    bad_id = await _user_id(auth, "bad@b.com")
    await auth.handle(post("/admin/ban-user", {"user_id": bad_id}, boss))
    await auth.handle(post("/admin/unban-user", {"user_id": bad_id}, boss))
    resp = await signin(auth, "bad@b.com")
    assert resp.status == 200


async def test_admin_create_and_remove_user() -> None:
    auth = build_auth()
    boss = await signup(auth, "boss@b.com")
    created = await auth.handle(
        post("/admin/create-user", {"email": "made@b.com", "password": "hunter2pw"}, boss)
    )
    assert created.status == 200
    signed_in = await signin(auth, "made@b.com")
    assert signed_in.status == 200

    made_id = await _user_id(auth, "made@b.com")
    removed = await auth.handle(post("/admin/remove-user", {"user_id": made_id}, boss))
    assert removed.status == 200
    gone = await signin(auth, "made@b.com")
    assert gone.status == 401


async def test_revoke_user_sessions() -> None:
    auth = build_auth()
    boss = await signup(auth, "boss@b.com")
    victim = await signup(auth, "victim@b.com")
    victim_id = await _user_id(auth, "victim@b.com")
    resp = await auth.handle(post("/admin/revoke-user-sessions", {"user_id": victim_id}, boss))
    assert json.loads(resp.body)["revoked"] >= 1
    check = await auth.handle(db.AuthRequest(method="GET", path="/get-session", cookies=victim))
    assert json.loads(check.body)["user"] is None


async def test_ban_expired_allows_sign_in() -> None:
    auth = build_auth()
    boss = await signup(auth, "boss@b.com")
    await signup(auth, "temp@b.com")
    temp_id = await _user_id(auth, "temp@b.com")
    await auth.handle(post("/admin/ban-user", {"user_id": temp_id, "expires_in": -1}, boss))
    resp = await signin(auth, "temp@b.com")
    assert resp.status == 200
