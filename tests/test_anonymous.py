from __future__ import annotations

import json

import pytest

import deadbolt as db
from _helpers import fast_hasher
from deadbolt.plugins.anonymous import anonymous

pytestmark = pytest.mark.anyio


def build_auth() -> db.Auth:
    return db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=fast_hasher(),
        plugins=[anonymous()],
    )


async def test_anonymous_sign_in_grants_working_session() -> None:
    auth = build_auth()
    resp = await auth.handle(db.AuthRequest(method="POST", path="/sign-in/anonymous"))
    assert resp.status == 200
    body = json.loads(resp.body)
    assert body["is_anonymous"] is True
    assert body["user"]["email"].startswith("anon-")
    cookie = next(c for c in resp.cookies if c.value)

    who = await auth.handle(
        db.AuthRequest(method="GET", path="/get-session", cookies={cookie.name: cookie.value})
    )
    assert json.loads(who.body)["user"]["id"] == body["user"]["id"]


async def test_each_guest_is_distinct() -> None:
    auth = build_auth()
    first = json.loads(
        (await auth.handle(db.AuthRequest(method="POST", path="/sign-in/anonymous"))).body
    )
    second = json.loads(
        (await auth.handle(db.AuthRequest(method="POST", path="/sign-in/anonymous"))).body
    )
    assert first["user"]["id"] != second["user"]["id"]
    assert first["user"]["email"] != second["user"]["email"]


async def test_guest_is_recorded_in_anonymous_table() -> None:
    auth = build_auth()
    body = json.loads(
        (await auth.handle(db.AuthRequest(method="POST", path="/sign-in/anonymous"))).body
    )
    row = await auth.adapter.find_one(
        model="anonymous", where=[db.Where("user_id", body["user"]["id"])]
    )
    assert row is not None
