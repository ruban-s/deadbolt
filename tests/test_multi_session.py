from __future__ import annotations

import json

import pytest

import deadbolt as db
from _helpers import fast_hasher
from deadbolt.plugins.multi_session import multi_session

pytestmark = pytest.mark.anyio

MULTI = "__Host-multi_session"
MAIN = "__Host-session"


def build_auth() -> db.Auth:
    return db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=fast_hasher(),
        plugins=[multi_session()],
    )


def cookies_of(resp: db.AuthResponse) -> dict[str, str]:
    return {c.name: c.value for c in resp.cookies if c.value}


async def sign_up(auth: db.Auth, email: str, jar: dict[str, str]) -> dict[str, str]:
    resp = await auth.handle(
        db.AuthRequest(
            method="POST",
            path="/sign-up/email",
            body=json.dumps({"email": email, "password": "hunter2pw"}).encode(),
            cookies=jar,
        )
    )
    return {**jar, **cookies_of(resp)}


async def test_two_accounts_tracked_in_one_browser() -> None:
    auth = build_auth()
    jar = await sign_up(auth, "a@b.com", {})
    assert MULTI in jar
    jar = await sign_up(auth, "c@d.com", jar)  # same browser, second account

    listing = await auth.handle(
        db.AuthRequest(method="GET", path="/multi-session/list", cookies=jar)
    )
    sessions = json.loads(listing.body)["sessions"]
    emails = {s["user"]["email"] for s in sessions}
    assert emails == {"a@b.com", "c@d.com"}
    active = [s for s in sessions if s["active"]]
    assert len(active) == 1 and active[0]["user"]["email"] == "c@d.com"


async def test_set_active_switches_primary_session() -> None:
    auth = build_auth()
    jar = await sign_up(auth, "a@b.com", {})
    jar = await sign_up(auth, "c@d.com", jar)

    listing = json.loads(
        (
            await auth.handle(db.AuthRequest(method="GET", path="/multi-session/list", cookies=jar))
        ).body
    )["sessions"]
    a_id = next(s["session_id"] for s in listing if s["user"]["email"] == "a@b.com")

    switched = await auth.handle(
        db.AuthRequest(
            method="POST",
            path="/multi-session/set-active",
            body=json.dumps({"session_id": a_id}).encode(),
            cookies=jar,
        )
    )
    assert switched.status == 200
    new_main = next(c for c in switched.cookies if c.name == MAIN and c.value)

    who = await auth.handle(
        db.AuthRequest(method="GET", path="/get-session", cookies={MAIN: new_main.value})
    )
    assert json.loads(who.body)["user"]["email"] == "a@b.com"


async def test_revoke_removes_and_invalidates_session() -> None:
    auth = build_auth()
    jar = await sign_up(auth, "a@b.com", {})
    jar = await sign_up(auth, "c@d.com", jar)

    listing = json.loads(
        (
            await auth.handle(db.AuthRequest(method="GET", path="/multi-session/list", cookies=jar))
        ).body
    )["sessions"]
    a_id = next(s["session_id"] for s in listing if s["user"]["email"] == "a@b.com")

    revoked = await auth.handle(
        db.AuthRequest(
            method="POST",
            path="/multi-session/revoke",
            body=json.dumps({"session_id": a_id}).encode(),
            cookies=jar,
        )
    )
    assert json.loads(revoked.body) == {"success": True}
    jar.update(cookies_of(revoked))

    remaining = json.loads(
        (
            await auth.handle(db.AuthRequest(method="GET", path="/multi-session/list", cookies=jar))
        ).body
    )["sessions"]
    assert {s["user"]["email"] for s in remaining} == {"c@d.com"}


async def test_set_active_unknown_session_is_404() -> None:
    auth = build_auth()
    jar = await sign_up(auth, "a@b.com", {})
    resp = await auth.handle(
        db.AuthRequest(
            method="POST",
            path="/multi-session/set-active",
            body=json.dumps({"session_id": "nope"}).encode(),
            cookies=jar,
        )
    )
    assert resp.status == 404
