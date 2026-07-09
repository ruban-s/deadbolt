from __future__ import annotations

import json

import pytest

import deadbolt as db
from _helpers import fast_hasher
from deadbolt.http import MultiDict
from deadbolt.plugins.device_authorization import device_authorization

pytestmark = pytest.mark.anyio

URI = "https://example.com/device"


def build_auth(*, interval: int = 0, expires_in: int = 600) -> db.Auth:
    return db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=fast_hasher(),
        plugins=[
            device_authorization(verification_uri=URI, interval=interval, expires_in=expires_in)
        ],
    )


def post(path: str, body: object, cookies: dict[str, str] | None = None) -> db.AuthRequest:
    return db.AuthRequest(
        method="POST", path=path, body=json.dumps(body).encode(), cookies=cookies or {}
    )


async def approver(auth: db.Auth) -> dict[str, str]:
    resp = await auth.handle(post("/sign-up/email", {"email": "a@b.com", "password": "hunter2pw"}))
    return {c.name: c.value for c in resp.cookies if c.value}


async def start(auth: db.Auth) -> dict[str, str]:
    resp = await auth.handle(post("/device/code", {"client_id": "cli"}))
    assert resp.status == 200
    return json.loads(resp.body)


async def test_full_device_flow() -> None:
    auth = build_auth()
    cookies = await approver(auth)
    codes = await start(auth)
    assert codes["verification_uri"] == URI
    assert codes["verification_uri_complete"].endswith(codes["user_code"])

    pending = await auth.handle(post("/device/token", {"device_code": codes["device_code"]}))
    assert pending.status == 400
    assert json.loads(pending.body)["error"]["code"] == "authorization_pending"

    lookup = await auth.handle(
        db.AuthRequest(
            method="GET",
            path="/device",
            query=MultiDict([("user_code", codes["user_code"])]),
            cookies=cookies,
        )
    )
    assert json.loads(lookup.body)["client_id"] == "cli"

    approved = await auth.handle(
        post("/device/approve", {"user_code": codes["user_code"]}, cookies)
    )
    assert json.loads(approved.body) == {"success": True}

    granted = await auth.handle(post("/device/token", {"device_code": codes["device_code"]}))
    assert granted.status == 200
    body = json.loads(granted.body)
    assert body["token_type"] == "Bearer"
    assert body["user"]["email"] == "a@b.com"
    session = next(c for c in granted.cookies if c.value)

    who = await auth.handle(
        db.AuthRequest(method="GET", path="/get-session", cookies={session.name: session.value})
    )
    assert json.loads(who.body)["user"]["email"] == "a@b.com"

    # The device code is single-use.
    again = await auth.handle(post("/device/token", {"device_code": codes["device_code"]}))
    assert again.status == 400
    assert json.loads(again.body)["error"]["code"] == "invalid_grant"


async def test_denied_request() -> None:
    auth = build_auth()
    cookies = await approver(auth)
    codes = await start(auth)
    await auth.handle(post("/device/deny", {"user_code": codes["user_code"]}, cookies))
    resp = await auth.handle(post("/device/token", {"device_code": codes["device_code"]}))
    assert json.loads(resp.body)["error"]["code"] == "access_denied"


async def test_slow_down_enforced() -> None:
    auth = build_auth(interval=5)
    await start(auth)
    codes = await start(auth)
    first = await auth.handle(post("/device/token", {"device_code": codes["device_code"]}))
    assert json.loads(first.body)["error"]["code"] == "authorization_pending"
    second = await auth.handle(post("/device/token", {"device_code": codes["device_code"]}))
    assert json.loads(second.body)["error"]["code"] == "slow_down"


async def test_expired_token() -> None:
    auth = build_auth(expires_in=-1)
    codes = await start(auth)
    resp = await auth.handle(post("/device/token", {"device_code": codes["device_code"]}))
    assert json.loads(resp.body)["error"]["code"] == "expired_token"


async def test_unknown_device_code() -> None:
    auth = build_auth()
    resp = await auth.handle(post("/device/token", {"device_code": "nope"}))
    assert json.loads(resp.body)["error"]["code"] == "invalid_grant"


async def test_approve_requires_session() -> None:
    auth = build_auth()
    codes = await start(auth)
    resp = await auth.handle(post("/device/approve", {"user_code": codes["user_code"]}))
    assert resp.status == 401


async def test_approve_unknown_user_code() -> None:
    auth = build_auth()
    cookies = await approver(auth)
    resp = await auth.handle(post("/device/approve", {"user_code": "ZZZZ-ZZZZ"}, cookies))
    assert resp.status == 404
