from __future__ import annotations

import json

import pytest

import deadbolt as db
from _helpers import fast_hasher
from deadbolt.plugins.phone import phone_number

pytestmark = pytest.mark.anyio


class CapturingSms:
    def __init__(self) -> None:
        self.code: str | None = None

    async def send_sms(self, *, to: str, body: str) -> None:
        self.code = body.rsplit(" ", 1)[1].strip()


def build_auth(sms: CapturingSms, *, disable_signup: bool = False) -> db.Auth:
    return db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=fast_hasher(),
        plugins=[phone_number(sms_sender=sms, disable_signup=disable_signup)],
    )


def post(path: str, body: object, cookies: dict[str, str] | None = None) -> db.AuthRequest:
    return db.AuthRequest(
        method="POST", path=path, body=json.dumps(body).encode(), cookies=cookies or {}
    )


async def signup(auth: db.Auth) -> dict[str, str]:
    resp = await auth.handle(post("/sign-up/email", {"email": "a@b.com", "password": "hunter2pw"}))
    return {c.name: c.value for c in resp.cookies if c.value}


async def test_phone_sign_in_creates_user() -> None:
    sms = CapturingSms()
    auth = build_auth(sms)
    await auth.handle(post("/phone/send-otp", {"phone": "+15551234567"}))
    assert sms.code is not None

    resp = await auth.handle(post("/sign-in/phone", {"phone": "+15551234567", "otp": sms.code}))
    assert resp.status == 200
    assert await auth.adapter.count(model="user") == 1
    assert any(c.name == "__Host-session" for c in resp.cookies)


async def test_otp_single_use() -> None:
    sms = CapturingSms()
    auth = build_auth(sms)
    await auth.handle(post("/phone/send-otp", {"phone": "+1555"}))
    first = await auth.handle(post("/sign-in/phone", {"phone": "+1555", "otp": sms.code}))
    assert first.status == 200
    reused = await auth.handle(post("/sign-in/phone", {"phone": "+1555", "otp": sms.code}))
    assert reused.status == 400


async def test_wrong_code_rejected() -> None:
    sms = CapturingSms()
    auth = build_auth(sms)
    await auth.handle(post("/phone/send-otp", {"phone": "+1555"}))
    resp = await auth.handle(post("/sign-in/phone", {"phone": "+1555", "otp": "000000"}))
    assert resp.status == 400


async def test_link_phone_to_existing_user() -> None:
    sms = CapturingSms()
    auth = build_auth(sms)
    cookies = await signup(auth)
    await auth.handle(post("/phone/send-otp", {"phone": "+1999"}))
    linked = await auth.handle(post("/phone/verify", {"phone": "+1999", "otp": sms.code}, cookies))
    assert linked.status == 200

    # signing in with that phone returns the same user
    await auth.handle(post("/phone/send-otp", {"phone": "+1999"}))
    resp = await auth.handle(post("/sign-in/phone", {"phone": "+1999", "otp": sms.code}))
    assert json.loads(resp.body)["user"]["email"] == "a@b.com"
    assert await auth.adapter.count(model="user") == 1


async def test_phone_taken_by_another() -> None:
    sms = CapturingSms()
    auth = build_auth(sms)
    a = await signup(auth)
    b_resp = await auth.handle(
        post("/sign-up/email", {"email": "b@b.com", "password": "hunter2pw"})
    )
    b = {c.name: c.value for c in b_resp.cookies if c.value}

    await auth.handle(post("/phone/send-otp", {"phone": "+1777"}))
    await auth.handle(post("/phone/verify", {"phone": "+1777", "otp": sms.code}, a))
    await auth.handle(post("/phone/send-otp", {"phone": "+1777"}))
    resp = await auth.handle(post("/phone/verify", {"phone": "+1777", "otp": sms.code}, b))
    assert resp.status == 409


async def test_disable_signup_blocks_unknown_phone() -> None:
    sms = CapturingSms()
    auth = build_auth(sms, disable_signup=True)
    await auth.handle(post("/phone/send-otp", {"phone": "+1222"}))
    resp = await auth.handle(post("/sign-in/phone", {"phone": "+1222", "otp": sms.code}))
    assert resp.status == 400


async def test_attempts_limited() -> None:
    sms = CapturingSms()
    auth = build_auth(sms)
    await auth.handle(post("/phone/send-otp", {"phone": "+1555"}))
    for _ in range(3):
        assert (
            await auth.handle(post("/sign-in/phone", {"phone": "+1555", "otp": "999999"}))
        ).status == 400
    consumed = await auth.handle(post("/sign-in/phone", {"phone": "+1555", "otp": sms.code}))
    assert consumed.status == 400
