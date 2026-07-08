from __future__ import annotations

import json

import pytest

import deadbolt as db
from _helpers import fast_hasher
from deadbolt.plugins.email_otp import email_otp

pytestmark = pytest.mark.anyio


class CapturingEmail:
    def __init__(self) -> None:
        self.code: str | None = None

    async def send(self, *, to: str, subject: str, body: str) -> None:
        self.code = body.rsplit(":", 1)[1].strip()


def build_auth(
    mail: CapturingEmail, *, max_attempts: int = 3, disable_signup: bool = False
) -> db.Auth:
    return db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        hasher=fast_hasher(),
        email_sender=mail,
        plugins=[email_otp(max_attempts=max_attempts, disable_signup=disable_signup)],
    )


def post(path: str, body: object) -> db.AuthRequest:
    return db.AuthRequest(method="POST", path=path, body=json.dumps(body).encode())


async def test_otp_sign_in_creates_user() -> None:
    mail = CapturingEmail()
    auth = build_auth(mail)
    await auth.handle(post("/email-otp/send", {"email": "a@b.com"}))
    assert mail.code is not None and len(mail.code) == 6

    resp = await auth.handle(post("/sign-in/email-otp", {"email": "a@b.com", "otp": mail.code}))
    assert resp.status == 200
    payload = json.loads(resp.body)
    assert payload["user"]["email"] == "a@b.com"
    assert payload["user"]["email_verified"] is True
    assert any(c.name == "__Host-session" for c in resp.cookies)


async def test_otp_is_single_use() -> None:
    mail = CapturingEmail()
    auth = build_auth(mail)
    await auth.handle(post("/email-otp/send", {"email": "a@b.com"}))
    first = await auth.handle(post("/sign-in/email-otp", {"email": "a@b.com", "otp": mail.code}))
    assert first.status == 200
    reused = await auth.handle(post("/sign-in/email-otp", {"email": "a@b.com", "otp": mail.code}))
    assert reused.status == 400


async def test_wrong_code_rejected() -> None:
    mail = CapturingEmail()
    auth = build_auth(mail)
    await auth.handle(post("/email-otp/send", {"email": "a@b.com"}))
    resp = await auth.handle(post("/sign-in/email-otp", {"email": "a@b.com", "otp": "000000"}))
    assert resp.status == 400
    assert json.loads(resp.body)["error"]["code"] == "invalid_otp"


async def test_attempts_are_limited() -> None:
    mail = CapturingEmail()
    auth = build_auth(mail, max_attempts=3)
    await auth.handle(post("/email-otp/send", {"email": "a@b.com"}))
    for _ in range(3):
        bad = await auth.handle(post("/sign-in/email-otp", {"email": "a@b.com", "otp": "999999"}))
        assert bad.status == 400
    # the OTP is now consumed; even the correct code fails
    resp = await auth.handle(post("/sign-in/email-otp", {"email": "a@b.com", "otp": mail.code}))
    assert resp.status == 400


async def test_unknown_email_rejected() -> None:
    mail = CapturingEmail()
    auth = build_auth(mail)
    resp = await auth.handle(post("/sign-in/email-otp", {"email": "ghost@b.com", "otp": "123456"}))
    assert resp.status == 400


async def test_disable_signup_blocks_new_user() -> None:
    mail = CapturingEmail()
    auth = build_auth(mail, disable_signup=True)
    await auth.handle(post("/email-otp/send", {"email": "new@b.com"}))
    resp = await auth.handle(post("/sign-in/email-otp", {"email": "new@b.com", "otp": mail.code}))
    assert resp.status == 400


async def test_resend_replaces_previous_code() -> None:
    mail = CapturingEmail()
    auth = build_auth(mail)
    await auth.handle(post("/email-otp/send", {"email": "a@b.com"}))
    await auth.handle(post("/email-otp/send", {"email": "a@b.com"}))
    # only one OTP row exists for the email, and the latest code works
    assert await auth.adapter.count(model="email_otp") == 1
    ok = await auth.handle(post("/sign-in/email-otp", {"email": "a@b.com", "otp": mail.code}))
    assert ok.status == 200
