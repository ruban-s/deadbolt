from __future__ import annotations

import json

import pyotp
import pytest

import deadbolt as db
from _helpers import fast_hasher
from deadbolt.plugins.totp import totp

pytestmark = pytest.mark.anyio


def build_auth() -> db.Auth:
    return db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=fast_hasher(),
        plugins=[totp()],
    )


def post(path: str, body: object, cookies: dict[str, str] | None = None) -> db.AuthRequest:
    return db.AuthRequest(
        method="POST", path=path, body=json.dumps(body).encode(), cookies=cookies or {}
    )


def cookies_of(resp: db.AuthResponse) -> dict[str, str]:
    return {c.name: c.value for c in resp.cookies if c.value}


async def signup(auth: db.Auth) -> dict[str, str]:
    resp = await auth.handle(post("/sign-up/email", {"email": "a@b.com", "password": "hunter2pw"}))
    return cookies_of(resp)


async def enroll_and_enable(auth: db.Auth, cookies: dict[str, str]) -> tuple[str, list[str]]:
    enrolled = await auth.handle(post("/2fa/totp/enroll", {}, cookies))
    secret = json.loads(enrolled.body)["secret"]
    code = pyotp.TOTP(secret).now()
    enabled = await auth.handle(post("/2fa/totp/enable", {"code": code}, cookies))
    assert enabled.status == 200
    return secret, json.loads(enabled.body)["backup_codes"]


async def test_enroll_requires_session() -> None:
    auth = build_auth()
    resp = await auth.handle(post("/2fa/totp/enroll", {}))
    assert resp.status == 401


async def test_enroll_returns_secret_and_uri() -> None:
    auth = build_auth()
    cookies = await signup(auth)
    resp = await auth.handle(post("/2fa/totp/enroll", {}, cookies))
    body = json.loads(resp.body)
    assert body["secret"]
    assert body["uri"].startswith("otpauth://totp/")


async def test_secret_is_encrypted_at_rest() -> None:
    auth = build_auth()
    cookies = await signup(auth)
    resp = await auth.handle(post("/2fa/totp/enroll", {}, cookies))
    secret = json.loads(resp.body)["secret"]
    stored = (await auth.adapter.find_many(model="two_factor"))[0]["secret"]
    assert stored != secret


async def test_enable_rejects_wrong_code() -> None:
    auth = build_auth()
    cookies = await signup(auth)
    await auth.handle(post("/2fa/totp/enroll", {}, cookies))
    resp = await auth.handle(post("/2fa/totp/enable", {"code": "000000"}, cookies))
    assert resp.status == 400
    assert json.loads(resp.body)["error"]["code"] == "invalid_code"


async def test_sign_in_challenges_when_enabled() -> None:
    auth = build_auth()
    cookies = await signup(auth)
    secret, _ = await enroll_and_enable(auth, cookies)

    signin = await auth.handle(
        post("/sign-in/email", {"email": "a@b.com", "password": "hunter2pw"})
    )
    body = json.loads(signin.body)
    assert body["two_factor_required"] is True
    assert "challenge" in body
    assert all(not c.value for c in signin.cookies)

    completed = await auth.handle(
        post(
            "/2fa/totp/challenge",
            {"challenge": body["challenge"], "code": pyotp.TOTP(secret).now()},
        )
    )
    assert completed.status == 200
    assert json.loads(completed.body)["user"]["email"] == "a@b.com"
    session = await auth.handle(
        db.AuthRequest(method="GET", path="/get-session", cookies=cookies_of(completed))
    )
    assert json.loads(session.body)["user"]["email"] == "a@b.com"


async def test_backup_code_is_single_use() -> None:
    auth = build_auth()
    cookies = await signup(auth)
    _, backups = await enroll_and_enable(auth, cookies)

    signin = await auth.handle(
        post("/sign-in/email", {"email": "a@b.com", "password": "hunter2pw"})
    )
    challenge = json.loads(signin.body)["challenge"]
    ok = await auth.handle(
        post("/2fa/totp/challenge", {"challenge": challenge, "code": backups[0]})
    )
    assert ok.status == 200

    signin2 = await auth.handle(
        post("/sign-in/email", {"email": "a@b.com", "password": "hunter2pw"})
    )
    challenge2 = json.loads(signin2.body)["challenge"]
    reused = await auth.handle(
        post("/2fa/totp/challenge", {"challenge": challenge2, "code": backups[0]})
    )
    assert reused.status == 400


async def test_challenge_rejects_bad_code() -> None:
    auth = build_auth()
    cookies = await signup(auth)
    await enroll_and_enable(auth, cookies)
    signin = await auth.handle(
        post("/sign-in/email", {"email": "a@b.com", "password": "hunter2pw"})
    )
    challenge = json.loads(signin.body)["challenge"]
    resp = await auth.handle(
        post("/2fa/totp/challenge", {"challenge": challenge, "code": "000000"})
    )
    assert resp.status == 400


async def test_disable_restores_normal_sign_in() -> None:
    auth = build_auth()
    cookies = await signup(auth)
    secret, _ = await enroll_and_enable(auth, cookies)
    disabled = await auth.handle(
        post("/2fa/totp/disable", {"code": pyotp.TOTP(secret).now()}, cookies)
    )
    assert disabled.status == 200

    signin = await auth.handle(
        post("/sign-in/email", {"email": "a@b.com", "password": "hunter2pw"})
    )
    body = json.loads(signin.body)
    assert "two_factor_required" not in body
    assert body["user"]["email"] == "a@b.com"


async def test_invalid_challenge_token() -> None:
    auth = build_auth()
    resp = await auth.handle(post("/2fa/totp/challenge", {"challenge": "nope", "code": "000000"}))
    assert resp.status == 400
    assert json.loads(resp.body)["error"]["code"] == "invalid_challenge"


async def test_enable_without_enroll() -> None:
    auth = build_auth()
    cookies = await signup(auth)
    resp = await auth.handle(post("/2fa/totp/enable", {"code": "000000"}, cookies))
    assert resp.status == 400
    assert json.loads(resp.body)["error"]["code"] == "not_enrolled"


async def test_reenroll_replaces_and_resets() -> None:
    auth = build_auth()
    cookies = await signup(auth)
    secret, _ = await enroll_and_enable(auth, cookies)
    re_enrolled = await auth.handle(post("/2fa/totp/enroll", {}, cookies))
    new_secret = json.loads(re_enrolled.body)["secret"]
    assert new_secret != secret
    rows = await auth.adapter.find_many(model="two_factor")
    assert len(rows) == 1
    assert rows[0]["enabled"] is False
