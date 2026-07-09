from __future__ import annotations

import json

import pytest

import deadbolt as db
from _helpers import fast_hasher
from deadbolt.http import MultiDict
from deadbolt.plugins.captcha import captcha

pytestmark = pytest.mark.anyio


def build_auth(verify) -> db.Auth:
    return db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=fast_hasher(),
        plugins=[captcha(verify=verify)],
    )


def accepts(token: str) -> bool:
    return token == "good-token"


async def verifier(token: str) -> bool:
    return accepts(token)


def signup(token: str | None) -> db.AuthRequest:
    headers = MultiDict([("x-captcha-response", token)]) if token is not None else MultiDict()
    return db.AuthRequest(
        method="POST",
        path="/sign-up/email",
        body=json.dumps({"email": "a@b.com", "password": "hunter2pw"}).encode(),
        headers=headers,
    )


async def test_valid_captcha_allows_signup() -> None:
    auth = build_auth(verifier)
    resp = await auth.handle(signup("good-token"))
    assert resp.status == 200


async def test_invalid_captcha_rejected() -> None:
    auth = build_auth(verifier)
    resp = await auth.handle(signup("bad-token"))
    assert resp.status == 400
    assert json.loads(resp.body)["error"]["code"] == "captcha_failed"


async def test_missing_captcha_rejected() -> None:
    auth = build_auth(verifier)
    resp = await auth.handle(signup(None))
    assert resp.status == 400
    assert json.loads(resp.body)["error"]["code"] == "captcha_failed"


async def test_unknown_provider_raises() -> None:
    with pytest.raises(ValueError, match="Unknown captcha provider"):
        captcha(provider="nope")
