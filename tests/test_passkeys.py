from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from webauthn.helpers import bytes_to_base64url

import deadbolt as db
from _helpers import fast_hasher
from deadbolt.plugins import passkeys as pk

pytestmark = pytest.mark.anyio

_CRED_ID = b"credential-id-bytes"
_CRED_ID_B64 = bytes_to_base64url(_CRED_ID)


def build_auth() -> db.Auth:
    return db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=fast_hasher(),
        plugins=[pk.passkeys(rp_id="example.com", rp_name="Example", origin="https://example.com")],
    )


def post(path: str, body: object, cookies: dict[str, str] | None = None) -> db.AuthRequest:
    return db.AuthRequest(
        method="POST", path=path, body=json.dumps(body).encode(), cookies=cookies or {}
    )


async def signup(auth: db.Auth) -> dict[str, str]:
    resp = await auth.handle(post("/sign-up/email", {"email": "a@b.com", "password": "hunter2pw"}))
    return {c.name: c.value for c in resp.cookies if c.value}


async def test_register_options_returns_challenge() -> None:
    auth = build_auth()
    cookies = await signup(auth)
    resp = await auth.handle(post("/passkey/register-options", {}, cookies))
    assert resp.status == 200
    body = json.loads(resp.body)
    assert body["options"]["rp"]["id"] == "example.com"
    assert body["options"]["user"]["name"] == "a@b.com"
    assert "challenge" in body["options"]
    assert body["challenge_token"]
    assert await auth.adapter.count(model="verification") == 1


async def test_register_then_authenticate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        pk,
        "_verify_registration",
        lambda *a, **k: SimpleNamespace(
            credential_id=_CRED_ID, credential_public_key=b"pubkey", sign_count=0
        ),
    )
    monkeypatch.setattr(
        pk, "_verify_authentication", lambda *a, **k: SimpleNamespace(new_sign_count=1)
    )
    auth = build_auth()
    cookies = await signup(auth)

    options = await auth.handle(post("/passkey/register-options", {}, cookies))
    token = json.loads(options.body)["challenge_token"]
    verified = await auth.handle(
        post(
            "/passkey/register-verify",
            {"challenge_token": token, "credential": {"id": _CRED_ID_B64, "response": {}}},
            cookies,
        )
    )
    assert verified.status == 200
    assert await auth.adapter.count(model="passkey") == 1

    auth_options = await auth.handle(post("/passkey/authenticate-options", {"email": "a@b.com"}))
    auth_token = json.loads(auth_options.body)["challenge_token"]
    signed_in = await auth.handle(
        post(
            "/passkey/authenticate-verify",
            {"challenge_token": auth_token, "credential": {"id": _CRED_ID_B64, "response": {}}},
        )
    )
    assert signed_in.status == 200
    assert json.loads(signed_in.body)["user"]["email"] == "a@b.com"
    assert any(c.name == "__Host-session" for c in signed_in.cookies)


async def test_register_options_requires_session() -> None:
    auth = build_auth()
    resp = await auth.handle(post("/passkey/register-options", {}))
    assert resp.status == 401


async def test_register_verify_invalid_challenge() -> None:
    auth = build_auth()
    cookies = await signup(auth)
    resp = await auth.handle(
        post(
            "/passkey/register-verify",
            {"challenge_token": "nope", "credential": {"id": "x"}},
            cookies,
        )
    )
    assert resp.status == 400
    assert json.loads(resp.body)["error"]["code"] == "invalid_challenge"


async def test_authenticate_unknown_passkey() -> None:
    auth = build_auth()
    options = await auth.handle(post("/passkey/authenticate-options", {}))
    token = json.loads(options.body)["challenge_token"]
    resp = await auth.handle(
        post(
            "/passkey/authenticate-verify",
            {"challenge_token": token, "credential": {"id": "unknown"}},
        )
    )
    assert resp.status == 400
    assert json.loads(resp.body)["error"]["code"] == "unknown_passkey"


async def test_list_and_delete(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        pk,
        "_verify_registration",
        lambda *a, **k: SimpleNamespace(
            credential_id=_CRED_ID, credential_public_key=b"pubkey", sign_count=0
        ),
    )
    auth = build_auth()
    cookies = await signup(auth)
    options = await auth.handle(post("/passkey/register-options", {}, cookies))
    token = json.loads(options.body)["challenge_token"]
    await auth.handle(
        post(
            "/passkey/register-verify",
            {"challenge_token": token, "credential": {"id": _CRED_ID_B64}, "name": "MacBook"},
            cookies,
        )
    )

    listed = await auth.handle(db.AuthRequest(method="GET", path="/passkey/list", cookies=cookies))
    keys = json.loads(listed.body)["passkeys"]
    assert len(keys) == 1
    assert keys[0]["name"] == "MacBook"

    deleted = await auth.handle(post("/passkey/delete", {"id": keys[0]["id"]}, cookies))
    assert deleted.status == 200
    empty = await auth.handle(db.AuthRequest(method="GET", path="/passkey/list", cookies=cookies))
    assert json.loads(empty.body)["passkeys"] == []
