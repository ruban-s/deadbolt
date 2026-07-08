from __future__ import annotations

import json

import pytest

import deadbolt as db
from _helpers import build_auth as _build_auth

pytestmark = pytest.mark.anyio


def build_auth() -> db.Auth:
    return _build_auth(email_and_password=db.EmailPassword(enabled=True, max_password_length=16))


def post(path: str, body: object) -> db.AuthRequest:
    return db.AuthRequest(method="POST", path=path, body=json.dumps(body).encode())


async def test_password_too_long() -> None:
    auth = build_auth()
    resp = await auth.handle(post("/sign-up/email", {"email": "a@b.com", "password": "x" * 50}))
    assert resp.status == 400
    assert json.loads(resp.body)["error"]["code"] == "password_too_long"


async def test_missing_required_field() -> None:
    auth = build_auth()
    resp = await auth.handle(post("/sign-in/email", {"email": "a@b.com"}))
    assert resp.status == 400
    assert json.loads(resp.body)["error"]["code"] == "invalid_request"


async def test_non_object_json_body_rejected() -> None:
    auth = build_auth()
    resp = await auth.handle(post("/sign-in/email", [1, 2, 3]))
    assert resp.status == 400
    assert json.loads(resp.body)["error"]["code"] == "invalid_json"


async def test_change_password_without_credential_account() -> None:
    auth = build_auth()
    signed_up = await auth.handle(
        post("/sign-up/email", {"email": "a@b.com", "password": "hunter2pw"})
    )
    cookies = {c.name: c.value for c in signed_up.cookies}
    from deadbolt.db import Where  # noqa: PLC0415

    await auth.adapter.delete(model="account", where=[Where("account_id", "a@b.com")])

    req = db.AuthRequest(
        method="POST",
        path="/change-password",
        body=json.dumps({"current_password": "hunter2pw", "new_password": "newpass99"}).encode(),
        cookies=cookies,
    )
    resp = await auth.handle(req)
    assert resp.status == 400
    assert json.loads(resp.body)["error"]["code"] == "no_credential"


async def test_direct_api_unknown_endpoint_raises() -> None:
    auth = build_auth()
    with pytest.raises(AttributeError):
        auth.api.nonexistent_endpoint  # noqa: B018
