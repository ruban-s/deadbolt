from __future__ import annotations

import json
from urllib.parse import urlencode

import pytest

import deadbolt as db
from _helpers import fast_hasher
from deadbolt.http import MultiDict

pytestmark = pytest.mark.anyio


def build_auth() -> db.Auth:
    return db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=fast_hasher(),
    )


def form(path: str, fields: dict[str, str]) -> db.AuthRequest:
    return db.AuthRequest(
        method="POST",
        path=path,
        body=urlencode(fields).encode(),
        headers=MultiDict([("content-type", "application/x-www-form-urlencoded")]),
    )


async def test_form_encoded_body_is_parsed() -> None:
    auth = build_auth()
    resp = await auth.handle(form("/sign-up/email", {"email": "a@b.com", "password": "hunter2pw"}))
    assert resp.status == 200
    assert json.loads(resp.body)["user"]["email"] == "a@b.com"


async def test_json_body_still_works() -> None:
    auth = build_auth()
    resp = await auth.handle(
        db.AuthRequest(
            method="POST",
            path="/sign-up/email",
            body=json.dumps({"email": "a@b.com", "password": "hunter2pw"}).encode(),
        )
    )
    assert resp.status == 200
