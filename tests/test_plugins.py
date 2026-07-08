from __future__ import annotations

import json

import pytest

import deadbolt as db
from _helpers import fast_hasher
from deadbolt.plugins.magic_link import magic_link

pytestmark = pytest.mark.anyio


class CapturingEmail:
    def __init__(self) -> None:
        self.token: str | None = None

    async def send(self, *, to: str, subject: str, body: str) -> None:
        self.token = body.rsplit(":", 1)[1].strip()


def build_auth(email: CapturingEmail | None = None) -> db.Auth:
    return db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=fast_hasher(),
        email_sender=email,
        plugins=[magic_link()],
    )


def post(path: str, body: object, cookies: dict[str, str] | None = None) -> db.AuthRequest:
    return db.AuthRequest(
        method="POST", path=path, body=json.dumps(body).encode(), cookies=cookies or {}
    )


async def test_plugin_endpoints_registered() -> None:
    auth = build_auth()
    assert hasattr(auth.api, "magic_link_send")
    assert hasattr(auth.api, "magic_link_verify")


async def test_magic_link_signs_in_new_user() -> None:
    email = CapturingEmail()
    auth = build_auth(email)

    sent = await auth.handle(post("/magic-link/send", {"email": "new@b.com"}))
    assert sent.status == 200
    assert email.token is not None
    assert await auth.adapter.count(model="user") == 0

    verified = await auth.handle(post("/magic-link/verify", {"token": email.token}))
    assert verified.status == 200
    payload = json.loads(verified.body)
    assert payload["user"]["email"] == "new@b.com"
    assert payload["user"]["email_verified"] is True
    assert any(c.name == "__Host-session" for c in verified.cookies)
    assert await auth.adapter.count(model="user") == 1


async def test_magic_link_token_is_single_use() -> None:
    email = CapturingEmail()
    auth = build_auth(email)
    await auth.handle(post("/magic-link/send", {"email": "a@b.com"}))
    first = await auth.handle(post("/magic-link/verify", {"token": email.token}))
    assert first.status == 200
    second = await auth.handle(post("/magic-link/verify", {"token": email.token}))
    assert second.status == 400


async def test_magic_link_invalid_token() -> None:
    auth = build_auth()
    resp = await auth.handle(post("/magic-link/verify", {"token": "nope"}))
    assert resp.status == 400
    assert json.loads(resp.body)["error"]["code"] == "invalid_token"


async def test_password_reset_token_is_not_a_magic_link() -> None:
    auth = build_auth()
    await auth.handle(post("/sign-up/email", {"email": "a@b.com", "password": "hunter2pw"}))
    reset = await auth.adapter.create(
        model="verification",
        data={
            "id": "v1",
            "identifier": "a@b.com",
            "value": "reset-token",
            "expires_at": _future(),
            "created_at": _future(),
        },
    )
    assert reset["value"] == "reset-token"
    resp = await auth.handle(post("/magic-link/verify", {"token": "reset-token"}))
    assert resp.status == 400


async def test_core_endpoints_still_work_with_plugin() -> None:
    auth = build_auth()
    resp = await auth.handle(post("/sign-up/email", {"email": "a@b.com", "password": "hunter2pw"}))
    assert resp.status == 200


async def test_missing_email_field() -> None:
    auth = build_auth()
    resp = await auth.handle(post("/magic-link/send", {}))
    assert resp.status == 400
    assert json.loads(resp.body)["error"]["code"] == "invalid_request"


async def test_plugin_exposed_on_auth() -> None:
    auth = build_auth()
    assert [p.id for p in auth.plugins] == ["magic-link"]
    assert db.Plugin is not None


def _future() -> object:
    from datetime import UTC, datetime, timedelta  # noqa: PLC0415

    return datetime.now(UTC) + timedelta(hours=1)
