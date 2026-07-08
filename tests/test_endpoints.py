from __future__ import annotations

import json
from typing import Any

import pytest

import deadbolt as db
from _helpers import build_auth
from deadbolt.http import AuthRequest, MultiDict

pytestmark = pytest.mark.anyio


class CapturingEmail:
    def __init__(self) -> None:
        self.token: str | None = None

    async def send(self, *, to: str, subject: str, body: str) -> None:
        self.token = body.rsplit(":", 1)[1].strip()


def request(
    method: str,
    path: str,
    *,
    body: dict[str, Any] | None = None,
    cookies: dict[str, str] | None = None,
) -> AuthRequest:
    return AuthRequest(
        method=method,
        path=path,
        body=json.dumps(body).encode() if body is not None else None,
        cookies=cookies or {},
    )


async def _cookie_from(resp: db.AuthResponse) -> dict[str, str]:
    return {c.name: c.value for c in resp.cookies if c.value}


async def test_sign_up_sets_session_cookie() -> None:
    auth = build_auth()
    resp = await auth.handle(
        request("POST", "/sign-up/email", body={"email": "a@b.com", "password": "hunter2pw"})
    )
    assert resp.status == 200
    payload = json.loads(resp.body)
    assert payload["user"]["email"] == "a@b.com"
    assert "password" not in payload["user"]
    assert any(c.name == "__Host-session" for c in resp.cookies)


async def test_duplicate_sign_up_rejected() -> None:
    auth = build_auth()
    body = {"email": "a@b.com", "password": "hunter2pw"}
    await auth.handle(request("POST", "/sign-up/email", body=body))
    resp = await auth.handle(request("POST", "/sign-up/email", body=body))
    assert resp.status == 422
    assert json.loads(resp.body)["error"]["code"] == "user_already_exists"


async def test_short_password_rejected() -> None:
    auth = build_auth()
    resp = await auth.handle(
        request("POST", "/sign-up/email", body={"email": "a@b.com", "password": "x"})
    )
    assert resp.status == 400
    assert json.loads(resp.body)["error"]["code"] == "password_too_short"


async def test_sign_in_valid_and_invalid() -> None:
    auth = build_auth()
    await auth.handle(
        request("POST", "/sign-up/email", body={"email": "a@b.com", "password": "hunter2pw"})
    )

    ok = await auth.handle(
        request("POST", "/sign-in/email", body={"email": "a@b.com", "password": "hunter2pw"})
    )
    assert ok.status == 200

    bad = await auth.handle(
        request("POST", "/sign-in/email", body={"email": "a@b.com", "password": "wrongpass"})
    )
    assert bad.status == 401
    assert json.loads(bad.body)["error"]["code"] == "invalid_credentials"


async def test_unknown_user_sign_in_does_not_enumerate() -> None:
    auth = build_auth()
    resp = await auth.handle(
        request("POST", "/sign-in/email", body={"email": "nobody@b.com", "password": "hunter2pw"})
    )
    assert resp.status == 401
    assert json.loads(resp.body)["error"]["code"] == "invalid_credentials"


async def test_get_session_via_http() -> None:
    auth = build_auth()
    signed_up = await auth.handle(
        request("POST", "/sign-up/email", body={"email": "a@b.com", "password": "hunter2pw"})
    )
    cookies = await _cookie_from(signed_up)

    resp = await auth.handle(request("GET", "/get-session", cookies=cookies))
    assert json.loads(resp.body)["user"]["email"] == "a@b.com"

    anon = await auth.handle(request("GET", "/get-session"))
    assert json.loads(anon.body) == {"session": None, "user": None}


async def test_change_password_then_sign_in() -> None:
    auth = build_auth()
    signed_up = await auth.handle(
        request("POST", "/sign-up/email", body={"email": "a@b.com", "password": "hunter2pw"})
    )
    cookies = await _cookie_from(signed_up)

    changed = await auth.handle(
        request(
            "POST",
            "/change-password",
            cookies=cookies,
            body={"current_password": "hunter2pw", "new_password": "newpass99"},
        )
    )
    assert changed.status == 200

    old = await auth.handle(
        request("POST", "/sign-in/email", body={"email": "a@b.com", "password": "hunter2pw"})
    )
    assert old.status == 401
    new = await auth.handle(
        request("POST", "/sign-in/email", body={"email": "a@b.com", "password": "newpass99"})
    )
    assert new.status == 200


async def test_change_password_requires_session() -> None:
    auth = build_auth()
    resp = await auth.handle(
        request(
            "POST", "/change-password", body={"current_password": "x", "new_password": "newpass99"}
        )
    )
    assert resp.status == 401


async def test_password_reset_flow() -> None:
    email = CapturingEmail()
    auth = build_auth(email_sender=email)
    await auth.handle(
        request("POST", "/sign-up/email", body={"email": "a@b.com", "password": "hunter2pw"})
    )

    req = await auth.handle(request("POST", "/request-password-reset", body={"email": "a@b.com"}))
    assert req.status == 200
    assert email.token is not None

    reset = await auth.handle(
        request(
            "POST", "/reset-password", body={"token": email.token, "new_password": "resetpass1"}
        )
    )
    assert reset.status == 200

    signed_in = await auth.handle(
        request("POST", "/sign-in/email", body={"email": "a@b.com", "password": "resetpass1"})
    )
    assert signed_in.status == 200


async def test_reset_with_bad_token() -> None:
    auth = build_auth()
    resp = await auth.handle(
        request("POST", "/reset-password", body={"token": "nope", "new_password": "resetpass1"})
    )
    assert resp.status == 400
    assert json.loads(resp.body)["error"]["code"] == "invalid_token"


async def test_reset_request_for_unknown_email_still_succeeds() -> None:
    email = CapturingEmail()
    auth = build_auth(email_sender=email)
    resp = await auth.handle(
        request("POST", "/request-password-reset", body={"email": "ghost@b.com"})
    )
    assert resp.status == 200
    assert email.token is None


async def test_disabled_email_password() -> None:
    auth = db.Auth(adapter=db.MemoryAdapter(), secret="x" * 32)
    resp = await auth.handle(
        request("POST", "/sign-up/email", body={"email": "a@b.com", "password": "hunter2pw"})
    )
    assert resp.status == 403


async def test_unknown_route_is_404() -> None:
    auth = build_auth()
    resp = await auth.handle(request("POST", "/nope"))
    assert resp.status == 404


async def test_invalid_json_body() -> None:
    auth = build_auth()
    req = AuthRequest(method="POST", path="/sign-in/email", body=b"{not json")
    resp = await auth.handle(req)
    assert resp.status == 400
    assert json.loads(resp.body)["error"]["code"] == "invalid_json"


async def test_query_multidict_type() -> None:
    req = AuthRequest(method="GET", path="/get-session", query=MultiDict([("a", "1")]))
    assert req.query.get("a") == "1"
