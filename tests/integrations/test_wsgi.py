from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from werkzeug.test import Client

import deadbolt as db
from _helpers import fast_hasher

if TYPE_CHECKING:
    from collections.abc import Iterator

BASE = "https://localhost"


def make_auth() -> db.Auth:
    return db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=fast_hasher(),
    )


@pytest.fixture
def wsgi_client() -> Iterator[Client]:
    auth = make_auth()
    yield Client(auth.wsgi_app())
    auth.close()


def _body(response: object) -> dict[str, object]:
    data = response.get_data(as_text=True)  # type: ignore[attr-defined]
    parsed: dict[str, object] = json.loads(data)
    return parsed


def test_full_flow_over_generic_wsgi(wsgi_client: Client) -> None:
    signup = wsgi_client.post(
        "/api/auth/sign-up/email",
        json={"email": "a@b.com", "password": "hunter2pw"},
        base_url=BASE,
    )
    assert signup.status_code == 200
    assert _body(signup)["user"]["email"] == "a@b.com"  # type: ignore[index]

    session = wsgi_client.get("/api/auth/get-session", base_url=BASE)
    assert _body(session)["user"]["email"] == "a@b.com"  # type: ignore[index]

    signout = wsgi_client.post("/api/auth/sign-out", base_url=BASE)
    assert _body(signout) == {"success": True}

    after = wsgi_client.get("/api/auth/get-session", base_url=BASE)
    assert _body(after) == {"session": None, "user": None}


def test_cookie_flags_present(wsgi_client: Client) -> None:
    resp = wsgi_client.post(
        "/api/auth/sign-up/email",
        json={"email": "a@b.com", "password": "hunter2pw"},
        base_url=BASE,
    )
    set_cookie = resp.headers["Set-Cookie"].lower()
    assert "httponly" in set_cookie
    assert "secure" in set_cookie
    assert "samesite=lax" in set_cookie


def test_invalid_credentials(wsgi_client: Client) -> None:
    resp = wsgi_client.post(
        "/api/auth/sign-in/email",
        json={"email": "ghost@b.com", "password": "hunter2pw"},
        base_url=BASE,
    )
    assert resp.status_code == 401
    assert _body(resp)["error"]["code"] == "invalid_credentials"  # type: ignore[index]


def test_mounted_under_script_name(wsgi_client: Client) -> None:
    resp = wsgi_client.post(
        "/sign-up/email",
        json={"email": "a@b.com", "password": "hunter2pw"},
        base_url=BASE,
        environ_overrides={"SCRIPT_NAME": "/api/auth"},
    )
    assert resp.status_code == 200
