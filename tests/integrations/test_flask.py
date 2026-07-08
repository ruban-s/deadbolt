from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from flask import Flask

import deadbolt as db
from _helpers import fast_hasher
from deadbolt.integrations.flask import mount

if TYPE_CHECKING:
    from collections.abc import Iterator

    from flask.testing import FlaskClient

BASE = "https://localhost"


def make_auth() -> db.Auth:
    return db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=fast_hasher(),
    )


@pytest.fixture
def flask_client() -> Iterator[FlaskClient]:
    app = Flask(__name__)
    auth = make_auth()
    mount(app, auth)
    yield app.test_client()
    auth.close()


def test_full_flow_over_wsgi(flask_client: FlaskClient) -> None:
    signup = flask_client.post(
        "/api/auth/sign-up/email",
        json={"email": "a@b.com", "password": "hunter2pw"},
        base_url=BASE,
    )
    assert signup.status_code == 200
    assert signup.get_json()["user"]["email"] == "a@b.com"

    session = flask_client.get("/api/auth/get-session", base_url=BASE)
    assert session.get_json()["user"]["email"] == "a@b.com"

    signout = flask_client.post("/api/auth/sign-out", base_url=BASE)
    assert signout.get_json() == {"success": True}

    after = flask_client.get("/api/auth/get-session", base_url=BASE)
    assert after.get_json() == {"session": None, "user": None}


def test_cookie_flags_present(flask_client: FlaskClient) -> None:
    resp = flask_client.post(
        "/api/auth/sign-up/email",
        json={"email": "a@b.com", "password": "hunter2pw"},
        base_url=BASE,
    )
    set_cookie = resp.headers["Set-Cookie"].lower()
    assert "httponly" in set_cookie
    assert "secure" in set_cookie
    assert "samesite=lax" in set_cookie


def test_invalid_credentials(flask_client: FlaskClient) -> None:
    resp = flask_client.post(
        "/api/auth/sign-in/email",
        json={"email": "ghost@b.com", "password": "hunter2pw"},
        base_url=BASE,
    )
    assert resp.status_code == 401
    assert resp.get_json()["error"]["code"] == "invalid_credentials"


@pytest.mark.anyio
async def test_handle_sync_refused_in_async_context() -> None:
    auth = make_auth()
    try:
        with pytest.raises(RuntimeError):
            auth.handle_sync(db.AuthRequest(method="GET", path="/get-session"))
    finally:
        auth.close()
