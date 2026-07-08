from __future__ import annotations

import httpx
import pytest
from fastapi import FastAPI

import deadbolt as db
from _helpers import fast_hasher
from deadbolt.integrations.fastapi import mount

pytestmark = pytest.mark.anyio


def make_app() -> FastAPI:
    app = FastAPI()
    auth = db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=fast_hasher(),
    )
    mount(app, auth)
    return app


def client(app: FastAPI) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="https://test")


async def test_full_flow_over_http() -> None:
    async with client(make_app()) as http:
        signup = await http.post(
            "/api/auth/sign-up/email", json={"email": "a@b.com", "password": "hunter2pw"}
        )
        assert signup.status_code == 200
        assert signup.json()["user"]["email"] == "a@b.com"
        assert "__Host-session" in signup.cookies

        session = await http.get("/api/auth/get-session")
        assert session.json()["user"]["email"] == "a@b.com"

        signout = await http.post("/api/auth/sign-out")
        assert signout.json() == {"success": True}

        after = await http.get("/api/auth/get-session")
        assert after.json() == {"session": None, "user": None}


async def test_set_cookie_flags_present() -> None:
    async with client(make_app()) as http:
        resp = await http.post(
            "/api/auth/sign-up/email", json={"email": "a@b.com", "password": "hunter2pw"}
        )
        set_cookie = resp.headers["set-cookie"].lower()
        assert "httponly" in set_cookie
        assert "secure" in set_cookie
        assert "samesite=lax" in set_cookie


async def test_invalid_credentials_status() -> None:
    async with client(make_app()) as http:
        resp = await http.post(
            "/api/auth/sign-in/email", json={"email": "ghost@b.com", "password": "hunter2pw"}
        )
        assert resp.status_code == 401
        assert resp.json()["error"]["code"] == "invalid_credentials"


async def test_custom_prefix() -> None:
    app = FastAPI()
    auth = db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=fast_hasher(),
    )
    mount(app, auth, prefix="/auth")
    async with client(app) as http:
        resp = await http.post(
            "/auth/sign-up/email", json={"email": "a@b.com", "password": "hunter2pw"}
        )
        assert resp.status_code == 200
