from __future__ import annotations

import httpx
import pytest

import deadbolt as db
from _helpers import fast_hasher

pytestmark = pytest.mark.anyio


def make_auth() -> db.Auth:
    return db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=fast_hasher(),
    )


def client(auth: db.Auth) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=auth.asgi_app())
    return httpx.AsyncClient(transport=transport, base_url="https://test")


async def test_full_flow_over_generic_asgi() -> None:
    async with client(make_auth()) as http:
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


async def test_cookie_flags_present() -> None:
    async with client(make_auth()) as http:
        resp = await http.post(
            "/api/auth/sign-up/email", json={"email": "a@b.com", "password": "hunter2pw"}
        )
        set_cookie = resp.headers["set-cookie"].lower()
        assert "httponly" in set_cookie
        assert "secure" in set_cookie
        assert "samesite=lax" in set_cookie


async def test_query_string_is_forwarded() -> None:
    async with client(make_auth()) as http:
        resp = await http.get("/api/auth/get-session?foo=bar")
        assert resp.status_code == 200


async def test_unknown_endpoint_is_404() -> None:
    async with client(make_auth()) as http:
        resp = await http.get("/api/auth/nope")
        assert resp.status_code == 404
        assert resp.json()["error"]["code"] == "not_found"


async def test_lifespan_startup_and_shutdown() -> None:
    app = make_auth().asgi_app()
    events = ["lifespan.startup", "lifespan.shutdown"]
    sent: list[str] = []

    async def receive() -> dict[str, str]:
        return {"type": events.pop(0)}

    async def send(message: dict[str, str]) -> None:
        sent.append(message["type"])

    await app({"type": "lifespan"}, receive, send)  # type: ignore[arg-type]
    assert sent == ["lifespan.startup.complete", "lifespan.shutdown.complete"]
