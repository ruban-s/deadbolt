from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

import deadbolt as db
from _helpers import fast_hasher
from deadbolt.crypto import hash_token
from deadbolt.db import Where
from deadbolt.http import MultiDict
from deadbolt.plugins.oauth import github, google, social

if TYPE_CHECKING:
    from collections.abc import Callable

pytestmark = pytest.mark.anyio

REDIRECT = "https://app.com/api/auth/oauth/callback"


def auth_with(handle: Callable[[httpx.Request], httpx.Response]) -> db.Auth:
    plugin = social(
        providers=[google(client_id="c", client_secret="s", redirect_uri=REDIRECT)],
        client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(handle)),
    )
    return db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=fast_hasher(),
        plugins=[plugin],
    )


def provider_handler(user: dict[str, object]) -> httpx.MockTransport:
    def handle(request: httpx.Request) -> httpx.Response:
        if "token" in request.url.path:
            return httpx.Response(200, json={"access_token": "access-123"})
        return httpx.Response(200, json=user)

    return httpx.MockTransport(handle)


def build_auth(user: dict[str, object], *, success_redirect: str | None = None) -> db.Auth:
    transport = provider_handler(user)
    prov = google(client_id="cid", client_secret="sec", redirect_uri=REDIRECT)
    if success_redirect is not None:
        from dataclasses import replace  # noqa: PLC0415

        prov = replace(prov, success_redirect=success_redirect)
    plugin = social(
        providers=[prov],
        client_factory=lambda: httpx.AsyncClient(transport=transport),
    )
    return db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=fast_hasher(),
        plugins=[plugin],
    )


def start(provider: str = "google") -> db.AuthRequest:
    return db.AuthRequest(
        method="POST", path="/sign-in/social", body=json.dumps({"provider": provider}).encode()
    )


def callback(state: str, code: str = "code-1") -> db.AuthRequest:
    return db.AuthRequest(
        method="GET",
        path="/oauth/callback",
        query=MultiDict([("code", code), ("state", state)]),
    )


async def _state_from(auth: db.Auth) -> str:
    resp = await auth.handle(start())
    url = json.loads(resp.body)["url"]
    query = parse_qs(urlsplit(url).query)
    assert url.startswith("https://accounts.google.com")
    assert "code_challenge" in query
    return str(query["state"][0])


async def test_oauth_full_flow_creates_user() -> None:
    auth = build_auth({"sub": "g-1", "email": "a@b.com", "name": "Alice"})
    state = await _state_from(auth)
    resp = await auth.handle(callback(state))
    assert resp.status == 200
    payload = json.loads(resp.body)
    assert payload["user"]["email"] == "a@b.com"
    assert payload["user"]["email_verified"] is True
    assert any(c.name == "__Host-session" for c in resp.cookies)
    assert await auth.adapter.count(model="user") == 1
    assert await auth.adapter.count(model="account") == 1


async def test_oauth_links_existing_account() -> None:
    auth = build_auth({"sub": "g-1", "email": "a@b.com", "name": "Alice"})
    await auth.handle(callback(await _state_from(auth)))
    await auth.handle(callback(await _state_from(auth)))
    assert await auth.adapter.count(model="user") == 1
    assert await auth.adapter.count(model="account") == 1


async def test_oauth_success_redirect() -> None:
    auth = build_auth({"sub": "g-1", "email": "a@b.com"}, success_redirect="https://app.com/home")
    resp = await auth.handle(callback(await _state_from(auth)))
    assert resp.status == 302
    assert resp.headers.get("Location") == "https://app.com/home"


async def test_oauth_invalid_state() -> None:
    auth = build_auth({"sub": "g-1", "email": "a@b.com"})
    resp = await auth.handle(callback("not-a-real-state"))
    assert resp.status == 400
    assert json.loads(resp.body)["error"]["code"] == "invalid_state"


async def test_oauth_missing_code() -> None:
    auth = build_auth({"sub": "g-1", "email": "a@b.com"})
    resp = await auth.handle(db.AuthRequest(method="GET", path="/oauth/callback"))
    assert resp.status == 400
    assert json.loads(resp.body)["error"]["code"] == "invalid_request"


async def test_oauth_unknown_provider() -> None:
    auth = build_auth({"sub": "g-1", "email": "a@b.com"})
    resp = await auth.handle(start("facebook"))
    assert resp.status == 400
    assert json.loads(resp.body)["error"]["code"] == "unknown_provider"


async def test_oauth_state_is_single_use() -> None:
    auth = build_auth({"sub": "g-1", "email": "a@b.com"})
    state = await _state_from(auth)
    assert (await auth.handle(callback(state))).status == 200
    assert (await auth.handle(callback(state))).status == 400


async def test_oauth_token_error() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": "invalid_grant"})

    plugin = social(
        providers=[google(client_id="c", client_secret="s", redirect_uri=REDIRECT)],
        client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(handle)),
    )
    auth = db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=fast_hasher(),
        plugins=[plugin],
    )
    state = await _state_from(auth)
    resp = await auth.handle(callback(state))
    assert resp.status == 502
    assert json.loads(resp.body)["error"]["code"] == "oauth_token_error"


async def test_oauth_no_access_token() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        if "token" in request.url.path:
            return httpx.Response(200, json={})
        return httpx.Response(200, json={"sub": "g-1", "email": "a@b.com"})

    auth = auth_with(handle)
    resp = await auth.handle(callback(await _state_from(auth)))
    assert resp.status == 502
    assert json.loads(resp.body)["error"]["code"] == "oauth_token_error"


async def test_oauth_userinfo_error() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        if "token" in request.url.path:
            return httpx.Response(200, json={"access_token": "a"})
        return httpx.Response(500, json={})

    auth = auth_with(handle)
    resp = await auth.handle(callback(await _state_from(auth)))
    assert resp.status == 502
    assert json.loads(resp.body)["error"]["code"] == "oauth_userinfo_error"


async def test_oauth_expired_state() -> None:
    auth = build_auth({"sub": "g-1", "email": "a@b.com"})
    state = await _state_from(auth)
    past = datetime.now(UTC) - timedelta(hours=1)
    await auth.adapter.update(
        model="verification",
        where=[Where("value", hash_token(state))],
        update={"expires_at": past},
    )
    resp = await auth.handle(callback(state))
    assert resp.status == 400
    assert json.loads(resp.body)["error"]["code"] == "invalid_state"


async def test_github_provider_maps_login_as_name() -> None:
    transport = provider_handler({"id": 42, "login": "octocat", "email": None})
    plugin = social(
        providers=[github(client_id="c", client_secret="s", redirect_uri=REDIRECT)],
        client_factory=lambda: httpx.AsyncClient(transport=transport),
    )
    auth = db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=fast_hasher(),
        plugins=[plugin],
    )
    resp = await auth.handle(start("github"))
    state = parse_qs(urlsplit(json.loads(resp.body)["url"]).query)["state"][0]
    result = await auth.handle(callback(state))
    assert result.status == 200
    assert json.loads(result.body)["user"]["name"] == "octocat"
