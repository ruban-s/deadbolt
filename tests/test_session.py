from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from deadbolt.core.config import CookieConfig, SessionConfig
from deadbolt.crypto import CookieSigner
from deadbolt.db import MemoryAdapter
from deadbolt.session import SessionManager

pytestmark = pytest.mark.anyio


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 1, 1, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kw: float) -> None:
        self.now += timedelta(**kw)


def make_manager(clock: Clock) -> SessionManager:
    return SessionManager(
        adapter=MemoryAdapter(),
        signer=CookieSigner("s" * 32),
        config=SessionConfig(),
        cookie=CookieConfig(),
        now=clock,
    )


async def test_create_and_validate() -> None:
    clock = Clock()
    sm = make_manager(clock)
    token, row = await sm.create("user-1", ip="1.2.3.4")
    assert row["token"] != token
    validated = await sm.validate(token)
    assert validated is not None
    assert validated["user_id"] == "user-1"


async def test_validate_rejects_unknown_token() -> None:
    sm = make_manager(Clock())
    assert await sm.validate("nope") is None


async def test_session_expires() -> None:
    clock = Clock()
    sm = make_manager(clock)
    token, _ = await sm.create("user-1")
    clock.advance(days=8)
    assert await sm.validate(token) is None


async def test_sliding_refresh_extends_expiry() -> None:
    clock = Clock()
    sm = make_manager(clock)
    token, row = await sm.create("user-1")
    original = row["expires_at"]
    clock.advance(days=2)
    refreshed = await sm.validate(token)
    assert refreshed is not None
    assert refreshed["expires_at"] > original


async def test_no_refresh_before_update_age() -> None:
    clock = Clock()
    sm = make_manager(clock)
    token, row = await sm.create("user-1")
    clock.advance(hours=1)
    same = await sm.validate(token)
    assert same is not None
    assert same["updated_at"] == row["updated_at"]


async def test_revoke_and_revoke_all() -> None:
    sm = make_manager(Clock())
    t1, _ = await sm.create("user-1")
    await sm.revoke(t1)
    assert await sm.validate(t1) is None

    a, _ = await sm.create("user-2")
    b, _ = await sm.create("user-2")
    assert await sm.revoke_all("user-2") == 2
    assert await sm.validate(a) is None
    assert await sm.validate(b) is None


async def test_cookie_roundtrip_and_tamper() -> None:
    sm = make_manager(Clock())
    assert sm.cookie_name == "__Host-session"
    cookie = sm.build_cookie("tok")
    assert cookie.http_only and cookie.secure
    assert sm.read_token({sm.cookie_name: cookie.value}) == "tok"
    assert sm.read_token({sm.cookie_name: cookie.value + "x"}) is None
    assert sm.read_token({}) is None
