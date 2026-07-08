from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import StaticPool
from sqlalchemy.ext.asyncio import create_async_engine

import deadbolt as db
from _helpers import fast_hasher
from deadbolt.db.sqlalchemy_async import SQLAlchemyAdapter
from deadbolt.db.types import Where
from deadbolt.models import CORE_TABLES

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

pytestmark = pytest.mark.anyio


def _auth(adapter: db.AsyncDatabaseAdapter) -> db.Auth:
    return db.Auth(
        adapter=adapter,
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=fast_hasher(),
    )


async def _seed_sessions(adapter: db.AsyncDatabaseAdapter) -> None:
    now = datetime.now(UTC)
    for i, delta in enumerate([timedelta(days=-1), timedelta(days=1)]):
        await adapter.create(
            model="session",
            data={
                "id": f"s{i}",
                "user_id": "u1",
                "token": f"t{i}",
                "expires_at": now + delta,
                "created_at": now,
                "updated_at": now,
                "ip_address": None,
                "user_agent": None,
            },
        )


async def test_cleanup_expired_memory() -> None:
    adapter = db.MemoryAdapter()
    await _seed_sessions(adapter)
    result = await _auth(adapter).cleanup_expired()
    assert result["sessions"] == 1
    remaining = await adapter.find_many(model="session")
    assert [r["id"] for r in remaining] == ["s1"]


@pytest.fixture
async def sql_adapter() -> AsyncIterator[SQLAlchemyAdapter]:
    engine = create_async_engine("sqlite+aiosqlite://", poolclass=StaticPool)
    adapter = SQLAlchemyAdapter(engine)
    await adapter.create_schema(tables=CORE_TABLES)
    yield adapter
    await engine.dispose()


async def test_cleanup_expired_sqlalchemy(sql_adapter: SQLAlchemyAdapter) -> None:
    await _seed_sessions(sql_adapter)
    result = await _auth(sql_adapter).cleanup_expired()
    assert result["sessions"] == 1
    remaining = await sql_adapter.find_many(model="session")
    assert [r["id"] for r in remaining] == ["s1"]


async def test_date_range_where_is_portable(sql_adapter: SQLAlchemyAdapter) -> None:
    await _seed_sessions(sql_adapter)
    future = datetime.now(UTC) + timedelta(hours=1)
    expired = await sql_adapter.find_many(
        model="session", where=[Where("expires_at", future, "lte")]
    )
    assert {r["id"] for r in expired} == {"s0"}


async def test_audit_log_emitted(caplog: pytest.LogCaptureFixture) -> None:
    auth = _auth(db.MemoryAdapter())
    req = db.AuthRequest(
        method="POST",
        path="/sign-in/email",
        body=json.dumps({"email": "ghost@b.com", "password": "hunter2pw"}).encode(),
        client_ip="9.9.9.9",
    )
    with caplog.at_level(logging.INFO, logger="deadbolt.audit"):
        resp = await auth.handle(req)
    assert resp.status == 401
    assert "event=/sign-in/email" in caplog.text
    assert "status=401" in caplog.text
    assert "ip=9.9.9.9" in caplog.text
    assert "password" not in caplog.text
