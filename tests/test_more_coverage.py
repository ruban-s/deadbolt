from __future__ import annotations

import json
from typing import Any

import pytest

import deadbolt as db
from deadbolt.db import MemoryAdapter, SortBy, Where

pytestmark = pytest.mark.anyio


def build_auth(**kw: Any) -> db.Auth:
    return db.Auth(
        adapter=MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        **kw,
    )


def post(path: str, body: object, cookies: dict[str, str] | None = None) -> db.AuthRequest:
    return db.AuthRequest(
        method="POST", path=path, body=json.dumps(body).encode(), cookies=cookies or {}
    )


async def test_sign_out_revokes_active_session() -> None:
    auth = build_auth()
    signed_up = await auth.handle(
        post("/sign-up/email", {"email": "a@b.com", "password": "hunter2pw"})
    )
    cookies = {c.name: c.value for c in signed_up.cookies}

    out = await auth.handle(post("/sign-out", {}, cookies=cookies))
    assert json.loads(out.body) == {"success": True}
    assert await auth.adapter.count(model="session") == 0


async def test_change_password_wrong_current() -> None:
    auth = build_auth()
    signed_up = await auth.handle(
        post("/sign-up/email", {"email": "a@b.com", "password": "hunter2pw"})
    )
    cookies = {c.name: c.value for c in signed_up.cookies}

    resp = await auth.handle(
        post("/change-password", {"current_password": "nope", "new_password": "newpass99"}, cookies)
    )
    assert resp.status == 401
    assert json.loads(resp.body)["error"]["code"] == "invalid_credentials"


async def test_reset_request_without_email_sender() -> None:
    auth = build_auth()
    await auth.handle(post("/sign-up/email", {"email": "a@b.com", "password": "hunter2pw"}))
    resp = await auth.handle(post("/request-password-reset", {"email": "a@b.com"}))
    assert resp.status == 200
    assert await auth.adapter.count(model="verification") == 1


class _Email:
    token: str | None = None

    async def send(self, *, to: str, subject: str, body: str) -> None:
        self.token = body.rsplit(":", 1)[1].strip()


async def test_reset_with_valid_token_but_deleted_user() -> None:
    email = _Email()
    auth = build_auth(email_sender=email)
    await auth.handle(post("/sign-up/email", {"email": "a@b.com", "password": "hunter2pw"}))
    await auth.handle(post("/request-password-reset", {"email": "a@b.com"}))
    assert email.token is not None
    await auth.adapter.delete(model="user", where=[Where("email", "a@b.com")])

    resp = await auth.handle(
        post("/reset-password", {"token": email.token, "new_password": "newpass99"})
    )
    assert resp.status == 400
    assert json.loads(resp.body)["error"]["code"] == "invalid_token"


async def test_sign_out_without_session_is_ok() -> None:
    auth = build_auth()
    out = await auth.handle(post("/sign-out", {}))
    assert json.loads(out.body) == {"success": True}


async def test_memory_delete_matches_later_row() -> None:
    adapter = MemoryAdapter()
    for i in range(3):
        await adapter.create(model="t", data={"id": str(i)})
    await adapter.delete(model="t", where=[Where("id", "2")])
    remaining = await adapter.find_many(model="t")
    assert {r["id"] for r in remaining} == {"0", "1"}


async def test_memory_create_schema_returns_empty() -> None:
    adapter = MemoryAdapter()
    from deadbolt.db import TableSpec  # noqa: PLC0415

    assert await adapter.create_schema(tables=[TableSpec(model="t")]) == ""


async def test_memory_ne_operator() -> None:
    adapter = MemoryAdapter()
    for i in range(3):
        await adapter.create(model="t", data={"id": str(i)})
    rows = await adapter.find_many(model="t", where=[Where("id", "1", "ne")])
    assert {r["id"] for r in rows} == {"0", "2"}


async def test_memory_ordering_op_on_missing_field() -> None:
    adapter = MemoryAdapter()
    await adapter.create(model="t", data={"id": "1"})
    assert await adapter.find_many(model="t", where=[Where("age", 5, "gt")]) == []


async def test_memory_sort_with_nulls() -> None:
    adapter = MemoryAdapter()
    await adapter.create(model="t", data={"id": "1", "rank": 2})
    await adapter.create(model="t", data={"id": "2"})
    await adapter.create(model="t", data={"id": "3", "rank": 1})
    ordered = await adapter.find_many(model="t", sort_by=SortBy("rank", "asc"))
    assert [r["id"] for r in ordered] == ["2", "3", "1"]


