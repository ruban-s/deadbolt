from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import StaticPool
from sqlalchemy.ext.asyncio import create_async_engine

import deadbolt as db
from _helpers import fast_hasher
from deadbolt.db.sqlalchemy_async import SQLAlchemyAdapter
from deadbolt.db.types import FieldSpec, SortBy, TableSpec, Where
from deadbolt.errors import APIError
from deadbolt.models import CORE_TABLES

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

pytestmark = pytest.mark.anyio


@pytest.fixture
async def auth() -> AsyncIterator[db.Auth]:
    engine = create_async_engine("sqlite+aiosqlite://", poolclass=StaticPool)
    adapter = SQLAlchemyAdapter(engine)
    await adapter.create_schema(tables=CORE_TABLES)
    yield db.Auth(
        adapter=adapter,
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=fast_hasher(),
    )
    await engine.dispose()


async def test_full_auth_flow_on_sqlite(auth: db.Auth) -> None:
    up = await auth.api.sign_up_email(email="a@b.com", password="hunter2pw", as_response=True)
    cookies = {up.cookies[0].name: up.cookies[0].value}
    assert up.data["user"]["email"] == "a@b.com"
    assert await auth.adapter.count(model="user") == 1
    assert await auth.adapter.count(model="session") == 1

    session = await auth.api.get_session(cookies=cookies)
    assert session["user"]["email"] == "a@b.com"
    assert isinstance(session["session"]["expires_at"], datetime)

    with pytest.raises(APIError):
        await auth.api.sign_in_email(email="a@b.com", password="wrongpass")

    signed_in = await auth.api.sign_in_email(email="a@b.com", password="hunter2pw")
    assert signed_in["user"]["email"] == "a@b.com"


async def test_change_password_persists(auth: db.Auth) -> None:
    up = await auth.api.sign_up_email(email="a@b.com", password="hunter2pw", as_response=True)
    cookies = {up.cookies[0].name: up.cookies[0].value}
    await auth.api.change_password(
        cookies=cookies, current_password="hunter2pw", new_password="newpass99"
    )
    with pytest.raises(APIError):
        await auth.api.sign_in_email(email="a@b.com", password="hunter2pw")
    ok = await auth.api.sign_in_email(email="a@b.com", password="newpass99")
    assert ok["user"]["email"] == "a@b.com"


WIDGET = TableSpec(
    model="widget",
    fields={
        "id": FieldSpec(type="string", required=True, unique=True, input=False),
        "email": FieldSpec(type="string", unique=True),
        "n": FieldSpec(type="number"),
        "active": FieldSpec(type="boolean"),
        "tags": FieldSpec(type="json"),
        "created_at": FieldSpec(type="date"),
    },
)


@pytest.fixture
async def widget_adapter() -> AsyncIterator[SQLAlchemyAdapter]:
    engine = create_async_engine("sqlite+aiosqlite://", poolclass=StaticPool)
    adapter = SQLAlchemyAdapter(engine, schema=[WIDGET])
    await adapter.create_schema(tables=[WIDGET])
    yield adapter
    await engine.dispose()


async def _seed(adapter: SQLAlchemyAdapter) -> None:
    for i in range(3):
        await adapter.create(
            model="widget",
            data={
                "id": str(i),
                "email": f"u{i}@x.com",
                "n": i,
                "active": i != 1,
                "tags": ["a", i],
                "created_at": None,
            },
        )


async def test_crud_operators_sort_pagination(widget_adapter: SQLAlchemyAdapter) -> None:
    await _seed(widget_adapter)
    assert await widget_adapter.count(model="widget") == 3

    gt = await widget_adapter.find_many(model="widget", where=[Where("n", 0, "gt")])
    assert {r["id"] for r in gt} == {"1", "2"}

    contains = await widget_adapter.find_many(
        model="widget", where=[Where("email", "u1", "contains")]
    )
    assert [r["id"] for r in contains] == ["1"]

    members = await widget_adapter.find_many(model="widget", where=[Where("id", ["0", "2"], "in")])
    assert {r["id"] for r in members} == {"0", "2"}

    page = await widget_adapter.find_many(
        model="widget", sort_by=SortBy("n", "desc"), limit=2, offset=1
    )
    assert [r["id"] for r in page] == ["1", "0"]

    one = await widget_adapter.find_one(model="widget", where=[Where("id", "0")])
    assert one is not None
    assert one["active"] is True
    assert one["tags"] == ["a", 0]


async def test_update_and_delete(widget_adapter: SQLAlchemyAdapter) -> None:
    await _seed(widget_adapter)
    updated = await widget_adapter.update(
        model="widget", where=[Where("id", "1")], update={"email": "new@x.com"}
    )
    assert updated is not None
    assert updated["email"] == "new@x.com"
    assert await widget_adapter.update(model="widget", where=[Where("id", "x")], update={}) is None

    await widget_adapter.delete(model="widget", where=[Where("id", "0")])
    assert await widget_adapter.count(model="widget") == 2
    removed = await widget_adapter.delete_many(model="widget", where=[Where("active", True)])
    assert removed == 1


async def test_timezone_aware_date_roundtrip(widget_adapter: SQLAlchemyAdapter) -> None:
    moment = datetime(2026, 7, 8, 12, 0, tzinfo=UTC)
    await widget_adapter.create(
        model="widget", data={"id": "1", "email": "a@x.com", "created_at": moment}
    )
    row = await widget_adapter.find_one(model="widget", where=[Where("id", "1")])
    assert row is not None
    assert row["created_at"] == moment
