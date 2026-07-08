from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from deadbolt.db import MemoryAdapter, SortBy, Where

if TYPE_CHECKING:
    from deadbolt.protocols import AsyncDatabaseAdapter

pytestmark = pytest.mark.anyio


@pytest.fixture(params=["memory"])
def adapter(request: pytest.FixtureRequest) -> AsyncDatabaseAdapter:
    if request.param == "memory":
        return MemoryAdapter()
    raise AssertionError(request.param)


async def _seed(adapter: AsyncDatabaseAdapter) -> None:
    for i in range(3):
        await adapter.create(
            model="user",
            data={"id": str(i), "email": f"u{i}@x.com", "n": i, "active": i != 1},
        )


async def test_create_and_find_one(adapter: AsyncDatabaseAdapter) -> None:
    await adapter.create(model="user", data={"id": "1", "email": "a@b.com"})
    found = await adapter.find_one(model="user", where=[Where("email", "a@b.com")])
    assert found is not None
    assert found["id"] == "1"


async def test_find_one_missing_returns_none(adapter: AsyncDatabaseAdapter) -> None:
    assert await adapter.find_one(model="user", where=[Where("id", "nope")]) is None


async def test_isolation_of_returned_rows(adapter: AsyncDatabaseAdapter) -> None:
    await adapter.create(model="user", data={"id": "1", "email": "a@b.com"})
    found = await adapter.find_one(model="user", where=[Where("id", "1")])
    assert found is not None
    found["email"] = "mutated"
    again = await adapter.find_one(model="user", where=[Where("id", "1")])
    assert again is not None
    assert again["email"] == "a@b.com"


async def test_operators(adapter: AsyncDatabaseAdapter) -> None:
    await _seed(adapter)
    gt = await adapter.find_many(model="user", where=[Where("n", 0, "gt")])
    assert {r["id"] for r in gt} == {"1", "2"}
    inc = await adapter.find_many(model="user", where=[Where("email", "u1", "contains")])
    assert [r["id"] for r in inc] == ["1"]
    members = await adapter.find_many(model="user", where=[Where("id", ["0", "2"], "in")])
    assert {r["id"] for r in members} == {"0", "2"}


async def test_sort_limit_offset(adapter: AsyncDatabaseAdapter) -> None:
    await _seed(adapter)
    page = await adapter.find_many(model="user", sort_by=SortBy("n", "desc"), limit=2, offset=1)
    assert [r["id"] for r in page] == ["1", "0"]


async def test_update_and_count(adapter: AsyncDatabaseAdapter) -> None:
    await _seed(adapter)
    updated = await adapter.update(
        model="user", where=[Where("id", "1")], update={"email": "new@x.com"}
    )
    assert updated is not None
    assert updated["email"] == "new@x.com"
    assert await adapter.count(model="user") == 3
    assert await adapter.count(model="user", where=[Where("active", True)]) == 2


async def test_delete_and_delete_many(adapter: AsyncDatabaseAdapter) -> None:
    await _seed(adapter)
    await adapter.delete(model="user", where=[Where("id", "0")])
    assert await adapter.count(model="user") == 2
    removed = await adapter.delete_many(model="user", where=[Where("active", True)])
    assert removed == 1
    assert await adapter.count(model="user") == 1


async def test_connectors(adapter: AsyncDatabaseAdapter) -> None:
    await _seed(adapter)
    rows = await adapter.find_many(
        model="user",
        where=[Where("id", "0", "eq", "OR"), Where("id", "2", "eq", "OR")],
    )
    assert {r["id"] for r in rows} == {"0", "2"}
