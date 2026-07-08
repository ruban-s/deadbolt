"""User and credential-account helpers shared across endpoints."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .._util import new_id, utcnow
from ..db.types import Row, Where

if TYPE_CHECKING:
    from ..protocols import AsyncDatabaseAdapter

CREDENTIAL_PROVIDER = "credential"

_PUBLIC_USER_FIELDS = ("id", "email", "email_verified", "name", "image", "created_at", "updated_at")


def public_user(user: Row) -> Row:
    return {k: user[k] for k in _PUBLIC_USER_FIELDS if k in user}


async def find_user_by_email(adapter: AsyncDatabaseAdapter, email: str) -> Row | None:
    return await adapter.find_one(model="user", where=[Where("email", email)])


async def find_user_by_id(adapter: AsyncDatabaseAdapter, user_id: str) -> Row | None:
    return await adapter.find_one(model="user", where=[Where("id", user_id)])


async def credential_account(adapter: AsyncDatabaseAdapter, user_id: str) -> Row | None:
    return await adapter.find_one(
        model="account",
        where=[Where("user_id", user_id), Where("provider_id", CREDENTIAL_PROVIDER)],
    )


async def create_user(adapter: AsyncDatabaseAdapter, *, email: str, name: str | None) -> Row:
    now = utcnow()
    user: Row = {
        "id": new_id(),
        "email": email,
        "email_verified": False,
        "name": name,
        "image": None,
        "created_at": now,
        "updated_at": now,
    }
    await adapter.create(model="user", data=user)
    return user


async def create_credential_account(
    adapter: AsyncDatabaseAdapter, *, user_id: str, email: str, password_hash: str
) -> Row:
    now = utcnow()
    account: Row = {
        "id": new_id(),
        "user_id": user_id,
        "provider_id": CREDENTIAL_PROVIDER,
        "account_id": email,
        "password": password_hash,
        "created_at": now,
        "updated_at": now,
    }
    await adapter.create(model="account", data=account)
    return account


async def set_account_password(
    adapter: AsyncDatabaseAdapter, *, account_id: str, password_hash: str
) -> None:
    await adapter.update(
        model="account",
        where=[Where("id", account_id)],
        update={"password": password_hash, "updated_at": utcnow()},
    )


async def find_provider_account(
    adapter: AsyncDatabaseAdapter, *, provider_id: str, account_id: str
) -> Row | None:
    return await adapter.find_one(
        model="account",
        where=[Where("provider_id", provider_id), Where("account_id", account_id)],
    )


async def create_provider_account(
    adapter: AsyncDatabaseAdapter, *, user_id: str, provider_id: str, account_id: str
) -> Row:
    now = utcnow()
    account: Row = {
        "id": new_id(),
        "user_id": user_id,
        "provider_id": provider_id,
        "account_id": account_id,
        "password": None,
        "created_at": now,
        "updated_at": now,
    }
    await adapter.create(model="account", data=account)
    return account


async def mark_email_verified(adapter: AsyncDatabaseAdapter, *, user_id: str) -> None:
    await adapter.update(
        model="user", where=[Where("id", user_id)], update={"email_verified": True}
    )
