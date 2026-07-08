"""Core table definitions: user, session, account, verification."""

from __future__ import annotations

from ..db.types import FieldSpec, TableSpec

USER = TableSpec(
    model="user",
    fields={
        "id": FieldSpec(type="string", required=True, unique=True, input=False),
        "email": FieldSpec(type="string", required=True, unique=True),
        "email_verified": FieldSpec(type="boolean", required=True, default_value=False),
        "name": FieldSpec(type="string"),
        "image": FieldSpec(type="string"),
        "created_at": FieldSpec(type="date", required=True, input=False),
        "updated_at": FieldSpec(type="date", required=True, input=False),
    },
)

SESSION = TableSpec(
    model="session",
    fields={
        "id": FieldSpec(type="string", required=True, unique=True, input=False),
        "user_id": FieldSpec(type="string", required=True, references="user.id", input=False),
        "token": FieldSpec(type="string", required=True, unique=True, input=False),
        "expires_at": FieldSpec(type="date", required=True, input=False),
        "created_at": FieldSpec(type="date", required=True, input=False),
        "updated_at": FieldSpec(type="date", required=True, input=False),
        "ip_address": FieldSpec(type="string", input=False),
        "user_agent": FieldSpec(type="string", input=False),
    },
)

ACCOUNT = TableSpec(
    model="account",
    fields={
        "id": FieldSpec(type="string", required=True, unique=True, input=False),
        "user_id": FieldSpec(type="string", required=True, references="user.id", input=False),
        "provider_id": FieldSpec(type="string", required=True, input=False),
        "account_id": FieldSpec(type="string", required=True, input=False),
        "password": FieldSpec(type="string", input=False),
        "created_at": FieldSpec(type="date", required=True, input=False),
        "updated_at": FieldSpec(type="date", required=True, input=False),
    },
)

VERIFICATION = TableSpec(
    model="verification",
    fields={
        "id": FieldSpec(type="string", required=True, unique=True, input=False),
        "identifier": FieldSpec(type="string", required=True, input=False),
        "value": FieldSpec(type="string", required=True, input=False),
        "expires_at": FieldSpec(type="date", required=True, input=False),
        "created_at": FieldSpec(type="date", required=True, input=False),
    },
)

CORE_TABLES: tuple[TableSpec, ...] = (USER, SESSION, ACCOUNT, VERIFICATION)

__all__ = ["ACCOUNT", "CORE_TABLES", "SESSION", "USER", "VERIFICATION"]
