"""Username sign-in as a plugin: set a username and sign in with it."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from .._util import new_id, utcnow
from ..db.types import FieldSpec, Row, TableSpec, Where
from ..endpoints import _service as svc
from ..endpoints.context import EndpointResult
from ..endpoints.registry import Endpoint
from ..errors import APIError
from . import Plugin

if TYPE_CHECKING:
    from ..core.auth import Auth
    from ..endpoints.context import EndpointRequest

_PATTERN = re.compile(r"^[a-z0-9_]{3,32}$")
_INVALID = APIError(401, "invalid_credentials", "Invalid username or password.")

USERNAME_TABLE = TableSpec(
    model="username",
    fields={
        "id": FieldSpec(type="string", required=True, unique=True, input=False),
        "user_id": FieldSpec(type="string", required=True, unique=True, references="user.id"),
        "username": FieldSpec(type="string", required=True, unique=True),
        "display_username": FieldSpec(type="string", required=True),
        "created_at": FieldSpec(type="date", required=True, input=False),
        "updated_at": FieldSpec(type="date", required=True, input=False),
    },
)


def username() -> Plugin:
    """Return a plugin adding ``/username/set``, ``/sign-in/username``, and availability."""
    return Plugin(
        id="username",
        schema=(USERNAME_TABLE,),
        endpoints=(
            Endpoint("POST", "/username/set", _set, "username_set"),
            Endpoint("GET", "/username/available", _available, "username_available"),
            Endpoint("POST", "/sign-in/username", _sign_in, "sign_in_username"),
        ),
    )


async def _set(auth: Auth, req: EndpointRequest) -> EndpointResult:
    _, user = await svc.require_session(auth, req)
    display = svc.require_str(req.body, "username")
    normalized = display.lower()
    if not _PATTERN.match(normalized):
        raise APIError(400, "invalid_username", "Usernames are 3-32 chars: a-z, 0-9, underscore.")

    existing = await _by_username(auth, normalized)
    if existing is not None and existing["user_id"] != user["id"]:
        raise APIError(409, "username_taken", "That username is taken.")

    now = utcnow()
    mine = await auth.adapter.find_one(model="username", where=[Where("user_id", user["id"])])
    if mine is not None:
        await auth.adapter.update(
            model="username",
            where=[Where("user_id", user["id"])],
            update={"username": normalized, "display_username": display, "updated_at": now},
        )
    else:
        await auth.adapter.create(
            model="username",
            data={
                "id": new_id(),
                "user_id": user["id"],
                "username": normalized,
                "display_username": display,
                "created_at": now,
                "updated_at": now,
            },
        )
    return EndpointResult(data={"username": display})


async def _available(auth: Auth, req: EndpointRequest) -> EndpointResult:
    value = req.query.get("username") if req.query else None
    if not value:
        raise APIError(400, "invalid_request", "Missing username.")
    normalized = value.lower()
    taken = await _by_username(auth, normalized) is not None
    return EndpointResult(data={"available": _PATTERN.match(normalized) is not None and not taken})


async def _sign_in(auth: Auth, req: EndpointRequest) -> EndpointResult:
    normalized = svc.require_str(req.body, "username").lower()
    password = svc.require_str(req.body, "password")
    row = await _by_username(auth, normalized)
    user = await svc.find_user_by_id(auth.adapter, row["user_id"]) if row else None
    account = await svc.credential_account(auth.adapter, user["id"]) if user else None
    if user is None or account is None or not account.get("password"):
        await auth.hasher.verify(svc.DECOY_HASH, password)
        raise _INVALID
    if not await auth.hasher.verify(account["password"], password):
        raise _INVALID
    if auth.hasher.needs_rehash(account["password"]):
        await svc.set_account_password(
            auth.adapter, account_id=account["id"], password_hash=await auth.hasher.hash(password)
        )
    token, _ = await auth.sessions.create(user["id"], ip=req.client_ip)
    return EndpointResult(
        data={"user": svc.public_user(user)}, cookies=[auth.sessions.build_cookie(token)]
    )


async def _by_username(auth: Auth, normalized: str) -> Row | None:
    return await auth.adapter.find_one(model="username", where=[Where("username", normalized)])
