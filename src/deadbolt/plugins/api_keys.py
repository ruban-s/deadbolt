"""API keys for programmatic access as a plugin.

Keys are shown once at creation and stored only as a SHA-256 hash. Verify a key
with ``/api-key/verify`` to authenticate machine-to-machine requests.
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

from .._util import new_id, utcnow
from ..crypto import generate_token, hash_token
from ..db.types import FieldSpec, Row, TableSpec, Where
from ..endpoints import _service as svc
from ..endpoints.context import EndpointResult
from ..endpoints.registry import Endpoint
from ..errors import APIError
from . import Plugin

if TYPE_CHECKING:
    from ..core.auth import Auth
    from ..endpoints.context import EndpointRequest

API_KEY_TABLE = TableSpec(
    model="api_key",
    fields={
        "id": FieldSpec(type="string", required=True, unique=True, input=False),
        "user_id": FieldSpec(type="string", required=True, references="user.id", input=False),
        "name": FieldSpec(type="string", required=True),
        "key": FieldSpec(type="string", required=True, unique=True, input=False),
        "start": FieldSpec(type="string", required=True, input=False),
        "expires_at": FieldSpec(type="date", input=False),
        "last_used_at": FieldSpec(type="date", input=False),
        "created_at": FieldSpec(type="date", required=True, input=False),
    },
)

_PREFIX = "dbk_"
_PUBLIC = ("id", "name", "start", "expires_at", "last_used_at", "created_at")


def api_keys() -> Plugin:
    """Return a plugin adding create/list/revoke/verify for API keys."""
    return Plugin(
        id="api-keys",
        schema=(API_KEY_TABLE,),
        endpoints=(
            Endpoint("POST", "/api-key/create", _create, "api_key_create"),
            Endpoint("GET", "/api-key/list", _list, "api_key_list"),
            Endpoint("POST", "/api-key/revoke", _revoke, "api_key_revoke"),
            Endpoint("POST", "/api-key/verify", _verify, "api_key_verify"),
        ),
    )


async def _create(auth: Auth, req: EndpointRequest) -> EndpointResult:
    _, user = await svc.require_session(auth, req)
    name = svc.require_str(req.body, "name")
    key = f"{_PREFIX}{generate_token()}"
    now = utcnow()
    expires_at = None
    if isinstance(req.body.get("expires_in"), int):
        expires_at = now + timedelta(seconds=req.body["expires_in"])
    record: Row = {
        "id": new_id(),
        "user_id": user["id"],
        "name": name,
        "key": hash_token(key),
        "start": key[: len(_PREFIX) + 6],
        "expires_at": expires_at,
        "last_used_at": None,
        "created_at": now,
    }
    await auth.adapter.create(model="api_key", data=record)
    return EndpointResult(data={"key": key, "api_key": _public(record)})


async def _list(auth: Auth, req: EndpointRequest) -> EndpointResult:
    _, user = await svc.require_session(auth, req)
    rows = await auth.adapter.find_many(model="api_key", where=[Where("user_id", user["id"])])
    return EndpointResult(data={"api_keys": [_public(row) for row in rows]})


async def _revoke(auth: Auth, req: EndpointRequest) -> EndpointResult:
    _, user = await svc.require_session(auth, req)
    key_id = svc.require_str(req.body, "id")
    existing = await auth.adapter.find_one(
        model="api_key", where=[Where("id", key_id), Where("user_id", user["id"])]
    )
    if existing is None:
        raise APIError(404, "not_found", "No such API key.")
    await auth.adapter.delete(model="api_key", where=[Where("id", key_id)])
    return EndpointResult(data={"success": True})


async def _verify(auth: Auth, req: EndpointRequest) -> EndpointResult:
    key = svc.require_str(req.body, "key")
    record = await auth.adapter.find_one(model="api_key", where=[Where("key", hash_token(key))])
    if record is None or (record["expires_at"] is not None and record["expires_at"] <= utcnow()):
        raise APIError(401, "invalid_key", "The API key is invalid or expired.")
    await auth.adapter.update(
        model="api_key", where=[Where("id", record["id"])], update={"last_used_at": utcnow()}
    )
    return EndpointResult(data={"valid": True, "user_id": record["user_id"]})


def _public(record: Row) -> Row:
    return {k: record[k] for k in _PUBLIC if k in record}
