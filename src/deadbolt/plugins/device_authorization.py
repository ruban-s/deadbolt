"""OAuth 2.0 Device Authorization Grant (RFC 8628) for input-constrained clients.

A device with no browser or keyboard — a CLI, a TV app, an IoT box — requests a
short ``user_code``, shows it to the user, and polls while the user approves it on
another device where they are already signed in. On approval the device's next poll
returns a session token it can use as a bearer credential.

Flow:

1. ``POST /device/code`` — the device gets ``device_code`` (its secret) and a
   human-friendly ``user_code`` plus a ``verification_uri``.
2. ``POST /device/token`` — the device polls with ``device_code``; it receives
   ``authorization_pending`` / ``slow_down`` until the user acts.
3. ``GET /device`` then ``POST /device/approve`` (or ``/device/deny``) — the signed-in
   user validates the ``user_code`` and approves it.
4. The device's next poll returns ``{access_token, user}`` and the session cookie.
"""

from __future__ import annotations

import secrets
from datetime import timedelta
from typing import TYPE_CHECKING

from .._util import new_id, utcnow
from ..crypto import generate_token, hash_token
from ..db.types import FieldSpec, TableSpec, Where
from ..endpoints import _service as svc
from ..endpoints.context import EndpointResult
from ..endpoints.registry import Endpoint
from ..errors import APIError
from . import Plugin

if TYPE_CHECKING:
    from ..core.auth import Auth
    from ..db.types import Row
    from ..endpoints.context import EndpointRequest

# Unambiguous alphabet (no 0/O/1/I) for codes read off a screen and typed by hand.
_ALPHABET = "BCDFGHJKLMNPQRSTVWXYZ23456789"
_PENDING, _APPROVED, _DENIED = "pending", "approved", "denied"

DEVICE_TABLE = TableSpec(
    model="device_request",
    fields={
        "id": FieldSpec(type="string", required=True, unique=True, input=False),
        "device_code": FieldSpec(type="string", required=True, unique=True, input=False),
        "user_code": FieldSpec(type="string", required=True, unique=True, input=False),
        "client_id": FieldSpec(type="string", input=False),
        "user_id": FieldSpec(type="string", references="user.id", input=False),
        "status": FieldSpec(type="string", required=True, input=False),
        "expires_at": FieldSpec(type="date", required=True, input=False),
        "created_at": FieldSpec(type="date", required=True, input=False),
        "last_polled_at": FieldSpec(type="date", input=False),
    },
)


def device_authorization(
    *,
    verification_uri: str,
    expires_in: int = 600,
    interval: int = 5,
    user_code_length: int = 8,
) -> Plugin:
    """Return the device-authorization plugin.

    ``verification_uri`` is the page where the user enters the code. ``expires_in``
    is the request lifetime (seconds), ``interval`` the minimum poll spacing, and
    ``user_code_length`` the number of characters in the user code (split as XXXX-XXXX).
    """

    async def start(auth: Auth, req: EndpointRequest) -> EndpointResult:
        device_code = generate_token()
        user_code = _user_code(user_code_length)
        now = utcnow()
        await auth.adapter.create(
            model="device_request",
            data={
                "id": new_id(),
                "device_code": hash_token(device_code),
                "user_code": user_code,
                "client_id": req.body.get("client_id"),
                "user_id": None,
                "status": _PENDING,
                "expires_at": now + timedelta(seconds=expires_in),
                "created_at": now,
                "last_polled_at": None,
            },
        )
        return EndpointResult(
            data={
                "device_code": device_code,
                "user_code": user_code,
                "verification_uri": verification_uri,
                "verification_uri_complete": f"{verification_uri}?user_code={user_code}",
                "expires_in": expires_in,
                "interval": interval,
            }
        )

    async def token(auth: Auth, req: EndpointRequest) -> EndpointResult:
        raw = svc.require_str(req.body, "device_code")
        row = await auth.adapter.find_one(
            model="device_request", where=[Where("device_code", hash_token(raw))]
        )
        now = utcnow()
        if row is None:
            raise APIError(400, "invalid_grant", "Unknown device code.")
        if row["expires_at"] <= now:
            await _delete(auth, row)
            raise APIError(400, "expired_token", "The device code has expired.")
        if row["last_polled_at"] is not None and now - row["last_polled_at"] < timedelta(
            seconds=interval
        ):
            raise APIError(400, "slow_down", "Polling too frequently; slow down.")
        await auth.adapter.update(
            model="device_request",
            where=[Where("device_code", row["device_code"])],
            update={"last_polled_at": now},
        )
        if row["status"] == _DENIED:
            await _delete(auth, row)
            raise APIError(400, "access_denied", "The request was denied.")
        if row["status"] != _APPROVED:
            raise APIError(400, "authorization_pending", "Waiting for user approval.")

        user = await svc.find_user_by_id(auth.adapter, row["user_id"])
        if user is None:
            await _delete(auth, row)
            raise APIError(400, "invalid_grant", "The approving user no longer exists.")
        await _delete(auth, row)
        session_token, _ = await auth.sessions.create(user["id"], ip=req.client_ip)
        cookie = auth.sessions.build_cookie(session_token)
        return EndpointResult(
            data={
                "access_token": cookie.value,
                "token_type": "Bearer",
                "user": svc.public_user(user),
            },
            cookies=[cookie],
        )

    async def lookup(auth: Auth, req: EndpointRequest) -> EndpointResult:
        await svc.require_session(auth, req)
        row = await _pending(auth, req.query.get("user_code") if req.query else None)
        return EndpointResult(
            data={"user_code": row["user_code"], "client_id": row["client_id"], "status": _PENDING}
        )

    async def approve(auth: Auth, req: EndpointRequest) -> EndpointResult:
        _, user = await svc.require_session(auth, req)
        row = await _pending(auth, req.body.get("user_code"))
        await auth.adapter.update(
            model="device_request",
            where=[Where("user_code", row["user_code"])],
            update={"status": _APPROVED, "user_id": user["id"]},
        )
        return EndpointResult(data={"success": True})

    async def deny(auth: Auth, req: EndpointRequest) -> EndpointResult:
        await svc.require_session(auth, req)
        row = await _pending(auth, req.body.get("user_code"))
        await auth.adapter.update(
            model="device_request",
            where=[Where("user_code", row["user_code"])],
            update={"status": _DENIED},
        )
        return EndpointResult(data={"success": True})

    return Plugin(
        id="device_authorization",
        schema=(DEVICE_TABLE,),
        endpoints=(
            Endpoint("POST", "/device/code", start, "device_code"),
            Endpoint("POST", "/device/token", token, "device_token"),
            Endpoint("GET", "/device", lookup, "device_lookup"),
            Endpoint("POST", "/device/approve", approve, "device_approve"),
            Endpoint("POST", "/device/deny", deny, "device_deny"),
        ),
    )


def _user_code(length: int) -> str:
    body = "".join(secrets.choice(_ALPHABET) for _ in range(length))
    return "-".join(body[i : i + 4] for i in range(0, length, 4))


async def _pending(auth: Auth, user_code: str | None) -> Row:
    if not user_code:
        raise APIError(400, "invalid_request", "Missing user_code.")
    normalized = user_code.strip().upper()
    row = await auth.adapter.find_one(
        model="device_request",
        where=[Where("user_code", normalized), Where("status", _PENDING)],
    )
    if row is None or row["expires_at"] <= utcnow():
        raise APIError(404, "invalid_user_code", "Unknown or expired code.")
    return row


async def _delete(auth: Auth, row: Row) -> None:
    await auth.adapter.delete(
        model="device_request", where=[Where("device_code", row["device_code"])]
    )
