"""Passwordless magic-link authentication as a plugin."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any

from .._util import new_id, utcnow
from ..crypto import generate_token, hash_token
from ..db.types import Where
from ..endpoints._service import create_user, find_user_by_email, public_user
from ..endpoints.context import EndpointResult
from ..endpoints.registry import Endpoint
from ..errors import APIError
from . import Plugin

if TYPE_CHECKING:
    from ..core.auth import Auth
    from ..endpoints.context import EndpointRequest

_IDENTIFIER_PREFIX = "magic-link:"
_DEFAULT_TTL = 600


def magic_link(*, expires_in: int = _DEFAULT_TTL) -> Plugin:
    """Return a plugin adding ``/magic-link/send`` and ``/magic-link/verify``."""

    async def send(auth: Auth, req: EndpointRequest) -> EndpointResult:
        email = _require(req.body, "email").lower()
        token = generate_token()
        now = utcnow()
        await auth.adapter.create(
            model="verification",
            data={
                "id": new_id(),
                "identifier": f"{_IDENTIFIER_PREFIX}{email}",
                "value": hash_token(token),
                "expires_at": now + timedelta(seconds=expires_in),
                "created_at": now,
            },
        )
        if auth.email_sender is not None:
            await auth.email_sender.send(
                to=email, subject="Your magic link", body=f"Magic token: {token}"
            )
        return EndpointResult(data={"success": True})

    async def verify(auth: Auth, req: EndpointRequest) -> EndpointResult:
        token = _require(req.body, "token")
        token_hash = hash_token(token)
        record = await auth.adapter.find_one(
            model="verification", where=[Where("value", token_hash)]
        )
        if record is None or not _is_magic(record) or record["expires_at"] <= utcnow():
            raise APIError(400, "invalid_token", "The magic link is invalid or expired.")

        email = record["identifier"].removeprefix(_IDENTIFIER_PREFIX)
        user = await find_user_by_email(auth.adapter, email)
        if user is None:
            user = await create_user(auth.adapter, email=email, name=None)
        await auth.adapter.update(
            model="user", where=[Where("id", user["id"])], update={"email_verified": True}
        )
        user["email_verified"] = True

        await auth.adapter.delete(model="verification", where=[Where("value", token_hash)])
        session_token, _ = await auth.sessions.create(user["id"], ip=req.client_ip)
        return EndpointResult(
            data={"user": public_user(user)}, cookies=[auth.sessions.build_cookie(session_token)]
        )

    return Plugin(
        id="magic-link",
        endpoints=(
            Endpoint("POST", "/magic-link/send", send, "magic_link_send"),
            Endpoint("POST", "/magic-link/verify", verify, "magic_link_verify"),
        ),
    )


def _require(body: dict[str, Any], key: str) -> str:
    value = body.get(key)
    if not isinstance(value, str) or not value:
        raise APIError(400, "invalid_request", f"Missing or invalid field: {key}.")
    return value


def _is_magic(record: dict[str, Any]) -> bool:
    return str(record["identifier"]).startswith(_IDENTIFIER_PREFIX)
