"""One-time tokens: mint a short-lived, single-use token to hand off a session.

A signed-in user generates an opaque token bound to their user id; presenting it
once — on another subdomain, device, or app — exchanges it for a fresh session.
Only ``SHA-256(token)`` is stored, the token is deleted on first use, and it
expires quickly, so a leaked token grants at most one short window.
"""

from __future__ import annotations

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
    from ..endpoints.context import EndpointRequest

TOKEN_TABLE = TableSpec(
    model="one_time_token",
    fields={
        "id": FieldSpec(type="string", required=True, unique=True, input=False),
        "user_id": FieldSpec(type="string", required=True, references="user.id", input=False),
        "token": FieldSpec(type="string", required=True, unique=True, input=False),
        "expires_at": FieldSpec(type="date", required=True, input=False),
        "created_at": FieldSpec(type="date", required=True, input=False),
    },
)

_INVALID = APIError(401, "invalid_token", "The token is invalid, expired, or already used.")


def one_time_token(*, expires_in: int = 60) -> Plugin:
    """Return a plugin adding ``/one-time-token/generate`` and ``/verify``.

    ``expires_in`` is the token lifetime in seconds (default 60).
    """

    async def generate(auth: Auth, req: EndpointRequest) -> EndpointResult:
        _, user = await svc.require_session(auth, req)
        token = generate_token()
        now = utcnow()
        await auth.adapter.create(
            model="one_time_token",
            data={
                "id": new_id(),
                "user_id": user["id"],
                "token": hash_token(token),
                "expires_at": now + timedelta(seconds=expires_in),
                "created_at": now,
            },
        )
        return EndpointResult(data={"token": token, "expires_in": expires_in})

    async def verify(auth: Auth, req: EndpointRequest) -> EndpointResult:
        raw = svc.require_str(req.body, "token")
        row = await auth.adapter.find_one(
            model="one_time_token", where=[Where("token", hash_token(raw))]
        )
        if row is None:
            raise _INVALID
        await auth.adapter.delete(model="one_time_token", where=[Where("token", row["token"])])
        if row["expires_at"] <= utcnow():
            raise _INVALID
        user = await svc.find_user_by_id(auth.adapter, row["user_id"])
        if user is None:
            raise _INVALID
        session_token, _ = await auth.sessions.create(user["id"], ip=req.client_ip)
        return EndpointResult(
            data={"user": svc.public_user(user)},
            cookies=[auth.sessions.build_cookie(session_token)],
        )

    return Plugin(
        id="one_time_token",
        schema=(TOKEN_TABLE,),
        endpoints=(
            Endpoint("POST", "/one-time-token/generate", generate, "one_time_token_generate"),
            Endpoint("POST", "/one-time-token/verify", verify, "one_time_token_verify"),
        ),
    )
