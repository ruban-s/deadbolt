"""Session-management endpoints: list and revoke."""

from __future__ import annotations

from typing import TYPE_CHECKING

from . import _service as svc
from .context import EndpointResult

if TYPE_CHECKING:
    from ..core.auth import Auth
    from ..db.types import Row
    from .context import EndpointRequest

_PUBLIC_FIELDS = ("id", "expires_at", "created_at", "updated_at", "ip_address", "user_agent")


def _public_session(session: Row) -> Row:
    return {k: session[k] for k in _PUBLIC_FIELDS if k in session}


async def list_sessions(auth: Auth, req: EndpointRequest) -> EndpointResult:
    _, user = await svc.require_session(auth, req)
    rows = await auth.sessions.list_for(user["id"])
    return EndpointResult(data={"sessions": [_public_session(row) for row in rows]})


async def revoke_session(auth: Auth, req: EndpointRequest) -> EndpointResult:
    _, user = await svc.require_session(auth, req)
    session_id = svc.require_str(req.body, "session_id")
    revoked = await auth.sessions.revoke_by_id(session_id, user["id"])
    return EndpointResult(data={"success": revoked})


async def revoke_other_sessions(auth: Auth, req: EndpointRequest) -> EndpointResult:
    _, user = await svc.require_session(auth, req)
    current = auth.sessions.read_token(req.cookies)
    revoked = await auth.sessions.revoke_others(user["id"], current) if current else 0
    return EndpointResult(data={"revoked": revoked})


async def revoke_sessions(auth: Auth, req: EndpointRequest) -> EndpointResult:
    _, user = await svc.require_session(auth, req)
    revoked = await auth.sessions.revoke_all(user["id"])
    return EndpointResult(data={"revoked": revoked}, cookies=[auth.sessions.clear_cookie()])
