"""Hold several signed-in accounts in one browser and switch between them.

Every successful sign-in is appended to a signed ``multi_session`` cookie alongside
the primary session cookie. ``/multi-session/list`` returns each still-valid
account, ``/multi-session/set-active`` swaps which one the primary session cookie
points at, and ``/multi-session/revoke`` drops one.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from ..crypto import CookieSigner
from ..endpoints import _service as svc
from ..endpoints.context import EndpointResult
from ..endpoints.registry import Endpoint
from ..errors import APIError
from ..hooks import Hook
from ..http import Cookie
from . import Plugin

if TYPE_CHECKING:
    from ..core.auth import Auth
    from ..db.types import Row
    from ..endpoints.context import EndpointRequest
    from ..hooks import HookContext

_SALT = "multi-session"
_NOT_FOUND = APIError(404, "session_not_found", "No such session in this browser.")


def multi_session(*, max_sessions: int = 5) -> Plugin:
    """Return a plugin that tracks up to ``max_sessions`` accounts per browser."""

    async def append(context: HookContext) -> None:
        result = context.result
        if result is None:
            return
        auth = context.auth
        fresh = next(
            (c.value for c in result.cookies if c.name == auth.sessions.cookie_name and c.value),
            None,
        )
        if fresh is None:
            return
        signer = _signer(auth)
        values = [v for v in _read(context.request.cookies, auth, signer) if v != fresh]
        values.append(fresh)
        result.cookies.append(_cookie(auth, signer, values[-max_sessions:]))

    async def list_sessions(auth: Auth, req: EndpointRequest) -> EndpointResult:
        active = req.cookies.get(auth.sessions.cookie_name)
        accounts = []
        for value in _read(req.cookies, auth, _signer(auth)):
            session, user = await _resolve(auth, value)
            if session is not None and user is not None:
                accounts.append(
                    {
                        "session_id": session["id"],
                        "user": svc.public_user(user),
                        "active": value == active,
                    }
                )
        return EndpointResult(data={"sessions": accounts})

    async def set_active(auth: Auth, req: EndpointRequest) -> EndpointResult:
        target = svc.require_str(req.body, "session_id")
        for value in _read(req.cookies, auth, _signer(auth)):
            session, _ = await _resolve(auth, value)
            if session is not None and session["id"] == target:
                token = auth.sessions.read_token({auth.sessions.cookie_name: value})
                if token is not None:
                    return EndpointResult(
                        data={"active": target}, cookies=[auth.sessions.build_cookie(token)]
                    )
        raise _NOT_FOUND

    async def revoke(auth: Auth, req: EndpointRequest) -> EndpointResult:
        target = svc.require_str(req.body, "session_id")
        signer = _signer(auth)
        remaining, removed = [], False
        for value in _read(req.cookies, auth, signer):
            session, _ = await _resolve(auth, value)
            if session is not None and session["id"] == target:
                token = auth.sessions.read_token({auth.sessions.cookie_name: value})
                if token is not None:
                    await auth.sessions.revoke(token)
                removed = True
            else:
                remaining.append(value)
        if not removed:
            raise _NOT_FOUND
        return EndpointResult(data={"success": True}, cookies=[_cookie(auth, signer, remaining)])

    return Plugin(
        id="multi_session",
        after=(Hook(append),),
        endpoints=(
            Endpoint("GET", "/multi-session/list", list_sessions, "multi_session_list"),
            Endpoint("POST", "/multi-session/set-active", set_active, "multi_session_set_active"),
            Endpoint("POST", "/multi-session/revoke", revoke, "multi_session_revoke"),
        ),
    )


def _signer(auth: Auth) -> CookieSigner:
    return CookieSigner(auth.secret, salt=_SALT)


def _cookie_name(auth: Auth) -> str:
    if auth.cookie.host_prefix and auth.cookie.secure:
        return "__Host-multi_session"
    return "multi_session"


def _read(cookies: dict[str, str], auth: Auth, signer: CookieSigner) -> list[str]:
    raw = cookies.get(_cookie_name(auth))
    unsigned = signer.unsign(raw) if raw else None
    if unsigned is None:
        return []
    try:
        data = json.loads(unsigned)
    except json.JSONDecodeError:
        return []
    return [v for v in data if isinstance(v, str)] if isinstance(data, list) else []


def _cookie(auth: Auth, signer: CookieSigner, values: list[str]) -> Cookie:
    return Cookie(
        name=_cookie_name(auth),
        value=signer.sign(json.dumps(values)),
        max_age=auth.session.expires_in,
        path=auth.cookie.path,
        domain=None if auth.cookie.host_prefix else auth.cookie.domain,
        secure=auth.cookie.secure,
        http_only=True,
        same_site=auth.cookie.same_site,
    )


async def _resolve(auth: Auth, signed_value: str) -> tuple[Row | None, Row | None]:
    token = auth.sessions.read_token({auth.sessions.cookie_name: signed_value})
    session = await auth.sessions.validate(token) if token else None
    user = await svc.find_user_by_id(auth.adapter, session["user_id"]) if session else None
    return session, user
