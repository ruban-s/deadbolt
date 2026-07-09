"""Bearer-token auth: authenticate with ``Authorization`` instead of a cookie.

Non-browser clients — mobile apps, SPAs, server-to-server callers — cannot rely on
cookies. This plugin lets them send the signed session token in the
``Authorization: Bearer <token>`` header instead. A before-hook copies that token
into the session-cookie slot, so the rest of the core treats it exactly like a
cookie-borne session (signature check, expiry, rotation, revocation all apply). An
after-hook echoes a freshly issued token in the ``set-auth-token`` response header
on sign-in, so a cookie-less client can capture it.

The token is the same HMAC-signed value the session cookie carries, so a tampered
or forged bearer token is rejected before any database lookup.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..hooks import Hook
from . import Plugin

if TYPE_CHECKING:
    from ..hooks import HookContext

_SCHEME = "bearer "


def bearer(*, response_header: str = "set-auth-token") -> Plugin:
    """Return a plugin that accepts bearer tokens and exposes them on sign-in.

    ``response_header`` names the response header the freshly issued token is
    written to when a request establishes a new session.
    """

    async def accept(context: HookContext) -> None:
        request = context.request
        name = context.auth.sessions.cookie_name
        if name in request.cookies or request.headers is None:
            return
        authorization = request.headers.get("authorization")
        if authorization and authorization[: len(_SCHEME)].lower() == _SCHEME:
            request.cookies[name] = authorization[len(_SCHEME) :].strip()

    async def expose(context: HookContext) -> None:
        result = context.result
        if result is None:
            return
        name = context.auth.sessions.cookie_name
        for cookie in result.cookies:
            if cookie.name == name and cookie.value:
                result.headers[response_header] = cookie.value

    return Plugin(id="bearer", before=(Hook(accept),), after=(Hook(expose),))
