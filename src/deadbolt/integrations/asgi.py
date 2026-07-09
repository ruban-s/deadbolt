"""Generic ASGI mount — stdlib-only, works with any ASGI server or framework.

Mount the app returned by :meth:`deadbolt.Auth.asgi_app` at ``base_path`` with
your framework's mounting primitive (e.g. Starlette ``Mount``), or serve it
directly. Requests are translated to the normalized :class:`AuthRequest`
contract and back, so no third-party dependency is required.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl

from ..http import AuthRequest, MultiDict
from ._common import endpoint_path, parse_cookies, render_set_cookie

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, MutableMapping

    from ..core.auth import Auth
    from ..http import AuthResponse

    Scope = MutableMapping[str, Any]
    Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
    Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]
    ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


def create_asgi_app(auth: Auth) -> ASGIApp:
    """Build a generic ASGI application that serves ``auth``."""

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await _serve_lifespan(receive, send)
            return
        if scope["type"] != "http":
            message = f"deadbolt ASGI app cannot serve {scope['type']!r} requests."
            raise NotImplementedError(message)
        request = await _to_auth_request(scope, receive, auth.base_path)
        await _send_response(send, await auth.handle(request))

    return app


async def _serve_lifespan(receive: Receive, send: Send) -> None:
    while True:
        message = await receive()
        if message["type"] == "lifespan.startup":
            await send({"type": "lifespan.startup.complete"})
        elif message["type"] == "lifespan.shutdown":
            await send({"type": "lifespan.shutdown.complete"})
            return


async def _to_auth_request(scope: Scope, receive: Receive, base_path: str) -> AuthRequest:
    headers = MultiDict(
        (key.decode("latin-1"), value.decode("latin-1")) for key, value in scope["headers"]
    )
    scheme = scope.get("scheme", "http")
    host = headers.get("host")
    client = scope.get("client")
    return AuthRequest(
        method=scope["method"],
        path=endpoint_path(scope["path"], base_path),
        headers=headers,
        query=MultiDict(parse_qsl(scope.get("query_string", b"").decode("latin-1"))),
        cookies=parse_cookies(headers.get("cookie")),
        body=await _read_body(receive),
        client_ip=client[0] if client else None,
        scheme=scheme,
        base_url=f"{scheme}://{host}" if host else None,
    )


async def _read_body(receive: Receive) -> bytes:
    chunks: list[bytes] = []
    more_body = True
    while more_body:
        message = await receive()
        chunks.append(message.get("body", b""))
        more_body = message.get("more_body", False)
    return b"".join(chunks)


async def _send_response(send: Send, result: AuthResponse) -> None:
    headers = [
        (name.encode("latin-1"), value.encode("latin-1")) for name, value in result.headers.items()
    ]
    headers.append((b"content-type", result.media_type.encode("latin-1")))
    headers.extend((b"set-cookie", render_set_cookie(c).encode("latin-1")) for c in result.cookies)
    await send({"type": "http.response.start", "status": result.status, "headers": headers})
    await send({"type": "http.response.body", "body": result.body})
