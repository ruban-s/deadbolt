"""Generic WSGI mount — stdlib-only, works with any WSGI server or framework.

Mount the app returned by :meth:`deadbolt.Auth.wsgi_app` at ``base_path``. The
synchronous app bridges to the async core through :meth:`Auth.handle_sync`, so
no third-party dependency is required.
"""

from __future__ import annotations

from http import HTTPStatus
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl

from ..http import AuthRequest, MultiDict
from ._common import endpoint_path, parse_cookies, render_set_cookie

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from ..core.auth import Auth

    Environ = dict[str, Any]
    StartResponse = Callable[[str, list[tuple[str, str]]], Any]
    WSGIApp = Callable[[Environ, StartResponse], Iterable[bytes]]


def create_wsgi_app(auth: Auth) -> WSGIApp:
    """Build a generic WSGI application that serves ``auth``."""

    def app(environ: Environ, start_response: StartResponse) -> Iterable[bytes]:
        result = auth.handle_sync(_to_auth_request(environ, auth.base_path))
        headers = [(name, value) for name, value in result.headers.items()]
        headers.append(("Content-Type", result.media_type))
        headers.extend(("Set-Cookie", render_set_cookie(c)) for c in result.cookies)
        start_response(f"{result.status} {_reason(result.status)}", headers)
        return [result.body]

    return app


def _reason(status: int) -> str:
    try:
        return HTTPStatus(status).phrase
    except ValueError:
        return ""


def _to_auth_request(environ: Environ, base_path: str) -> AuthRequest:
    raw_path = environ.get("SCRIPT_NAME", "") + environ.get("PATH_INFO", "")
    scheme = environ.get("wsgi.url_scheme", "http")
    host = environ.get("HTTP_HOST")
    return AuthRequest(
        method=environ["REQUEST_METHOD"],
        path=endpoint_path(raw_path, base_path),
        headers=_headers(environ),
        query=MultiDict(parse_qsl(environ.get("QUERY_STRING", ""))),
        cookies=parse_cookies(environ.get("HTTP_COOKIE")),
        body=_read_body(environ),
        client_ip=environ.get("REMOTE_ADDR"),
        scheme=scheme,
        base_url=f"{scheme}://{host}" if host else None,
    )


def _headers(environ: Environ) -> MultiDict:
    headers = MultiDict()
    for key, value in environ.items():
        if key.startswith("HTTP_"):
            headers.add(key[5:].replace("_", "-").title(), value)
    if environ.get("CONTENT_TYPE"):
        headers.add("Content-Type", environ["CONTENT_TYPE"])
    if environ.get("CONTENT_LENGTH"):
        headers.add("Content-Length", environ["CONTENT_LENGTH"])
    return headers


def _read_body(environ: Environ) -> bytes:
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
    except ValueError:
        return b""
    stream = environ.get("wsgi.input")
    if length <= 0 or stream is None:
        return b""
    body: bytes = stream.read(length)
    return body
