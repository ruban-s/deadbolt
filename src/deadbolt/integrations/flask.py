"""Flask (WSGI) mount adapter. Requires ``deadbolt[flask]``.

The synchronous view bridges to the async core through ``Auth.handle_sync``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flask import Response, request

from ..http import AuthRequest, MultiDict

if TYPE_CHECKING:
    from flask import Flask

    from ..core.auth import Auth
    from ..http import AuthResponse

_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]


def mount(app: Flask, auth: Auth, *, prefix: str = "/api/auth") -> None:
    """Mount ``auth`` on a Flask ``app`` under ``prefix``."""

    def view(path: str) -> Response:
        result = auth.handle_sync(_to_auth_request(path))
        return _to_response(result)

    app.add_url_rule(
        f"{prefix}/<path:path>", endpoint="deadbolt_auth", view_func=view, methods=_METHODS
    )


def _to_auth_request(path: str) -> AuthRequest:
    return AuthRequest(
        method=request.method,
        path=f"/{path}",
        headers=MultiDict(request.headers.items()),
        query=MultiDict(request.args.items(multi=True)),
        cookies=dict(request.cookies),
        body=request.get_data(cache=True),
        client_ip=request.remote_addr,
        base_url=request.host_url,
    )


def _to_response(result: AuthResponse) -> Response:
    response = Response(response=result.body, status=result.status, mimetype=result.media_type)
    for cookie in result.cookies:
        response.set_cookie(
            cookie.name,
            cookie.value,
            max_age=cookie.max_age,
            path=cookie.path,
            domain=cookie.domain,
            secure=cookie.secure,
            httponly=cookie.http_only,
            samesite=cookie.same_site,
        )
    return response
