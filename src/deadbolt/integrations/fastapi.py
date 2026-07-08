"""FastAPI / Starlette mount adapter. Requires ``deadbolt[fastapi]``."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from starlette.responses import Response
from starlette.routing import Route

from ..http import AuthRequest, MultiDict

if TYPE_CHECKING:
    from starlette.applications import Starlette
    from starlette.requests import Request

    from ..core.auth import Auth
    from ..http import AuthResponse

_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]


def mount(app: Starlette, auth: Auth, *, prefix: str = "/api/auth") -> None:
    """Mount ``auth`` on a FastAPI/Starlette ``app`` under ``prefix``."""

    async def endpoint(request: Request) -> Response:
        result = await auth.handle(await _to_auth_request(request))
        return _to_response(result)

    app.router.routes.append(Route(f"{prefix}/{{path:path}}", endpoint, methods=_METHODS))


async def _to_auth_request(request: Request) -> AuthRequest:
    path = request.path_params.get("path", "")
    return AuthRequest(
        method=request.method,
        path=f"/{path}",
        headers=MultiDict(request.headers.items()),
        query=MultiDict(request.query_params.multi_items()),
        cookies=dict(request.cookies),
        body=await request.body(),
        client_ip=request.client.host if request.client else None,
        base_url=str(request.base_url),
    )


def _to_response(result: AuthResponse) -> Response:
    response = Response(
        content=result.body, status_code=result.status, media_type=result.media_type
    )
    for name, value in result.headers.items():
        response.headers[name] = value
    for cookie in result.cookies:
        response.set_cookie(
            cookie.name,
            cookie.value,
            max_age=cookie.max_age,
            path=cookie.path,
            domain=cookie.domain,
            secure=cookie.secure,
            httponly=cookie.http_only,
            samesite=_samesite(cookie.same_site),
        )
    return response


def _samesite(value: str) -> Literal["lax", "strict", "none"]:
    normalized = value.lower()
    if normalized == "strict":
        return "strict"
    if normalized == "none":
        return "none"
    return "lax"
