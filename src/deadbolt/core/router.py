"""Match requests to endpoints and serialize results to responses."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl

from .._csrf import is_trusted_request
from ..endpoints import EndpointRequest
from ..errors import APIError
from ..hooks import HookContext
from ..http import AuthResponse, MultiDict

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from ..endpoints import EndpointResult, Registry
    from ..http import AuthRequest
    from .auth import Auth

    Handler = Callable[[Auth, EndpointRequest], Awaitable[EndpointResult]]

_AUDIT = logging.getLogger("deadbolt.audit")


def _json_default(value: object) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"cannot serialize {type(value).__name__}")  # pragma: no cover


def _encode(data: object) -> bytes:
    return json.dumps(data, default=_json_default).encode()


class Router:
    def __init__(self, auth: Auth, registry: Registry) -> None:
        self._auth = auth
        self._registry = registry

    async def handle(self, request: AuthRequest) -> AuthResponse:
        response = await self._dispatch(request)
        _AUDIT.info(
            "event=%s method=%s status=%d ip=%s",
            request.path,
            request.method,
            response.status,
            request.client_ip or "-",
        )
        return response

    async def _dispatch(self, request: AuthRequest) -> AuthResponse:
        endpoint = self._registry.by_route.get((request.method, request.path))
        if endpoint is None:
            return self._error(APIError(404, "not_found", "No such endpoint."))

        try:
            rejection = await self._preflight(request)
            if rejection is not None:
                return self._error(rejection)
            body = self._parse_body(request)
        except APIError as error:
            return self._error(error)

        req = EndpointRequest(
            body=body,
            cookies=dict(request.cookies),
            query=request.query,
            headers=request.headers,
            client_ip=request.client_ip,
        )
        try:
            result = await self._run(endpoint.handler, req, request.path)
        except APIError as error:
            return self._error(error)

        headers = MultiDict(list(result.headers.items()))
        return AuthResponse(
            status=result.status, headers=headers, body=_encode(result.data), cookies=result.cookies
        )

    async def _run(self, handler: Handler, req: EndpointRequest, path: str) -> EndpointResult:
        for hook in self._auth.before_hooks:
            if hook.matches(path):
                await hook.run(HookContext(self._auth, req, path))
        result = await handler(self._auth, req)
        for hook in self._auth.after_hooks:
            if hook.matches(path):
                context = HookContext(self._auth, req, path, result)
                await hook.run(context)
                if context.result is not None:
                    result = context.result
        return result

    async def _preflight(self, request: AuthRequest) -> APIError | None:
        if not is_trusted_request(request, self._auth.trusted_origins):
            return APIError(403, "untrusted_origin", "Request origin is not trusted.")
        if not await self._auth.rate_limiter.check(request.path, request.client_ip):
            return APIError(429, "rate_limited", "Too many requests.")
        if request.body is not None and len(request.body) > self._auth.max_body_bytes:
            return APIError(413, "payload_too_large", "Request body is too large.")
        return None

    @staticmethod
    def _parse_body(request: AuthRequest) -> dict[str, Any]:
        if request.method == "GET" or not request.body:
            return {}
        content_type = request.headers.get("content-type") or ""
        if "application/x-www-form-urlencoded" in content_type:
            return dict(parse_qsl(request.body.decode("utf-8", "replace")))
        try:
            parsed = json.loads(request.body)
        except json.JSONDecodeError as error:
            raise APIError(400, "invalid_json", "Request body is not valid JSON.") from error
        if not isinstance(parsed, dict):
            raise APIError(400, "invalid_json", "Request body must be a JSON object.")
        return parsed

    @staticmethod
    def _error(error: APIError) -> AuthResponse:
        payload = {"error": {"code": error.code, "message": error.message}}
        return AuthResponse(status=error.status, body=_encode(payload))
