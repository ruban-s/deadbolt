"""Match requests to endpoints and serialize results to responses."""

from __future__ import annotations

import json
from datetime import datetime
from typing import TYPE_CHECKING, Any

from .._csrf import is_trusted_request
from ..endpoints import EndpointRequest
from ..errors import APIError
from ..http import AuthResponse

if TYPE_CHECKING:
    from ..endpoints import Registry
    from ..http import AuthRequest
    from .auth import Auth


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
            result = await endpoint.handler(self._auth, req)
        except APIError as error:
            return self._error(error)

        return AuthResponse(status=result.status, body=_encode(result.data), cookies=result.cookies)

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
