"""The direct-call API: invoke endpoints as functions, without HTTP."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..endpoints import EndpointRequest

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from ..endpoints import Registry
    from .auth import Auth


class Api:
    """Exposes each endpoint as ``await auth.api.<name>(**body)``.

    Returns the endpoint's parsed data by default, or the full
    :class:`~deadbolt.endpoints.EndpointResult` when ``as_response=True``.
    """

    def __init__(self, auth: Auth, registry: Registry) -> None:
        self._auth = auth
        self._registry = registry

    def __getattr__(self, name: str) -> Callable[..., Awaitable[Any]]:
        endpoint = self._registry.by_name.get(name)
        if endpoint is None:
            raise AttributeError(name)

        async def call(
            *,
            as_response: bool = False,
            cookies: dict[str, str] | None = None,
            client_ip: str | None = None,
            **body: Any,
        ) -> Any:
            req = EndpointRequest(body=dict(body), cookies=cookies or {}, client_ip=client_ip)
            result = await endpoint.handler(self._auth, req)
            return result if as_response else result.data

        return call
