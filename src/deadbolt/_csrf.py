"""Origin-based CSRF defense-in-depth for state-changing requests."""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from collections.abc import Sequence

    from .http import AuthRequest

_STATE_CHANGING = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def origin_of(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def _matches(origin: str, allowed: str) -> bool:
    if allowed.endswith("*"):
        return origin.startswith(allowed[:-1])
    return origin == allowed


def is_trusted_request(request: AuthRequest, trusted: Sequence[str]) -> bool:
    """Return whether a request may perform a state-changing action.

    Non-mutating methods and requests without an ``Origin`` header (server-side
    and native clients) are always allowed. A browser cross-origin request must
    match ``trusted`` or the request's own origin.
    """
    if request.method not in _STATE_CHANGING:
        return True
    origin = request.headers.get("origin")
    if origin is None:
        return True
    allowed = list(trusted)
    if request.base_url:
        allowed.append(origin_of(request.base_url))
    return any(_matches(origin, candidate) for candidate in allowed)
