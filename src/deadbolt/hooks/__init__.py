"""Before/after request hooks: block, observe, or rewrite endpoint results."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from ..core.auth import Auth
    from ..endpoints.context import EndpointRequest, EndpointResult


@dataclass
class HookContext:
    auth: Auth
    request: EndpointRequest
    path: str
    result: EndpointResult | None = None


@dataclass(frozen=True)
class Hook:
    """A hook bound to an exact ``path`` (or all paths when ``path`` is None)."""

    run: Callable[[HookContext], Awaitable[None]]
    path: str | None = None

    def matches(self, path: str) -> bool:
        return self.path is None or self.path == path


@dataclass(frozen=True)
class Hooks:
    before: tuple[Hook, ...] = ()
    after: tuple[Hook, ...] = ()


__all__ = ["Hook", "HookContext", "Hooks"]
