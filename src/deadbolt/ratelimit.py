"""Fixed-window rate limiting for auth endpoints, with pluggable storage."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Callable


@dataclass(frozen=True)
class RateLimitRule:
    """A per-path override; ``path`` matches an endpoint path exactly."""

    path: str
    max: int
    window: int


DEFAULT_RULES: tuple[RateLimitRule, ...] = (
    RateLimitRule("/sign-in/email", max=10, window=60),
    RateLimitRule("/sign-up/email", max=10, window=60),
    RateLimitRule("/request-password-reset", max=5, window=60),
    RateLimitRule("/reset-password", max=10, window=60),
)


@dataclass(frozen=True)
class RateLimit:
    """Global window/max plus per-path rule overrides."""

    enabled: bool = True
    window: int = 60
    max: int = 100
    rules: tuple[RateLimitRule, ...] = DEFAULT_RULES


@runtime_checkable
class RateLimitStore(Protocol):
    """Counts hits per key within a window; return the running count."""

    async def increment(self, key: str, window: int) -> int: ...


@dataclass
class MemoryRateLimitStore:
    now: Callable[[], float] = time.monotonic
    _buckets: dict[str, tuple[float, int]] = field(default_factory=dict)

    async def increment(self, key: str, window: int) -> int:
        moment = self.now()
        start, count = self._buckets.get(key, (moment, 0))
        if moment - start >= window:
            start, count = moment, 0
        count += 1
        self._buckets[key] = (start, count)
        return count


class RateLimiter:
    def __init__(self, config: RateLimit, store: RateLimitStore | None = None) -> None:
        self._config = config
        self._store = store or MemoryRateLimitStore()

    def _rule_for(self, path: str) -> tuple[int, int]:
        for rule in self._config.rules:
            if rule.path == path:
                return rule.max, rule.window
        return self._config.max, self._config.window

    async def check(self, path: str, client_ip: str | None) -> bool:
        if not self._config.enabled:
            return True
        limit, window = self._rule_for(path)
        key = f"{client_ip or 'global'}:{path}"
        return await self._store.increment(key, window) <= limit
