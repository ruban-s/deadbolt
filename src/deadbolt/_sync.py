"""Bridge synchronous (WSGI) callers to the async core via one background loop."""

from __future__ import annotations

from typing import TYPE_CHECKING, TypeVar

import sniffio
from anyio.from_thread import start_blocking_portal

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from contextlib import AbstractContextManager

    from anyio.from_thread import BlockingPortal

T = TypeVar("T")


class SyncBridge:
    """Runs coroutines from sync code on a single long-lived event loop.

    A dedicated background thread holds one loop, so pooled resources created on
    it are never torn between loops. Refuses to run from within a running loop,
    where the async entrypoint should be used instead.
    """

    def __init__(self) -> None:
        self._portal: BlockingPortal | None = None
        self._cm: AbstractContextManager[BlockingPortal] | None = None

    def run(self, func: Callable[..., Awaitable[T]], *args: object) -> T:
        try:
            sniffio.current_async_library()
        except sniffio.AsyncLibraryNotFoundError:
            return self._ensure_portal().call(func, *args)
        raise RuntimeError(
            "Synchronous mount called from an async context; use the async mount instead."
        )

    def _ensure_portal(self) -> BlockingPortal:
        if self._portal is None:
            self._cm = start_blocking_portal()
            self._portal = self._cm.__enter__()
        return self._portal

    def close(self) -> None:
        if self._cm is not None:
            self._cm.__exit__(None, None, None)
            self._cm = None
            self._portal = None
