"""Reject breached passwords via Have I Been Pwned's k-anonymity range API.

On sign-up and any password change, the password's SHA-1 is computed locally; only
the first five hex characters are sent to ``api.pwnedpasswords.com``, which returns
every breached suffix under that prefix. The full hash never leaves the process, so
the check is privacy-preserving. A password found in the breach corpus is rejected
with ``400 pwned_password``.

The network call is injectable via ``fetch`` so it can be stubbed in tests.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from ..errors import APIError
from ..hooks import Hook
from . import Plugin

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from ..hooks import HookContext

    Fetch = Callable[[str], Awaitable[str]]

_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
# (endpoint path, body field carrying the new password)
_GUARDED = (
    ("/sign-up/email", "password"),
    ("/change-password", "new_password"),
    ("/reset-password", "new_password"),
)
_PWNED = APIError(
    400, "pwned_password", "This password has appeared in a data breach; choose another."
)


async def _default_fetch(prefix: str) -> str:
    import httpx  # noqa: PLC0415 — optional dependency, imported only when used

    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.get(
            _RANGE_URL.format(prefix=prefix), headers={"Add-Padding": "true"}
        )
        response.raise_for_status()
        return response.text


async def _is_breached(password: str, fetch: Fetch) -> bool:
    digest = hashlib.sha1(password.encode(), usedforsecurity=False).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    for line in (await fetch(prefix)).splitlines():
        candidate, _, count = line.partition(":")
        if candidate.strip() == suffix and count.strip() not in {"", "0"}:
            return True
    return False


def haveibeenpwned(*, fetch: Fetch | None = None) -> Plugin:
    """Return a plugin that rejects breached passwords on sign-up and password change.

    ``fetch`` overrides the HIBP range lookup (a coroutine taking the 5-char hash
    prefix and returning the raw range response); the default uses ``httpx``.
    """
    lookup = fetch or _default_fetch

    def guard(field: str) -> Callable[[HookContext], Awaitable[None]]:
        async def check(context: HookContext) -> None:
            password = context.request.body.get(field)
            if isinstance(password, str) and password and await _is_breached(password, lookup):
                raise _PWNED

        return check

    return Plugin(
        id="haveibeenpwned",
        before=tuple(Hook(guard(field), path=path) for path, field in _GUARDED),
    )
