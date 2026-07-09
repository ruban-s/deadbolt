"""Require a CAPTCHA solution on sensitive endpoints (sign-in, sign-up).

Supports Cloudflare Turnstile, hCaptcha, and Google reCAPTCHA — any provider with a
token-verification endpoint. The client sends the solution token in a header
(default ``x-captcha-response``); a before-hook verifies it with the provider before
the request reaches the handler. A missing or failed solution is rejected with
``400 captcha_failed``.

The verification call is injectable via ``verify`` so it can be stubbed in tests.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..errors import APIError
from ..hooks import Hook
from . import Plugin

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Sequence

    from ..hooks import HookContext

    Verify = Callable[[str], Awaitable[bool]]

_ENDPOINTS = {
    "turnstile": "https://challenges.cloudflare.com/turnstile/v0/siteverify",
    "hcaptcha": "https://hcaptcha.com/siteverify",
    "recaptcha": "https://www.google.com/recaptcha/api/siteverify",
}
_DEFAULT_PATHS = ("/sign-in/email", "/sign-up/email")
_FAILED = APIError(400, "captcha_failed", "CAPTCHA verification failed.")


def captcha(
    *,
    provider: str = "turnstile",
    secret_key: str = "",
    header: str = "x-captcha-response",
    paths: Sequence[str] = _DEFAULT_PATHS,
    verify: Verify | None = None,
) -> Plugin:
    """Return a plugin that requires a CAPTCHA solution on ``paths``.

    ``provider`` selects the verification endpoint (``turnstile``, ``hcaptcha``, or
    ``recaptcha``); ``secret_key`` is the provider secret. ``header`` names the
    request header carrying the client's solution token. ``verify`` overrides the
    HTTP verification with ``async (token: str) -> bool``.
    """
    checker = verify or _http_verifier(provider, secret_key)

    async def guard(context: HookContext) -> None:
        headers = context.request.headers
        token = headers.get(header) if headers else None
        if not token or not await checker(token):
            raise _FAILED

    return Plugin(id="captcha", before=tuple(Hook(guard, path=path) for path in paths))


def _http_verifier(provider: str, secret_key: str) -> Verify:
    url = _ENDPOINTS.get(provider)
    if url is None:
        raise ValueError(f"Unknown captcha provider: {provider!r}.")

    async def verify(token: str) -> bool:
        import httpx  # noqa: PLC0415 — optional dependency, imported only when used

        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(url, data={"secret": secret_key, "response": token})
            response.raise_for_status()
            payload = response.json()
        return bool(payload.get("success"))

    return verify
