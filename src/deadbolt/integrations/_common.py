"""Helpers shared by the stdlib-only generic ASGI and WSGI mounts."""

from __future__ import annotations

from http.cookies import SimpleCookie
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..http import Cookie


def endpoint_path(raw: str, base_path: str) -> str:
    """Strip ``base_path`` so the router sees the sub-path it registered."""
    if base_path and (raw == base_path or raw.startswith(f"{base_path}/")):
        return raw[len(base_path) :] or "/"
    return raw or "/"


def parse_cookies(header: str | None) -> dict[str, str]:
    """Parse a ``Cookie`` request header into a name/value mapping."""
    if not header:
        return {}
    jar: SimpleCookie = SimpleCookie()
    jar.load(header)
    return {name: morsel.value for name, morsel in jar.items()}


def render_set_cookie(cookie: Cookie) -> str:
    """Render a structured :class:`Cookie` as a ``Set-Cookie`` header value."""
    parts = [f"{cookie.name}={cookie.value}", f"Path={cookie.path}"]
    if cookie.max_age is not None:
        parts.append(f"Max-Age={cookie.max_age}")
    if cookie.domain:
        parts.append(f"Domain={cookie.domain}")
    if cookie.secure:
        parts.append("Secure")
    if cookie.http_only:
        parts.append("HttpOnly")
    if cookie.same_site:
        parts.append(f"SameSite={cookie.same_site}")
    return "; ".join(parts)
