"""The normalized request/response contract every framework adapter speaks."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .multidict import MultiDict

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Mapping


@dataclass(frozen=True)
class AuthRequest:
    """A framework-neutral request handed to the core.

    ``body`` is the raw, unparsed payload: adapters must not consume the request
    stream before building this, or the core cannot read it.
    """

    method: str
    path: str
    headers: MultiDict = field(default_factory=MultiDict)
    query: MultiDict = field(default_factory=MultiDict)
    cookies: Mapping[str, str] = field(default_factory=dict)
    body: bytes | None = None
    stream: AsyncIterator[bytes] | None = None
    client_ip: str | None = None
    scheme: str = "https"
    base_url: str | None = None


@dataclass
class Cookie:
    """A cookie to set, applied by each adapter through its native cookie API."""

    name: str
    value: str
    max_age: int | None = None
    path: str = "/"
    domain: str | None = None
    secure: bool = True
    http_only: bool = True
    same_site: str = "Lax"


@dataclass
class AuthResponse:
    """A framework-neutral response returned by the core.

    ``cookies`` are carried as structured data rather than raw ``Set-Cookie``
    headers so adapters can apply them via the framework's own response object.
    """

    status: int = 200
    headers: MultiDict = field(default_factory=MultiDict)
    body: bytes = b""
    cookies: list[Cookie] = field(default_factory=list)
    media_type: str = "application/json"
