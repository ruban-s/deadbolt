"""Input and output value objects passed to and from endpoint handlers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..http import Cookie, MultiDict


@dataclass
class EndpointRequest:
    body: dict[str, Any]
    cookies: dict[str, str]
    query: MultiDict | None = None
    headers: MultiDict | None = None
    client_ip: str | None = None


@dataclass
class EndpointResult:
    data: Any = None
    status: int = 200
    cookies: list[Cookie] = field(default_factory=list)
