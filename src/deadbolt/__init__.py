"""deadbolt: a framework-agnostic authentication library for Python.

The whole supported API is reachable from this alias::

    import deadbolt as db

    auth = db.Auth(adapter=..., secret=..., email_and_password=db.EmailPassword(enabled=True))

Optional, dependency-carrying pieces load lazily on attribute access, so
``import deadbolt`` never pulls in a web framework or database driver.
"""

from __future__ import annotations

from importlib import metadata
from typing import TYPE_CHECKING, Any

from . import errors
from .core import Auth, CookieConfig, EmailPassword, SessionConfig
from .db import FieldSpec, MemoryAdapter, SortBy, TableSpec, Where
from .http import AuthRequest, AuthResponse, Cookie
from .plugins import Plugin
from .protocols import (
    AsyncDatabaseAdapter,
    EmailSender,
    Hasher,
    SessionStore,
)
from .ratelimit import RateLimit, RateLimitRule, RateLimitStore

try:
    __version__ = metadata.version("deadbolt")
except metadata.PackageNotFoundError:  # pragma: no cover
    __version__ = "0.0.0"

if TYPE_CHECKING:
    from .db import SQLAlchemyAdapter

__all__ = [
    "AsyncDatabaseAdapter",
    "Auth",
    "AuthRequest",
    "AuthResponse",
    "Cookie",
    "CookieConfig",
    "EmailPassword",
    "EmailSender",
    "FieldSpec",
    "Hasher",
    "MemoryAdapter",
    "Plugin",
    "RateLimit",
    "RateLimitRule",
    "RateLimitStore",
    "SQLAlchemyAdapter",
    "SessionConfig",
    "SessionStore",
    "SortBy",
    "TableSpec",
    "Where",
    "__version__",
    "errors",
]


def __getattr__(name: str) -> Any:
    if name == "SQLAlchemyAdapter":
        from .db import SQLAlchemyAdapter  # noqa: PLC0415

        return SQLAlchemyAdapter
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
