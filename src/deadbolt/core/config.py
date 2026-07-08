"""Configuration value objects for :class:`~deadbolt.core.auth.Auth`."""

from __future__ import annotations

from dataclasses import dataclass

_DAY = 60 * 60 * 24


@dataclass(frozen=True)
class EmailPassword:
    enabled: bool = False
    min_password_length: int = 8
    max_password_length: int = 128
    require_email_verification: bool = False


@dataclass(frozen=True)
class SessionConfig:
    expires_in: int = 7 * _DAY
    update_age: int = _DAY
    fresh_age: int = _DAY
    max_lifetime: int = 30 * _DAY


@dataclass(frozen=True)
class CookieConfig:
    name: str = "session"
    host_prefix: bool = True
    secure: bool = True
    http_only: bool = True
    same_site: str = "Lax"
    domain: str | None = None
    path: str = "/"
