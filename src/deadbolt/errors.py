"""Exception hierarchy for deadbolt."""

from __future__ import annotations


class AuthError(Exception):
    """Base class for every error raised by deadbolt."""


class ConfigError(AuthError):
    """Raised when the ``Auth`` configuration is invalid or a secret is missing."""


class APIError(AuthError):
    """An error mapped to an HTTP response.

    Endpoints raise this to signal a client- or server-facing failure. Adapters
    translate it into an ``AuthResponse`` with the given ``status``.
    """

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def is_api_error(error: object) -> bool:
    """Return whether ``error`` is an :class:`APIError`."""
    return isinstance(error, APIError)
