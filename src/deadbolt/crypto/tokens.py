"""Opaque session tokens: high-entropy generation and hashed storage."""

from __future__ import annotations

import hashlib
import secrets

_TOKEN_BYTES = 32


def generate_token(nbytes: int = _TOKEN_BYTES) -> str:
    """Return a URL-safe token with ``nbytes`` of entropy (256 bits by default)."""
    return secrets.token_urlsafe(nbytes)


def hash_token(token: str) -> str:
    """Return the hex SHA-256 of ``token`` for storage; the input is high-entropy."""
    return hashlib.sha256(token.encode()).hexdigest()


def tokens_equal(a: str, b: str) -> bool:
    """Constant-time comparison of two token strings."""
    return secrets.compare_digest(a, b)
