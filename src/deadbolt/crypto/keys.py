"""Derive per-purpose subkeys from one master secret via HKDF."""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_KEY_LENGTH = 32


def as_bytes(secret: str | bytes) -> bytes:
    return secret.encode() if isinstance(secret, str) else secret


def derive_key(master: str | bytes, info: bytes, length: int = _KEY_LENGTH) -> bytes:
    """Return a subkey bound to ``info`` for cryptographic domain separation."""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info)
    return hkdf.derive(as_bytes(master))
