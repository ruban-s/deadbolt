"""Authenticated symmetric encryption for sensitive fields (e.g. TOTP secrets)."""

from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .keys import derive_key

_ENCRYPTION_INFO = b"deadbolt/field-encryption"
_NONCE_BYTES = 12


class Encryptor:
    """AES-256-GCM encryption keyed by an HKDF-derived subkey of the master secret."""

    def __init__(self, secret: str | bytes) -> None:
        self._aead = AESGCM(derive_key(secret, _ENCRYPTION_INFO))

    def encrypt(self, plaintext: str) -> str:
        nonce = os.urandom(_NONCE_BYTES)
        ciphertext = self._aead.encrypt(nonce, plaintext.encode(), None)
        return base64.urlsafe_b64encode(nonce + ciphertext).decode()

    def decrypt(self, token: str) -> str:
        raw = base64.urlsafe_b64decode(token)
        nonce, ciphertext = raw[:_NONCE_BYTES], raw[_NONCE_BYTES:]
        return self._aead.decrypt(nonce, ciphertext, None).decode()
