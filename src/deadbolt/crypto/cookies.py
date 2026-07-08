"""Sign and verify opaque cookie values with an HKDF-derived key."""

from __future__ import annotations

import hashlib

from itsdangerous import BadSignature, Signer

from .keys import derive_key

_COOKIE_INFO = b"deadbolt/session-cookie-hmac"


class CookieSigner:
    """HMAC-signs cookie values so tampering is rejected before any DB lookup."""

    def __init__(self, secret: str | bytes, *, salt: str = "session") -> None:
        key = derive_key(secret, _COOKIE_INFO)
        self._signer = Signer(key, salt=salt, digest_method=hashlib.sha256, key_derivation="hmac")

    def sign(self, value: str) -> str:
        return self._signer.sign(value).decode()

    def unsign(self, signed: str) -> str | None:
        try:
            return self._signer.unsign(signed).decode()
        except BadSignature:
            return None
