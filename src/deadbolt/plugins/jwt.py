"""Issue and verify signed JWTs for stateless API access. Requires ``deadbolt[jwt]``.

Two signing modes, both keyed off the master secret via HKDF (independent of the
cookie-signing key):

- ``HS256`` (default) — symmetric; verifiers need the shared secret.
- ``EdDSA`` — asymmetric (Ed25519); the private key stays server-side and a
  ``GET /jwks`` endpoint publishes the public key as a JWK Set, so third parties
  verify tokens without any shared secret.

Tokens are short-lived; pair them with the revocable session for anything sensitive.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import timedelta
from typing import TYPE_CHECKING, Any

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from .._util import utcnow
from ..crypto import derive_key
from ..endpoints import _service as svc
from ..endpoints.context import EndpointResult
from ..endpoints.registry import Endpoint
from ..errors import APIError
from . import Plugin

if TYPE_CHECKING:
    from ..core.auth import Auth
    from ..endpoints.context import EndpointRequest

_HS_INFO = b"deadbolt/jwt-hs256"
_ED_INFO = b"deadbolt/jwt-eddsa"
_ALGORITHMS = ("HS256", "EdDSA")


def jwt(*, expires_in: int = 900, issuer: str = "deadbolt", algorithm: str = "HS256") -> Plugin:
    """Return a plugin adding ``GET /token`` and ``POST /token/verify``.

    ``algorithm`` is ``HS256`` (symmetric, default) or ``EdDSA`` (asymmetric). In
    ``EdDSA`` mode the plugin also serves ``GET /jwks`` with the public key set.
    """
    if algorithm not in _ALGORITHMS:
        raise ValueError(f"algorithm must be one of {_ALGORITHMS}, not {algorithm!r}.")

    async def issue(auth: Auth, req: EndpointRequest) -> EndpointResult:
        _, user = await svc.require_session(auth, req)
        now = utcnow()
        payload = {
            "sub": user["id"],
            "email": user["email"],
            "iss": issuer,
            "iat": now,
            "exp": now + timedelta(seconds=expires_in),
        }
        return EndpointResult(
            data={"token": _encode(auth, payload, algorithm), "expires_in": expires_in}
        )

    async def verify(auth: Auth, req: EndpointRequest) -> EndpointResult:
        token = svc.require_str(req.body, "token")
        try:
            claims = _decode(auth, token, algorithm, issuer)
        except pyjwt.InvalidTokenError as error:
            raise APIError(401, "invalid_token", "The token is invalid or expired.") from error
        return EndpointResult(data={"valid": True, "user_id": claims["sub"], "claims": claims})

    endpoints = [
        Endpoint("GET", "/token", issue, "jwt_issue"),
        Endpoint("POST", "/token/verify", verify, "jwt_verify"),
    ]
    if algorithm == "EdDSA":

        async def jwks(auth: Auth, req: EndpointRequest) -> EndpointResult:
            return EndpointResult(data=_jwks(auth))

        endpoints.append(Endpoint("GET", "/jwks", jwks, "jwt_jwks"))

    return Plugin(id="jwt", endpoints=tuple(endpoints))


def _hs_key(auth: Auth) -> bytes:
    return derive_key(auth.secret, _HS_INFO)


def _ed_private(auth: Auth) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(derive_key(auth.secret, _ED_INFO))


def _encode(auth: Auth, payload: dict[str, Any], algorithm: str) -> str:
    if algorithm == "HS256":
        return pyjwt.encode(payload, _hs_key(auth), algorithm="HS256")
    private = _ed_private(auth)
    pem = private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    return pyjwt.encode(payload, pem, algorithm="EdDSA", headers={"kid": _kid(private)})


def _decode(auth: Auth, token: str, algorithm: str, issuer: str) -> dict[str, Any]:
    if algorithm == "HS256":
        return pyjwt.decode(token, _hs_key(auth), algorithms=["HS256"], issuer=issuer)
    public_pem = (
        _ed_private(auth).public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )
    return pyjwt.decode(token, public_pem, algorithms=["EdDSA"], issuer=issuer)


def _raw_public(auth: Auth) -> bytes:
    return _ed_private(auth).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _kid(private: Ed25519PrivateKey) -> str:
    raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def _jwks(auth: Auth) -> dict[str, Any]:
    raw = _raw_public(auth)
    x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    return {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": x,
                "use": "sig",
                "alg": "EdDSA",
                "kid": hashlib.sha256(raw).hexdigest()[:16],
            }
        ]
    }
