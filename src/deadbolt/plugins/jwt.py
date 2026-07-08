"""Issue and verify signed JWTs for stateless API access. Requires ``deadbolt[jwt]``.

The signing key is an HKDF-derived subkey of the master secret, independent of the
cookie-signing key. Tokens are short-lived; pair them with the revocable session.
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

import jwt as pyjwt

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

_ALGORITHM = "HS256"
_KEY_INFO = b"deadbolt/jwt-hs256"


def jwt(*, expires_in: int = 900, issuer: str = "deadbolt") -> Plugin:
    """Return a plugin adding ``GET /token`` and ``POST /token/verify``."""

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
        token = pyjwt.encode(payload, _key(auth), algorithm=_ALGORITHM)
        return EndpointResult(data={"token": token, "expires_in": expires_in})

    async def verify(auth: Auth, req: EndpointRequest) -> EndpointResult:
        token = svc.require_str(req.body, "token")
        try:
            claims = pyjwt.decode(token, _key(auth), algorithms=[_ALGORITHM], issuer=issuer)
        except pyjwt.InvalidTokenError as error:
            raise APIError(401, "invalid_token", "The token is invalid or expired.") from error
        return EndpointResult(data={"valid": True, "user_id": claims["sub"], "claims": claims})

    return Plugin(
        id="jwt",
        endpoints=(
            Endpoint("GET", "/token", issue, "jwt_issue"),
            Endpoint("POST", "/token/verify", verify, "jwt_verify"),
        ),
    )


def _key(auth: Auth) -> bytes:
    return derive_key(auth.secret, _KEY_INFO)
