"""Act as an OpenID Connect provider (identity provider). Requires ``deadbolt[jwt]``.

Turns a `deadbolt` instance into an OIDC provider that third-party applications can
sign in against — the mirror image of the ``oauth`` plugin (which makes `deadbolt` a
*client* of Google/GitHub). It implements the authorization-code flow with PKCE:

- ``GET  /oauth2/authorize`` — the signed-in resource owner authorizes a client and
  is redirected back with a single-use code.
- ``POST /oauth2/token`` — the client exchanges the code (with its secret or a PKCE
  verifier) for an access token and a signed ``id_token``.
- ``GET  /oauth2/userinfo`` — the client reads standard claims with the access token.
- ``GET  /oauth2/jwks`` and ``GET /.well-known/openid-configuration`` — public key
  set and discovery document.

``id_token`` uses EdDSA (Ed25519) with a key derived from the master secret; the
access token is an ordinary, revocable `deadbolt` session.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from .._util import new_id, utcnow
from ..crypto import derive_key, generate_token, hash_token, tokens_equal
from ..db.types import FieldSpec, TableSpec, Where
from ..endpoints import _service as svc
from ..endpoints.context import EndpointResult
from ..endpoints.registry import Endpoint
from ..errors import APIError
from . import Plugin

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ..core.auth import Auth
    from ..db.types import Row
    from ..endpoints.context import EndpointRequest

_ED_INFO = b"deadbolt/oidc-id-token"

CODE_TABLE = TableSpec(
    model="oauth_code",
    fields={
        "id": FieldSpec(type="string", required=True, unique=True, input=False),
        "code": FieldSpec(type="string", required=True, unique=True, input=False),
        "client_id": FieldSpec(type="string", required=True, input=False),
        "user_id": FieldSpec(type="string", required=True, references="user.id", input=False),
        "redirect_uri": FieldSpec(type="string", required=True, input=False),
        "scope": FieldSpec(type="string", required=True, input=False),
        "code_challenge": FieldSpec(type="string", input=False),
        "nonce": FieldSpec(type="string", input=False),
        "expires_at": FieldSpec(type="date", required=True, input=False),
        "created_at": FieldSpec(type="date", required=True, input=False),
    },
)


@dataclass(frozen=True)
class OIDCClient:
    """A relying party registered with the provider."""

    client_id: str
    client_secret: str
    redirect_uris: tuple[str, ...]
    scopes: tuple[str, ...] = ("openid", "profile", "email")


def oidc_provider(
    *,
    issuer: str,
    clients: Sequence[OIDCClient],
    code_ttl: int = 60,
    id_token_ttl: int = 3600,
) -> Plugin:
    """Return the OIDC-provider plugin.

    ``issuer`` is the provider's public base URL (the mount's URL, e.g.
    ``https://example.com/api/auth``). ``clients`` are the registered relying
    parties. ``code_ttl`` is the authorization-code lifetime and ``id_token_ttl`` the
    ``id_token`` lifetime, both in seconds.
    """
    registry = {c.client_id: c for c in clients}

    async def authorize(auth: Auth, req: EndpointRequest) -> EndpointResult:
        query = req.query
        client = registry.get(query.get("client_id") or "") if query else None
        redirect_uri = (query.get("redirect_uri") if query else None) or ""
        if client is None or redirect_uri not in client.redirect_uris:
            raise APIError(400, "invalid_request", "Unknown client or redirect_uri.")

        state = query.get("state") if query else None
        if (query.get("response_type") if query else None) != "code":
            return _redirect(redirect_uri, {"error": "unsupported_response_type"}, state)
        scope = (query.get("scope") if query else None) or "openid"
        if not set(scope.split()) <= set(client.scopes):
            return _redirect(redirect_uri, {"error": "invalid_scope"}, state)

        try:
            _, user = await svc.require_session(auth, req)
        except APIError:
            return _redirect(redirect_uri, {"error": "login_required"}, state)

        code = generate_token()
        now = utcnow()
        await auth.adapter.create(
            model="oauth_code",
            data={
                "id": new_id(),
                "code": hash_token(code),
                "client_id": client.client_id,
                "user_id": user["id"],
                "redirect_uri": redirect_uri,
                "scope": scope,
                "code_challenge": query.get("code_challenge") if query else None,
                "nonce": query.get("nonce") if query else None,
                "expires_at": now + timedelta(seconds=code_ttl),
                "created_at": now,
            },
        )
        return _redirect(redirect_uri, {"code": code}, state)

    async def token(auth: Auth, req: EndpointRequest) -> EndpointResult:
        if req.body.get("grant_type") != "authorization_code":
            raise APIError(400, "unsupported_grant_type", "Only authorization_code is supported.")
        client = registry.get(req.body.get("client_id") or "")
        if client is None:
            raise APIError(401, "invalid_client", "Unknown client.")

        row = await _consume_code(auth, req.body.get("code"))
        if row["client_id"] != client.client_id or row["redirect_uri"] != req.body.get(
            "redirect_uri"
        ):
            raise APIError(400, "invalid_grant", "Code does not match this client.")
        _authenticate(client, row, req.body)

        user = await svc.find_user_by_id(auth.adapter, row["user_id"])
        if user is None:
            raise APIError(400, "invalid_grant", "The authorizing user no longer exists.")

        session_token, _ = await auth.sessions.create(user["id"], ip=req.client_ip)
        data: dict[str, Any] = {
            "access_token": auth.sessions.build_cookie(session_token).value,
            "token_type": "Bearer",
            "expires_in": auth.session.expires_in,
            "scope": row["scope"],
        }
        if "openid" in row["scope"].split():
            data["id_token"] = _sign_id_token(auth, user, row, issuer, id_token_ttl)
        return EndpointResult(data=data)

    async def userinfo(auth: Auth, req: EndpointRequest) -> EndpointResult:
        access = _bearer(req)
        raw = auth.sessions.read_token({auth.sessions.cookie_name: access}) if access else None
        session = await auth.sessions.validate(raw) if raw else None
        user = await svc.find_user_by_id(auth.adapter, session["user_id"]) if session else None
        if user is None:
            raise APIError(401, "invalid_token", "A valid access token is required.")
        return EndpointResult(data=_claims(user))

    async def jwks(auth: Auth, req: EndpointRequest) -> EndpointResult:
        return EndpointResult(data=_jwks(auth))

    async def discovery(auth: Auth, req: EndpointRequest) -> EndpointResult:
        return EndpointResult(
            data={
                "issuer": issuer,
                "authorization_endpoint": f"{issuer}/oauth2/authorize",
                "token_endpoint": f"{issuer}/oauth2/token",
                "userinfo_endpoint": f"{issuer}/oauth2/userinfo",
                "jwks_uri": f"{issuer}/oauth2/jwks",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["EdDSA"],
                "scopes_supported": ["openid", "profile", "email"],
                "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
                "code_challenge_methods_supported": ["S256"],
            }
        )

    return Plugin(
        id="oidc_provider",
        schema=(CODE_TABLE,),
        endpoints=(
            Endpoint("GET", "/oauth2/authorize", authorize, "oidc_authorize"),
            Endpoint("POST", "/oauth2/token", token, "oidc_token"),
            Endpoint("GET", "/oauth2/userinfo", userinfo, "oidc_userinfo"),
            Endpoint("GET", "/oauth2/jwks", jwks, "oidc_jwks"),
            Endpoint("GET", "/.well-known/openid-configuration", discovery, "oidc_discovery"),
        ),
    )


def _redirect(uri: str, params: dict[str, str], state: str | None) -> EndpointResult:
    if state:
        params = {**params, "state": state}
    return EndpointResult(status=302, headers={"Location": f"{uri}?{urlencode(params)}"})


async def _consume_code(auth: Auth, code: str | None) -> Row:
    row = None
    if code:
        row = await auth.adapter.find_one(
            model="oauth_code", where=[Where("code", hash_token(code))]
        )
    if row is None:
        raise APIError(400, "invalid_grant", "Unknown or used authorization code.")
    await auth.adapter.delete(model="oauth_code", where=[Where("code", row["code"])])
    if row["expires_at"] <= utcnow():
        raise APIError(400, "invalid_grant", "The authorization code has expired.")
    return row


def _authenticate(client: OIDCClient, row: Row, body: dict[str, Any]) -> None:
    challenge = row["code_challenge"]
    if challenge:
        verifier = body.get("code_verifier") or ""
        if not tokens_equal(_pkce(verifier), challenge):
            raise APIError(400, "invalid_grant", "PKCE verification failed.")
    elif not tokens_equal(body.get("client_secret") or "", client.client_secret):
        raise APIError(401, "invalid_client", "Bad client credentials.")


def _pkce(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _bearer(req: EndpointRequest) -> str | None:
    header = req.headers.get("authorization") if req.headers else None
    if header and header[:7].lower() == "bearer ":
        return header[7:].strip()
    return None


def _claims(user: Row) -> dict[str, Any]:
    return {
        "sub": user["id"],
        "email": user["email"],
        "email_verified": user["email_verified"],
        "name": user.get("name"),
    }


def _sign_id_token(auth: Auth, user: Row, row: Row, issuer: str, ttl: int) -> str:
    now = utcnow()
    claims: dict[str, Any] = {
        "iss": issuer,
        "sub": user["id"],
        "aud": row["client_id"],
        "iat": now,
        "exp": now + timedelta(seconds=ttl),
    }
    if row["nonce"]:
        claims["nonce"] = row["nonce"]
    scopes = row["scope"].split()
    if "email" in scopes:
        claims["email"] = user["email"]
        claims["email_verified"] = user["email_verified"]
    if "profile" in scopes:
        claims["name"] = user.get("name")
    private = _ed_private(auth)
    pem = private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    return pyjwt.encode(claims, pem, algorithm="EdDSA", headers={"kid": _kid(private)})


def _ed_private(auth: Auth) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(derive_key(auth.secret, _ED_INFO))


def _kid(private: Ed25519PrivateKey) -> str:
    raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def _jwks(auth: Auth) -> dict[str, Any]:
    raw = _ed_private(auth).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
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
