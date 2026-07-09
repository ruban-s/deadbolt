from __future__ import annotations

import base64
import hashlib
import json
from typing import TYPE_CHECKING, cast
from urllib.parse import parse_qs, urlencode, urlparse

import jwt as pyjwt
import pytest
from jwt.algorithms import OKPAlgorithm

import deadbolt as db
from _helpers import fast_hasher
from deadbolt.http import MultiDict
from deadbolt.plugins.oidc_provider import OIDCClient, oidc_provider

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

pytestmark = pytest.mark.anyio

ISSUER = "https://id.example/api/auth"
PUBLIC = OIDCClient("public-app", "", ("https://app.example/cb",))
CONFIDENTIAL = OIDCClient("conf-app", "s3cret", ("https://conf.example/cb",))
VERIFIER = "a" * 64  # PKCE code_verifier


def build_auth() -> db.Auth:
    return db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=fast_hasher(),
        plugins=[oidc_provider(issuer=ISSUER, clients=[PUBLIC, CONFIDENTIAL])],
    )


def challenge() -> str:
    digest = hashlib.sha256(VERIFIER.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


async def owner_cookies(auth: db.Auth) -> dict[str, str]:
    resp = await auth.handle(
        db.AuthRequest(
            method="POST",
            path="/sign-up/email",
            body=json.dumps({"email": "owner@b.com", "password": "hunter2pw"}).encode(),
        )
    )
    return {c.name: c.value for c in resp.cookies if c.value}


async def authorize(auth: db.Auth, cookies: dict[str, str], **overrides: str) -> db.AuthResponse:
    params = {
        "client_id": "public-app",
        "redirect_uri": "https://app.example/cb",
        "response_type": "code",
        "scope": "openid email",
        "state": "xyz",
        "code_challenge": challenge(),
        "code_challenge_method": "S256",
        **overrides,
    }
    return await auth.handle(
        db.AuthRequest(
            method="GET", path="/oauth2/authorize", query=MultiDict(params.items()), cookies=cookies
        )
    )


def code_of(resp: db.AuthResponse) -> str:
    location = resp.headers.get("Location") or ""
    return parse_qs(urlparse(location).query)["code"][0]


def token_req(fields: dict[str, str]) -> db.AuthRequest:
    return db.AuthRequest(method="POST", path="/oauth2/token", body=json.dumps(fields).encode())


async def test_authorization_code_pkce_flow() -> None:
    auth = build_auth()
    cookies = await owner_cookies(auth)

    redirect = await authorize(auth, cookies)
    assert redirect.status == 302
    location = redirect.headers.get("Location") or ""
    assert location.startswith("https://app.example/cb?")
    assert "state=xyz" in location
    code = code_of(redirect)

    granted = await auth.handle(
        token_req(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://app.example/cb",
                "client_id": "public-app",
                "code_verifier": VERIFIER,
            }
        )
    )
    assert granted.status == 200
    body = json.loads(granted.body)
    assert body["token_type"] == "Bearer"
    assert body["id_token"]

    # Verify the id_token against the published JWKS.
    jwks = json.loads((await auth.handle(db.AuthRequest(method="GET", path="/oauth2/jwks"))).body)
    key = cast("Ed25519PublicKey", OKPAlgorithm.from_jwk(json.dumps(jwks["keys"][0])))
    claims = pyjwt.decode(
        body["id_token"], key, algorithms=["EdDSA"], audience="public-app", issuer=ISSUER
    )
    assert claims["email"] == "owner@b.com"

    # The access token drives userinfo.
    info = await auth.handle(
        db.AuthRequest(
            method="GET",
            path="/oauth2/userinfo",
            headers=MultiDict([("authorization", f"Bearer {body['access_token']}")]),
        )
    )
    assert json.loads(info.body)["email"] == "owner@b.com"


async def test_confidential_client_with_secret() -> None:
    auth = build_auth()
    cookies = await owner_cookies(auth)
    redirect = await auth.handle(
        db.AuthRequest(
            method="GET",
            path="/oauth2/authorize",
            query=MultiDict(
                {
                    "client_id": "conf-app",
                    "redirect_uri": "https://conf.example/cb",
                    "response_type": "code",
                    "scope": "openid",
                }.items()
            ),
            cookies=cookies,
        )
    )
    code = code_of(redirect)
    granted = await auth.handle(
        token_req(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://conf.example/cb",
                "client_id": "conf-app",
                "client_secret": "s3cret",
            }
        )
    )
    assert granted.status == 200


async def test_wrong_client_secret_rejected() -> None:
    auth = build_auth()
    cookies = await owner_cookies(auth)
    redirect = await auth.handle(
        db.AuthRequest(
            method="GET",
            path="/oauth2/authorize",
            query=MultiDict(
                {
                    "client_id": "conf-app",
                    "redirect_uri": "https://conf.example/cb",
                    "response_type": "code",
                    "scope": "openid",
                }.items()
            ),
            cookies=cookies,
        )
    )
    code = code_of(redirect)
    granted = await auth.handle(
        token_req(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://conf.example/cb",
                "client_id": "conf-app",
                "client_secret": "wrong",
            }
        )
    )
    assert granted.status == 401
    assert json.loads(granted.body)["error"]["code"] == "invalid_client"


async def test_pkce_mismatch_rejected() -> None:
    auth = build_auth()
    cookies = await owner_cookies(auth)
    code = code_of(await authorize(auth, cookies))
    granted = await auth.handle(
        token_req(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://app.example/cb",
                "client_id": "public-app",
                "code_verifier": "wrong-verifier",
            }
        )
    )
    assert granted.status == 400
    assert json.loads(granted.body)["error"]["code"] == "invalid_grant"


async def test_code_is_single_use() -> None:
    auth = build_auth()
    cookies = await owner_cookies(auth)
    code = code_of(await authorize(auth, cookies))
    fields = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "https://app.example/cb",
        "client_id": "public-app",
        "code_verifier": VERIFIER,
    }
    assert (await auth.handle(token_req(fields))).status == 200
    assert (await auth.handle(token_req(fields))).status == 400


async def test_authorize_without_login_redirects_error() -> None:
    auth = build_auth()
    resp = await authorize(auth, {})  # no session cookie
    assert resp.status == 302
    assert "error=login_required" in (resp.headers.get("Location") or "")


async def test_unknown_client_rejected() -> None:
    auth = build_auth()
    cookies = await owner_cookies(auth)
    resp = await authorize(auth, cookies, client_id="ghost")
    assert resp.status == 400
    assert json.loads(resp.body)["error"]["code"] == "invalid_request"


async def test_token_endpoint_accepts_form_encoding() -> None:
    auth = build_auth()
    cookies = await owner_cookies(auth)
    code = code_of(await authorize(auth, cookies))
    resp = await auth.handle(
        db.AuthRequest(
            method="POST",
            path="/oauth2/token",
            body=urlencode(
                {
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": "https://app.example/cb",
                    "client_id": "public-app",
                    "code_verifier": VERIFIER,
                }
            ).encode(),
            headers=MultiDict([("content-type", "application/x-www-form-urlencoded")]),
        )
    )
    assert resp.status == 200
    assert json.loads(resp.body)["id_token"]


async def test_discovery_document() -> None:
    auth = build_auth()
    resp = await auth.handle(db.AuthRequest(method="GET", path="/.well-known/openid-configuration"))
    doc = json.loads(resp.body)
    assert doc["issuer"] == ISSUER
    assert doc["token_endpoint"] == f"{ISSUER}/oauth2/token"
    assert doc["id_token_signing_alg_values_supported"] == ["EdDSA"]


async def test_unsupported_grant_type() -> None:
    auth = build_auth()
    resp = await auth.handle(token_req({"grant_type": "password", "client_id": "public-app"}))
    assert resp.status == 400
    assert json.loads(resp.body)["error"]["code"] == "unsupported_grant_type"


async def test_token_unknown_client() -> None:
    auth = build_auth()
    resp = await auth.handle(token_req({"grant_type": "authorization_code", "client_id": "ghost"}))
    assert resp.status == 401
    assert json.loads(resp.body)["error"]["code"] == "invalid_client"


async def test_unsupported_response_type() -> None:
    auth = build_auth()
    cookies = await owner_cookies(auth)
    resp = await authorize(auth, cookies, response_type="token")
    assert "error=unsupported_response_type" in (resp.headers.get("Location") or "")


async def test_invalid_scope() -> None:
    auth = build_auth()
    cookies = await owner_cookies(auth)
    resp = await authorize(auth, cookies, scope="openid admin")
    assert "error=invalid_scope" in (resp.headers.get("Location") or "")


async def test_userinfo_requires_token() -> None:
    auth = build_auth()
    resp = await auth.handle(db.AuthRequest(method="GET", path="/oauth2/userinfo"))
    assert resp.status == 401
    assert json.loads(resp.body)["error"]["code"] == "invalid_token"


async def test_id_token_carries_nonce_and_profile() -> None:
    auth = build_auth()
    cookies = await owner_cookies(auth)
    redirect = await authorize(auth, cookies, scope="openid profile email", nonce="n-123")
    granted = await auth.handle(
        token_req(
            {
                "grant_type": "authorization_code",
                "code": code_of(redirect),
                "redirect_uri": "https://app.example/cb",
                "client_id": "public-app",
                "code_verifier": VERIFIER,
            }
        )
    )
    id_token = json.loads(granted.body)["id_token"]
    jwks = json.loads((await auth.handle(db.AuthRequest(method="GET", path="/oauth2/jwks"))).body)
    key = cast("Ed25519PublicKey", OKPAlgorithm.from_jwk(json.dumps(jwks["keys"][0])))
    claims = pyjwt.decode(id_token, key, algorithms=["EdDSA"], audience="public-app", issuer=ISSUER)
    assert claims["nonce"] == "n-123"
    assert "name" in claims
