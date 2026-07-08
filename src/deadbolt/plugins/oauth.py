"""Social OAuth2 (authorization code + PKCE) as a plugin. Requires ``deadbolt[oauth]``."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode

import httpx

from .._util import new_id, utcnow
from ..crypto import generate_token, hash_token
from ..db.types import Where
from ..endpoints import _service as svc
from ..endpoints.context import EndpointResult
from ..endpoints.registry import Endpoint
from ..errors import APIError
from . import Plugin

if TYPE_CHECKING:
    from collections.abc import Callable

    from ..core.auth import Auth
    from ..endpoints.context import EndpointRequest

_STATE_PREFIX = "oauth"
_STATE_TTL = 600


@dataclass(frozen=True)
class ProviderUser:
    account_id: str
    email: str | None
    name: str | None


@dataclass(frozen=True)
class OAuthProvider:
    id: str
    client_id: str
    client_secret: str
    redirect_uri: str
    authorize_url: str
    token_url: str
    userinfo_url: str
    scopes: tuple[str, ...]
    map_user: Callable[[dict[str, Any]], ProviderUser]
    success_redirect: str | None = None


def google(*, client_id: str, client_secret: str, redirect_uri: str) -> OAuthProvider:
    return OAuthProvider(
        id="google",
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
        authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
        token_url="https://oauth2.googleapis.com/token",  # noqa: S106
        userinfo_url="https://openidconnect.googleapis.com/v1/userinfo",
        scopes=("openid", "email", "profile"),
        map_user=lambda d: ProviderUser(str(d["sub"]), d.get("email"), d.get("name")),
    )


def github(*, client_id: str, client_secret: str, redirect_uri: str) -> OAuthProvider:
    return OAuthProvider(
        id="github",
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
        authorize_url="https://github.com/login/oauth/authorize",
        token_url="https://github.com/login/oauth/access_token",  # noqa: S106
        userinfo_url="https://api.github.com/user",
        scopes=("read:user", "user:email"),
        map_user=lambda d: ProviderUser(
            str(d["id"]), d.get("email"), d.get("name") or d.get("login")
        ),
    )


def social(
    *,
    providers: list[OAuthProvider],
    client_factory: Callable[[], httpx.AsyncClient] | None = None,
) -> Plugin:
    """Return a plugin adding ``/sign-in/social`` and ``/oauth/callback``."""

    registry = {p.id: p for p in providers}
    make_client = client_factory or (lambda: httpx.AsyncClient(timeout=10))

    async def start(auth: Auth, req: EndpointRequest) -> EndpointResult:
        provider = _provider(registry, req.body.get("provider"))
        state = generate_token()
        verifier = generate_token()
        now = utcnow()
        await auth.adapter.create(
            model="verification",
            data={
                "id": new_id(),
                "identifier": f"{_STATE_PREFIX}:{provider.id}:{verifier}",
                "value": hash_token(state),
                "expires_at": now + timedelta(seconds=_STATE_TTL),
                "created_at": now,
            },
        )
        params = {
            "client_id": provider.client_id,
            "redirect_uri": provider.redirect_uri,
            "response_type": "code",
            "scope": " ".join(provider.scopes),
            "state": state,
            "code_challenge": _pkce_challenge(verifier),
            "code_challenge_method": "S256",
        }
        return EndpointResult(data={"url": f"{provider.authorize_url}?{urlencode(params)}"})

    async def callback(auth: Auth, req: EndpointRequest) -> EndpointResult:
        query = req.query
        code = query.get("code") if query else None
        state = query.get("state") if query else None
        if not code or not state:
            raise APIError(400, "invalid_request", "Missing code or state.")

        record = await auth.adapter.find_one(
            model="verification", where=[Where("value", hash_token(state))]
        )
        if record is None or not record["identifier"].startswith(f"{_STATE_PREFIX}:"):
            raise APIError(400, "invalid_state", "The OAuth state is invalid or expired.")
        if record["expires_at"] <= utcnow():
            raise APIError(400, "invalid_state", "The OAuth state is invalid or expired.")
        await auth.adapter.delete(model="verification", where=[Where("value", hash_token(state))])

        _, provider_id, verifier = record["identifier"].split(":", 2)
        provider = registry[provider_id]
        profile = await _fetch_profile(make_client, provider, code, verifier)
        user = await _link_user(auth, provider, profile)

        token, _ = await auth.sessions.create(user["id"], ip=req.client_ip)
        cookie = auth.sessions.build_cookie(token)
        if provider.success_redirect is not None:
            return EndpointResult(
                data={"redirect": provider.success_redirect},
                status=302,
                cookies=[cookie],
                headers={"Location": provider.success_redirect},
            )
        return EndpointResult(data={"user": svc.public_user(user)}, cookies=[cookie])

    return Plugin(
        id="social-oauth",
        endpoints=(
            Endpoint("POST", "/sign-in/social", start, "sign_in_social"),
            Endpoint("GET", "/oauth/callback", callback, "oauth_callback"),
        ),
    )


async def _fetch_profile(
    make_client: Callable[[], httpx.AsyncClient], provider: OAuthProvider, code: str, verifier: str
) -> ProviderUser:
    async with make_client() as client:
        token_response = await client.post(
            provider.token_url,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": provider.redirect_uri,
                "client_id": provider.client_id,
                "client_secret": provider.client_secret,
                "code_verifier": verifier,
            },
            headers={"Accept": "application/json"},
        )
        if token_response.status_code != httpx.codes.OK:
            raise APIError(502, "oauth_token_error", "Failed to exchange the authorization code.")
        access_token = token_response.json().get("access_token")
        if not access_token:
            raise APIError(502, "oauth_token_error", "The provider returned no access token.")

        userinfo_response = await client.get(
            provider.userinfo_url,
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
        )
        if userinfo_response.status_code != httpx.codes.OK:
            raise APIError(502, "oauth_userinfo_error", "Failed to fetch the user profile.")
    return provider.map_user(userinfo_response.json())


async def _link_user(auth: Auth, provider: OAuthProvider, profile: ProviderUser) -> dict[str, Any]:
    account = await svc.find_provider_account(
        auth.adapter, provider_id=provider.id, account_id=profile.account_id
    )
    if account is not None:
        existing = await svc.find_user_by_id(auth.adapter, account["user_id"])
        if existing is not None:
            return existing

    email = profile.email or f"{provider.id}:{profile.account_id}"
    user = await svc.find_user_by_email(auth.adapter, email)
    if user is None:
        user = await svc.create_user(auth.adapter, email=email, name=profile.name)
    if profile.email:
        await svc.mark_email_verified(auth.adapter, user_id=user["id"])
        user["email_verified"] = True
    await svc.create_provider_account(
        auth.adapter, user_id=user["id"], provider_id=provider.id, account_id=profile.account_id
    )
    return user


def _provider(registry: dict[str, OAuthProvider], provider_id: object) -> OAuthProvider:
    if not isinstance(provider_id, str) or provider_id not in registry:
        raise APIError(400, "unknown_provider", "Unknown or unconfigured OAuth provider.")
    return registry[provider_id]


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
