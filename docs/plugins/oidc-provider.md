# OIDC provider

Turn `deadbolt` into an **OpenID Connect provider** — an identity provider that other applications
sign in against. This is the mirror image of the [Social OAuth](oauth.md) plugin: that one makes
`deadbolt` a *client* of Google/GitHub; this one makes *your* `deadbolt` the login provider for
third-party relying parties. It implements the OAuth 2.0 authorization-code flow with PKCE and issues
signed OpenID Connect `id_token`s.

## Install

`pip install "deadbolt[jwt]"`  *(id_tokens are signed JWTs)*

## Setup

```python
import deadbolt as db
from deadbolt.plugins.oidc_provider import OIDCClient, oidc_provider

auth = db.Auth(
    adapter=db.MemoryAdapter(),
    secret="a-32-byte-or-longer-secret......",
    email_and_password=db.EmailPassword(enabled=True),
    plugins=[
        oidc_provider(
            issuer="https://id.example.com/api/auth",   # this mount's public base URL
            clients=[
                OIDCClient(
                    client_id="dashboard",
                    client_secret="",                    # empty => public client, PKCE required
                    redirect_uris=("https://dashboard.example.com/callback",),
                    scopes=("openid", "profile", "email"),
                ),
            ],
        )
    ],
)
```

Run the schema generator (or your migration) so the `oauth_code` table exists.

## Configuration

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `issuer` | string | — | **Required.** The provider's public base URL (equals this mount's URL). |
| `clients` | sequence of `OIDCClient` | — | **Required.** Registered relying parties. |
| `code_ttl` | integer | `60` | Authorization-code lifetime in seconds. |
| `id_token_ttl` | integer | `3600` | `id_token` lifetime in seconds. |

`OIDCClient(client_id, client_secret, redirect_uris, scopes=("openid","profile","email"))`. A client
with an empty `client_secret` is a **public client** and must use PKCE; one with a secret is a
**confidential client** authenticated with `client_secret`.

## Endpoints

| Endpoint | Purpose |
| --- | --- |
| `GET /oauth2/authorize` | The signed-in user authorizes a client; redirects back with a `code`. |
| `POST /oauth2/token` | Exchange the code (+ PKCE verifier or client secret) for tokens. |
| `GET /oauth2/userinfo` | Read standard claims with the access token (`Authorization: Bearer`). |
| `GET /oauth2/jwks` | Public key set (Ed25519) for verifying `id_token`s. |
| `GET /.well-known/openid-configuration` | Discovery document. |

The token endpoint accepts both JSON and standard `application/x-www-form-urlencoded` bodies, so
off-the-shelf OIDC relying-party libraries interoperate.

## The flow (PKCE)

1. The relying party redirects the user to `GET /oauth2/authorize` with `client_id`, `redirect_uri`,
   `response_type=code`, `scope`, `state`, `code_challenge`, `code_challenge_method=S256`.
2. If the user has a `deadbolt` session, an authorization `code` is issued and the user is redirected
   to `redirect_uri?code=...&state=...`. If not signed in, they are redirected with
   `error=login_required`.
3. The relying party calls `POST /oauth2/token` with `grant_type=authorization_code`, the `code`,
   `redirect_uri`, `client_id`, and `code_verifier` (public) **or** `client_secret` (confidential).
4. The response contains `access_token`, `token_type`, `expires_in`, `scope`, and — for the `openid`
   scope — a signed `id_token`.
5. The relying party can call `GET /oauth2/userinfo` with the access token, and verify the `id_token`
   against `GET /oauth2/jwks`.

## Notes

- **Authorization codes are single-use and hashed.** Only `SHA-256(code)` is stored, and the row is
  deleted on exchange, so a replayed code fails.
- **`id_token` is EdDSA (Ed25519).** The private key is derived from the master secret and never
  leaves the server; relying parties verify with the published JWKS — no shared secret. Claims include
  `iss`, `sub`, `aud`, `iat`, `exp`, `nonce` (when supplied), and `email`/`name` per requested scope.
- **The access token is a real session.** It is an ordinary, revocable `deadbolt` session, so signing
  the user out invalidates the token issued to the relying party.
- **First-party trust model.** Authorization is granted whenever the resource owner has a valid
  session; a dedicated consent screen (persisted per-client grants) is not yet included — wrap
  `/oauth2/authorize` with your own consent UI if you need explicit per-client approval.
