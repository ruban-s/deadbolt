# Social OAuth

Sign users in (or link an additional identity to a signed-in user) through an OAuth 2.0 authorization-code flow with PKCE. Ships helpers for Google and GitHub, and a generic `OAuthProvider` for any other provider.

## Install

`pip install "deadbolt[oauth]"`

## Setup

```python
import deadbolt as db
from deadbolt.plugins.oauth import social, google, github

auth = db.Auth(
    adapter=db.MemoryAdapter(),
    secret="a-32-byte-or-longer-secret......",
    email_and_password=db.EmailPassword(enabled=True),
    plugins=[
        social(
            providers=[
                google(
                    client_id="...",
                    client_secret="...",
                    redirect_uri="https://app.com/api/auth/oauth/callback",
                ),
                github(
                    client_id="...",
                    client_secret="...",
                    redirect_uri="https://app.com/api/auth/oauth/callback",
                ),
            ]
        ),
    ],
)
```

## Configuration

The `social()` plugin factory:

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `providers` | `list[OAuthProvider]` | required | The configured providers. Each is keyed by its `id`; the client picks one by name in the request body. |
| `client_factory` | `Callable[[], httpx.AsyncClient] \| None` | `None` | Factory for the HTTP client used for token/userinfo calls. Defaults to `httpx.AsyncClient(timeout=10)`. Mainly for tests. |

### The `OAuthProvider` dataclass

`OAuthProvider` (frozen dataclass) describes one provider:

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `id` | `str` | required | Provider key, e.g. `"google"`. This is the value clients send as `provider`. |
| `client_id` | `str` | required | OAuth client ID. |
| `client_secret` | `str` | required | OAuth client secret. |
| `redirect_uri` | `str` | required | Callback URL registered with the provider; must resolve to `/oauth/callback`. |
| `authorize_url` | `str` | required | Provider authorization endpoint. |
| `token_url` | `str` | required | Provider token endpoint. |
| `userinfo_url` | `str` | required | Provider userinfo endpoint. |
| `scopes` | `tuple[str, ...]` | required | Scopes requested; space-joined into the authorize URL. |
| `map_user` | `Callable[[dict], ProviderUser]` | required | Maps the raw userinfo JSON to a `ProviderUser(account_id, email, name)`. |
| `success_redirect` | `str \| None` | `None` | If set, the callback responds `302` to this URL instead of a JSON body. |

`ProviderUser` (frozen dataclass) has `account_id: str`, `email: str | None`, `name: str | None`.

### Built-in helpers

- `google(*, client_id, client_secret, redirect_uri) -> OAuthProvider` — id `"google"`, scopes `openid email profile`, maps `sub`/`email`/`name`.
- `github(*, client_id, client_secret, redirect_uri) -> OAuthProvider` — id `"github"`, scopes `read:user user:email`, maps `id`/`email`/`name` (falls back to `login` for the name).

Both return an `OAuthProvider` you can further customize with `dataclasses.replace`, e.g. to set `success_redirect`.

## API

### `POST /sign-in/social`

Begins a social sign-in. Creates a short-lived state/PKCE-verifier record and returns the provider authorization URL for the browser to visit. **Auth:** public.

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `provider` | `string` | yes | A configured provider `id` (e.g. `"google"`). |

**Response `200`**:

```json
{
  "url": "https://accounts.google.com/o/oauth2/v2/auth?client_id=...&redirect_uri=...&response_type=code&scope=openid+email+profile&state=...&code_challenge=...&code_challenge_method=S256"
}
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `400` | `unknown_provider` | `provider` missing, not a string, or not configured. |

**Example**:

```bash
curl -X POST https://app.com/api/auth/sign-in/social \
  -H 'Content-Type: application/json' \
  -d '{"provider":"google"}'
```

### `POST /link-social`

Begins linking a provider identity to the currently signed-in user. Same shape as `/sign-in/social`, but the callback attaches the account to the session user instead of creating a session. **Auth:** session required.

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `provider` | `string` | yes | A configured provider `id`. |

**Response `200`**:

```json
{ "url": "https://accounts.google.com/o/oauth2/v2/auth?..." }
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `401` | `unauthorized` | No valid session cookie. |
| `400` | `unknown_provider` | `provider` missing or not configured. |

### `GET /oauth/callback`

The provider redirects the browser here with `code` and `state`. Validates state (single-use, TTL 600s), exchanges the code for a token, fetches the profile, then either creates a session (sign-in flow) or links the account (link flow). **Auth:** public (state proves the flow).

**Request** (query string):

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `code` | `string` | yes | Authorization code from the provider. |
| `state` | `string` | yes | Opaque state that matches the stored (hashed) value. |

**Response `200`** (sign-in flow):

```json
{
  "user": {
    "id": "...",
    "email": "a@b.com",
    "email_verified": true,
    "name": "Alice",
    "image": null,
    "created_at": "...",
    "updated_at": "..."
  }
}
```

A `__Host-session` cookie is set alongside the body.

**Response `200`** (link flow):

```json
{ "success": true }
```

**Response `302`** (when the provider has `success_redirect` set): empty-ish body `{"redirect": "<url>"}` with a `Location` header to `success_redirect`; the session cookie is still set on the sign-in flow.

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `400` | `invalid_request` | `code` or `state` missing from the query. |
| `400` | `invalid_state` | State not found, wrong prefix, or expired. |
| `409` | `account_linked` | (Link flow) that provider account is already linked to a different user. |
| `502` | `oauth_token_error` | Token exchange failed or returned no `access_token`. |
| `502` | `oauth_userinfo_error` | Userinfo request failed. |

## Flow

1. Client `POST /sign-in/social` with `{"provider":"google"}`.
2. Server stores a `verification` row keyed `oauth:<provider>:<verifier>` holding the hashed `state`, and returns the authorize `url` (with `code_challenge`, `state`).
3. Browser visits `url`, authenticates at the provider, and is redirected to `redirect_uri`.
4. Browser hits `GET /oauth/callback?code=...&state=...`.
5. Server matches the hashed state, deletes it (single-use), exchanges `code` + `code_verifier` for a token, and fetches the profile.
6. Sign-in flow: finds or creates the user, links the provider account, issues a session cookie. Link flow: attaches the account to the session user and returns `{"success": true}`.

## Notes

- **PKCE + state.** Each start generates a random `state` and a random PKCE `verifier`. Only the SHA-256 `code_challenge` (S256) is sent to the provider; the verifier stays server-side in the `verification` row and is submitted at token exchange. The `state` is stored hashed (`hash_token`) and matched on callback.
- **Single-use, TTL 600s.** The state/verifier record expires after 600 seconds and is deleted on first successful callback, so a state cannot be replayed.
- **Account resolution.** On sign-in, an existing provider account resolves to its user; otherwise the user is matched by `email` (or created). When the provider supplies an email it is marked verified. When no email is present, a synthetic `"<provider>:<account_id>"` identifier is used.
- **`success_redirect`.** Set it (e.g. via `dataclasses.replace(provider, success_redirect=...)`) to have the callback issue a `302` to your app instead of returning JSON — useful for full-page redirect flows.
