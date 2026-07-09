# One-time token

Mint a short-lived, single-use token bound to the current session's user, then exchange it once for
a fresh session. Use it to hand a session off across subdomains, apps, or devices without exposing
the session cookie itself — for example, a "continue on your phone" flow or a redirect between two
first-party apps.

## Install

Ships with the core; there is no extra to install.

## Setup

```python
import deadbolt as db
from deadbolt.plugins.one_time_token import one_time_token

auth = db.Auth(
    adapter=db.MemoryAdapter(),
    secret="a-32-byte-or-longer-secret......",
    email_and_password=db.EmailPassword(enabled=True),
    plugins=[one_time_token(expires_in=60)],
)
```

Run the schema generator (or your migration) so the `one_time_token` table exists.

## Configuration

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `expires_in` | integer | `60` | Token lifetime in seconds. Keep it short — the token is a bearer credential. |

## API

Error responses use the envelope `{"error": {"code": "...", "message": "..."}}`.

#### `POST /one-time-token/generate`

Mints a token for the current session's user. **Auth:** session required.

**Request**: no body.

**Response `200`**:

```json
{ "token": "<opaque-token>", "expires_in": 60 }
```

| Status | Code | When |
| --- | --- | --- |
| `401` | `unauthorized` | No valid session. |

#### `POST /one-time-token/verify`

Redeems a token and returns a new session (as a `Set-Cookie`). **Auth:** public.

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `token` | string | yes | The token returned by `generate`. |

**Response `200`**: `{ "user": { ... } }`, plus the session cookie.

| Status | Code | When |
| --- | --- | --- |
| `401` | `invalid_token` | Token is unknown, expired, or already used. |

## Notes

- **Single use.** The token row is deleted the moment it is looked up, so a replay — even within the
  expiry window — fails.
- **Hashed at rest.** Only `SHA-256(token)` is stored; a database leak yields no usable tokens.
- **Short-lived by design.** The default 60-second lifetime bounds the window in which a leaked token
  is useful. The redeemed session follows your normal `SessionConfig` lifetime.
