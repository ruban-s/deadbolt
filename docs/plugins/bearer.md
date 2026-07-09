# Bearer token

Authenticate with an `Authorization: Bearer <token>` header instead of a cookie. This is what
non-browser clients — mobile apps, native SPAs, server-to-server callers — use when cookies are not
available. The bearer token is the same HMAC-signed value the session cookie carries, so every
session guarantee still holds: signature verification, expiry, rotation, and revocation all apply.

The plugin adds **no endpoints and no tables** — it is a pair of request hooks.

## Install

Bearer support ships with the core; there is no extra to install.

## Setup

```python
import deadbolt as db
from deadbolt.plugins.bearer import bearer

auth = db.Auth(
    adapter=db.MemoryAdapter(),
    secret="a-32-byte-or-longer-secret......",
    email_and_password=db.EmailPassword(enabled=True),
    plugins=[bearer()],
)
```

## Configuration

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `response_header` | string | `"set-auth-token"` | Response header the freshly issued token is written to when a request establishes a new session. |

## How it works

The plugin registers two hooks:

- **Before every request** — if the request carries no session cookie but does carry an
  `Authorization: Bearer <token>` header, the token is copied into the session-cookie slot. The core
  then validates it exactly as it would a cookie: a tampered or forged token fails the signature
  check before any database lookup, and an expired or revoked token is rejected.
- **After every request** — if the response established a new session (sign-up, sign-in), the signed
  token is echoed in the `set-auth-token` response header so a cookie-less client can store it and
  send it back on subsequent requests.

A request that presents **both** a valid session cookie and a bearer header uses the cookie — the
bearer header is only consulted when no session cookie is present.

## Usage

Capture the token from a sign-in response, then present it on later requests:

```bash
# 1. Sign in and read the token from the response header.
curl -i -X POST http://127.0.0.1:8000/api/auth/sign-in/email \
     -H 'Content-Type: application/json' \
     -d '{"email":"a@b.com","password":"hunter2pw"}'
# ... HTTP/1.1 200 OK
# ... set-auth-token: <signed-token>

# 2. Use it as a bearer token — no cookie jar needed.
curl http://127.0.0.1:8000/api/auth/get-session \
     -H 'Authorization: Bearer <signed-token>'
```

## Notes

- **Same token, same guarantees.** The bearer value is the signed session token, not a separate
  credential. Revoking the session (sign-out, "log out all devices") immediately invalidates the
  bearer token too — unlike a bare [JWT](jwt.md), which stays valid until it expires.
- **Store it securely.** On mobile, keep the token in the platform keychain/keystore, not in plain
  storage. It grants full session access.
- **Pairs with the generic mounts.** Combined with the [ASGI/WSGI mounts](../integrations/generic.md),
  bearer auth lets any framework serve a fully cookie-less API.
