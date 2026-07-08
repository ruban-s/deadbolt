# Security

`deadbolt` is secure by default: the safe configuration is the one you get when you write the
least code. This page documents what each defense actually does and how you tune it. Every key,
cookie, and token here derives from the single `secret` you pass to `Auth`.

## Password hashing

Passwords are hashed with **Argon2id** via `argon2-cffi`. `Argon2Hasher` wraps a
`PasswordHasher` and runs both `hash` and `verify` in a worker thread so hashing never blocks the
event loop. Stored values are full **PHC strings** (`$argon2id$v=19$m=...,t=...,p=...$salt$hash`),
so the parameters travel with each hash.

On every successful sign-in, deadbolt calls `needs_rehash` (backed by
`PasswordHasher.check_needs_rehash`). If the stored hash used weaker parameters than the current
policy, the password is transparently re-hashed and written back — an automatic upgrade path with
no forced password reset.

Tune the cost parameters by passing your own `PasswordHasher`:

```python
import deadbolt as db
from argon2 import PasswordHasher

auth = db.Auth(
    adapter=db.MemoryAdapter(),
    secret=SECRET,
    hasher=db.Argon2Hasher(PasswordHasher(time_cost=4, memory_cost=131072, parallelism=4)),
)
```

Password length bounds live on `EmailPassword`:

| Field | Default | Meaning |
| --- | --- | --- |
| `min_password_length` | `8` | Reject shorter passwords on sign-up and change. |
| `max_password_length` | `128` | Upper bound (Argon2 has no practical limit, but caps abuse). |

## Session tokens

Sessions are **opaque, DB-authoritative bearer tokens** — not JWTs. `generate_token` draws a
URL-safe token with 32 bytes (**256 bits**) of entropy from `secrets.token_urlsafe`. deadbolt never
stores the token itself: `hash_token` takes the hex **SHA-256** of the token and only the digest is
written to the `session` table. A plain SHA-256 is sufficient here precisely because the input is
already high-entropy — there is nothing to brute-force.

Validation hashes the incoming token and looks it up by digest, then checks expiry against the
database. Token equality helpers use `secrets.compare_digest` for **constant-time** comparison.

!!! note
    Because sessions are DB-backed, revocation is immediate and real. Deleting the row ends the
    session on the next request — there is no signed-but-still-valid window as with stateless
    tokens.

## Cookies

The session token is delivered in a cookie that is **HMAC-signed with `itsdangerous`** before it
ever reaches the browser. `CookieSigner` signs with `Signer(..., digest_method=sha256,
key_derivation="hmac")`, so a tampered cookie is rejected during `unsign` — before any database
lookup happens.

When `host_prefix` and `secure` are both on, the cookie name gets the **`__Host-` prefix**, which
browsers only accept when the cookie is `Secure`, `Path=/`, and has no `Domain`. deadbolt enforces
those conditions to match.

Cookie behavior is configured with `CookieConfig`:

| Field | Default | Meaning |
| --- | --- | --- |
| `name` | `"session"` | Base cookie name (prefixed to `__Host-session` when eligible). |
| `host_prefix` | `True` | Apply the `__Host-` prefix and drop `Domain`. |
| `secure` | `True` | `Secure` attribute — HTTPS only. |
| `http_only` | `True` | `HttpOnly` — hidden from JavaScript. |
| `same_site` | `"Lax"` | `SameSite` policy. |
| `domain` | `None` | Only used when `host_prefix=False`. |
| `path` | `"/"` | Cookie path. |

```python
import deadbolt as db

auth = db.Auth(
    adapter=db.MemoryAdapter(),
    secret=SECRET,
    cookie=db.CookieConfig(same_site="Strict"),
)
```

!!! warning
    Setting `secure=False` or `host_prefix=False` drops the `__Host-` prefix and weakens the
    cookie. Only do so for local HTTP development, never in production.

## Key management

There is **one master secret**. `Auth` rejects any secret shorter than 32 bytes. Every subordinate
key is derived from it with **HKDF-SHA256** (`derive_key`) using a per-purpose `info` label for
cryptographic domain separation, so the cookie-signing key and the field-encryption key are
unrelated even though they share a root:

| Purpose | HKDF `info` label |
| --- | --- |
| Cookie signing | `deadbolt/session-cookie-hmac` |
| Field encryption | `deadbolt/field-encryption` |

```python
import deadbolt as db

auth = db.Auth(
    adapter=db.MemoryAdapter(),
    secret="load-me-from-the-environment-32-bytes-min",
)
```

!!! warning
    Rotating `secret` invalidates **all** signed cookies (users are logged out) and makes any
    field encrypted under the old secret **undecryptable**. If you use field encryption (e.g. TOTP
    secrets), plan a migration that re-encrypts stored data before retiring the old secret rather
    than swapping it out in place.

## Field encryption

Sensitive fields are encrypted at rest with `Encryptor`, an **AEAD** wrapper around
**AES-256-GCM** keyed by the HKDF `deadbolt/field-encryption` subkey. Each `encrypt` call draws a
fresh 12-byte random nonce and returns `base64url(nonce || ciphertext)`; `decrypt` reverses it and
GCM authentication rejects any tampered value.

The TOTP plugin uses this to store 2FA secrets — they are encrypted on enrollment and decrypted
only when a code is verified:

```python
from deadbolt.crypto import Encryptor

enc = Encryptor(auth.secret)
stored = enc.encrypt(totp_secret)   # base64url string, safe to persist
totp_secret = enc.decrypt(stored)   # raises on tampering or wrong key
```

## CSRF

deadbolt applies an **origin-based CSRF check** as defense-in-depth on state-changing requests.
`is_trusted_request` only guards the mutating methods `POST`, `PUT`, `PATCH`, and `DELETE`.
A request with **no `Origin` header** (server-to-server and native clients) is allowed; a browser
request must match the request's own origin or one of your configured trusted origins.

Configure the allow-list with the **`trusted_origins`** parameter on `Auth`. A trailing `*` is a
prefix wildcard:

```python
import deadbolt as db

auth = db.Auth(
    adapter=db.MemoryAdapter(),
    secret=SECRET,
    trusted_origins=["https://app.example.com", "https://*.example.com"],
)
```

## Rate limiting

Auth endpoints are protected by a **fixed-window** rate limiter with **per-path rules** and a
pluggable store. The global settings and overrides live on `RateLimit`; each override is a
`RateLimitRule`:

| Class | Field | Meaning |
| --- | --- | --- |
| `RateLimit` | `enabled` | Master on/off switch (default `True`). |
| `RateLimit` | `window` | Global window in seconds (default `60`). |
| `RateLimit` | `max` | Global max hits per window (default `100`). |
| `RateLimit` | `rules` | Tuple of per-path `RateLimitRule` overrides. |
| `RateLimitRule` | `path` | Endpoint path, matched **exactly**. |
| `RateLimitRule` | `max` | Max hits per window for this path. |
| `RateLimitRule` | `window` | Window in seconds for this path. |

Sensitive endpoints ship with tighter defaults (e.g. `/sign-in/email` at 10/60s,
`/request-password-reset` at 5/60s). Counters are keyed on `client_ip` plus path; a request passes
while its running count stays at or below the limit.

```python
import deadbolt as db
from deadbolt.ratelimit import RateLimit, RateLimitRule

auth = db.Auth(
    adapter=db.MemoryAdapter(),
    secret=SECRET,
    rate_limit=RateLimit(
        max=100,
        window=60,
        rules=(
            RateLimitRule(path="/sign-in/email", max=5, window=60),
            RateLimitRule(path="/reset-password", max=5, window=300),
        ),
    ),
)
```

The default `MemoryRateLimitStore` is **per-process**, so counts are not shared across workers or
hosts. For any multi-process deployment, supply a shared store (e.g. Redis-backed) through
`rate_limit_store`, which must satisfy the `RateLimitStore` protocol (`async increment(key,
window) -> int`).

!!! warning
    Design your store to **fail closed**. If the backing store raises instead of returning a
    count, the limiter cannot enforce the limit for that request. A resilient store should treat
    its own errors as "limit reached" rather than silently allowing traffic through.

## Timing-safe sign-in

Credential sign-in is written so that an **unknown email and a known email with the wrong
password take the same time**, closing the account-enumeration side channel. When no user or
credential account is found, the service still verifies the supplied password against a fixed valid
Argon2id hash, `DECOY_HASH`, before returning the same `invalid_credentials` error:

```python
user = await svc.find_user_by_email(auth.adapter, email)
account = await svc.credential_account(auth.adapter, user["id"]) if user else None
if user is None or account is None or not account.get("password"):
    await auth.hasher.verify(svc.DECOY_HASH, password)   # burn equivalent CPU
    raise _INVALID_CREDENTIALS
```

No configuration is required — this is always on for email/password sign-in.

## Session hardening

`SessionConfig` gives sessions both a sliding idle timeout and a hard ceiling:

| Field | Default | Meaning |
| --- | --- | --- |
| `expires_in` | 7 days | Idle window; each refresh extends expiry by this much. |
| `update_age` | 1 day | A session is only refreshed once it is this old, limiting writes. |
| `fresh_age` | 1 day | Window in which a session counts as "fresh" for sensitive operations. |
| `max_lifetime` | 30 days | **Absolute cap** — no refresh can extend a session past this, ever. |

Validation deletes and rejects any session past either its `expires_at` or the absolute
`created_at + max_lifetime` boundary. `is_fresh` lets sensitive endpoints demand a recently created
session.

**Rotation on privilege change.** Changing a password can atomically revoke every existing session
and mint a fresh one, so a stolen session cannot survive a credential change. Trigger it by sending
`revoke_other_sessions` on the change-password request; deadbolt calls `revoke_all` then issues a
new cookie.

**Logout everywhere.** `revoke_all(user_id)` ends every session for a user (exposed as the
revoke-all-sessions endpoint), while `revoke_others(user_id, keep_token)` ends every session except
the current one, and `revoke_by_id` ends a single listed session.

```python
import deadbolt as db

auth = db.Auth(
    adapter=db.MemoryAdapter(),
    secret=SECRET,
    session=db.SessionConfig(expires_in=86400, max_lifetime=7 * 86400),
)
```

## Audit logging

Every handled request is logged to the standard-library logger named **`deadbolt.audit`** at
`INFO`. Each line records the endpoint path, method, response status, and client IP:

```text
event=/sign-in/email method=POST status=200 ip=203.0.113.7
```

Consume it like any Python logger — attach a handler, ship it to your SIEM, or filter on it. Never
suppress it below `INFO` in production:

```python
import logging

handler = logging.FileHandler("auth-audit.log")
handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
audit = logging.getLogger("deadbolt.audit")
audit.setLevel(logging.INFO)
audit.addHandler(handler)
```

## Expired-data cleanup

Expired sessions and verification tokens are not deleted on a schedule by the library itself.
`Auth.cleanup_expired()` deletes every `session` and `verification` row whose `expires_at` is in the
past and returns the counts removed. Run it periodically from a cron job or background task:

```python
removed = await auth.cleanup_expired()
# {"sessions": 42, "verifications": 3}
```

!!! note
    Expired sessions are already rejected at validation time, so this is hygiene, not a security
    gate — it keeps the tables from growing unbounded.

## Responsible disclosure

Found a vulnerability? **Do not open a public issue.** See
[`SECURITY.md`](https://github.com/ruban-s/deadbolt/blob/main/SECURITY.md) for private reporting via
GitHub Security Advisories and our response-time targets.
