# Sessions

deadbolt uses opaque, database-backed sessions. A sign-in mints a random token, stores only its hash
server-side, and hands the client a signed cookie. Every subsequent request is authenticated by
looking the token's hash up in the database — the database is always the source of truth, so a
session can be expired or revoked the instant its row changes.

## The token

On `create`, the session manager generates a fresh token with `secrets.token_urlsafe(32)` — 256 bits
of entropy from the operating system's cryptographically secure generator. The token is opaque:
it carries no user data and means nothing on its own.

The plaintext token is returned to the caller once (to be placed in a cookie) and is **never**
stored. What lands in the database is its hex SHA-256 digest. A plain hash is safe here precisely
because the token is already high-entropy — there is nothing to brute-force — so a leaked database
row cannot be turned back into a usable token. Lookups hash the incoming token and match on the
digest.

```python
# what the manager stores for a session (abridged)
row = {
    "id": new_id(),
    "user_id": user_id,
    "token": hash_token(token),          # SHA-256 hex, not the token itself
    "expires_at": moment + timedelta(seconds=config.expires_in),
    "created_at": moment,
    "updated_at": moment,
    "ip_address": ip,
    "user_agent": user_agent,
}
```

## The cookie

The token travels to the browser inside a signed cookie. deadbolt signs the value with
`itsdangerous` using an HMAC key derived from your `secret` via HKDF, so a tampered cookie is
rejected before any database lookup ever happens. Signing is authentication of the cookie's
integrity, not encryption — the token inside is already opaque.

By default the cookie is issued with the `__Host-` prefix. When `host_prefix` and `secure` are both
on, the manager names the cookie `__Host-<name>` (for example `__Host-session`), which the browser
only accepts when it is `Secure`, `Path=/`, and has no `Domain` — the strongest binding a cookie can
have. The cookie is also `HttpOnly` (invisible to JavaScript) and `SameSite=Lax` by default.

## Expiry

Two independent clocks bound a session, and both are enforced server-side on every `validate`:

- **Idle expiry** — `expires_at`. Reached when a session sits unused past `expires_in`. Activity
  slides this window forward (see rotation below).
- **Absolute expiry** — `created_at + max_lifetime`. A hard ceiling that activity can never push
  past. Once a session is older than `max_lifetime` it is dead no matter how recently it was used.

`validate` hashes the presented token, loads the row, and deletes it and returns `None` if either
clock has passed. Because the check reads the live row, expiry cannot be forged from the client side.

To keep expired rows from accumulating, `Auth.cleanup_expired()` bulk-deletes sessions (and
verifications) whose `expires_at` is in the past. Run it periodically in production.

## Refresh and rotation

deadbolt refreshes a session lazily rather than on every request. When a validated session is older
than `update_age`, `validate` slides `expires_at` forward (capped at the absolute ceiling) and
stamps `updated_at`. Requests inside the `update_age` window skip the write entirely, so refresh
costs at most one update per window.

On a privilege change — sign-in, or any operation that should not inherit an old session's trust —
the old row is deleted and a brand-new token is issued, so the identifier in the browser never
outlives the trust boundary it was minted under. For sensitive operations, `is_fresh` reports
whether a session was created within `fresh_age`, letting you require a recent re-authentication
before, say, changing a password.

## Revocation

Revocation is deletion. Because the database row is authoritative, removing it invalidates the
session immediately — there is no token blocklist to maintain and no window where a revoked token
still works.

| Action | Method | Effect |
| --- | --- | --- |
| Sign out this session | `revoke(token)` | delete the row for this token |
| Sign out one session by id | `revoke_by_id(session_id, user_id)` | delete that user's session, if it exists |
| Sign out everywhere | `revoke_all(user_id)` | delete every session for the user |
| Sign out other devices | `revoke_others(user_id, keep_token)` | delete all but the current session |
| List active sessions | `list_for(user_id)` | every stored session for the user |

## `auth.sessions`

The session manager is exposed on the `Auth` object as `auth.sessions`. It is the same
`SessionManager` the HTTP endpoints use, so you can drive the full lifecycle directly from
server-side code.

```python
import deadbolt as db

auth = db.Auth(
    adapter=db.MemoryAdapter(),
    secret="a-32-byte-or-longer-random-secret-please",
    email_and_password=db.EmailPassword(enabled=True),
)

token, row = await auth.sessions.create("user-123", ip="203.0.113.7")
session = await auth.sessions.validate(token)          # None once expired or revoked
cookie = auth.sessions.build_cookie(token)             # a signed __Host- cookie to set
await auth.sessions.revoke_all("user-123")             # sign the user out everywhere
```

`build_cookie` returns a framework-neutral `Cookie` (name, signed value, `max_age` from
`expires_in`, plus the flags below); `clear_cookie` returns the same cookie emptied with `max_age=0`
to log a user out; and `read_token` unsigns an incoming cookie value back into a token, returning
`None` if the signature is invalid.

## Configuration

Session lifetimes come from `SessionConfig` and cookie attributes from `CookieConfig`; both are
frozen dataclasses passed to `Auth` (as `session=` and `cookie=`) and default to secure values.

### `SessionConfig`

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `expires_in` | `int` | `604800` (7 days) | idle lifetime, in seconds |
| `update_age` | `int` | `86400` (1 day) | minimum age before a validated session is refreshed |
| `fresh_age` | `int` | `86400` (1 day) | how long a session counts as "fresh" for sensitive ops |
| `max_lifetime` | `int` | `2592000` (30 days) | absolute lifetime ceiling, in seconds |

### `CookieConfig`

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `name` | `str` | `"session"` | base cookie name (prefixed with `__Host-` when applicable) |
| `host_prefix` | `bool` | `True` | apply the `__Host-` prefix (requires `secure`) |
| `secure` | `bool` | `True` | set the `Secure` flag (HTTPS only) |
| `http_only` | `bool` | `True` | set `HttpOnly` (hidden from JavaScript) |
| `same_site` | `str` | `"Lax"` | the `SameSite` attribute |
| `domain` | `str | None` | `None` | cookie domain (ignored while `host_prefix` is on) |
| `path` | `str` | `"/"` | cookie path |
