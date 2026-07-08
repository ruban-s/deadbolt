# Core authentication

deadbolt's core is email/password authentication backed by server-side sessions. Every endpoint is a plain handler mounted under a configurable prefix (`base_path`, default `/api/auth`), so a route like `/sign-in/email` is served at `/api/auth/sign-in/email`. The same handlers are callable in-process without HTTP through `auth.api.<name>(...)`. Sessions are carried by a signed, HttpOnly cookie named `__Host-session`.

All request bodies are JSON objects. All error responses share the envelope `{"error": {"code": "...", "message": "..."}}` and the codes below refer to that `code` field. Successful responses return the `data` object shown under each endpoint.

## Configuration

Passed to `Auth(...)` as `email_and_password=`, `session=`, and `cookie=`.

### `EmailPassword`

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `enabled` | `bool` | `False` | Master switch for email/password. When off, `sign-up`, `sign-in`, and `request-password-reset` return `403 email_password_disabled`. |
| `min_password_length` | `int` | `8` | Minimum length for new passwords; below it → `400 password_too_short`. |
| `max_password_length` | `int` | `128` | Maximum length for new passwords; above it → `400 password_too_long`. |
| `require_email_verification` | `bool` | `False` | When `True`, unverified users cannot sign in (`403 email_not_verified`), and `change-email` requires confirming the new address. |

### `SessionConfig`

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `expires_in` | `int` (s) | `604800` (7 days) | Rolling session lifetime and cookie `Max-Age`. |
| `update_age` | `int` (s) | `86400` (1 day) | How stale a session may get before `expires_at` is refreshed on validation. |
| `fresh_age` | `int` (s) | `86400` (1 day) | Window in which a session counts as "fresh" for sensitive operations. |
| `max_lifetime` | `int` (s) | `2592000` (30 days) | Absolute cap from creation; past it the session is invalid regardless of refresh. |

### `CookieConfig`

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `name` | `str` | `"session"` | Base cookie name. With `host_prefix` + `secure` it becomes `__Host-session`. |
| `host_prefix` | `bool` | `True` | Adds the `__Host-` prefix (requires `secure`, no `Domain`, `Path=/`). |
| `secure` | `bool` | `True` | Sets the `Secure` attribute. Required for the `__Host-` prefix to apply. |
| `http_only` | `bool` | `True` | Sets `HttpOnly` so JavaScript cannot read the cookie. |
| `same_site` | `str` | `"Lax"` | `SameSite` attribute value. |
| `domain` | `str \| None` | `None` | Cookie `Domain`; ignored when `host_prefix` is on. |
| `path` | `str` | `"/"` | Cookie `Path`. |

The session cookie is therefore `__Host-session`, `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/` by default. Its value is a signed token, not the raw session token.

### Errors common to every endpoint

| Status | Code | When |
| --- | --- | --- |
| `404` | `not_found` | No endpoint matches the method + path. |
| `400` | `invalid_json` | Body is not valid JSON, or is not a JSON object. |
| `403` | `untrusted_origin` | Request `Origin` is not in `trusted_origins`. |
| `429` | `rate_limited` | Rate limit exceeded. |
| `413` | `payload_too_large` | Body exceeds `max_body_bytes`. |

## Endpoints

### Sign up & in

#### `POST /sign-up/email`

Creates a user + credential account and starts a session. **Auth:** public.

**Request** (JSON body):

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `email` | `string` | yes | Lower-cased before storage. |
| `password` | `string` | yes | Validated against min/max length. |
| `name` | `string` | no | Optional display name. |

**Response `200`**:

```json
{
  "user": {
    "id": "…",
    "email": "a@b.com",
    "email_verified": false,
    "name": null,
    "image": null,
    "created_at": "…",
    "updated_at": "…"
  }
}
```

Sets the `__Host-session` cookie.

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `403` | `email_password_disabled` | `EmailPassword.enabled` is `False`. |
| `400` | `invalid_request` | Missing/empty `email` or `password`. |
| `400` | `password_too_short` | Password shorter than `min_password_length`. |
| `400` | `password_too_long` | Password longer than `max_password_length`. |
| `422` | `user_already_exists` | Email already registered. |

#### `POST /sign-in/email`

Verifies credentials and starts a session. **Auth:** public.

**Request** (JSON body):

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `email` | `string` | yes | Lower-cased before lookup. |
| `password` | `string` | yes | Verified against the stored hash. |

**Response `200`**:

```json
{
  "user": {
    "id": "…",
    "email": "a@b.com",
    "email_verified": true,
    "name": null,
    "image": null,
    "created_at": "…",
    "updated_at": "…"
  }
}
```

Sets the `__Host-session` cookie. If the stored hash needs upgrading it is transparently rehashed on success.

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `403` | `email_password_disabled` | `EmailPassword.enabled` is `False`. |
| `400` | `invalid_request` | Missing/empty `email` or `password`. |
| `401` | `invalid_credentials` | Unknown email or wrong password (unified to prevent enumeration; a decoy hash is verified on the miss path). |
| `403` | `email_not_verified` | `require_email_verification` is on and the user is unverified. |

#### `POST /sign-out`

Revokes the current session and clears the cookie. **Auth:** public (no-op if no session).

**Request**: no fields.

**Response `200`**:

```json
{ "success": true }
```

Clears the `__Host-session` cookie.

### Sessions

#### `GET /get-session`

Returns the current session and user, or nulls if unauthenticated. **Auth:** public.

**Request**: no body; reads the session cookie.

**Response `200`** (authenticated):

```json
{
  "session": {
    "id": "…",
    "user_id": "…",
    "expires_at": "…",
    "created_at": "…",
    "updated_at": "…"
  },
  "user": {
    "id": "…",
    "email": "a@b.com",
    "email_verified": true,
    "name": null,
    "image": null,
    "created_at": "…",
    "updated_at": "…"
  }
}
```

**Response `200`** (unauthenticated or invalid/expired session):

```json
{ "session": null, "user": null }
```

**Errors**: none (missing/invalid sessions return the null shape).

#### `GET /list-sessions`

Lists all active sessions for the current user. **Auth:** session required.

**Request**: no body.

**Response `200`**:

```json
{
  "sessions": [
    {
      "id": "…",
      "expires_at": "…",
      "created_at": "…",
      "updated_at": "…",
      "ip_address": null,
      "user_agent": null
    }
  ]
}
```

The session token is never included.

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `401` | `unauthorized` | No valid session. |

#### `POST /revoke-session`

Revokes one of the current user's sessions by id. **Auth:** session required.

**Request** (JSON body):

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `session_id` | `string` | yes | Id of the session to revoke (must belong to the caller). |

**Response `200`**:

```json
{ "success": true }
```

`success` is `false` if no matching session was found for the user.

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `401` | `unauthorized` | No valid session. |
| `400` | `invalid_request` | Missing/empty `session_id`. |

#### `POST /revoke-sessions`

Revokes all of the current user's sessions, including the current one. **Auth:** session required.

**Request**: no fields.

**Response `200`**:

```json
{ "revoked": 2 }
```

Clears the `__Host-session` cookie.

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `401` | `unauthorized` | No valid session. |

#### `POST /revoke-other-sessions`

Revokes every session except the current one. **Auth:** session required.

**Request**: no fields.

**Response `200`**:

```json
{ "revoked": 1 }
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `401` | `unauthorized` | No valid session. |

### Password

#### `POST /change-password`

Changes the password for the signed-in user after re-checking the current one. **Auth:** session required.

**Request** (JSON body):

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `current_password` | `string` | yes | Verified against the stored hash. |
| `new_password` | `string` | yes | Validated against min/max length. |
| `revoke_other_sessions` | `bool` | no | If truthy, revoke all sessions and issue a fresh cookie for the caller. |

**Response `200`**:

```json
{ "success": true }
```

When `revoke_other_sessions` is truthy, a new `__Host-session` cookie is set.

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `401` | `unauthorized` | No valid session. |
| `400` | `invalid_request` | Missing/empty `current_password` or `new_password`. |
| `400` | `password_too_short` / `password_too_long` | New password fails length rules. |
| `400` | `no_credential` | Account has no password set. |
| `401` | `invalid_credentials` | `current_password` is wrong. |

#### `POST /request-password-reset`

Issues a reset token and emails it, if the email is registered. **Auth:** public.

**Request** (JSON body):

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `email` | `string` | yes | Lower-cased before lookup. |

**Response `200`**:

```json
{ "success": true }
```

Always returns success — even for unknown emails — to avoid enumeration. The token is delivered only via the configured `email_sender` and expires after 1 hour.

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `403` | `email_password_disabled` | `EmailPassword.enabled` is `False`. |
| `400` | `invalid_request` | Missing/empty `email`. |

#### `POST /reset-password`

Sets a new password from a valid reset token and revokes all of the user's sessions. **Auth:** public (token-scoped).

**Request** (JSON body):

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `token` | `string` | yes | The reset token from the email. |
| `new_password` | `string` | yes | Validated against min/max length. |

**Response `200`**:

```json
{ "success": true }
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `400` | `invalid_request` | Missing/empty `token` or `new_password`. |
| `400` | `password_too_short` / `password_too_long` | New password fails length rules. |
| `400` | `invalid_token` | Token unknown, expired, or its user/account no longer exists. |

### Email verification

#### `POST /send-verification-email`

Issues and emails a verification token for an unverified user. **Auth:** public.

**Request** (JSON body):

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `email` | `string` | yes | Lower-cased before lookup. |

**Response `200`**:

```json
{ "success": true }
```

Silently no-ops (still `200`) if the email is unknown or already verified. The token is delivered only via the configured `email_sender` and expires after 1 hour.

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `400` | `invalid_request` | Missing/empty `email`. |

#### `POST /verify-email`

Consumes a token to verify an email — or to confirm a pending email change. **Auth:** public (token-scoped).

**Request** (JSON body):

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `token` | `string` | yes | Verification or change-email confirmation token. |

**Response `200`**:

```json
{ "success": true }
```

For a change-email token, applies the new address (setting `email_verified` to `true`).

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `400` | `invalid_request` | Missing/empty `token`. |
| `400` | `invalid_token` | Token unknown, expired, or of an unrecognized type. |
| `409` | `email_taken` | Change-email target address is now in use. |

### Account & user management

#### `POST /change-email`

Changes the signed-in user's email, immediately or via confirmation. **Auth:** session required.

**Request** (JSON body):

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `new_email` | `string` | yes | Lower-cased before use. |

**Response `200`** — verification off (immediate change):

```json
{
  "user": {
    "id": "…",
    "email": "new@b.com",
    "email_verified": false,
    "name": null,
    "image": null,
    "created_at": "…",
    "updated_at": "…"
  }
}
```

**Response `200`** — verification on (confirmation emailed):

```json
{ "status": "verification_sent" }
```

If `new_email` equals the current email, returns `{ "success": true }` and does nothing.

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `401` | `unauthorized` | No valid session. |
| `400` | `invalid_request` | Missing/empty `new_email`. |
| `409` | `email_taken` | Address already belongs to another user. |

#### `POST /update-user`

Updates the signed-in user's profile fields. **Auth:** session required.

**Request** (JSON body — send any subset):

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | `string` | no | New display name. |
| `image` | `string` | no | New avatar URL. |

Only `name` and `image` are read; other keys are ignored.

**Response `200`**:

```json
{
  "user": {
    "id": "…",
    "email": "a@b.com",
    "email_verified": true,
    "name": "Alice",
    "image": "http://x/a.png",
    "created_at": "…",
    "updated_at": "…"
  }
}
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `401` | `unauthorized` | No valid session. |

#### `POST /delete-user`

Deletes the signed-in user, their accounts, and all their sessions. **Auth:** session required.

**Request** (JSON body):

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `password` | `string` | conditional | Required when the account has a password set; verified before deletion. |

**Response `200`**:

```json
{ "success": true }
```

Clears the `__Host-session` cookie.

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `401` | `unauthorized` | No valid session. |
| `400` | `invalid_request` | Password required but missing/empty. |
| `401` | `invalid_credentials` | Supplied password is wrong. |

#### `GET /list-accounts`

Lists the sign-in accounts linked to the current user. **Auth:** session required.

**Request**: no body.

**Response `200`**:

```json
{
  "accounts": [
    {
      "id": "…",
      "provider_id": "credential",
      "account_id": "a@b.com",
      "created_at": "…"
    }
  ]
}
```

Password hashes are never included.

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `401` | `unauthorized` | No valid session. |

#### `POST /unlink-account`

Removes a linked provider account. **Auth:** session required.

**Request** (JSON body):

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `provider_id` | `string` | yes | Provider to unlink (e.g. `google`, `github`, `credential`). |

**Response `200`**:

```json
{ "success": true }
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `401` | `unauthorized` | No valid session. |
| `400` | `invalid_request` | Missing/empty `provider_id`. |
| `400` | `last_account` | Cannot unlink the only remaining sign-in method. |
| `404` | `account_not_found` | No linked account for that provider. |

## Calling without HTTP

Every endpoint is also reachable in-process through `auth.api.<name>(...)`, taking the body fields as keyword arguments. It returns the `data` object by default, or the full `EndpointResult` (including cookies) when `as_response=True`:

```python
result = await auth.api.sign_in_email(
    email="a@b.com",
    password="hunter2pw",
    as_response=True,
)
user = result.data["user"]
cookie = result.cookies[0]  # the __Host-session cookie to set on your response
```

The call also accepts `cookies=` (a `dict[str, str]`, for endpoints that read the session) and `client_ip=`.
