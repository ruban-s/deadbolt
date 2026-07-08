# TOTP Two-Factor Auth

Time-based one-time-password (TOTP) second factor for authenticator apps, with single-use backup codes. Once enabled, `/sign-in/email` stops issuing a session directly and instead returns a challenge that must be completed with a valid code.

## Install

`pip install "deadbolt[totp]"`

## Setup

```python
import deadbolt as db
from deadbolt.plugins.totp import totp

auth = db.Auth(
    adapter=db.MemoryAdapter(),
    secret="a-32-byte-or-longer-secret......",
    email_and_password=db.EmailPassword(enabled=True),
    plugins=[
        totp(issuer="Example", backup_code_count=10),
    ],
)
```

The plugin registers a `two_factor` table (`id`, `user_id`, `secret`, `enabled`, `backup_codes`, `created_at`, `updated_at`) and installs an `after` hook on `/sign-in/email`.

## Configuration

The `totp()` plugin factory:

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `issuer` | `str` | `"deadbolt"` | Issuer name embedded in the `otpauth://` provisioning URI (shown in authenticator apps). |
| `backup_code_count` | `int` | `10` | Number of single-use backup codes generated at enable and on regeneration. |

## API

### `POST /2fa/totp/enroll`

Generates a new TOTP secret for the signed-in user, stores it encrypted (disabled until confirmed), and returns the plaintext secret and provisioning URI for QR display. Re-enrolling replaces any existing secret and resets `enabled` to `false`. **Auth:** session required.

**Request**: no fields.

**Response `200`**:

```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "uri": "otpauth://totp/a@b.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
}
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `401` | `unauthorized` | No valid session cookie. |

### `POST /2fa/totp/enable`

Confirms enrollment by verifying a current code, marks TOTP enabled, and returns freshly generated backup codes (shown once). **Auth:** session required.

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `code` | `string` | yes | A valid current TOTP code from the enrolled secret. |

**Response `200`**:

```json
{ "backup_codes": ["a1b2c3d4e5", "..."] }
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `401` | `unauthorized` | No valid session cookie. |
| `400` | `invalid_request` | `code` missing or not a non-empty string. |
| `400` | `not_enrolled` | No TOTP secret enrolled yet. |
| `400` | `invalid_code` | The code did not verify. |

### `POST /2fa/totp/disable`

Disables and deletes the user's TOTP record after verifying a code (a TOTP code or a backup code). **Auth:** session required.

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `code` | `string` | yes | A valid TOTP code or backup code. |

**Response `200`**:

```json
{ "success": true }
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `401` | `unauthorized` | No valid session cookie. |
| `400` | `invalid_request` | `code` missing or not a non-empty string. |
| `400` | `invalid_code` | Not enrolled, or the code did not verify. |

### `POST /2fa/totp/challenge`

Completes a two-factor sign-in. Takes the `challenge` token from the `/sign-in/email` response plus a code, and on success issues the session. **Auth:** public (the challenge token proves the pending sign-in).

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `challenge` | `string` | yes | The `challenge` token returned by `/sign-in/email`. |
| `code` | `string` | yes | A valid TOTP code or a single-use backup code. |

**Response `200`**:

```json
{
  "user": {
    "id": "...",
    "email": "a@b.com",
    "email_verified": true,
    "name": null,
    "image": null,
    "created_at": "...",
    "updated_at": "..."
  }
}
```

A `__Host-session` cookie is set alongside the body.

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `400` | `invalid_request` | `challenge` or `code` missing/invalid. |
| `400` | `invalid_challenge` | Challenge token unknown, wrong prefix, expired (TTL 300s), or the user is gone. |
| `400` | `invalid_code` | Neither the TOTP code nor a backup code verified. |

### `POST /2fa/totp/backup-codes`

Regenerates the backup code set (invalidating the old ones) after verifying a current TOTP code. Only valid when TOTP is enabled. **Auth:** session required.

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `code` | `string` | yes | A valid current TOTP code. |

**Response `200`**:

```json
{ "backup_codes": ["f6a7b8c9d0", "..."] }
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `401` | `unauthorized` | No valid session cookie. |
| `400` | `invalid_request` | `code` missing or not a non-empty string. |
| `400` | `not_enrolled` | TOTP is not enabled. |
| `400` | `invalid_code` | The TOTP code did not verify. |

## Flow

1. **Enroll** — signed-in user `POST /2fa/totp/enroll`; scan the returned `uri`/`secret` into an authenticator app.
2. **Enable** — `POST /2fa/totp/enable` with a current `code`; store the returned backup codes.
3. **Sign in returns a challenge** — `POST /sign-in/email` no longer sets a session; the after-hook detects that 2FA is enabled, revokes the just-issued session, clears the cookie, and returns `{"two_factor_required": true, "challenge": "<token>"}`.
4. **Challenge** — `POST /2fa/totp/challenge` with that `challenge` and a `code` (TOTP or backup code).
5. **Session** — on success a `__Host-session` cookie is set and the `user` is returned.

## Notes

- **Sign-in after-hook.** The plugin attaches an `after` hook to `/sign-in/email`. When the signed-in user has TOTP enabled, it revokes the session that email/password just created, clears the session cookie, and rewrites the response to `{"two_factor_required": true, "challenge": "<token>"}`. Users without TOTP enabled sign in normally. Disabling TOTP restores normal single-step sign-in.
- **Secret encrypted at rest.** The TOTP secret is encrypted with `Encryptor(auth.secret)` before storage; the plaintext `secret` is only ever returned once at enroll. Verification decrypts on demand.
- **Backup codes.** Each is a 10-hex-character token (`secrets.token_hex(5)`). They are stored hashed (`hash_token`), returned in plaintext only at generation, and are single-use — a used backup code is removed from the stored set and cannot be reused.
- **Verification window.** TOTP codes verify with a valid window of ±1 step to tolerate clock skew.
- **Challenge lifetime.** The sign-in challenge is a `verification` row keyed `2fa-challenge:<user_id>` holding the hashed token, with a 300-second TTL; it is deleted on successful completion.
