# Email OTP

Passwordless email sign-in with a numeric one-time password (OTP). The user requests a code by email, then signs in by submitting it. Unknown emails are signed up on first success unless signup is disabled.

## Install

Included in the core install. No extra is required.

```
pip install deadbolt
```

Delivery is your responsibility: pass an `EmailSender` as `email_sender=` to `db.Auth`. Without one, the send endpoint still stores the code but no email is dispatched (useful in tests).

## Setup

```python
import deadbolt as db
from deadbolt.plugins.email_otp import email_otp

auth = db.Auth(
    adapter=db.MemoryAdapter(),
    secret=SECRET,
    email_and_password=db.EmailPassword(enabled=True),
    email_sender=my_email_sender,
    plugins=[email_otp()],
)
```

## Configuration

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `length` | int | `6` | Number of digits in the generated code. |
| `ttl` | int | `300` | Code time-to-live in seconds (5 minutes by default). |
| `max_attempts` | int | `3` | Failed verification attempts allowed before the code is consumed. |
| `disable_signup` | bool | `False` | When `True`, sign-in for an unknown email is rejected instead of creating a user. |

## API

### `POST /email-otp/send`

Generates a numeric code, stores its hash (with attempts reset to 0 and a fresh expiry) in the `email_otp` table keyed by email, and emails the raw code via the configured `EmailSender`. A resend replaces any existing code for that email. **Auth:** public.

**Request** (body JSON):

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `email` | string | Yes | Email address to send the code to. Lowercased before storage. |

**Response `200`**:

```json
{
  "success": true
}
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| 400 | `invalid_request` | `email` field missing or not a non-empty string. |

**Example**:

```bash
curl -X POST https://api.example.com/email-otp/send \
  -H "Content-Type: application/json" \
  -d '{"email": "a@b.com"}'
```

### `POST /sign-in/email-otp`

Verifies an emailed code. Checks the code against the stored hash in constant time, enforces the attempts limit, then finds or creates the user, marks the email verified, deletes the code, and creates a session. **Auth:** public.

**Request** (body JSON):

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `email` | string | Yes | Email the code was sent to. Lowercased before lookup. |
| `otp` | string | Yes | The numeric code from the email. |

**Response `200`**:

```json
{
  "user": {
    "id": "usr_123",
    "email": "a@b.com",
    "email_verified": true,
    "name": null,
    "image": null,
    "created_at": "2026-07-08T00:00:00Z",
    "updated_at": "2026-07-08T00:00:00Z"
  }
}
```

A session cookie is set in the response.

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| 400 | `invalid_request` | `email` or `otp` field missing or empty. |
| 400 | `invalid_otp` | No code on file, code expired, wrong code, attempts exhausted, or unknown email with `disable_signup=True`. |

**Example**:

```bash
curl -X POST https://api.example.com/sign-in/email-otp \
  -H "Content-Type: application/json" \
  -d '{"email": "a@b.com", "otp": "123456"}'
```

## Notes

- **Hashed at rest**: only the code hash (`hash_token`) is stored in the `email_otp` table; the raw code exists only in the email.
- **Single-use**: the OTP row is deleted on successful sign-in, so a code cannot be replayed — a second sign-in returns `invalid_otp`.
- **Timing-safe comparison**: submitted codes are compared with `tokens_equal` (constant-time) against the stored hash.
- **Attempts limit**: each wrong code increments `attempts`. Once the next failure would reach `max_attempts`, the code is deleted, so even the correct code afterwards fails with `invalid_otp`.
- **Resend replaces**: sending again for the same email overwrites the existing code and resets attempts to 0 rather than creating a second row.
- **Find-or-create**: an unknown email creates a new user (`name=None`) on success; with `disable_signup=True`, unknown emails are rejected as `invalid_otp`.
- **Email marked verified**: a successful sign-in sets `email_verified = true` on the user.
- **TTL**: codes expire after `ttl` seconds (default 300); expired codes are rejected as `invalid_otp`.
