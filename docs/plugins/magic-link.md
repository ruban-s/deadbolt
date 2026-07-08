# Magic Link

Passwordless email sign-in: the user requests a link, receives a one-time token by email, and verifies it to get a session. Unknown emails are signed up on first verify (find-or-create).

## Install

Included in the core install. No extra is required.

```bash
pip install deadbolt
```

Delivery is your responsibility: pass an `EmailSender` as `email_sender=` to `db.Auth`. Without one, the send endpoint still records the token but no email is dispatched (useful in tests).

## Setup

```python
import deadbolt as db
from deadbolt.plugins.magic_link import magic_link

auth = db.Auth(
    adapter=db.MemoryAdapter(),
    secret=SECRET,
    email_and_password=db.EmailPassword(enabled=True),
    email_sender=my_email_sender,
    plugins=[magic_link()],
)
```

## Configuration

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `expires_in` | int | `600` | Token time-to-live in seconds (10 minutes by default). |

## API

### `POST /magic-link/send`

Generates a magic-link token, stores its hash in the `verification` table under a `magic-link:` identifier, and emails the raw token via the configured `EmailSender`. **Auth:** public.

**Request** (body JSON):

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `email` | string | Yes | Email address to send the link to. Lowercased before storage. |

**Response `200`**:

```json
{
  "success": true
}
```

The endpoint always returns success once the token is recorded; it does not reveal whether the email exists.

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| 400 | `invalid_request` | `email` field missing or not a non-empty string. |

**Example**:

```bash
curl -X POST https://api.example.com/magic-link/send \
  -H "Content-Type: application/json" \
  -d '{"email": "new@b.com"}'
```

### `POST /magic-link/verify`

Verifies a magic-link token. Looks up the record by token hash, checks it is a magic-link record and not expired, finds or creates the user, marks the email verified, deletes the token, and creates a session. **Auth:** public.

**Request** (body JSON):

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `token` | string | Yes | The raw token from the emailed magic link. |

**Response `200`**:

```json
{
  "user": {
    "id": "usr_123",
    "email": "new@b.com",
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
| 400 | `invalid_request` | `token` field missing or empty. |
| 400 | `invalid_token` | Token not found, not a magic-link record, or expired. |

**Example**:

```bash
curl -X POST https://api.example.com/magic-link/verify \
  -H "Content-Type: application/json" \
  -d '{"token": "3f9a...c1"}'
```

## Notes

- **Hashed at rest**: only the token hash (`hash_token`) is stored in the `verification` table; the raw token exists only in the email.
- **Single-use**: the verification record is deleted on successful verify, so a token cannot be replayed — a second verify returns `invalid_token`.
- **Find-or-create**: verifying a token for an unknown email creates a new user with `name=None`; existing users are matched by email.
- **Email marked verified**: a successful verify sets `email_verified = true` on the user.
- **Namespaced records**: magic-link tokens are stored under an `identifier` prefixed with `magic-link:`. Other verification records (e.g. password-reset tokens) are ignored by verify even if the token value matched.
- **TTL**: tokens expire after `expires_in` seconds (default 600); expired tokens are rejected as `invalid_token`.
