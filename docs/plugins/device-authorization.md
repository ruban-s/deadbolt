# Device authorization

Sign in on a device with no browser or keyboard — a CLI, a smart TV, an IoT box — using the
[OAuth 2.0 Device Authorization Grant (RFC 8628)](https://datatracker.ietf.org/doc/html/rfc8628).
The device shows a short code; the user approves it on a phone or laptop where they are already
signed in; the device then receives a session token.

## Install

Ships with the core; there is no extra to install.

## Setup

```python
import deadbolt as db
from deadbolt.plugins.device_authorization import device_authorization

auth = db.Auth(
    adapter=db.MemoryAdapter(),
    secret="a-32-byte-or-longer-secret......",
    email_and_password=db.EmailPassword(enabled=True),
    plugins=[device_authorization(verification_uri="https://app.example.com/device")],
)
```

Run the schema generator (or your migration) so the `device_request` table exists.

## Configuration

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `verification_uri` | string | — | **Required.** The page where the user enters the code. |
| `expires_in` | integer | `600` | Request lifetime in seconds. |
| `interval` | integer | `5` | Minimum seconds between device polls; faster polling gets `slow_down`. |
| `user_code_length` | integer | `8` | Characters in the user code (shown as `XXXX-XXXX`). |

## The flow

```text
device                        deadbolt                         user (signed in)
  │ POST /device/code            │                                   │
  │─────────────────────────────▶│  device_code + user_code          │
  │◀─────────────────────────────│                                   │
  │ show user_code + uri ─────────────────────────────────────────▶ │ visits /device
  │ POST /device/token (poll) ───▶│ authorization_pending             │ GET /device?user_code=…
  │◀──────────────────────────────│                                   │ POST /device/approve
  │ POST /device/token (poll) ───▶│ access_token + user  ◀────────────│
```

## API

#### `POST /device/code`

Starts a request. **Auth:** public. **Request:** optional `{ "client_id": "..." }`.

**Response `200`**: `device_code`, `user_code`, `verification_uri`, `verification_uri_complete`,
`expires_in`, `interval`.

#### `POST /device/token`

The device polls here with `{ "device_code": "..." }`. **Auth:** public. On success returns
`{ "access_token": "...", "token_type": "Bearer", "user": { ... } }` plus the session cookie — the
`access_token` is a session credential usable with the [bearer](bearer.md) plugin. Until then it
returns `400` with one of these codes:

| Code | Meaning |
| --- | --- |
| `authorization_pending` | The user has not acted yet; keep polling. |
| `slow_down` | Polling faster than `interval`; back off. |
| `access_denied` | The user denied the request. |
| `expired_token` | The request lifetime elapsed. |
| `invalid_grant` | Unknown device code (or the approving user was deleted). |

#### `GET /device`

Validates a code so the approval page can name the device. **Auth:** session required.
**Query:** `user_code`. **Response:** `{ "user_code": "...", "client_id": "...", "status": "pending" }`.

#### `POST /device/approve` · `POST /device/deny`

The signed-in user approves or denies `{ "user_code": "..." }`. **Auth:** session required.
**Response:** `{ "success": true }`.

## Notes

- **Device code is hashed and single-use.** Only `SHA-256(device_code)` is stored, and the row is
  deleted the moment a token is issued, denied, or expired.
- **User code is unambiguous.** Codes use an alphabet without `0/O/1/I` so they are easy to read off a
  screen and type.
- **Approval binds the user.** The session the device receives belongs to whoever approved the code,
  and is a normal, independently revocable deadbolt session.
