# Phone Number

Phone-number authentication via SMS one-time codes. Users can sign in with a phone number (find-or-create) or link a verified phone to an existing signed-in account.

## Install

Included in the core install. No extra is required.

```
pip install deadbolt
```

Delivery is your responsibility: the `phone_number()` factory **requires** an `SmsSender`, passed as `sms_sender=` to the plugin (not to `db.Auth`). The plugin always calls `sms_sender.send_sms(...)` when a code is generated.

## Setup

```python
import deadbolt as db
from deadbolt.plugins.phone import phone_number

auth = db.Auth(
    adapter=db.MemoryAdapter(),
    secret=SECRET,
    email_and_password=db.EmailPassword(enabled=True),
    plugins=[phone_number(sms_sender=my_sms_sender)],
)
```

## Configuration

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `sms_sender` | SmsSender | _(required)_ | Sender used to deliver codes via `send_sms(to=..., body=...)`. |
| `disable_signup` | bool | `False` | When `True`, sign-in for an unknown phone is rejected instead of creating a user. |
| `length` | int | `6` | Number of digits in the generated code. |
| `ttl` | int | `300` | Code time-to-live in seconds (5 minutes by default). |
| `max_attempts` | int | `3` | Failed verification attempts allowed before the code is deleted. |

## API

### `POST /phone/send-otp`

Generates a numeric code, stores its hash (attempts reset to 0, fresh expiry) in the `phone_otp` table keyed by phone, and sends the raw code by SMS. A resend replaces any existing code for that phone. **Auth:** public.

**Request** (body JSON):

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `phone` | string | Yes | Phone number to send the code to. Used verbatim (not normalised). |

**Response `200`**:

```json
{
  "success": true
}
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| 400 | `invalid_request` | `phone` field missing or not a non-empty string. |

**Example**:

```bash
curl -X POST https://api.example.com/phone/send-otp \
  -H "Content-Type: application/json" \
  -d '{"phone": "+15551234567"}'
```

### `POST /phone/verify`

Verifies a code and links the phone number to the currently signed-in user. **Auth:** session required.

**Request** (body JSON):

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `phone` | string | Yes | Phone number being linked. |
| `otp` | string | Yes | The code from the SMS. |

**Response `200`**:

```json
{
  "success": true
}
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| 401 | `unauthorized` | No valid session on the request. |
| 400 | `invalid_request` | `phone` or `otp` field missing or empty. |
| 400 | `invalid_otp` | No code on file, code expired, wrong code, or attempts exhausted. |
| 409 | `phone_taken` | The phone number is already linked to a different account. |

**Example**:

```bash
curl -X POST https://api.example.com/phone/verify \
  -H "Content-Type: application/json" \
  -b "__Host-session=<session-cookie>" \
  -d '{"phone": "+15551234567", "otp": "123456"}'
```

### `POST /sign-in/phone`

Verifies a code and signs in. If the phone is already linked it returns that user; otherwise it creates a new user and links the phone, unless signup is disabled. **Auth:** public.

**Request** (body JSON):

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `phone` | string | Yes | Phone number to sign in with. |
| `otp` | string | Yes | The code from the SMS. |

**Response `200`**:

```json
{
  "user": {
    "id": "usr_123",
    "email": "+15551234567@phone.deadbolt",
    "email_verified": false,
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
| 400 | `invalid_request` | `phone` or `otp` field missing or empty. |
| 400 | `invalid_otp` | No code on file, code expired, wrong code, attempts exhausted, or unknown phone with `disable_signup=True`. |

**Example**:

```bash
curl -X POST https://api.example.com/sign-in/phone \
  -H "Content-Type: application/json" \
  -d '{"phone": "+15551234567", "otp": "123456"}'
```

## Notes

- **Hashed at rest**: only the code hash (`hash_token`) is stored in the `phone_otp` table; the raw code exists only in the SMS.
- **Single-use**: the OTP row is deleted once a code is successfully consumed (by either verify or sign-in), so a code cannot be replayed — a second use returns `invalid_otp`.
- **Timing-safe comparison**: submitted codes are compared with `tokens_equal` (constant-time) against the stored hash.
- **Attempts limit**: each wrong code increments `attempts`. Once the next failure would reach `max_attempts`, the code is deleted, so even the correct code afterwards fails with `invalid_otp`.
- **Resend replaces**: sending again for the same phone overwrites the existing code and resets attempts to 0 rather than creating a second row.
- **Synthetic email on signup**: sign-in for an unknown phone creates a user with a placeholder email of the form `<phone>@phone.deadbolt` and links the phone (marked `verified`). With `disable_signup=True`, unknown phones are rejected as `invalid_otp`.
- **One phone per user**: linking sets or updates a single `phone_number` row per `user_id`; re-linking replaces the stored number.
- **Ownership check on verify**: linking a phone already owned by a different account returns `phone_taken` (409).
- **TTL**: codes expire after `ttl` seconds (default 300); expired codes are rejected as `invalid_otp`.
