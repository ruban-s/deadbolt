# Username

Lets users claim a unique username and sign in with `username` + `password` instead of their email. The username maps to the same credential account created by email/password sign-up.

## Install

Included in the core install. No extra is required.

```
pip install deadbolt
```

The plugin reuses the existing password credential account, so the core `email_and_password` provider must be enabled for sign-in to work.

## Setup

```python
import deadbolt as db
from deadbolt.plugins.username import username

auth = db.Auth(
    adapter=db.MemoryAdapter(),
    secret=SECRET,
    email_and_password=db.EmailPassword(enabled=True),
    plugins=[username()],
)
```

## Configuration

The `username()` factory takes no parameters.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| _(none)_ | | | The plugin has no configuration options. |

## API

### `POST /username/set`

Sets or changes the current user's username. Normalises the value to lowercase for storage and matching, but keeps the original casing as the display username. **Auth:** session required.

**Request** (body JSON):

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `username` | string | Yes | Desired username. Must match `^[a-z0-9_]{3,32}$` after lowercasing (3–32 chars: a–z, 0–9, underscore). |

**Response `200`**:

```json
{
  "username": "Alice_01"
}
```

The returned `username` is the display value (original casing).

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| 401 | `unauthorized` | No valid session on the request. |
| 400 | `invalid_request` | `username` field missing or not a non-empty string. |
| 400 | `invalid_username` | Normalised value fails the `a-z0-9_`, 3–32 char pattern. |
| 409 | `username_taken` | The username already belongs to another user. |

**Example**:

```bash
curl -X POST https://api.example.com/username/set \
  -H "Content-Type: application/json" \
  -b "__Host-session=<session-cookie>" \
  -d '{"username": "Alice_01"}'
```

### `GET /username/available`

Checks whether a username is both valid and free. Public helper for signup forms. **Auth:** public.

**Request** (query):

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `username` | string | Yes | Candidate username to check. Compared after lowercasing. |

**Response `200`**:

```json
{
  "available": true
}
```

`available` is `true` only when the value matches the format pattern **and** is not already taken.

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| 400 | `invalid_request` | `username` query parameter missing or empty. |

**Example**:

```bash
curl "https://api.example.com/username/available?username=free_name"
```

### `POST /sign-in/username`

Signs in with a username and password, verifying against the user's existing password credential account. On success it creates a session and sets the session cookie. **Auth:** public.

**Request** (body JSON):

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `username` | string | Yes | Username to sign in as. Matched after lowercasing. |
| `password` | string | Yes | The account password. |

**Response `200`**:

```json
{
  "user": {
    "id": "usr_123",
    "email": "a@b.com",
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
| 400 | `invalid_request` | `username` or `password` field missing or empty. |
| 401 | `invalid_credentials` | Unknown username, no password credential on the account, or wrong password. |

**Example**:

```bash
curl -X POST https://api.example.com/sign-in/username \
  -H "Content-Type: application/json" \
  -d '{"username": "alice_01", "password": "hunter2pw"}'
```

## Notes

- **Case handling**: usernames are stored normalised to lowercase (`username`) alongside the original casing (`display_username`). Lookups and availability checks compare the lowercased value, so `Alice_01` and `alice_01` collide.
- **One username per user**: setting a username again updates the existing record rather than creating a second one; the previous username stops working immediately.
- **Ownership check on set**: re-setting your own current username is allowed; the `username_taken` conflict only triggers when the row belongs to a different `user_id`.
- **Timing-safe sign-in**: when the username is unknown or the account has no password, the password is still verified against a fixed decoy hash before returning `invalid_credentials`, keeping response timing uniform and avoiding username enumeration.
- **Password rehashing**: if the stored hash needs upgrading (`needs_rehash`), the password is re-hashed and persisted on successful sign-in.
- **Shared credential**: sign-in verifies against the same password credential account as email/password auth, so passwords stay in sync across both methods.
