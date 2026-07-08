# API Keys

Programmatic access keys for machine-to-machine authentication. Keys are shown once at creation and stored only as a SHA-256 hash; verify a key to authenticate a request.

## Install

Included in the core install.

## Setup

```python
import deadbolt as db
from deadbolt.plugins.api_keys import api_keys

auth = db.Auth(
    adapter=db.MemoryAdapter(),
    secret="a-32-byte-or-longer-secret......",
    email_and_password=db.EmailPassword(enabled=True),
    plugins=[api_keys()],
)
```

## Configuration

The `api_keys()` factory takes no arguments.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| — | — | — | No configuration. |

## API

Create/list/revoke require a valid session cookie; verify is public. Error responses use the envelope `{"error": {"code": "...", "message": "..."}}` with the listed HTTP status.

The public representation of a key never includes the secret. It contains: `id`, `name`, `start`, `expires_at`, `last_used_at`, `created_at`.

#### `POST /api-key/create`

Creates a new API key for the caller. The full secret is returned once and never again. **Auth:** session required.

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | string | yes | Human-readable label. |
| `expires_in` | integer | no | Lifetime in seconds; sets `expires_at`. Omit for a non-expiring key. |

**Response `200`**:

```json
{
  "key": "dbk_a1b2c3d4e5...",
  "api_key": {
    "id": "key_1",
    "name": "ci",
    "start": "dbk_a1b2c3",
    "expires_at": null,
    "last_used_at": null,
    "created_at": "2026-07-08T00:00:00Z"
  }
}
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `401` | `unauthorized` | No valid session. |

#### `GET /api-key/list`

Lists the caller's API keys in public form (no secrets). **Auth:** session required.

**Response `200`**:

```json
{
  "api_keys": [
    {
      "id": "key_1",
      "name": "ci",
      "start": "dbk_a1b2c3",
      "expires_at": null,
      "last_used_at": null,
      "created_at": "2026-07-08T00:00:00Z"
    }
  ]
}
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `401` | `unauthorized` | No valid session. |

#### `POST /api-key/revoke`

Deletes one of the caller's API keys. **Auth:** session required.

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `id` | string | yes | Key id to revoke. |

**Response `200`**:

```json
{ "success": true }
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `401` | `unauthorized` | No valid session. |
| `404` | `not_found` | No such key owned by the caller. |

#### `POST /api-key/verify`

Verifies a key and returns the owning user id. Updates the key's `last_used_at` on success. **Auth:** public.

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `key` | string | yes | The full `dbk_`-prefixed secret. |

**Response `200`**:

```json
{ "valid": true, "user_id": "usr_1" }
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `401` | `invalid_key` | Key is unknown or expired. |

## Notes

- **Hashed at rest.** Only a SHA-256 hash of the key is stored; the plaintext secret is returned once from `create` and cannot be recovered afterward.
- **`dbk_` prefix.** Every generated key is prefixed `dbk_`. The stored `start` field keeps the prefix plus the first 6 characters (`dbk_` + 6) so keys can be visually identified without exposing the secret.
- **Expiry.** `expires_in` (seconds) sets `expires_at`; omitting it produces a non-expiring key. `verify` rejects a key whose `expires_at` has passed with `401 invalid_key`.
- **Last used.** A successful `verify` stamps `last_used_at` with the current time.
- **Ownership.** `list` and `revoke` are scoped to the caller's own keys.
