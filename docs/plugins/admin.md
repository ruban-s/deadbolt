# Admin

Administration for roles, bans, and user management. Admins are bootstrapped by email or user id and can promote others; banned users are refused at sign-in by after-hooks.

## Install

Included in the core install.

## Setup

```python
import deadbolt as db
from deadbolt.plugins.admin import admin

auth = db.Auth(
    adapter=db.MemoryAdapter(),
    secret="a-32-byte-or-longer-secret......",
    email_and_password=db.EmailPassword(enabled=True),
    plugins=[admin(admin_emails=["boss@example.com"])],
)
```

## Configuration

Bootstrap the initial administrators via the `admin()` factory. A user counts as admin if their email is in `admin_emails`, their id is in `admin_user_ids`, or their `admin_meta.role` equals `"admin"` (set via `set-role`).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `admin_emails` | `Sequence[str]` | `()` | Emails always treated as admin; lowercased on load. |
| `admin_user_ids` | `Sequence[str]` | `()` | User ids always treated as admin. |

## API

Every endpoint requires the caller to be an administrator. Error responses use the envelope `{"error": {"code": "...", "message": "..."}}` with the listed HTTP status. Two errors are common to all endpoints:

| Status | Code | When |
| --- | --- | --- |
| `401` | `unauthorized` | No valid session. |
| `403` | `forbidden` | Caller is not an administrator. |

#### `POST /admin/set-role`

Sets a user's admin role (e.g. `"admin"` to grant admin access, `"user"` to revoke). **Auth:** admin required.

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `user_id` | string | yes | Target user. |
| `role` | string | yes | Role to assign; `"admin"` grants admin endpoint access. |

**Response `200`**:

```json
{ "success": true }
```

#### `POST /admin/ban-user`

Bans a user and revokes all their sessions. **Auth:** admin required.

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `user_id` | string | yes | Target user. |
| `reason` | string | no | Stored as `ban_reason`. |
| `expires_in` | integer | no | Ban lifetime in seconds; sets `ban_expires`. Omit for a permanent ban. |

**Response `200`**:

```json
{ "success": true }
```

#### `POST /admin/unban-user`

Lifts a ban, clearing the reason and expiry. **Auth:** admin required.

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `user_id` | string | yes | Target user. |

**Response `200`**:

```json
{ "success": true }
```

#### `GET /admin/list-users`

Lists all users with their role and ban status. **Auth:** admin required.

**Response `200`**:

```json
{
  "users": [
    { "id": "usr_1", "email": "boss@example.com", "name": null, "role": "user", "banned": false }
  ]
}
```

(Each entry is the public user object plus `role` and `banned`; users with no `admin_meta` default to `role: "user"`, `banned: false`.)

#### `POST /admin/create-user`

Creates a user with a credential (email + password) account. **Auth:** admin required.

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `email` | string | yes | New user's email; lowercased. |
| `password` | string | yes | Plaintext password; hashed before storage. |
| `name` | string | no | Display name. |
| `role` | string | no | Admin role to assign (applied only if a string). |

**Response `200`**:

```json
{ "user": { "id": "usr_2", "email": "made@example.com", "name": null } }
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `422` | `user_already_exists` | A user with this email already exists. |

#### `POST /admin/remove-user`

Deletes a user along with their sessions, accounts, and admin metadata. **Auth:** admin required.

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `user_id` | string | yes | Target user. |

**Response `200`**:

```json
{ "success": true }
```

#### `POST /admin/revoke-user-sessions`

Revokes all of a user's sessions and returns how many were revoked. **Auth:** admin required.

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `user_id` | string | yes | Target user. |

**Response `200`**:

```json
{ "revoked": 2 }
```

## Notes

- **Admin resolution.** `_require_admin` treats a caller as admin if their email is in `admin_emails`, their id is in `admin_user_ids`, or their `admin_meta.role == "admin"`. Bootstrap admins do not need an `admin_meta` row.
- **Ban gate via sign-in after-hooks.** The plugin registers an after-hook on `/sign-in/email`, `/sign-in/email-otp`, `/2fa/totp/challenge`, and `/oauth/callback`. When a sign-in result carries a `user`, the hook checks the ban state; if banned it revokes any just-issued session, clears the session cookie, and replaces the response with `403 banned` (`{"error": {"code": "banned", "message": "This account is banned."}}`).
- **Ban expiry.** A ban is active only while `ban_expires` is `None` (permanent) or still in the future. An expired ban is ignored, so a subsequently expired ban lets the user sign in again.
- **Ban revokes sessions.** `ban-user` calls `sessions.revoke_all(user_id)` immediately, in addition to the sign-in gate.
- **Metadata upsert.** Role and ban fields live in the `admin_meta` table, upserted per user with an `updated_at` timestamp.
