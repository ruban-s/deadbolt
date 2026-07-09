# Multi-session

Let one browser hold several signed-in accounts at once and switch between them — the pattern behind
"Add another account" in Google or Slack. Each successful sign-in is remembered in a signed
`multi_session` cookie next to the primary session cookie.

## Install

Ships with the core; there is no extra to install.

## Setup

```python
import deadbolt as db
from deadbolt.plugins.multi_session import multi_session

auth = db.Auth(
    adapter=db.MemoryAdapter(),
    secret="a-32-byte-or-longer-secret......",
    email_and_password=db.EmailPassword(enabled=True),
    plugins=[multi_session(max_sessions=5)],
)
```

## Configuration

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `max_sessions` | integer | `5` | Maximum accounts tracked per browser; the oldest is dropped past this. |

## API

Every account is identified by its `session_id` (as returned by `list`).

#### `GET /multi-session/list`

Returns each still-valid account held by the browser.

**Response `200`**:

```json
{ "sessions": [
  { "session_id": "ses_1", "user": { ... }, "active": false },
  { "session_id": "ses_2", "user": { ... }, "active": true }
] }
```

#### `POST /multi-session/set-active`

Makes one of the held sessions the primary one (rewrites the session cookie).

**Request:** `{ "session_id": "ses_1" }` · **Response `200`:** `{ "active": "ses_1" }` + session cookie.

#### `POST /multi-session/revoke`

Revokes one held session and removes it from the browser's set.

**Request:** `{ "session_id": "ses_1" }` · **Response `200`:** `{ "success": true }` + updated `multi_session` cookie.

| Status | Code | When |
| --- | --- | --- |
| `404` | `session_not_found` | The `session_id` is not among the browser's held sessions. |

## How it works

- An after-hook appends every newly established session (from *any* sign-in method) to a
  `multi_session` cookie, signed with an HKDF-derived key so it cannot be tampered with.
- `list` validates each held token against the database and silently drops any that have expired or
  been revoked, so the response only ever shows live accounts.
- `set-active` re-points the primary session cookie at a held session; the switched-to session is
  itself a normal, independently revocable session.
