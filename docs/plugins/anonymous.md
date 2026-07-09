# Anonymous

Give a visitor a real session with no credentials, so your app can persist state — carts, drafts,
preferences — against a stable user id before they ever register. When the guest later signs up,
your application decides how to migrate their data.

## Install

Ships with the core; there is no extra to install.

## Setup

```python
import deadbolt as db
from deadbolt.plugins.anonymous import anonymous

auth = db.Auth(
    adapter=db.MemoryAdapter(),
    secret="a-32-byte-or-longer-secret......",
    email_and_password=db.EmailPassword(enabled=True),
    plugins=[anonymous()],
)
```

Run the schema generator (or your migration) so the `anonymous` table exists.

## Configuration

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `email_domain` | string | `"anonymous.deadbolt"` | Domain used to synthesize each guest's unique placeholder email (`anon-<id>@<domain>`). |

## API

#### `POST /sign-in/anonymous`

Creates a guest user and returns a session. **Auth:** public. **Request:** no body.

**Response `200`**: `{ "user": { ... }, "is_anonymous": true }`, plus the session cookie.

## Notes

- **Real, working session.** The guest session behaves like any other — `get-session` returns the
  user, and every plugin sees a normal signed-in user.
- **Marked as a guest.** Each anonymous user has a row in the `anonymous` table, so you can detect
  guests (`SELECT ... FROM anonymous WHERE user_id = ?`) and treat them differently.
- **Linking is yours to define.** deadbolt does not auto-merge a guest into a real account, because
  what "migrate their data" means is application-specific. On sign-up, look up the current anonymous
  user, move whatever rows you own to the new user id, then delete the guest.
- **Housekeeping.** Guests accumulate; periodically prune stale `anonymous` users the same way you
  prune expired sessions.
