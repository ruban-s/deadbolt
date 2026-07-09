# Have I Been Pwned

Reject passwords that appear in known data breaches, checked against
[Have I Been Pwned](https://haveibeenpwned.com/)'s Pwned Passwords range API. The check runs on
sign-up and on every password change.

## Install

The default check uses `httpx`:

`pip install "deadbolt[oauth]"`  *(any extra that brings `httpx`)*

## Setup

```python
import deadbolt as db
from deadbolt.plugins.haveibeenpwned import haveibeenpwned

auth = db.Auth(
    adapter=db.MemoryAdapter(),
    secret="a-32-byte-or-longer-secret......",
    email_and_password=db.EmailPassword(enabled=True),
    plugins=[haveibeenpwned()],
)
```

## Configuration

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `fetch` | async callable | HTTP to HIBP | Overrides the range lookup: `async (prefix: str) -> str`, returning the raw range response. Use it to inject a client, cache, or a stub in tests. |

## How it works

The plugin registers a before-hook on `/sign-up/email`, `/change-password`, and `/reset-password`.
For the submitted password it:

1. Computes the SHA-1 digest **locally**.
2. Sends only the first **5 hex characters** to `api.pwnedpasswords.com/range/{prefix}` (with
   `Add-Padding: true`). The full hash never leaves the process — this is the k-anonymity model.
3. Scans the returned suffixes for a match with a non-zero breach count. A hit rejects the request
   with `400 pwned_password`; padding rows (count `0`) are ignored.

## Errors

| Status | Code | When |
| --- | --- | --- |
| `400` | `pwned_password` | The password was found in the breach corpus. |

## Notes

- **Privacy-preserving.** Only a 5-character prefix is sent; HIBP never sees the password or its full
  hash.
- **Fail behaviour.** If HIBP is unreachable the default `fetch` raises, which surfaces as a request
  error rather than silently allowing a breached password. Supply a custom `fetch` if you prefer to
  fail open (return an empty string on error).
- **Defence in depth.** This complements, and does not replace, a strong password policy and
  Argon2id hashing.
