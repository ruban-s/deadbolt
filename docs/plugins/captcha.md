# CAPTCHA

Require a CAPTCHA solution on sensitive endpoints — sign-in and sign-up by default — verified
server-side with Cloudflare Turnstile, hCaptcha, or Google reCAPTCHA.

## Install

The default verifier uses `httpx`:

`pip install "deadbolt[oauth]"`  *(any extra that brings `httpx`)*

## Setup

```python
import deadbolt as db
from deadbolt.plugins.captcha import captcha

auth = db.Auth(
    adapter=db.MemoryAdapter(),
    secret="a-32-byte-or-longer-secret......",
    email_and_password=db.EmailPassword(enabled=True),
    plugins=[captcha(provider="turnstile", secret_key="0x...")],
)
```

The client obtains a solution token from the provider widget and sends it in the `x-captcha-response`
header on the guarded requests.

## Configuration

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `provider` | string | `"turnstile"` | One of `turnstile`, `hcaptcha`, `recaptcha`. Selects the verify endpoint. |
| `secret_key` | string | `""` | The provider's server-side secret. |
| `header` | string | `"x-captcha-response"` | Request header carrying the client's solution token. |
| `paths` | sequence | `("/sign-in/email", "/sign-up/email")` | Endpoints to guard. |
| `verify` | async callable | provider HTTP | Overrides verification with `async (token: str) -> bool`. |

## How it works

A before-hook runs on each guarded path. It reads the solution token from the configured header and
verifies it with the provider's siteverify endpoint (sending your `secret_key`). A missing token or a
verification failure rejects the request with `400 captcha_failed` before the handler runs.

## Errors

| Status | Code | When |
| --- | --- | --- |
| `400` | `captcha_failed` | No token was supplied, or the provider rejected it. |

## Notes

- **Provider-agnostic.** Any provider with a token-verify endpoint works; supply a custom `verify`
  for one that is not built in, or to add caching.
- **Fail-closed.** If verification cannot complete, the request is rejected — a CAPTCHA that cannot be
  checked is treated as unsolved.
