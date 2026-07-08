# Getting started

## Install

```bash
pip install deadbolt                          # core (email/password + sessions)
pip install "deadbolt[fastapi,sqlalchemy]"    # + a framework mount + a database adapter
pip install "deadbolt[all]"                   # everything, including every plugin's deps
```

Each plugin that needs a heavy dependency ships behind its own [extra](#extras); `import deadbolt`
never pulls in a web framework or database driver.

## Your first `Auth`

Everything hangs off a single `Auth` object, reachable via the `deadbolt` alias:

```python
import deadbolt as db

auth = db.Auth(
    adapter=db.MemoryAdapter(),                          # swap for db.SQLAlchemyAdapter(engine)
    secret="a-32-byte-or-longer-random-secret-please",  # keep this out of source control
    email_and_password=db.EmailPassword(enabled=True),
)
```

## Two ways to call it

**Over HTTP** — mount it on your framework and it serves routes under a prefix:

```python
from deadbolt.integrations.fastapi import mount
mount(app, auth, prefix="/api/auth")
```

```bash
curl -c cookies.txt -b cookies.txt -X POST http://127.0.0.1:8000/api/auth/sign-up/email \
     -H 'Content-Type: application/json' -d '{"email":"a@b.com","password":"hunter2pw"}'
curl -c cookies.txt -b cookies.txt http://127.0.0.1:8000/api/auth/get-session
```

**Without HTTP** — every endpoint is also a plain callable for server-side code, jobs, and tests:

```python
result = await auth.api.sign_in_email(email="a@b.com", password="hunter2pw", as_response=True)
# result.data -> the user; result.cookies -> the session cookie to set
```

## Adding features

Features are **plugins** passed to `Auth(plugins=[...])`:

```python
from deadbolt.plugins.totp import totp
from deadbolt.plugins.oauth import social, google

auth = db.Auth(
    adapter=db.MemoryAdapter(),
    secret=SECRET,
    email_and_password=db.EmailPassword(enabled=True),
    plugins=[
        totp(),
        social(providers=[google(client_id=..., client_secret=..., redirect_uri=...)]),
    ],
)
```

Each plugin adds its own endpoints and database tables. See the [Plugins](plugins/username.md)
section for the full API of each.

## Extras

| Extra | Enables |
| --- | --- |
| `fastapi`, `starlette`, `litestar`, `flask`, `django` | Framework mount adapters |
| `sqlalchemy` | The SQLAlchemy Core database adapter |
| `oauth` | Social OAuth plugin (`httpx`) |
| `passkeys` | Passkeys/WebAuthn plugin (`webauthn`) |
| `totp` | TOTP 2FA plugin (`pyotp`) |
| `jwt` | JWT plugin (`pyjwt`) |
| `redis` | Redis-backed stores |
| `email` | `aiosmtplib` for the default email sender |

## Note on `secret`

`Auth` rejects a secret shorter than 32 bytes. Generate one with
`python -c "import secrets; print(secrets.token_urlsafe(32))"` and load it from the environment.
All signing/encryption keys are derived from it via HKDF, so keep it secret and rotate deliberately.
