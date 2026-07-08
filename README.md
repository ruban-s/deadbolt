# 🔒 deadbolt

A framework-agnostic, batteries-included authentication library for Python. Own your auth, mount it on any framework — no hosted service, no lock-in.

[![PyPI](https://img.shields.io/pypi/v/deadbolt.svg)](https://pypi.org/project/deadbolt/)
[![Python](https://img.shields.io/pypi/pyversions/deadbolt.svg)](https://pypi.org/project/deadbolt/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](https://opensource.org/license/mit)
![Typed](https://img.shields.io/badge/typed-mypy--strict-blue.svg)

`deadbolt` is what [Better Auth](https://better-auth.com) is for the TypeScript world, rebuilt
idiomatically for Python: a self-hosted auth engine with a database-adapter abstraction, signed
cookie-based sessions, and a plugin system — mountable onto **any** Python web framework.

## Why

- **Framework-agnostic.** One async-first core speaks a normalized request/response contract; a
  ~30-line adapter mounts it on FastAPI, Starlette, Flask, and more. WSGI frameworks are served from
  the async core through a background-loop sync bridge.
- **Bring your own database.** A uniform adapter interface (built on SQLAlchemy 2.0 Core) covers
  Postgres/MySQL/SQLite; an in-memory adapter ships for tests and local dev.
- **Secure by default.** Argon2id hashing, opaque DB-backed sessions stored hashed, signed `__Host-`
  cookies, session rotation, rate limiting, origin-based CSRF checks, and timing-safe sign-in.
- **Alias-first API.** Everything hangs off one object: `import deadbolt as db` → `db.Auth(...)`.

## Install

```bash
pip install deadbolt                          # core (email/password + sessions)
pip install "deadbolt[fastapi,sqlalchemy]"    # + a framework mount + a database adapter
pip install "deadbolt[all]"                   # everything, including every plugin's deps
```

## Quickstart

```python
import deadbolt as db
from deadbolt.integrations.fastapi import mount

auth = db.Auth(
    adapter=db.MemoryAdapter(),                 # or db.SQLAlchemyAdapter(engine)
    secret=SECRET,                              # 32+ random bytes
    email_and_password=db.EmailPassword(enabled=True),
)

# Mount on any framework — this is the whole integration:
mount(app, auth, prefix="/api/auth")

# ...or call endpoints directly, no HTTP:
result = await auth.api.sign_in_email(email="a@b.com", password="…", as_response=True)
```

Add features by dropping in plugins:

```python
from deadbolt.plugins.oauth import social, google
from deadbolt.plugins.totp import totp
from deadbolt.plugins.passkeys import passkeys

auth = db.Auth(
    adapter=db.MemoryAdapter(),
    secret=SECRET,
    email_and_password=db.EmailPassword(enabled=True),
    plugins=[
        social(providers=[google(client_id=..., client_secret=..., redirect_uri=...)]),
        totp(),
        passkeys(rp_id="example.com", rp_name="Example", origin="https://example.com"),
    ],
)
```

## Plugins

| Plugin | Import | What it adds |
|---|---|---|
| Username | `deadbolt.plugins.username` | Sign in with a username |
| Magic link | `deadbolt.plugins.magic_link` | Passwordless email links |
| Email OTP | `deadbolt.plugins.email_otp` | Passwordless email codes |
| Phone OTP | `deadbolt.plugins.phone` | Passwordless SMS codes |
| Social OAuth | `deadbolt.plugins.oauth` | Google, GitHub, or any OAuth2/OIDC provider |
| Passkeys | `deadbolt.plugins.passkeys` | WebAuthn registration + authentication |
| TOTP 2FA | `deadbolt.plugins.totp` | Authenticator apps + backup codes |
| Organizations | `deadbolt.plugins.organization` | Multi-tenancy, RBAC, invitations, teams |
| API keys | `deadbolt.plugins.api_keys` | Machine-to-machine keys |
| Admin | `deadbolt.plugins.admin` | Roles, bans, user management |
| JWT | `deadbolt.plugins.jwt` | Stateless bearer tokens |

## CLI

Generate SQL DDL for your full schema (core plus every enabled plugin) from your `Auth` config:

```bash
deadbolt generate --config myapp.auth:auth --dialect postgresql
```

## Development

```bash
uv sync --all-extras --group dev
uv run pre-commit install
uv run pytest
uv run ruff check . && uv run ruff format --check . && uv run mypy
```

## Security

Please report vulnerabilities via GitHub private advisories — see `SECURITY.md` in the repository.
Never open a public issue for a security bug. The architecture spec and STRIDE threat model live in
the repository's `docs/` directory.

## License

MIT © the deadbolt contributors.
