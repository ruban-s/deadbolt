# deadbolt

A **framework-agnostic, batteries-included authentication library for Python**. Own your auth,
mount it on any framework — no hosted service, no lock-in.

`deadbolt` is what [Better Auth](https://better-auth.com) is for the TypeScript world, rebuilt
idiomatically for Python: a self-hosted auth engine with a database-adapter abstraction, signed
cookie-based sessions, and a plugin system — mountable onto **any** Python web framework.

```python
import deadbolt as db
from deadbolt.integrations.fastapi import mount

auth = db.Auth(
    adapter=db.MemoryAdapter(),                 # or db.SQLAlchemyAdapter(engine)
    secret=SECRET,                              # 32+ random bytes
    email_and_password=db.EmailPassword(enabled=True),
)

mount(app, auth, prefix="/api/auth")            # the whole integration
```

## Highlights

- **Framework-agnostic.** One async-first core speaks a normalized request/response contract; a thin
  adapter mounts it on FastAPI/Starlette (native) or Flask/WSGI (via a background-loop sync bridge).
- **Bring your own database.** A uniform adapter interface built on SQLAlchemy 2.0 Core covers
  Postgres/MySQL/SQLite; an in-memory adapter ships for tests and local dev.
- **Secure by default.** Argon2id hashing, opaque DB-backed sessions stored hashed, signed `__Host-`
  cookies, session rotation, rate limiting, origin-based CSRF checks, and timing-safe sign-in.
- **Plugins for everything.** Passwordless (magic link, email/phone OTP, passkeys), social OAuth,
  TOTP 2FA, organizations with RBAC and teams, API keys, admin, JWT, and username sign-in.

## Where to go next

- [Getting started](getting-started.md) — install and your first authenticated request.
- [Core authentication](core-auth.md) — the built-in email/password and session API.
- [Concepts](concepts/architecture.md) — how the core, adapters, plugins, and hooks fit together.
- [Plugins](plugins/username.md) — add features by dropping them into `Auth(plugins=[...])`.
