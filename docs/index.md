---
hide:
  - navigation
  - toc
---

<div class="db-hero" markdown>

:material-shield-lock:{ .db-hero__icon }

# deadbolt

**A framework-agnostic, batteries-included authentication library for Python.**
Own your auth, mount it on any framework — no hosted service, no lock-in.

[Get started :material-arrow-right:](getting-started.md){ .md-button .md-button--primary }
[Star on GitHub :fontawesome-brands-github:](https://github.com/ruban-s/deadbolt){ .md-button }

</div>

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

`deadbolt` is what [Better Auth](https://better-auth.com) is for the TypeScript world, rebuilt
idiomatically for Python: a self-hosted auth engine with a database-adapter abstraction, signed
cookie-based sessions, and a plugin system — mountable onto **any** Python web framework.

## Why deadbolt

<div class="grid cards" markdown>

-   :material-swap-horizontal:{ .lg } **Framework-agnostic**

    ---

    One async-first core speaks a normalized request/response contract; a thin adapter mounts it on
    FastAPI/Starlette (native) or Flask/WSGI (via a background-loop sync bridge).

-   :material-database:{ .lg } **Bring your own database**

    ---

    A uniform adapter interface built on SQLAlchemy 2.0 Core covers Postgres/MySQL/SQLite; an
    in-memory adapter ships for tests and local dev.

-   :material-shield-check:{ .lg } **Secure by default**

    ---

    Argon2id hashing, opaque DB-backed sessions stored hashed, signed `__Host-` cookies, session
    rotation, rate limiting, origin CSRF checks, and timing-safe sign-in.

-   :material-puzzle:{ .lg } **Plugins for everything**

    ---

    Passwordless (magic link, email/phone OTP, passkeys), social OAuth, TOTP 2FA, organizations with
    RBAC and teams, API keys, admin, JWT, and username sign-in.

</div>

## Start here

<div class="grid cards" markdown>

-   :material-rocket-launch:{ .lg } **[Getting started](getting-started.md)**

    ---

    Install deadbolt and make your first authenticated request in minutes.

-   :material-key-variant:{ .lg } **[Core authentication](core-auth.md)**

    ---

    The built-in email/password and session API, endpoint by endpoint.

-   :material-sitemap:{ .lg } **[Concepts](concepts/architecture.md)**

    ---

    How the core, adapters, plugins, and hooks fit together.

-   :material-shield-lock:{ .lg } **[Security](security.md)**

    ---

    The full security model — hashing, tokens, cookies, CSRF, and rate limiting.

</div>
