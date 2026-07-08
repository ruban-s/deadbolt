<h1 align="center">🔒 deadbolt</h1>

<p align="center">
  <em>A framework-agnostic, batteries-included authentication library for Python.</em><br>
  Own your auth. Mount it on any framework. No hosted service, no lock-in.
</p>

---

> **Status: pre-alpha (Phase 0 — architecture & scaffold).** The public API below is the
> *target* shape; implementation lands in Phase 1. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
> and the [design plan](../Plans).

`deadbolt` is what [Better Auth](https://better-auth.com) is for the TypeScript world, rebuilt
idiomatically for Python: a self-hosted auth engine with a database-adapter abstraction, signed
cookie-based sessions, and a plugin system — that mounts onto **any** Python web framework.

## Why

- **Framework-agnostic.** One async-first core speaks a normalized request/response contract; a
  ~30-line adapter mounts it on FastAPI, Starlette, Litestar, Flask, Django, Quart, Sanic, aiohttp…
- **Bring your own database.** A uniform adapter interface (built on SQLAlchemy 2.0 Core) covers
  Postgres/MySQL/SQLite; Django ORM and in-memory adapters ship too.
- **Secure by default.** Argon2id hashing, opaque DB-backed sessions, signed `__Host-` cookies,
  session rotation on privilege change — the OWASP session model, not a pile of footguns.
- **Alias-first API.** Everything hangs off one object: `import deadbolt as db` → `db.Auth(...)`.

## Install

```bash
pip install deadbolt              # core
pip install "deadbolt[fastapi,sqlalchemy]"   # + integration + adapter
```

## Quickstart (target API)

```python
import deadbolt as db
from deadbolt.integrations.fastapi import mount

auth = db.Auth(
    adapter=db.SQLAlchemyAdapter(engine),
    secret=SECRET,                       # 32+ random bytes
    email_and_password=db.EmailPassword(enabled=True),
)

# Mount on any framework — this is the whole integration:
mount(app, auth, prefix="/api/auth")

# ...or call endpoints directly, no HTTP:
session = await auth.api.sign_in_email(email="a@b.com", password="…")
```

## Scope (v0.1 — Core only)

Email/password sign-up · sign-in · sign-out · get-session · change-password · password reset.
Social OAuth, 2FA, passkeys, organizations, and the CLI are plugins on the roadmap.

## Development

```bash
uv sync --all-extras --group dev
uv run pre-commit install
uv run pytest
uv run ruff check . && uv run ruff format --check . && uv run mypy
```

## Security

Please report vulnerabilities via GitHub private advisories — see [`SECURITY.md`](SECURITY.md).
Never open a public issue for a security bug.

## License

[MIT](LICENSE) © the deadbolt contributors.
