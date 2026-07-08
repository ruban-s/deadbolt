# Contributing to deadbolt

Thanks for helping build an auth library people can trust.

## Development setup

```bash
uv sync --all-extras --group dev
uv run pre-commit install
```

## Before you push

```bash
uv run ruff check . && uv run ruff format --check .
uv run mypy
uv run pytest
```

`pre-commit` runs the fast checks automatically on commit; CI runs the full matrix.

## Commit messages

We use [Conventional Commits](https://www.conventionalcommits.org/) — releases and the changelog are
generated from them.

```
feat(session): add sliding-window refresh
fix(cookie): reject tampered signatures before DB lookup
```

Any change to token, cookie, or session semantics must be flagged in the body and is treated as at
least a minor release.

## Ground rules for a security library

- New behaviour needs tests. Crypto, token, session, and password code must stay at 100% coverage.
- Never weaken a default (hashing params, cookie flags, session rotation) without an ADR in
  `docs/adr/` explaining why.
- Use `secrets` / `hmac.compare_digest` for anything secret-adjacent — never `random` or `==`.
- Keep the core free of framework and database imports; those live behind adapters.

## Architecture

Read [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) first. Significant design decisions get an ADR.
