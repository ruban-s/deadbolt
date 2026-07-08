# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Project scaffold: packaging, dev tooling, CI, and governance.
- Architecture specification, STRIDE threat model, and initial ADRs.
- Package skeleton with the alias-first public API, the `AuthRequest`/`AuthResponse`
  contract, database adapter Protocols, and configuration types.
- Core engine: in-memory database adapter, Argon2id password hashing, opaque
  DB-backed sessions with signed cookies and sliding refresh, and HKDF key derivation.
- Email/password endpoints (sign-up, sign-in, sign-out, get-session, change-password,
  password reset) served over one `handle()` and callable directly via `auth.api`.
- FastAPI/Starlette mount adapter (`deadbolt.integrations.fastapi.mount`).
- SQLAlchemy 2.0 Core async adapter over Postgres/MySQL/SQLite, with dates stored as
  ISO-8601 for identical timezone-aware round-trips across dialects.
