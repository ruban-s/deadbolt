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
- Flask (WSGI) mount adapter, with a sync bridge (`Auth.handle_sync`) that serves
  synchronous frameworks from the single async core via one background event loop.
- Plugin system (`Plugin`): plugins contribute endpoints and schema, merged into the
  router at construction. First plugin: `magic_link` passwordless sign-in/sign-up.

### Security

- Reset and magic-link tokens are hashed (SHA-256) at rest, like session tokens.
- Constant-time sign-in: a decoy Argon2 verify runs on the credential-miss path, so
  unknown and known emails cost the same (no timing/enumeration side-channel).
- Trusted-origin CSRF check on state-changing requests (`trusted_origins`, wildcards).
- Rate limiting with global window/max plus per-path rules and pluggable storage
  (`RateLimit`, `RateLimitRule`, `RateLimitStore`).
- Absolute session lifetime cap beyond sliding refresh; `SessionManager.is_fresh` for
  gating sensitive actions; request body-size limit (`max_body_bytes`).
- `Auth.cleanup_expired()` to purge expired sessions and verifications (run periodically).
- Redacting per-request audit logging on the `deadbolt.audit` logger.
- Portable date-range `Where` filtering across the memory and SQLAlchemy adapters.
- SQLAlchemy 2.0 Core async adapter over Postgres/MySQL/SQLite, with dates stored as
  ISO-8601 for identical timezone-aware round-trips across dialects.
