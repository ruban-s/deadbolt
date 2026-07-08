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
- Social OAuth plugin (`deadbolt.plugins.oauth.social`) with Google and GitHub providers:
  authorization-code flow with PKCE, hashed/single-use state, account linking, and optional
  post-login redirect. Endpoints double as callables and set response headers.
- Hook system (`Hook`, `Hooks`, `HookContext`): path-scoped before/after request hooks that can
  block requests or rewrite results, registered on `Auth` or contributed by plugins.
- AEAD field encryption (`Encryptor`, AES-256-GCM over an HKDF-derived subkey).
- TOTP two-factor plugin (`deadbolt.plugins.totp.totp`): encrypted secret at rest, enroll/enable/
  disable, hashed single-use backup codes, and a sign-in after-hook that turns login into a 2FA
  challenge for enrolled users.
- `deadbolt` CLI: `deadbolt generate --config module:attr --dialect {postgresql,mysql,sqlite}`
  emits SQL DDL for the full schema (core plus plugin tables) derived from your `Auth` config.
- Organizations plugin (`deadbolt.plugins.organization.organization`): organization/member/
  invitation tables, create/list/members/invite/accept/remove/update-role endpoints, and an
  owner > admin > member role hierarchy with permission checks.
- SQLAlchemy 2.0 Core async adapter over Postgres/MySQL/SQLite, with dates stored as
  ISO-8601 for identical timezone-aware round-trips across dialects.
