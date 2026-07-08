# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html), and entries are generated
from [Conventional Commits](https://www.conventionalcommits.org/).

## [Unreleased]

### Documentation
- Use absolute links in README so they render on PyPI
- Record username and phone plugins
- Rewrite README for the 0.1.0 release with badges and plugin list

### Features
- Add phone/SMS OTP plugin and SmsSender protocol
- Add username sign-in plugin

### Refactor
- Share the timing-safe decoy hash via the service layer

## [0.1.0] - 2026-07-08

### Bug Fixes
- Make date-range Where filtering portable across adapters
- Mark example placeholder secret
- Hash reset and magic-link tokens at rest

### Build & Packaging
- Update lockfile for aiosqlite
- Add uv lockfile
- Add pre-commit hooks and renovate config
- Configure packaging with uv, hatchling, and extras

### Continuous Integration
- Fetch full history in release build for version detection
- Add lint, type, test, and pypi release workflows

### Documentation
- Record passkeys plugin
- Record JWT plugin
- Record email-otp, api-keys, and admin plugins
- Record account/session/verification endpoints
- Record configurable roles and teams
- Record expanded organizations plugin
- Record organizations plugin in changelog
- Record schema-generation CLI in changelog
- Record TOTP 2FA and field encryption in changelog
- Record hook system in changelog
- Record social OAuth plugin in changelog
- Record cleanup and audit logging
- Update changelog and threat model for hardening pass
- Add runnable FastAPI example app
- Record plugin system and magic-link in changelog
- Record flask wsgi mount in changelog
- Record fastapi and sqlalchemy adapters in changelog
- Record phase 1 core in changelog
- Add ADRs for decision records and agnostic core
- Add STRIDE threat model
- Add architecture specification
- Set language on contributing code block
- Add security policy and contributor guidelines

### Features
- Add passkeys (WebAuthn) plugin with registration and authentication
- Add JWT bearer-token plugin for stateless API access
- Add admin plugin (roles, bans with sign-in gate, user management)
- Add API keys plugin (create/list/revoke/verify)
- Add passwordless email-OTP sign-in plugin
- Add TOTP backup-code regeneration
- Add OAuth link-social to link a provider to the current user
- Add email verification, user/session/account management endpoints
- Add session-management helpers and shared require_session
- Add configurable access control and teams to organizations plugin
- Expand organizations plugin with access control, invitation lifecycle, and active org
- Add organizations plugin with role-based access control
- Add schema-generation CLI (deadbolt generate)
- Add TOTP two-factor plugin with sign-in challenge and backup codes
- Add AEAD field encryption helper
- Run before/after hooks in the router, mergeable from plugins
- Add before/after hook types
- Add social OAuth plugin with Google and GitHub providers
- Add provider-account linking service helpers
- Let endpoints set response headers and mounts propagate them
- Emit redacting audit log per request
- Add cleanup_expired for sessions and verifications
- Enforce request body-size limit
- Add absolute session lifetime cap and freshness helper
- Add rate limiting with per-path rules and pluggable storage
- Enforce trusted-origin CSRF check on state-changing requests
- Add magic-link passwordless plugin
- Add plugin system and merge plugin endpoints into Auth
- Add Flask WSGI mount integration
- Add sync bridge for serving WSGI from the async core
- Implement SQLAlchemy Core async adapter
- Add FastAPI/Starlette mount integration
- Add request router and direct-call api, wire Auth
- Add email/password endpoints and account service
- Implement session manager with cookies and sliding refresh
- Implement argon2 hashing, tokens, key derivation, cookie signing
- Implement in-memory database adapter
- Define core user, session, account, verification models
- Add Auth engine skeleton and alias-first public API
- Add database adapter protocols and query types
- Add error types and normalized http contract

### Refactor
- Extract shared build_metadata from SQLAlchemy adapter
- Use a comparator table in the memory adapter


