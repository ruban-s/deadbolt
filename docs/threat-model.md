# deadbolt — Threat Model

A STRIDE view of the authentication surface. It records the assets, the trust boundaries, and the
mitigations the design commits to. Update it whenever a feature changes the attack surface.

## Assets

Credentials (password hashes), session tokens, the signing/encryption master secret, user PII
(email), and verification tokens (email verify, password reset).

## Trust boundaries

The network (client ↔ server), the cookie (attacker-influenceable, client-held), the database
(separate process, may be breached independently), and the host process environment (holds the master
secret).

## STRIDE

### Spoofing

- **Session forgery / fixation.** Opaque 256-bit tokens; only `SHA-256(token)` stored; the session id
  rotates on every privilege change and the prior row is deleted. Signed cookies let tampered values
  be rejected before a DB lookup.
- **Credential stuffing / brute force.** Argon2id is deliberately slow; sign-in, sign-up, and reset
  endpoints are rate-limited (built-in, per-path). A decoy Argon2 verify on the credential-miss path
  makes unknown and known emails cost the same — no timing-based user enumeration, and error messages
  are identical.

### Tampering

- **Cookie tampering.** Cookies are HMAC-signed (`itsdangerous`); optional cookie-cache modes are
  signed (JWT) or encrypted+authenticated (JWE/AEAD). Any tamper fails verification.
- **Request smuggling of parsed bodies.** The core reads the raw body itself; adapters must mount
  before body-parsing middleware.

### Repudiation

- Session rows carry `ip_address`, `user_agent`, and timestamps. Every request emits a redacting
  audit line on the `deadbolt.audit` logger (path, method, status, client IP — never secrets), which
  applications route to their own sinks.

### Information disclosure

- **Password/token leakage.** Passwords are never stored plaintext; session, reset, and magic-link
  tokens are all stored as SHA-256 hashes, so a database read yields no usable tokens. The library
  emits no logs today, so no secrets are logged; a redacting logger is planned.
- **Cookie readability.** Signed cookies are readable by design, so nothing sensitive goes in a merely
  signed payload; the encrypted cookie-cache mode (planned) uses AEAD with context-binding AAD.
- **Timing oracles.** Session tokens are looked up by hash; sign-in runs a decoy Argon2 verify on the
  miss path; MAC comparison uses `itsdangerous`' constant-time verify.

### Denial of service

- **Argon2 memory pressure.** Hashing runs off the event loop and behind per-path rate limits;
  parameters are tuned to a target latency, not maxed blindly.
- **Oversized payloads.** A request body-size limit (`max_body_bytes`) rejects large bodies; the ASGI
  server should also cap body size upstream.
- **Decompression / parser bombs.** JOSE handling avoids known-abandoned libraries (no `python-jose`);
  parsers are fuzzed (Atheris) before 1.0.

### Elevation of privilege

- **Mass-assignment.** Sensitive fields (`role`, org ids) are `input=False` and cannot be set at
  sign-up.
- **Algorithm confusion (JWT).** Every verify passes an explicit `algorithms=` allow-list; key types
  are never inferred from the token header.

## Key management

One high-entropy `MASTER_SECRET` from the environment; per-purpose subkeys via HKDF with distinct
`info` labels give domain separation and single-secret rotation. A missing or weak secret must fail
fast at startup.

## Out of scope

Transport security (assume TLS terminates in front), host/OS compromise, and vulnerabilities in the
downstream application's own code.
