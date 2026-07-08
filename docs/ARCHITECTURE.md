# deadbolt — Architecture

This is the design spec for `deadbolt`, a framework-agnostic authentication library for Python. It
expands the [design plan](../../Plans) into the concrete contracts the implementation must satisfy.
Nothing here is framework- or database-specific unless a section says so.

## 1. Goals and non-goals

**Goals.** Own authentication end to end (users, sessions, credentials) behind a neutral contract;
mount on any Python web framework via a thin adapter; bring-your-own database via a uniform adapter;
secure defaults (Argon2id, signed opaque sessions, OWASP cookie model); one consumable API surface
through the `deadbolt` package alias.

**Non-goals (v0.1).** Hosted service, social OAuth, 2FA, passkeys, organizations, SSO, admin UI, the
schema-generation CLI, and a typed client SDK. These are later phases.

## 2. The framework-agnostic spine

Python has no universal request/response object, so `deadbolt` mints its own. The core is a single
async function:

```python
async def handle(request: AuthRequest) -> AuthResponse: ...
```

Every web framework gets a small adapter that (a) translates its native request into `AuthRequest`,
(b) awaits `handle` (or bridges via a portal for WSGI), and (c) writes `AuthResponse` back using the
framework's **native cookie API**. The same endpoints are also plain callables, so server-side code
can invoke them without HTTP.

```text
 native request ──▶ AuthRequest ──▶ handle() ──▶ AuthResponse ──▶ native response
                                       │
                          endpoint registry (async callables)
                                       │
                    DB adapter · SessionStore · Hasher · EmailSender
```

### Load-bearing decisions

1. One async-first core; no parallel sync core.
2. `AuthRequest` / `AuthResponse` are the only cross-boundary contract.
3. Per-framework adapters are ~30 lines and hold no logic.
4. WSGI frameworks bridge through one long-lived `anyio.BlockingPortal`, never per-call
   `async_to_sync`. Caller context is checked with `sniffio`.
5. Persistence is pluggable; the core never owns the SQLAlchemy event-loop/greenlet problem.
6. Endpoints double as callables; direct calls accept `as_response` / `return_headers`.
7. Cookies travel as structured data and are applied through each framework's own API, because
   frameworks lock response headers at different moments.

Two failure modes are designed against from day one: the request body must reach the core
**unparsed** (adapters must not consume the stream first), and cookies — not routing — are the hard
part of every integration.

## 3. HTTP contract

```python
@dataclass(frozen=True)
class AuthRequest:
    method: str
    path: str                       # path within the mount, e.g. "/sign-in/email"
    headers: MultiDict[str, str]
    query: MultiDict[str, str]
    cookies: Mapping[str, str]
    body: bytes | None = None       # raw; adapters MUST NOT pre-parse
    stream: AsyncIterator[bytes] | None = None
    client_ip: str | None = None
    scheme: str = "https"
    base_url: str | None = None

@dataclass
class Cookie:
    name: str
    value: str
    max_age: int | None = None
    path: str = "/"
    domain: str | None = None
    secure: bool = True
    http_only: bool = True
    same_site: str = "Lax"

@dataclass
class AuthResponse:
    status: int = 200
    headers: MultiDict[str, str] = field(default_factory=MultiDict)
    body: bytes = b""
    cookies: list[Cookie] = field(default_factory=list)
    media_type: str = "application/json"
```

An adapter implements exactly one pair of functions: `to_auth_request(native) -> AuthRequest` and
`from_auth_response(AuthResponse, ...) -> native`, the latter applying each `Cookie` through the
framework's own `set_cookie`.

## 4. Database adapter

Built on SQLAlchemy 2.0 **Core** (a query builder, the Kysely analogue) so the schema can be
assembled at runtime from core + plugin + user fields and rows return as dicts. A shared factory owns
a transform pipeline (type coercion, default injection, key mapping, `Where` normalization); each
adapter implements only raw CRUD.

```python
Operator = Literal["eq","ne","lt","lte","gt","gte","in","contains","starts_with","ends_with"]

@dataclass(frozen=True)
class Where:
    field: str
    value: Any
    operator: Operator = "eq"
    connector: Literal["AND","OR"] = "AND"

@dataclass(frozen=True)
class FieldSpec:
    type: Literal["string","number","boolean","date","json"]
    required: bool = False
    unique: bool = False
    default_value: Any = None
    input: bool = True              # False => not settable at create (e.g. role)
    references: str | None = None   # "table.column"; the user owns the referenced table
    field_name: str | None = None   # physical column override

class AsyncDatabaseAdapter(Protocol):
    async def create(self, *, model, data, select=None) -> Row: ...
    async def find_one(self, *, model, where, select=None) -> Row | None: ...
    async def find_many(self, *, model, where=(), limit=None, offset=None, sort_by=None, select=None) -> list[Row]: ...
    async def update(self, *, model, where, update) -> Row | None: ...
    async def update_many(self, *, model, where, update) -> int: ...
    async def delete(self, *, model, where) -> None: ...
    async def delete_many(self, *, model, where) -> int: ...
    async def count(self, *, model, where=()) -> int: ...
    async def create_schema(self, *, tables, file=None) -> str: ...
```

The sync adapter shares the same query builder and swaps `AsyncConnection.execute` for
`Connection.execute`; WSGI callers use it directly and never touch an event loop. Migrations use
Alembic autogenerate (with human review) plus a driver-free raw-SQL renderer; the Django adapter
defers to the user's own models and migrations.

## 5. Data model (v0.1)

- **user** — id, email (unique), email_verified, name, image, created_at, updated_at, plus
  `additional_fields`.
- **session** — id, user_id, token (opaque; stored hashed), expires_at, created_at, ip_address,
  user_agent.
- **account** — id, user_id, provider_id, account_id, password (hash, for the credential provider),
  and OAuth token columns reserved for later.
- **verification** — id, identifier, value, expires_at, created_at (email verification, password
  reset).

## 6. Session and cookie security

- **Tokens.** `secrets.token_urlsafe(32)` (256 bits). Only `SHA-256(token)` is stored; comparison is
  constant-time. The DB row is the sole authority.
- **Cookie.** Signed via `itsdangerous` with a per-purpose salt. Flags: `HttpOnly`, `Secure`,
  `SameSite=Lax` (Strict for sensitive apps), `__Host-` prefix.
- **Lifecycle.** Sliding refresh past `update_age`; both idle and absolute timeout enforced
  server-side. The session id rotates on every privilege change (sign-in, sign-out) and the old row
  is deleted (fixation defense). Sign-out deletes the row; "sign out everywhere" deletes all rows for
  the user.
- **Keys.** One high-entropy `MASTER_SECRET`; per-purpose subkeys via HKDF with distinct `info`
  labels. `cryptography` provides AEAD, HKDF, and constant-time HMAC verification. Argon2 hashing runs
  off the event loop via `anyio.to_thread.run_sync`.

## 7. Passwords

Argon2id via `argon2-cffi`, storing the full PHC string; on each successful sign-in,
`check_needs_rehash` upgrades weak hashes. A `$2b$` prefix is verified with `bcrypt` and transparently
re-hashed to Argon2id, so existing tables migrate on login.

## 8. Public API (alias-first)

Everything supported is reachable from the top-level alias:

```python
import deadbolt as db

auth = db.Auth(adapter=..., secret=..., email_and_password=db.EmailPassword(enabled=True))
```

`deadbolt/__init__.py` re-exports the supported surface behind an explicit `__all__`. Internal modules
are private so they can be refactored without breaking the alias. The only sanctioned deep imports are
optional integrations — `from deadbolt.integrations.fastapi import mount` — which stay explicit so
`import deadbolt` never pulls in a web framework.

## 9. Testing strategy

Two layers: a **Protocol conformance suite** parametrized over every adapter (memory, SQLAlchemy,
Django) running identical behavioral assertions for parity, and **thin per-framework ASGI suites**
that assert the HTTP contract (cookies, redirects, headers) via `httpx` `ASGITransport`. The async
runner is `pytest` with the AnyIO plugin. Crypto, session, token, and password modules are held to
100% coverage.
