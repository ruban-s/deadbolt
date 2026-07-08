# Architecture

deadbolt is a single **async-first core** with everything concrete pushed behind an interface.

```
 native request ──▶ AuthRequest ──▶ handle() ──▶ AuthResponse ──▶ native response
                                       │
                          endpoint registry (async callables)
                                       │
              DB adapter · session manager · hasher · hooks · plugins
```

## The framework-agnostic contract

Python has no universal request/response object, so deadbolt mints its own. The core is one function:

```python
async def handle(request: AuthRequest) -> AuthResponse: ...
```

`AuthRequest` and `AuthResponse` are plain dataclasses (method, path, headers, query, cookies, raw
body / status, headers, body, cookies). Each web framework gets a ~30-line adapter that translates
its native request into an `AuthRequest`, awaits `handle`, and applies the response — including
cookies — through the framework's **own** cookie API. See [FastAPI](../integrations/fastapi.md) and
[Flask](../integrations/flask.md).

Because the contract is a dataclass and not raw ASGI, the same endpoints are also **plain callables**
(`auth.api.*`), giving you a server-side API with no HTTP.

## ASGI and WSGI from one core

The core is async. ASGI frameworks (FastAPI, Starlette) `await handle` directly. WSGI frameworks
(Flask, classic Django) are served through a single long-lived `anyio` **BlockingPortal** — one
background thread running one event loop — so synchronous request handlers can drive the async core
without per-call loop churn. `Auth.handle_sync()` is the sync entry point.

## The pieces

| Piece | Role |
|---|---|
| **`Auth`** | The one object you configure; exposes `handle`, `handle_sync`, `api`, and `sessions`. |
| **Endpoint registry** | Maps `(method, path)` to async handlers; core endpoints plus every plugin's. |
| **Router** | Runs pre-flight checks (CSRF, rate limit, body size), before-hooks, the handler, after-hooks; serializes to `AuthResponse` and emits an audit line. |
| **Database adapter** | A `Protocol` for CRUD over `user`/`session`/`account`/`verification` and plugin tables. See [Adapters](adapters.md). |
| **Session manager** | Creates, validates, rotates, and revokes sessions; builds signed cookies. See [Sessions](sessions.md). |
| **Plugins** | Add endpoints, tables, and hooks. See [Plugins](plugins.md). |
| **Hooks** | Before/after request interception. See [Hooks](hooks.md). |

## Data model

Four core tables: **user** (id, email, email_verified, name, image, timestamps), **session** (id,
user_id, hashed token, expiry, ip/user-agent), **account** (credential or OAuth provider rows,
password hash), and **verification** (short-lived tokens for reset/verify/OTP challenges). Plugins
add their own tables via `Plugin.schema`; the [CLI](../cli.md) generates DDL for the whole set.
