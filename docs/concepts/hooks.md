# Hooks

A hook is an `async` callback that runs around an endpoint handler. Before-hooks
observe or block a request; after-hooks observe the result or **rewrite it**. Hooks are
how plugins layer behavior onto endpoints they do not own — TOTP wraps password sign-in
with a second-factor challenge, and admin gates sign-in for banned accounts, both purely
through after-hooks.

## The `Hook` and `HookContext` model

A `Hook` is a frozen dataclass binding a callback to a path:

| Field | Type | Purpose |
| --- | --- | --- |
| `run` | `Callable[[HookContext], Awaitable[None]]` | The async callback to invoke. |
| `path` | `str \| None` | Exact path to match, or `None` for every path. |

A hook matches a request when `path` is `None` or equals the request path exactly
(`Hook.matches(path)`). The callback receives a single `HookContext`:

| Field | Type | Purpose |
| --- | --- | --- |
| `auth` | `Auth` | The live `Auth` instance (adapter, sessions, config). |
| `request` | `EndpointRequest` | The parsed request: body, cookies, query, headers, client IP. |
| `path` | `str` | The request path being handled. |
| `result` | `EndpointResult \| None` | The handler's result — `None` for before-hooks, populated for after-hooks. |

The callback returns `None`. It influences the response by mutating the context —
specifically by assigning to `ctx.result`.

## Before and after

Both hook phases run inside the router, around the handler call:

```python
for hook in self._auth.before_hooks:
    if hook.matches(path):
        await hook.run(HookContext(self._auth, req, path))
result = await handler(self._auth, req)
for hook in self._auth.after_hooks:
    if hook.matches(path):
        context = HookContext(self._auth, req, path, result)
        await hook.run(context)
        if context.result is not None:
            result = context.result
return result
```

A **before-hook** receives a context with `result=None`. It runs before the handler and
typically inspects `ctx.request` — to enforce a precondition (raise `APIError` to stop
the request) or to record an observation.

An **after-hook** receives a context whose `result` is the handler's `EndpointResult`.
If the hook assigns a new value to `ctx.result`, that value **replaces** the response.
This is the rewrite mechanism.

## Rewriting `ctx.result`

Two shipped plugins use after-hooks to replace a successful sign-in response.

**TOTP 2FA challenge.** The `totp()` plugin registers
`Hook(_challenge_after_sign_in, path="/sign-in/email")`. After a correct password, the
hook checks whether the user has TOTP enabled; if so, it revokes the freshly issued
session, stores a short-lived challenge token, and rewrites the result to demand a
second factor instead of returning a live session:

```python
async def _challenge_after_sign_in(ctx: HookContext) -> None:
    result = ctx.result
    if result is None or not isinstance(result.data, dict):
        return
    user = result.data.get("user")
    ...
    ctx.result = EndpointResult(
        data={"two_factor_required": True, "challenge": challenge_token},
        cookies=[ctx.auth.sessions.clear_cookie()],
    )
```

**Admin ban gate.** The `admin()` plugin registers an after-hook on each sign-in path.
If the signing-in user is banned, it revokes the session cookie and rewrites the result
to a `403`:

```python
async def _ban_gate(ctx: HookContext) -> None:
    ...
    ctx.result = EndpointResult(
        data={"error": {"code": "banned", "message": "This account is banned."}},
        status=403,
        cookies=[ctx.auth.sessions.clear_cookie()],
    )
```

In both cases the handler ran normally and produced a valid session; the after-hook
inspected that result and substituted its own.

## Registration

Hooks reach the router two ways, and both feed the same before/after lists.

**From `Auth(hooks=...)`.** Pass a `Hooks(before=..., after=...)` value to register
application-level hooks directly:

```python
import deadbolt as db
from deadbolt.hooks import Hook, HookContext, Hooks


async def _log_sign_in(ctx: HookContext) -> None:
    print(f"sign-in attempt from {ctx.request.client_ip}")


auth = db.Auth(
    adapter=db.MemoryAdapter(),
    secret=SECRET,
    email_and_password=db.EmailPassword(enabled=True),
    hooks=Hooks(before=(Hook(_log_sign_in, path="/sign-in/email"),)),
)
```

**From plugins.** Each plugin's `before` and `after` tuples are merged into the same
lists. `Auth` puts the hooks you passed first, then appends plugin hooks:

```python
self.before_hooks = [*(hooks.before if hooks else ()), *(h for p in self.plugins for h in p.before)]
self.after_hooks = [*(hooks.after if hooks else ()), *(h for p in self.plugins for h in p.after)]
```

Hooks run in list order, so your `Auth(hooks=...)` hooks run before any plugin hooks in
each phase.

## Ordering relative to pre-flight checks

Hooks run only after a request has cleared pre-flight. The router runs pre-flight
checks first, in this order, and rejects the request before any hook or handler runs:

1. **Origin / CSRF** — untrusted origins get `403 untrusted_origin`.
2. **Rate limit** — exceeding the limit gets `429 rate_limited`.
3. **Body size** — bodies over `max_body_bytes` get `413 payload_too_large`.

Only if all three pass does the router parse the JSON body, run the before-hooks,
invoke the handler, and run the after-hooks. A before-hook therefore never sees a
request that failed CSRF, rate limiting, or the body-size guard.

!!! note
    Hooks match on the endpoint path (for example `/sign-in/email`), not the mounted
    prefix such as `/api/auth`. Bind a `Hook` to the path exactly as it appears in the
    endpoint registry.
