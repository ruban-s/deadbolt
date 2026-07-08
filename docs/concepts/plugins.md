# Plugins

A plugin is a self-contained unit of extension. It contributes endpoints, request
hooks, and — when it needs to persist state — database tables. Every feature beyond
core email/password and sessions ships as a plugin, and you add one by passing it to
`Auth(plugins=[...])`.

## The `Plugin` dataclass

A `Plugin` is a frozen dataclass with five fields:

| Field | Type | Purpose |
| --- | --- | --- |
| `id` | `str` | Stable identifier for the plugin. |
| `endpoints` | `tuple[Endpoint, ...]` | Routes the plugin adds to the registry. |
| `schema` | `tuple[TableSpec, ...]` | Tables the plugin needs (empty if none). |
| `before` | `tuple[Hook, ...]` | Hooks run before the matched handler. |
| `after` | `tuple[Hook, ...]` | Hooks run after the handler, able to rewrite the result. |

Only `id` is required; the rest default to empty tuples. Because the dataclass is
frozen, a plugin is an immutable description — all of its behavior lives in the
handlers and hooks it references.

## How a plugin adds endpoints and tables

Each entry in `endpoints` is an `Endpoint(method, path, handler, name)`. A handler is
an `async` callable `(auth, request) -> EndpointResult`. When you construct `Auth`,
every plugin's endpoints are concatenated onto the core `ENDPOINTS` and registered, so
plugin routes are served exactly like built-in ones:

```python
plugin_endpoints = tuple(e for p in self.plugins for e in p.endpoints)
registry = Registry(ENDPOINTS + plugin_endpoints)
```

Entries in `schema` are `TableSpec` objects. A `TableSpec` has a `model` name and a
`fields` mapping of column name to `FieldSpec` (with `type`, `required`, `unique`,
`default_value`, `input`, and `references`). At startup, `Auth` merges plugin tables
into the schema alongside the core tables:

```python
self.schema = tuple(CORE_TABLES) + tuple(t for p in self.plugins for t in p.schema)
```

The `username` plugin, for example, declares a single `username` table:

```python
USERNAME_TABLE = TableSpec(
    model="username",
    fields={
        "id": FieldSpec(type="string", required=True, unique=True, input=False),
        "user_id": FieldSpec(type="string", required=True, unique=True, references="user.id"),
        "username": FieldSpec(type="string", required=True, unique=True),
        "display_username": FieldSpec(type="string", required=True),
        "created_at": FieldSpec(type="date", required=True, input=False),
        "updated_at": FieldSpec(type="date", required=True, input=False),
    },
)
```

## Module-level vs config-carrying plugins

Plugins are produced by factory functions. There are two common shapes.

**Module-level handlers.** When a plugin takes no configuration, its handlers can be
plain module-level functions referenced directly by each `Endpoint`. The `username()`
factory does exactly this — `_set`, `_available`, and `_sign_in` are defined at module
scope:

```python
def username() -> Plugin:
    return Plugin(
        id="username",
        schema=(USERNAME_TABLE,),
        endpoints=(
            Endpoint("POST", "/username/set", _set, "username_set"),
            Endpoint("GET", "/username/available", _available, "username_available"),
            Endpoint("POST", "/sign-in/username", _sign_in, "sign_in_username"),
        ),
    )
```

**Config-carrying handlers.** When a plugin accepts options, each handler needs access
to that configuration. Two patterns are used in `deadbolt`:

- **Closures.** The `totp(*, issuer="deadbolt", backup_code_count=10)` factory defines
  its handlers as nested `async` functions inside the factory, so they close over
  `issuer` and `backup_code_count` directly.
- **`functools.partial`.** The `admin(*, admin_emails=(), admin_user_ids=())` factory
  builds an `AdminConfig`, then binds it to every handler with
  `partial(handler, cfg=cfg)`, keeping the handlers as module-level functions with a
  keyword-only `cfg` parameter.

Both approaches yield an `async (auth, request) -> EndpointResult` callable, which is
all an `Endpoint` requires — the registry never sees the configuration.

## Registering before/after hooks

A plugin registers hooks simply by populating its `before` and `after` tuples with
`Hook` objects. Each `Hook` is bound to an exact `path` (or all paths when `path` is
`None`). The TOTP plugin adds an after-hook to `/sign-in/email` so it can intercept a
successful password sign-in and turn it into a second-factor challenge:

```python
return Plugin(
    id="two-factor-totp",
    schema=(TWO_FACTOR_TABLE,),
    endpoints=(...),
    after=(Hook(_challenge_after_sign_in, path="/sign-in/email"),),
)
```

When `Auth` is constructed, plugin hooks are collected into the global before/after
lists (after any hooks you passed via `Auth(hooks=...)`), so they run for every request
matching their path. See [Hooks](hooks.md) for the request-hook model and ordering.

## Write your own plugin

A minimal plugin needs an `id` and at least one endpoint. This one adds a single
`GET /ping` route that reports server time, with no tables and no hooks:

```python
import deadbolt as db
from datetime import datetime, timezone

from deadbolt.endpoints.context import EndpointResult
from deadbolt.endpoints.registry import Endpoint
from deadbolt.plugins import Plugin


async def _ping(auth, request) -> EndpointResult:
    return EndpointResult(data={"pong": datetime.now(timezone.utc).isoformat()})


def ping() -> Plugin:
    return Plugin(
        id="ping",
        endpoints=(Endpoint("GET", "/ping", _ping, "ping"),),
    )


auth = db.Auth(
    adapter=db.MemoryAdapter(),
    secret=SECRET,
    email_and_password=db.EmailPassword(enabled=True),
    plugins=[ping()],
)
```

To carry configuration, take arguments in the factory and bind them into your handlers
with a closure or `functools.partial`, exactly as `totp()` and `admin()` do. To persist
state, add a `TableSpec` to `schema`. To react to other endpoints, add a `Hook` to
`before` or `after`.

!!! note
    A handler returns an `EndpointResult` — its `data` is JSON-serialized as the
    response body, and any `cookies` it sets are written to the response.
