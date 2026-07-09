# Any framework (ASGI / WSGI)

Beyond the first-class FastAPI and Flask mounts, `deadbolt` ships **generic ASGI and WSGI apps**
that mount onto *any* Python web framework. They depend only on the standard library — no extra to
install — so the same core serves Starlette, Litestar, Quart, Sanic, aiohttp (ASGI) and Bottle,
CherryPy, or a bare `wsgiref` server (WSGI).

```python
asgi = auth.asgi_app()   # a standard ASGI 3 application
wsgi = auth.wsgi_app()   # a standard WSGI application
```

Each app translates the framework's native request into the normalized
[`AuthRequest`](../concepts/architecture.md) contract, calls the core, and writes the
[`AuthResponse`](../concepts/architecture.md) back — cookies included as real `Set-Cookie` headers.

!!! note "Mount at `base_path`"
    Unlike the FastAPI/Flask `mount(..., prefix=...)` helpers, the generic apps take no prefix
    argument. They strip the `Auth.base_path` you configured (default `/api/auth`) from the incoming
    path, so mount them at that same path. Set `base_path` on `Auth` to change it.

## ASGI

`auth.asgi_app()` returns an ASGI 3 callable. Mount it with your framework's sub-app primitive.

```python
import secrets

import deadbolt as db
from starlette.applications import Starlette
from starlette.routing import Mount

auth = db.Auth(
    adapter=db.MemoryAdapter(),                 # swap for db.SQLAlchemyAdapter(engine)
    secret=secrets.token_urlsafe(32),
    email_and_password=db.EmailPassword(enabled=True),
    base_path="/api/auth",
)

app = Starlette(routes=[Mount("/api/auth", app=auth.asgi_app())])
```

The app also answers the ASGI `lifespan` protocol, so it can be served directly by any ASGI server
(`uvicorn module:asgi`) as well as mounted. WebSocket scopes are rejected — auth is HTTP only.

## WSGI

`auth.wsgi_app()` returns a WSGI callable that bridges into the async core through
[`Auth.handle_sync`](flask.md#the-sync-bridge). Mount it with any WSGI dispatcher.

```python
import secrets
from wsgiref.simple_server import make_server

import deadbolt as db

auth = db.Auth(
    adapter=db.MemoryAdapter(),
    secret=secrets.token_urlsafe(32),
    email_and_password=db.EmailPassword(enabled=True),
    base_path="/api/auth",
)

# Serve the auth API directly (it strips base_path from the request path itself):
make_server("127.0.0.1", 8000, auth.wsgi_app()).serve_forever()
```

To mount under a larger WSGI app, put it behind a dispatcher such as
`werkzeug.middleware.dispatcher.DispatcherMiddleware`; the mount's `SCRIPT_NAME` is honoured, so the
sub-path still resolves against `base_path`.

!!! warning
    Because the WSGI app uses the sync bridge, call `auth.close()` on shutdown to stop the
    background loop, and never call it from inside a running event loop.

## Verify it

```bash
curl -c cookies.txt -b cookies.txt -X POST http://127.0.0.1:8000/api/auth/sign-up/email \
     -H 'Content-Type: application/json' -d '{"email":"a@b.com","password":"hunter2pw"}'
curl -c cookies.txt -b cookies.txt http://127.0.0.1:8000/api/auth/get-session
```
