# Flask

`deadbolt` mounts on Flask through a WSGI adapter. The core is async, so the synchronous Flask
view bridges into it via `Auth.handle_sync`.

Install the framework extra alongside a database adapter:

```bash
pip install "deadbolt[flask,sqlalchemy]"
```

## The sync bridge

Flask serves requests synchronously, but the `deadbolt` core is `async`. Rather than spin up a new
event loop per request — which would tear pooled database connections between loops — the adapter
routes every call through `Auth.handle_sync`. That method delegates to a `SyncBridge`, which holds
**one long-lived `anyio` `BlockingPortal`** running on a dedicated background thread. Every
synchronous call runs its coroutine on that single loop, so connection pools and other loop-bound
resources are created once and reused.

```python
result = auth.handle_sync(auth_request)   # blocks until the coroutine completes
```

!!! warning
    `handle_sync` refuses to run from inside a running event loop. If you are already in async
    code (FastAPI, Starlette, an async worker), use the async mount instead — calling the sync
    bridge there raises `RuntimeError`.

The portal starts lazily on first use. Call `auth.close()` on shutdown to stop the background loop.

## Mounting

```python
from deadbolt.integrations.flask import mount

mount(app, auth, prefix="/api/auth")
```

`mount` registers a single catch-all URL rule (endpoint name `deadbolt_auth`) that forwards every
method under `prefix` to `auth.handle_sync`. It returns `None` and mutates the app in place.

```python
def mount(app: Flask, auth: Auth, *, prefix: str = "/api/auth") -> None
```

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `app` | `Flask` | — | The Flask application to mount on. |
| `auth` | `Auth` | — | Your configured `deadbolt.Auth` instance. |
| `prefix` | `str` | `"/api/auth"` | Keyword-only. URL prefix the auth routes are served under. |

The mounted rule accepts `GET`, `POST`, `PUT`, `PATCH`, and `DELETE`. Cookies returned by the core
are applied via Flask's native `response.set_cookie`, preserving `Secure`, `HttpOnly`, `SameSite`,
`Max-Age`, `Path`, and `Domain`.

## A full example

```python
import secrets

import deadbolt as db
from deadbolt.integrations.flask import mount
from flask import Flask

auth = db.Auth(
    adapter=db.MemoryAdapter(),                 # swap for db.SQLAlchemyAdapter(engine)
    secret=secrets.token_urlsafe(32),           # load from the environment in production
    email_and_password=db.EmailPassword(enabled=True),
)

app = Flask(__name__)
mount(app, auth, prefix="/api/auth")

if __name__ == "__main__":
    app.run(port=8000)
```

Exercise the endpoints:

```bash
curl -c cookies.txt -b cookies.txt -X POST http://127.0.0.1:8000/api/auth/sign-up/email \
     -H 'Content-Type: application/json' -d '{"email":"a@b.com","password":"hunter2pw"}'
curl -c cookies.txt -b cookies.txt http://127.0.0.1:8000/api/auth/get-session
```

## Reading the session in your own routes

The mount only serves the auth routes. To read the current session inside your own views, call the
direct-call API with the request cookies. Since Flask views are synchronous, run the coroutine
through the same sync bridge with `auth.handle_sync` — or, more simply, hit the mounted
`get-session` route. Using the bridge directly:

```python
from flask import jsonify, request

@app.get("/me")
def me():
    result = auth.handle_sync(
        db.AuthRequest(
            method="GET",
            path="/get-session",
            cookies=dict(request.cookies),
        )
    )
    return app.response_class(result.body, status=result.status, mimetype=result.media_type)
```

The `get-session` payload is `{"session": ..., "user": ...}`, both `null` when there is no valid
session.
