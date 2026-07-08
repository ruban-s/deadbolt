# FastAPI / Starlette

`deadbolt` mounts natively on FastAPI and Starlette. The core is async-first, so the adapter
routes requests straight to `auth.handle` with no bridging. The same adapter works for both
FastAPI apps and plain Starlette apps — FastAPI *is* a Starlette application.

Install the framework extra alongside a database adapter:

```bash
pip install "deadbolt[fastapi,sqlalchemy]"
```

## Mounting

```python
from deadbolt.integrations.fastapi import mount

mount(app, auth, prefix="/api/auth")
```

`mount` appends a single catch-all route to `app.router.routes` that forwards every method under
`prefix` to the auth core. It returns `None` and mutates the app in place.

```python
def mount(app: Starlette, auth: Auth, *, prefix: str = "/api/auth") -> None
```

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `app` | `Starlette` | — | The FastAPI or Starlette application to mount on. |
| `auth` | `Auth` | — | Your configured `deadbolt.Auth` instance. |
| `prefix` | `str` | `"/api/auth"` | Keyword-only. URL prefix the auth routes are served under. |

The mounted route accepts `GET`, `POST`, `PUT`, `PATCH`, and `DELETE`. Cookies returned by the
core are applied through Starlette's native `response.set_cookie`, so `Secure`, `HttpOnly`,
`SameSite`, `Max-Age`, `Path`, and `Domain` are all preserved.

!!! note
    Keep `prefix` in sync with the `base_path` you passed to `Auth` (default `/api/auth`). The
    core builds absolute URLs, such as OAuth callbacks, from `base_path`.

## A full example

```python
import secrets

import deadbolt as db
from deadbolt.integrations.fastapi import mount
from fastapi import FastAPI

auth = db.Auth(
    adapter=db.MemoryAdapter(),                 # swap for db.SQLAlchemyAdapter(engine)
    secret=secrets.token_urlsafe(32),           # load from the environment in production
    email_and_password=db.EmailPassword(enabled=True),
)

app = FastAPI()
mount(app, auth, prefix="/api/auth")
```

Run it and exercise the endpoints:

```bash
uvicorn app:app --reload
```

```bash
curl -c cookies.txt -b cookies.txt -X POST http://127.0.0.1:8000/api/auth/sign-up/email \
     -H 'Content-Type: application/json' -d '{"email":"a@b.com","password":"hunter2pw"}'
curl -c cookies.txt -b cookies.txt http://127.0.0.1:8000/api/auth/get-session
```

## Reading the session in your own routes

The mount only serves the auth routes. To read the current session inside your own handlers, call
the direct-call API with the request cookies — `auth.api.get_session` returns `{"session": ...,
"user": ...}`, both `None` when there is no valid session:

```python
from fastapi import Depends, Request

async def current_user(request: Request):
    result = await auth.api.get_session(cookies=dict(request.cookies))
    return result["user"]

@app.get("/me")
async def me(user=Depends(current_user)):
    if user is None:
        return {"authenticated": False}
    return {"authenticated": True, "user": user}
```

Because `auth.api.<endpoint>` is a plain coroutine, every endpoint is also callable server-side
without going through HTTP — handy for background jobs and tests.

## Starlette

The adapter targets Starlette directly, so a bare Starlette app works with the identical import
and call:

```python
from deadbolt.integrations.fastapi import mount
from starlette.applications import Starlette

app = Starlette()
mount(app, auth, prefix="/api/auth")
```
