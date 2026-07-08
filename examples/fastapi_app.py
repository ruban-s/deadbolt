"""A runnable deadbolt example.

    uv run --extra fastapi uvicorn examples.fastapi_app:app --reload

Then, in another terminal (use -c cookies.txt to persist the session cookie):

    curl -c cookies.txt -b cookies.txt -X POST http://127.0.0.1:8000/api/auth/sign-up/email \
         -H 'Content-Type: application/json' \
         -d '{"email":"a@b.com","password":"hunter2pw"}'

    curl -c cookies.txt -b cookies.txt http://127.0.0.1:8000/api/auth/get-session

    curl -c cookies.txt -b cookies.txt -X POST http://127.0.0.1:8000/api/auth/sign-out

Note: the session cookie is Secure, so over plain http curl keeps it via the
cookie jar (-c/-b) even though a browser would require https.
"""

from __future__ import annotations

from fastapi import FastAPI

import deadbolt as db
from deadbolt.integrations.fastapi import mount
from deadbolt.plugins.magic_link import magic_link

app = FastAPI(title="deadbolt example")

auth = db.Auth(
    adapter=db.MemoryAdapter(),
    secret="change-me-to-32+-random-bytes-please",  # noqa: S106
    email_and_password=db.EmailPassword(enabled=True),
    plugins=[magic_link()],
)

mount(app, auth)
