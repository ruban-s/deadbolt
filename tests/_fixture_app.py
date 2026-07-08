from __future__ import annotations

import deadbolt as db
from deadbolt.plugins.totp import totp

auth = db.Auth(
    adapter=db.MemoryAdapter(),
    secret="x" * 32,
    email_and_password=db.EmailPassword(enabled=True),
    plugins=[totp()],
)
