"""Passwordless email one-time-password (OTP) sign-in as a plugin."""

from __future__ import annotations

import secrets
from datetime import timedelta
from typing import TYPE_CHECKING

from .._util import new_id, utcnow
from ..crypto import hash_token, tokens_equal
from ..db.types import FieldSpec, Row, TableSpec, Where
from ..endpoints import _service as svc
from ..endpoints.context import EndpointResult
from ..endpoints.registry import Endpoint
from ..errors import APIError
from . import Plugin

if TYPE_CHECKING:
    from ..core.auth import Auth
    from ..endpoints.context import EndpointRequest

EMAIL_OTP_TABLE = TableSpec(
    model="email_otp",
    fields={
        "id": FieldSpec(type="string", required=True, unique=True, input=False),
        "email": FieldSpec(type="string", required=True, unique=True, input=False),
        "code": FieldSpec(type="string", required=True, input=False),
        "attempts": FieldSpec(type="number", required=True, default_value=0, input=False),
        "expires_at": FieldSpec(type="date", required=True, input=False),
        "created_at": FieldSpec(type="date", required=True, input=False),
    },
)

_INVALID = APIError(400, "invalid_otp", "The code is invalid or expired.")


def email_otp(
    *, length: int = 6, ttl: int = 300, max_attempts: int = 3, disable_signup: bool = False
) -> Plugin:
    """Return a plugin adding ``/email-otp/send`` and ``/sign-in/email-otp``."""

    async def send(auth: Auth, req: EndpointRequest) -> EndpointResult:
        email = svc.require_str(req.body, "email").lower()
        code = _generate(length)
        now = utcnow()
        record: Row = {
            "id": new_id(),
            "email": email,
            "code": hash_token(code),
            "attempts": 0,
            "expires_at": now + timedelta(seconds=ttl),
            "created_at": now,
        }
        existing = await _load(auth, email)
        if existing is None:
            await auth.adapter.create(model="email_otp", data=record)
        else:
            await auth.adapter.update(
                model="email_otp",
                where=[Where("email", email)],
                update={"code": record["code"], "attempts": 0, "expires_at": record["expires_at"]},
            )
        if auth.email_sender is not None:
            await auth.email_sender.send(
                to=email, subject="Your sign-in code", body=f"Code: {code}"
            )
        return EndpointResult(data={"success": True})

    async def sign_in(auth: Auth, req: EndpointRequest) -> EndpointResult:
        email = svc.require_str(req.body, "email").lower()
        code = svc.require_str(req.body, "otp")
        record = await _load(auth, email)
        if record is None or record["expires_at"] <= utcnow():
            raise _INVALID
        if record["attempts"] + 1 >= max_attempts and not tokens_equal(
            hash_token(code), record["code"]
        ):
            await _delete(auth, email)
            raise _INVALID
        if not tokens_equal(hash_token(code), record["code"]):
            await auth.adapter.update(
                model="email_otp",
                where=[Where("email", email)],
                update={"attempts": record["attempts"] + 1},
            )
            raise _INVALID

        await _delete(auth, email)
        user = await svc.find_user_by_email(auth.adapter, email)
        if user is None:
            if disable_signup:
                raise _INVALID
            user = await svc.create_user(auth.adapter, email=email, name=None)
        await auth.adapter.update(
            model="user", where=[Where("id", user["id"])], update={"email_verified": True}
        )
        user["email_verified"] = True
        token, _ = await auth.sessions.create(user["id"], ip=req.client_ip)
        return EndpointResult(
            data={"user": svc.public_user(user)}, cookies=[auth.sessions.build_cookie(token)]
        )

    return Plugin(
        id="email-otp",
        schema=(EMAIL_OTP_TABLE,),
        endpoints=(
            Endpoint("POST", "/email-otp/send", send, "email_otp_send"),
            Endpoint("POST", "/sign-in/email-otp", sign_in, "sign_in_email_otp"),
        ),
    )


async def _load(auth: Auth, email: str) -> Row | None:
    return await auth.adapter.find_one(model="email_otp", where=[Where("email", email)])


async def _delete(auth: Auth, email: str) -> None:
    await auth.adapter.delete(model="email_otp", where=[Where("email", email)])


def _generate(length: int) -> str:
    return f"{secrets.randbelow(10**length):0{length}d}"
