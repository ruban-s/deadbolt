"""Phone-number sign-in via SMS one-time codes as a plugin."""

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
    from ..protocols import SmsSender

_INVALID = APIError(400, "invalid_otp", "The code is invalid or expired.")

PHONE_NUMBER_TABLE = TableSpec(
    model="phone_number",
    fields={
        "id": FieldSpec(type="string", required=True, unique=True, input=False),
        "user_id": FieldSpec(type="string", required=True, unique=True, references="user.id"),
        "phone": FieldSpec(type="string", required=True, unique=True),
        "verified": FieldSpec(type="boolean", required=True, default_value=False),
        "created_at": FieldSpec(type="date", required=True, input=False),
    },
)

PHONE_OTP_TABLE = TableSpec(
    model="phone_otp",
    fields={
        "id": FieldSpec(type="string", required=True, unique=True, input=False),
        "phone": FieldSpec(type="string", required=True, unique=True, input=False),
        "code": FieldSpec(type="string", required=True, input=False),
        "attempts": FieldSpec(type="number", required=True, default_value=0, input=False),
        "expires_at": FieldSpec(type="date", required=True, input=False),
        "created_at": FieldSpec(type="date", required=True, input=False),
    },
)


def phone_number(
    *,
    sms_sender: SmsSender,
    disable_signup: bool = False,
    length: int = 6,
    ttl: int = 300,
    max_attempts: int = 3,
) -> Plugin:
    """Return a plugin adding SMS-OTP send, phone linking, and phone sign-in."""

    async def send(auth: Auth, req: EndpointRequest) -> EndpointResult:
        phone = svc.require_str(req.body, "phone")
        code = f"{secrets.randbelow(10**length):0{length}d}"
        now = utcnow()
        existing = await _otp(auth, phone)
        payload = {
            "code": hash_token(code),
            "attempts": 0,
            "expires_at": now + timedelta(seconds=ttl),
        }
        if existing is None:
            await auth.adapter.create(
                model="phone_otp",
                data={"id": new_id(), "phone": phone, "created_at": now, **payload},
            )
        else:
            await auth.adapter.update(
                model="phone_otp", where=[Where("phone", phone)], update=payload
            )
        await sms_sender.send_sms(to=phone, body=f"Your code is {code}")
        return EndpointResult(data={"success": True})

    async def verify(auth: Auth, req: EndpointRequest) -> EndpointResult:
        _, user = await svc.require_session(auth, req)
        phone = svc.require_str(req.body, "phone")
        await _consume(auth, phone, svc.require_str(req.body, "otp"), max_attempts)
        owner = await _by_phone(auth, phone)
        if owner is not None and owner["user_id"] != user["id"]:
            raise APIError(409, "phone_taken", "That phone number is linked to another account.")
        await _link(auth, user["id"], phone)
        return EndpointResult(data={"success": True})

    async def sign_in(auth: Auth, req: EndpointRequest) -> EndpointResult:
        phone = svc.require_str(req.body, "phone")
        await _consume(auth, phone, svc.require_str(req.body, "otp"), max_attempts)
        record = await _by_phone(auth, phone)
        if record is not None:
            user = await svc.find_user_by_id(auth.adapter, record["user_id"])
        elif disable_signup:
            raise _INVALID
        else:
            user = await svc.create_user(auth.adapter, email=f"{phone}@phone.deadbolt", name=None)
            await _link(auth, user["id"], phone)
        if user is None:
            raise _INVALID
        token, _ = await auth.sessions.create(user["id"], ip=req.client_ip)
        return EndpointResult(
            data={"user": svc.public_user(user)}, cookies=[auth.sessions.build_cookie(token)]
        )

    return Plugin(
        id="phone-number",
        schema=(PHONE_NUMBER_TABLE, PHONE_OTP_TABLE),
        endpoints=(
            Endpoint("POST", "/phone/send-otp", send, "phone_send_otp"),
            Endpoint("POST", "/phone/verify", verify, "phone_verify"),
            Endpoint("POST", "/sign-in/phone", sign_in, "sign_in_phone"),
        ),
    )


async def _consume(auth: Auth, phone: str, code: str, max_attempts: int) -> None:
    record = await _otp(auth, phone)
    if record is None or record["expires_at"] <= utcnow():
        raise _INVALID
    if not tokens_equal(hash_token(code), record["code"]):
        if record["attempts"] + 1 >= max_attempts:
            await auth.adapter.delete(model="phone_otp", where=[Where("phone", phone)])
        else:
            await auth.adapter.update(
                model="phone_otp",
                where=[Where("phone", phone)],
                update={"attempts": record["attempts"] + 1},
            )
        raise _INVALID
    await auth.adapter.delete(model="phone_otp", where=[Where("phone", phone)])


async def _link(auth: Auth, user_id: str, phone: str) -> None:
    existing = await auth.adapter.find_one(model="phone_number", where=[Where("user_id", user_id)])
    if existing is not None:
        await auth.adapter.update(
            model="phone_number",
            where=[Where("user_id", user_id)],
            update={"phone": phone, "verified": True},
        )
        return
    await auth.adapter.create(
        model="phone_number",
        data={
            "id": new_id(),
            "user_id": user_id,
            "phone": phone,
            "verified": True,
            "created_at": utcnow(),
        },
    )


async def _otp(auth: Auth, phone: str) -> Row | None:
    return await auth.adapter.find_one(model="phone_otp", where=[Where("phone", phone)])


async def _by_phone(auth: Auth, phone: str) -> Row | None:
    return await auth.adapter.find_one(model="phone_number", where=[Where("phone", phone)])
