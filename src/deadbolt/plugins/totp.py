"""TOTP two-factor authentication as a plugin. Requires ``deadbolt[totp]``."""

from __future__ import annotations

import secrets
from datetime import timedelta
from typing import TYPE_CHECKING, Any

import pyotp

from .._util import new_id, utcnow
from ..crypto import Encryptor, generate_token, hash_token
from ..db.types import FieldSpec, Row, TableSpec, Where
from ..endpoints import _service as svc
from ..endpoints.context import EndpointResult
from ..endpoints.registry import Endpoint
from ..errors import APIError
from ..hooks import Hook
from . import Plugin

if TYPE_CHECKING:
    from ..core.auth import Auth
    from ..endpoints.context import EndpointRequest
    from ..hooks import HookContext

_CHALLENGE_PREFIX = "2fa-challenge"
_CHALLENGE_TTL = 300
_VALID_WINDOW = 1

TWO_FACTOR_TABLE = TableSpec(
    model="two_factor",
    fields={
        "id": FieldSpec(type="string", required=True, unique=True, input=False),
        "user_id": FieldSpec(type="string", required=True, unique=True, references="user.id"),
        "secret": FieldSpec(type="string", required=True, input=False),
        "enabled": FieldSpec(type="boolean", required=True, default_value=False),
        "backup_codes": FieldSpec(type="json", input=False),
        "created_at": FieldSpec(type="date", required=True, input=False),
        "updated_at": FieldSpec(type="date", required=True, input=False),
    },
)


def totp(*, issuer: str = "deadbolt", backup_code_count: int = 10) -> Plugin:
    """Return a plugin adding TOTP enrollment, verification, and a sign-in challenge."""

    async def enroll(auth: Auth, req: EndpointRequest) -> EndpointResult:
        user = await _session_user(auth, req)
        secret = pyotp.random_base32()
        await _store(auth, user["id"], secret=Encryptor(auth.secret).encrypt(secret))
        uri = pyotp.TOTP(secret).provisioning_uri(name=user["email"], issuer_name=issuer)
        return EndpointResult(data={"secret": secret, "uri": uri})

    async def enable(auth: Auth, req: EndpointRequest) -> EndpointResult:
        user = await _session_user(auth, req)
        row = await _load(auth, user["id"])
        if row is None:
            raise APIError(400, "not_enrolled", "TOTP is not enrolled.")
        if not _check_totp(auth, row, _require(req.body, "code")):
            raise APIError(400, "invalid_code", "The verification code is invalid.")
        codes = [_backup_code() for _ in range(backup_code_count)]
        await _update(auth, user["id"], enabled=True, backup_codes=[hash_token(c) for c in codes])
        return EndpointResult(data={"backup_codes": codes})

    async def disable(auth: Auth, req: EndpointRequest) -> EndpointResult:
        user = await _session_user(auth, req)
        row = await _load(auth, user["id"])
        if row is None or not await _verify(auth, user["id"], row, _require(req.body, "code")):
            raise APIError(400, "invalid_code", "The verification code is invalid.")
        await auth.adapter.delete(model="two_factor", where=[Where("user_id", user["id"])])
        return EndpointResult(data={"success": True})

    async def challenge(auth: Auth, req: EndpointRequest) -> EndpointResult:
        token = _require(req.body, "challenge")
        record = await auth.adapter.find_one(
            model="verification", where=[Where("value", hash_token(token))]
        )
        if record is None or not str(record["identifier"]).startswith(f"{_CHALLENGE_PREFIX}:"):
            raise APIError(400, "invalid_challenge", "The challenge is invalid or expired.")
        if record["expires_at"] <= utcnow():
            raise APIError(400, "invalid_challenge", "The challenge is invalid or expired.")

        user_id = str(record["identifier"]).split(":", 1)[1]
        row = await _load(auth, user_id)
        if row is None or not await _verify(auth, user_id, row, _require(req.body, "code")):
            raise APIError(400, "invalid_code", "The verification code is invalid.")

        await auth.adapter.delete(model="verification", where=[Where("value", hash_token(token))])
        user = await svc.find_user_by_id(auth.adapter, user_id)
        if user is None:
            raise APIError(400, "invalid_challenge", "The challenge is invalid or expired.")
        session_token, _ = await auth.sessions.create(user_id, ip=req.client_ip)
        return EndpointResult(
            data={"user": svc.public_user(user)},
            cookies=[auth.sessions.build_cookie(session_token)],
        )

    return Plugin(
        id="two-factor-totp",
        schema=(TWO_FACTOR_TABLE,),
        endpoints=(
            Endpoint("POST", "/2fa/totp/enroll", enroll, "totp_enroll"),
            Endpoint("POST", "/2fa/totp/enable", enable, "totp_enable"),
            Endpoint("POST", "/2fa/totp/disable", disable, "totp_disable"),
            Endpoint("POST", "/2fa/totp/challenge", challenge, "totp_challenge"),
        ),
        after=(Hook(_challenge_after_sign_in, path="/sign-in/email"),),
    )


async def _challenge_after_sign_in(ctx: HookContext) -> None:
    result = ctx.result
    if result is None or not isinstance(result.data, dict):
        return
    user = result.data.get("user")
    if not isinstance(user, dict):
        return
    row = await _load(ctx.auth, user["id"])
    if row is None or not row["enabled"]:
        return

    for cookie in result.cookies:
        token = ctx.auth.sessions.read_token({cookie.name: cookie.value})
        if token is not None:
            await ctx.auth.sessions.revoke(token)

    challenge_token = generate_token()
    now = utcnow()
    await ctx.auth.adapter.create(
        model="verification",
        data={
            "id": new_id(),
            "identifier": f"{_CHALLENGE_PREFIX}:{user['id']}",
            "value": hash_token(challenge_token),
            "expires_at": now + timedelta(seconds=_CHALLENGE_TTL),
            "created_at": now,
        },
    )
    ctx.result = EndpointResult(
        data={"two_factor_required": True, "challenge": challenge_token},
        cookies=[ctx.auth.sessions.clear_cookie()],
    )


async def _session_user(auth: Auth, req: EndpointRequest) -> Row:
    token = auth.sessions.read_token(req.cookies)
    session = await auth.sessions.validate(token) if token else None
    if session is None:
        raise APIError(401, "unauthorized", "A valid session is required.")
    user = await svc.find_user_by_id(auth.adapter, session["user_id"])
    if user is None:
        raise APIError(401, "unauthorized", "A valid session is required.")
    return user


async def _load(auth: Auth, user_id: str) -> Row | None:
    return await auth.adapter.find_one(model="two_factor", where=[Where("user_id", user_id)])


async def _store(auth: Auth, user_id: str, *, secret: str) -> None:
    now = utcnow()
    existing = await _load(auth, user_id)
    if existing is not None:
        await _update(auth, user_id, secret=secret, enabled=False, backup_codes=[])
        return
    await auth.adapter.create(
        model="two_factor",
        data={
            "id": new_id(),
            "user_id": user_id,
            "secret": secret,
            "enabled": False,
            "backup_codes": [],
            "created_at": now,
            "updated_at": now,
        },
    )


async def _update(auth: Auth, user_id: str, **fields: Any) -> None:
    await auth.adapter.update(
        model="two_factor",
        where=[Where("user_id", user_id)],
        update={**fields, "updated_at": utcnow()},
    )


def _check_totp(auth: Auth, row: Row, code: str) -> bool:
    secret = Encryptor(auth.secret).decrypt(row["secret"])
    return bool(pyotp.TOTP(secret).verify(code, valid_window=_VALID_WINDOW))


async def _verify(auth: Auth, user_id: str, row: Row, code: str) -> bool:
    if _check_totp(auth, row, code):
        return True
    codes: list[str] = list(row.get("backup_codes") or [])
    hashed = hash_token(code)
    if hashed in codes:
        codes.remove(hashed)
        await _update(auth, user_id, backup_codes=codes)
        return True
    return False


def _require(body: dict[str, Any], key: str) -> str:
    value = body.get(key)
    if not isinstance(value, str) or not value:
        raise APIError(400, "invalid_request", f"Missing or invalid field: {key}.")
    return value


def _backup_code() -> str:
    return secrets.token_hex(5)
