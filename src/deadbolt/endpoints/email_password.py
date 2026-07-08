"""Email/password authentication endpoint handlers."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any

from .._util import new_id, utcnow
from ..crypto import generate_token, hash_token
from ..db.types import Row, Where
from ..errors import APIError
from . import _service as svc
from .context import EndpointResult

if TYPE_CHECKING:
    from ..core.auth import Auth
    from .context import EndpointRequest

_INVALID_CREDENTIALS = APIError(401, "invalid_credentials", "Invalid email or password.")
_RESET_TTL_SECONDS = 60 * 60

# A fixed valid Argon2id hash verified on the credential-miss path so that an
# unknown email costs the same as a known one, closing the timing/enumeration
# side-channel. The plaintext behind it is irrelevant; verification always fails.
_DECOY_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=4$zDXizTs6UjYCMUf6zTqxcg$"
    "nt/WlMDPygbKT1Ojq4b1qjok02RRLkXG1XmGdNxdYm0"
)


def _require_str(body: dict[str, Any], key: str) -> str:
    value = body.get(key)
    if not isinstance(value, str) or not value:
        raise APIError(400, "invalid_request", f"Missing or invalid field: {key}.")
    return value


def _ensure_enabled(auth: Auth) -> None:
    if not auth.email_and_password.enabled:
        raise APIError(403, "email_password_disabled", "Email/password auth is disabled.")


def _validate_new_password(auth: Auth, password: str) -> None:
    cfg = auth.email_and_password
    if len(password) < cfg.min_password_length:
        raise APIError(400, "password_too_short", "Password is too short.")
    if len(password) > cfg.max_password_length:
        raise APIError(400, "password_too_long", "Password is too long.")


def _public_session(session: Row) -> Row:
    fields = ("id", "user_id", "expires_at", "created_at", "updated_at")
    return {k: session[k] for k in fields if k in session}


async def sign_up_email(auth: Auth, req: EndpointRequest) -> EndpointResult:
    _ensure_enabled(auth)
    email = _require_str(req.body, "email").lower()
    password = _require_str(req.body, "password")
    _validate_new_password(auth, password)
    name = req.body.get("name")

    if await svc.find_user_by_email(auth.adapter, email) is not None:
        raise APIError(422, "user_already_exists", "A user with this email already exists.")

    password_hash = await auth.hasher.hash(password)
    user = await svc.create_user(auth.adapter, email=email, name=name)
    await svc.create_credential_account(
        auth.adapter, user_id=user["id"], email=email, password_hash=password_hash
    )
    token, _ = await auth.sessions.create(user["id"], ip=req.client_ip)
    return EndpointResult(
        data={"user": svc.public_user(user)}, cookies=[auth.sessions.build_cookie(token)]
    )


async def sign_in_email(auth: Auth, req: EndpointRequest) -> EndpointResult:
    _ensure_enabled(auth)
    email = _require_str(req.body, "email").lower()
    password = _require_str(req.body, "password")

    user = await svc.find_user_by_email(auth.adapter, email)
    account = await svc.credential_account(auth.adapter, user["id"]) if user else None
    if user is None or account is None or not account.get("password"):
        await auth.hasher.verify(_DECOY_HASH, password)
        raise _INVALID_CREDENTIALS
    if not await auth.hasher.verify(account["password"], password):
        raise _INVALID_CREDENTIALS

    if auth.hasher.needs_rehash(account["password"]):
        await svc.set_account_password(
            auth.adapter, account_id=account["id"], password_hash=await auth.hasher.hash(password)
        )

    token, _ = await auth.sessions.create(user["id"], ip=req.client_ip)
    return EndpointResult(
        data={"user": svc.public_user(user)}, cookies=[auth.sessions.build_cookie(token)]
    )


async def sign_out(auth: Auth, req: EndpointRequest) -> EndpointResult:
    token = auth.sessions.read_token(req.cookies)
    if token is not None:
        await auth.sessions.revoke(token)
    return EndpointResult(data={"success": True}, cookies=[auth.sessions.clear_cookie()])


async def get_session(auth: Auth, req: EndpointRequest) -> EndpointResult:
    empty = {"session": None, "user": None}
    token = auth.sessions.read_token(req.cookies)
    if token is None:
        return EndpointResult(data=empty)
    session = await auth.sessions.validate(token)
    if session is None:
        return EndpointResult(data=empty)
    user = await svc.find_user_by_id(auth.adapter, session["user_id"])
    if user is None:
        return EndpointResult(data=empty)
    return EndpointResult(data={"session": _public_session(session), "user": svc.public_user(user)})


async def change_password(auth: Auth, req: EndpointRequest) -> EndpointResult:
    token = auth.sessions.read_token(req.cookies)
    session = await auth.sessions.validate(token) if token else None
    if session is None:
        raise APIError(401, "unauthorized", "A valid session is required.")

    current = _require_str(req.body, "current_password")
    new_password = _require_str(req.body, "new_password")
    _validate_new_password(auth, new_password)

    account = await svc.credential_account(auth.adapter, session["user_id"])
    if account is None or not account.get("password"):
        raise APIError(400, "no_credential", "This account has no password set.")
    if not await auth.hasher.verify(account["password"], current):
        raise _INVALID_CREDENTIALS

    await svc.set_account_password(
        auth.adapter, account_id=account["id"], password_hash=await auth.hasher.hash(new_password)
    )

    result = EndpointResult(data={"success": True})
    if req.body.get("revoke_other_sessions"):
        await auth.sessions.revoke_all(session["user_id"])
        new_token, _ = await auth.sessions.create(session["user_id"], ip=req.client_ip)
        result.cookies.append(auth.sessions.build_cookie(new_token))
    return result


async def request_password_reset(auth: Auth, req: EndpointRequest) -> EndpointResult:
    _ensure_enabled(auth)
    email = _require_str(req.body, "email").lower()
    user = await svc.find_user_by_email(auth.adapter, email)
    if user is not None:
        token = generate_token()
        await _create_verification(auth, identifier=email, value=hash_token(token))
        if auth.email_sender is not None:
            await auth.email_sender.send(
                to=email, subject="Reset your password", body=f"Reset token: {token}"
            )
    return EndpointResult(data={"success": True})


async def reset_password(auth: Auth, req: EndpointRequest) -> EndpointResult:
    token = _require_str(req.body, "token")
    new_password = _require_str(req.body, "new_password")
    _validate_new_password(auth, new_password)

    token_hash = hash_token(token)
    record = await auth.adapter.find_one(model="verification", where=[Where("value", token_hash)])
    if record is None or record["expires_at"] <= utcnow():
        raise APIError(400, "invalid_token", "The reset token is invalid or expired.")

    user = await svc.find_user_by_email(auth.adapter, record["identifier"])
    account = await svc.credential_account(auth.adapter, user["id"]) if user else None
    if user is None or account is None:
        raise APIError(400, "invalid_token", "The reset token is invalid or expired.")

    await svc.set_account_password(
        auth.adapter, account_id=account["id"], password_hash=await auth.hasher.hash(new_password)
    )
    await auth.adapter.delete(model="verification", where=[Where("value", token_hash)])
    await auth.sessions.revoke_all(user["id"])
    return EndpointResult(data={"success": True})


async def _create_verification(auth: Auth, *, identifier: str, value: str) -> None:
    now = utcnow()
    await auth.adapter.create(
        model="verification",
        data={
            "id": new_id(),
            "identifier": identifier,
            "value": value,
            "expires_at": now + timedelta(seconds=_RESET_TTL_SECONDS),
            "created_at": now,
        },
    )
