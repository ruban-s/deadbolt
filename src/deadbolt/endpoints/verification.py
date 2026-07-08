"""Email verification and change-email endpoints."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

from .._util import new_id, utcnow
from ..crypto import generate_token, hash_token
from ..db.types import Where
from ..errors import APIError
from . import _service as svc
from .context import EndpointResult

if TYPE_CHECKING:
    from ..core.auth import Auth
    from .context import EndpointRequest

_VERIFY_PREFIX = "verify-email"
_CHANGE_PREFIX = "change-email"
_TTL = 60 * 60


async def send_verification_email(auth: Auth, req: EndpointRequest) -> EndpointResult:
    email = svc.require_str(req.body, "email").lower()
    user = await svc.find_user_by_email(auth.adapter, email)
    if user is not None and not user["email_verified"]:
        token = generate_token()
        await _issue(auth, f"{_VERIFY_PREFIX}:{email}", token)
        if auth.email_sender is not None:
            await auth.email_sender.send(
                to=email, subject="Verify your email", body=f"Verification token: {token}"
            )
    return EndpointResult(data={"success": True})


async def verify_email(auth: Auth, req: EndpointRequest) -> EndpointResult:
    token = svc.require_str(req.body, "token")
    record = await auth.adapter.find_one(
        model="verification", where=[Where("value", hash_token(token))]
    )
    if record is None or record["expires_at"] <= utcnow():
        raise APIError(400, "invalid_token", "The token is invalid or expired.")
    identifier = str(record["identifier"])
    await auth.adapter.delete(model="verification", where=[Where("value", hash_token(token))])

    if identifier.startswith(f"{_VERIFY_PREFIX}:"):
        email = identifier.split(":", 1)[1]
        await auth.adapter.update(
            model="user", where=[Where("email", email)], update={"email_verified": True}
        )
        return EndpointResult(data={"success": True})

    if identifier.startswith(f"{_CHANGE_PREFIX}:"):
        _, user_id, new_email = identifier.split(":", 2)
        if await svc.find_user_by_email(auth.adapter, new_email) is not None:
            raise APIError(409, "email_taken", "That email is already in use.")
        await auth.adapter.update(
            model="user",
            where=[Where("id", user_id)],
            update={"email": new_email, "email_verified": True, "updated_at": utcnow()},
        )
        return EndpointResult(data={"success": True})

    raise APIError(400, "invalid_token", "The token is invalid or expired.")


async def change_email(auth: Auth, req: EndpointRequest) -> EndpointResult:
    _, user = await svc.require_session(auth, req)
    new_email = svc.require_str(req.body, "new_email").lower()
    if new_email == user["email"]:
        return EndpointResult(data={"success": True})
    existing = await svc.find_user_by_email(auth.adapter, new_email)
    if existing is not None:
        raise APIError(409, "email_taken", "That email is already in use.")

    if auth.email_and_password.require_email_verification:
        token = generate_token()
        await _issue(auth, f"{_CHANGE_PREFIX}:{user['id']}:{new_email}", token)
        if auth.email_sender is not None:
            await auth.email_sender.send(
                to=new_email, subject="Confirm your new email", body=f"Confirmation token: {token}"
            )
        return EndpointResult(data={"status": "verification_sent"})

    await auth.adapter.update(
        model="user",
        where=[Where("id", user["id"])],
        update={"email": new_email, "email_verified": False, "updated_at": utcnow()},
    )
    updated = await svc.find_user_by_id(auth.adapter, user["id"])
    return EndpointResult(data={"user": svc.public_user(updated)} if updated else {"success": True})


async def _issue(auth: Auth, identifier: str, token: str) -> None:
    now = utcnow()
    await auth.adapter.create(
        model="verification",
        data={
            "id": new_id(),
            "identifier": identifier,
            "value": hash_token(token),
            "expires_at": now + timedelta(seconds=_TTL),
            "created_at": now,
        },
    )
