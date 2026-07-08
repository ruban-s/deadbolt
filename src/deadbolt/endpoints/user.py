"""User self-management endpoints: update and delete."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .._util import utcnow
from ..db.types import Row, Where
from ..errors import APIError
from . import _service as svc
from .context import EndpointResult

if TYPE_CHECKING:
    from ..core.auth import Auth
    from .context import EndpointRequest


async def update_user(auth: Auth, req: EndpointRequest) -> EndpointResult:
    _, user = await svc.require_session(auth, req)
    update: Row = {}
    for key in ("name", "image"):
        if key in req.body:
            update[key] = req.body[key]
    if update:
        update["updated_at"] = utcnow()
        await auth.adapter.update(model="user", where=[Where("id", user["id"])], update=update)
    refreshed = await svc.find_user_by_id(auth.adapter, user["id"])
    return EndpointResult(data={"user": svc.public_user(refreshed)} if refreshed else {})


async def delete_user(auth: Auth, req: EndpointRequest) -> EndpointResult:
    _, user = await svc.require_session(auth, req)
    account = await svc.credential_account(auth.adapter, user["id"])
    if account is not None and account.get("password"):
        password = svc.require_str(req.body, "password")
        if not await auth.hasher.verify(account["password"], password):
            raise APIError(401, "invalid_credentials", "Invalid password.")

    await auth.sessions.revoke_all(user["id"])
    await auth.adapter.delete_many(model="account", where=[Where("user_id", user["id"])])
    await auth.adapter.delete(model="user", where=[Where("id", user["id"])])
    return EndpointResult(data={"success": True}, cookies=[auth.sessions.clear_cookie()])
