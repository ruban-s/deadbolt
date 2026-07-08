"""Account-linking endpoints: list linked accounts and unlink one."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..db.types import Where
from ..errors import APIError
from . import _service as svc
from .context import EndpointResult

if TYPE_CHECKING:
    from ..core.auth import Auth
    from ..db.types import Row
    from .context import EndpointRequest


def _public_account(account: Row) -> Row:
    return {
        "id": account["id"],
        "provider_id": account["provider_id"],
        "account_id": account["account_id"],
        "created_at": account["created_at"],
    }


async def list_accounts(auth: Auth, req: EndpointRequest) -> EndpointResult:
    _, user = await svc.require_session(auth, req)
    rows = await auth.adapter.find_many(model="account", where=[Where("user_id", user["id"])])
    return EndpointResult(data={"accounts": [_public_account(row) for row in rows]})


async def unlink_account(auth: Auth, req: EndpointRequest) -> EndpointResult:
    _, user = await svc.require_session(auth, req)
    provider_id = svc.require_str(req.body, "provider_id")
    accounts = await auth.adapter.find_many(model="account", where=[Where("user_id", user["id"])])
    if len(accounts) <= 1:
        raise APIError(400, "last_account", "Cannot unlink your only sign-in method.")
    target = next((a for a in accounts if a["provider_id"] == provider_id), None)
    if target is None:
        raise APIError(404, "account_not_found", "No linked account for that provider.")
    await auth.adapter.delete(model="account", where=[Where("id", target["id"])])
    return EndpointResult(data={"success": True})
