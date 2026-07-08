"""Administration plugin: roles, bans, and user management.

Admins are bootstrapped by ``admin_emails`` / ``admin_user_ids`` and can also be
promoted via ``set-role``. Banned users are refused at sign-in by after-hooks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from functools import partial
from typing import TYPE_CHECKING, Any

from .._util import new_id, utcnow
from ..db.types import FieldSpec, Row, TableSpec, Where
from ..endpoints import _service as svc
from ..endpoints.context import EndpointResult
from ..endpoints.registry import Endpoint
from ..errors import APIError
from ..hooks import Hook
from . import Plugin

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ..core.auth import Auth
    from ..endpoints.context import EndpointRequest
    from ..hooks import HookContext

_SIGN_IN_PATHS = ("/sign-in/email", "/sign-in/email-otp", "/2fa/totp/challenge", "/oauth/callback")

ADMIN_META_TABLE = TableSpec(
    model="admin_meta",
    fields={
        "id": FieldSpec(type="string", required=True, unique=True, input=False),
        "user_id": FieldSpec(type="string", required=True, unique=True, references="user.id"),
        "role": FieldSpec(type="string", required=True, default_value="user"),
        "banned": FieldSpec(type="boolean", required=True, default_value=False),
        "ban_reason": FieldSpec(type="string", input=False),
        "ban_expires": FieldSpec(type="date", input=False),
        "updated_at": FieldSpec(type="date", required=True, input=False),
    },
)


@dataclass(frozen=True)
class AdminConfig:
    admin_emails: frozenset[str] = field(default_factory=frozenset)
    admin_user_ids: frozenset[str] = field(default_factory=frozenset)


def admin(*, admin_emails: Sequence[str] = (), admin_user_ids: Sequence[str] = ()) -> Plugin:
    """Return the admin plugin. Bootstrap admins via ``admin_emails``/``admin_user_ids``."""
    cfg = AdminConfig(
        admin_emails=frozenset(e.lower() for e in admin_emails),
        admin_user_ids=frozenset(admin_user_ids),
    )

    def ep(method: str, path: str, handler: Any, name: str) -> Endpoint:
        return Endpoint(method, path, partial(handler, cfg=cfg), name)

    return Plugin(
        id="admin",
        schema=(ADMIN_META_TABLE,),
        endpoints=(
            ep("POST", "/admin/set-role", _set_role, "admin_set_role"),
            ep("POST", "/admin/ban-user", _ban, "admin_ban_user"),
            ep("POST", "/admin/unban-user", _unban, "admin_unban_user"),
            ep("GET", "/admin/list-users", _list_users, "admin_list_users"),
            ep("POST", "/admin/create-user", _create_user, "admin_create_user"),
            ep("POST", "/admin/remove-user", _remove_user, "admin_remove_user"),
            ep("POST", "/admin/revoke-user-sessions", _revoke_sessions, "admin_revoke_sessions"),
        ),
        after=tuple(Hook(_ban_gate, path=path) for path in _SIGN_IN_PATHS),
    )


async def _set_role(auth: Auth, req: EndpointRequest, *, cfg: AdminConfig) -> EndpointResult:
    await _require_admin(auth, req, cfg)
    user_id = svc.require_str(req.body, "user_id")
    role = svc.require_str(req.body, "role")
    await _upsert_meta(auth, user_id, role=role)
    return EndpointResult(data={"success": True})


async def _ban(auth: Auth, req: EndpointRequest, *, cfg: AdminConfig) -> EndpointResult:
    await _require_admin(auth, req, cfg)
    user_id = svc.require_str(req.body, "user_id")
    expires = None
    if isinstance(req.body.get("expires_in"), int):
        expires = utcnow() + timedelta(seconds=req.body["expires_in"])
    await _upsert_meta(
        auth, user_id, banned=True, ban_reason=req.body.get("reason"), ban_expires=expires
    )
    await auth.sessions.revoke_all(user_id)
    return EndpointResult(data={"success": True})


async def _unban(auth: Auth, req: EndpointRequest, *, cfg: AdminConfig) -> EndpointResult:
    await _require_admin(auth, req, cfg)
    user_id = svc.require_str(req.body, "user_id")
    await _upsert_meta(auth, user_id, banned=False, ban_reason=None, ban_expires=None)
    return EndpointResult(data={"success": True})


async def _list_users(auth: Auth, req: EndpointRequest, *, cfg: AdminConfig) -> EndpointResult:
    await _require_admin(auth, req, cfg)
    users = await auth.adapter.find_many(model="user")
    result = []
    for user in users:
        meta = await _meta(auth, user["id"])
        result.append(
            {
                **svc.public_user(user),
                "role": meta["role"] if meta else "user",
                "banned": bool(meta["banned"]) if meta else False,
            }
        )
    return EndpointResult(data={"users": result})


async def _create_user(auth: Auth, req: EndpointRequest, *, cfg: AdminConfig) -> EndpointResult:
    await _require_admin(auth, req, cfg)
    email = svc.require_str(req.body, "email").lower()
    password = svc.require_str(req.body, "password")
    if await svc.find_user_by_email(auth.adapter, email) is not None:
        raise APIError(422, "user_already_exists", "A user with this email already exists.")
    user = await svc.create_user(auth.adapter, email=email, name=req.body.get("name"))
    await svc.create_credential_account(
        auth.adapter,
        user_id=user["id"],
        email=email,
        password_hash=await auth.hasher.hash(password),
    )
    if isinstance(req.body.get("role"), str):
        await _upsert_meta(auth, user["id"], role=req.body["role"])
    return EndpointResult(data={"user": svc.public_user(user)})


async def _remove_user(auth: Auth, req: EndpointRequest, *, cfg: AdminConfig) -> EndpointResult:
    await _require_admin(auth, req, cfg)
    user_id = svc.require_str(req.body, "user_id")
    await auth.sessions.revoke_all(user_id)
    await auth.adapter.delete_many(model="account", where=[Where("user_id", user_id)])
    await auth.adapter.delete_many(model="admin_meta", where=[Where("user_id", user_id)])
    await auth.adapter.delete(model="user", where=[Where("id", user_id)])
    return EndpointResult(data={"success": True})


async def _revoke_sessions(auth: Auth, req: EndpointRequest, *, cfg: AdminConfig) -> EndpointResult:
    await _require_admin(auth, req, cfg)
    user_id = svc.require_str(req.body, "user_id")
    revoked = await auth.sessions.revoke_all(user_id)
    return EndpointResult(data={"revoked": revoked})


async def _ban_gate(ctx: HookContext) -> None:
    result = ctx.result
    if result is None or not isinstance(result.data, dict):
        return
    user = result.data.get("user")
    if not isinstance(user, dict):
        return
    if not await _is_banned(ctx.auth, user["id"]):
        return
    for cookie in result.cookies:
        token = ctx.auth.sessions.read_token({cookie.name: cookie.value})
        if token is not None:
            await ctx.auth.sessions.revoke(token)
    ctx.result = EndpointResult(
        data={"error": {"code": "banned", "message": "This account is banned."}},
        status=403,
        cookies=[ctx.auth.sessions.clear_cookie()],
    )


async def _require_admin(auth: Auth, req: EndpointRequest, cfg: AdminConfig) -> Row:
    _, user = await svc.require_session(auth, req)
    if user["email"] in cfg.admin_emails or user["id"] in cfg.admin_user_ids:
        return user
    meta = await _meta(auth, user["id"])
    if meta is not None and meta["role"] == "admin":
        return user
    raise APIError(403, "forbidden", "Administrator access is required.")


async def _is_banned(auth: Auth, user_id: str) -> bool:
    meta = await _meta(auth, user_id)
    if meta is None or not meta["banned"]:
        return False
    expires = meta["ban_expires"]
    return expires is None or expires > utcnow()


async def _meta(auth: Auth, user_id: str) -> Row | None:
    return await auth.adapter.find_one(model="admin_meta", where=[Where("user_id", user_id)])


async def _upsert_meta(auth: Auth, user_id: str, **fields: Any) -> None:
    existing = await _meta(auth, user_id)
    if existing is not None:
        await auth.adapter.update(
            model="admin_meta",
            where=[Where("user_id", user_id)],
            update={**fields, "updated_at": utcnow()},
        )
        return
    now = utcnow()
    record: Row = {
        "id": new_id(),
        "user_id": user_id,
        "role": "user",
        "banned": False,
        "ban_reason": None,
        "ban_expires": None,
        "updated_at": now,
        **fields,
    }
    await auth.adapter.create(model="admin_meta", data=record)
