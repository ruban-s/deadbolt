"""Organizations with role-based access control as a plugin."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any

from .._util import new_id, utcnow
from ..db.types import FieldSpec, Row, TableSpec, Where
from ..endpoints import _service as svc
from ..endpoints.context import EndpointResult
from ..endpoints.registry import Endpoint
from ..errors import APIError
from . import Plugin

if TYPE_CHECKING:
    from ..core.auth import Auth
    from ..endpoints.context import EndpointRequest

_ROLES = ("member", "admin", "owner")
_INVITATION_TTL = 7 * 24 * 60 * 60

ORGANIZATION_TABLE = TableSpec(
    model="organization",
    fields={
        "id": FieldSpec(type="string", required=True, unique=True, input=False),
        "name": FieldSpec(type="string", required=True),
        "slug": FieldSpec(type="string", required=True, unique=True),
        "created_at": FieldSpec(type="date", required=True, input=False),
    },
)

MEMBER_TABLE = TableSpec(
    model="member",
    fields={
        "id": FieldSpec(type="string", required=True, unique=True, input=False),
        "organization_id": FieldSpec(type="string", required=True, references="organization.id"),
        "user_id": FieldSpec(type="string", required=True, references="user.id"),
        "role": FieldSpec(type="string", required=True),
        "created_at": FieldSpec(type="date", required=True, input=False),
    },
)

INVITATION_TABLE = TableSpec(
    model="invitation",
    fields={
        "id": FieldSpec(type="string", required=True, unique=True, input=False),
        "organization_id": FieldSpec(type="string", required=True, references="organization.id"),
        "email": FieldSpec(type="string", required=True),
        "role": FieldSpec(type="string", required=True),
        "status": FieldSpec(type="string", required=True),
        "inviter_id": FieldSpec(type="string", required=True, references="user.id"),
        "expires_at": FieldSpec(type="date", required=True, input=False),
        "created_at": FieldSpec(type="date", required=True, input=False),
    },
)


def organization() -> Plugin:
    """Return a plugin adding organizations, members, invitations, and role checks."""
    return Plugin(
        id="organization",
        schema=(ORGANIZATION_TABLE, MEMBER_TABLE, INVITATION_TABLE),
        endpoints=(
            Endpoint("POST", "/organization/create", _create, "organization_create"),
            Endpoint("GET", "/organization/list", _list, "organization_list"),
            Endpoint("GET", "/organization/members", _members, "organization_members"),
            Endpoint("POST", "/organization/invite", _invite, "organization_invite"),
            Endpoint("POST", "/organization/accept-invitation", _accept, "organization_accept"),
            Endpoint("POST", "/organization/remove-member", _remove, "organization_remove"),
            Endpoint("POST", "/organization/update-role", _update_role, "organization_update_role"),
        ),
    )


async def _create(auth: Auth, req: EndpointRequest) -> EndpointResult:
    user = await _session_user(auth, req)
    name = _require(req.body, "name")
    slug = _require(req.body, "slug").lower()
    if await auth.adapter.find_one(model="organization", where=[Where("slug", slug)]) is not None:
        raise APIError(409, "slug_taken", "That organization slug is already in use.")
    now = utcnow()
    org: Row = {"id": new_id(), "name": name, "slug": slug, "created_at": now}
    await auth.adapter.create(model="organization", data=org)
    await _add_member(auth, org["id"], user["id"], "owner")
    return EndpointResult(data={"organization": org})


async def _list(auth: Auth, req: EndpointRequest) -> EndpointResult:
    user = await _session_user(auth, req)
    memberships = await auth.adapter.find_many(model="member", where=[Where("user_id", user["id"])])
    organizations = []
    for membership in memberships:
        org = await _organization(auth, membership["organization_id"])
        if org is not None:
            organizations.append({**org, "role": membership["role"]})
    return EndpointResult(data={"organizations": organizations})


async def _members(auth: Auth, req: EndpointRequest) -> EndpointResult:
    user = await _session_user(auth, req)
    org_id = req.query.get("organization_id") if req.query else None
    if not org_id:
        raise APIError(400, "invalid_request", "Missing organization_id.")
    await _require_role(auth, org_id, user["id"], "member")
    rows = await auth.adapter.find_many(model="member", where=[Where("organization_id", org_id)])
    members = []
    for row in rows:
        member_user = await svc.find_user_by_id(auth.adapter, row["user_id"])
        members.append(
            {
                "user_id": row["user_id"],
                "role": row["role"],
                "email": member_user["email"] if member_user else None,
            }
        )
    return EndpointResult(data={"members": members})


async def _invite(auth: Auth, req: EndpointRequest) -> EndpointResult:
    user = await _session_user(auth, req)
    org_id = _require(req.body, "organization_id")
    email = _require(req.body, "email").lower()
    role = req.body.get("role", "member")
    if role not in _ROLES:
        raise APIError(400, "invalid_role", "Unknown role.")
    await _require_role(auth, org_id, user["id"], "admin")

    now = utcnow()
    invitation: Row = {
        "id": new_id(),
        "organization_id": org_id,
        "email": email,
        "role": role,
        "status": "pending",
        "inviter_id": user["id"],
        "expires_at": now + timedelta(seconds=_INVITATION_TTL),
        "created_at": now,
    }
    await auth.adapter.create(model="invitation", data=invitation)
    if auth.email_sender is not None:
        await auth.email_sender.send(
            to=email, subject="You've been invited", body=f"Invitation id: {invitation['id']}"
        )
    return EndpointResult(data={"invitation": invitation})


async def _accept(auth: Auth, req: EndpointRequest) -> EndpointResult:
    user = await _session_user(auth, req)
    invitation_id = _require(req.body, "invitation_id")
    invitation = await auth.adapter.find_one(model="invitation", where=[Where("id", invitation_id)])
    if (
        invitation is None
        or invitation["status"] != "pending"
        or invitation["expires_at"] <= utcnow()
    ):
        raise APIError(400, "invalid_invitation", "The invitation is invalid or expired.")
    if invitation["email"] != user["email"]:
        raise APIError(403, "forbidden", "This invitation is for another email.")

    member = await _add_member(auth, invitation["organization_id"], user["id"], invitation["role"])
    await auth.adapter.update(
        model="invitation", where=[Where("id", invitation_id)], update={"status": "accepted"}
    )
    return EndpointResult(data={"member": member})


async def _remove(auth: Auth, req: EndpointRequest) -> EndpointResult:
    user = await _session_user(auth, req)
    org_id = _require(req.body, "organization_id")
    target_id = _require(req.body, "user_id")
    caller = await _require_role(auth, org_id, user["id"], "admin")
    target = await _member(auth, org_id, target_id)
    if target is None:
        raise APIError(404, "not_a_member", "That user is not a member.")
    if _rank(target["role"]) >= _rank(caller["role"]):
        raise APIError(403, "forbidden", "Cannot remove an equal or higher role.")
    await auth.adapter.delete(
        model="member", where=[Where("organization_id", org_id), Where("user_id", target_id)]
    )
    return EndpointResult(data={"success": True})


async def _update_role(auth: Auth, req: EndpointRequest) -> EndpointResult:
    user = await _session_user(auth, req)
    org_id = _require(req.body, "organization_id")
    target_id = _require(req.body, "user_id")
    role = _require(req.body, "role")
    if role not in _ROLES:
        raise APIError(400, "invalid_role", "Unknown role.")
    await _require_role(auth, org_id, user["id"], "owner")
    if await _member(auth, org_id, target_id) is None:
        raise APIError(404, "not_a_member", "That user is not a member.")
    await auth.adapter.update(
        model="member",
        where=[Where("organization_id", org_id), Where("user_id", target_id)],
        update={"role": role},
    )
    return EndpointResult(data={"success": True})


async def _session_user(auth: Auth, req: EndpointRequest) -> Row:
    token = auth.sessions.read_token(req.cookies)
    session = await auth.sessions.validate(token) if token else None
    if session is None:
        raise APIError(401, "unauthorized", "A valid session is required.")
    user = await svc.find_user_by_id(auth.adapter, session["user_id"])
    if user is None:
        raise APIError(401, "unauthorized", "A valid session is required.")
    return user


async def _organization(auth: Auth, org_id: str) -> Row | None:
    return await auth.adapter.find_one(model="organization", where=[Where("id", org_id)])


async def _member(auth: Auth, org_id: str, user_id: str) -> Row | None:
    return await auth.adapter.find_one(
        model="member", where=[Where("organization_id", org_id), Where("user_id", user_id)]
    )


async def _add_member(auth: Auth, org_id: str, user_id: str, role: str) -> Row:
    member: Row = {
        "id": new_id(),
        "organization_id": org_id,
        "user_id": user_id,
        "role": role,
        "created_at": utcnow(),
    }
    await auth.adapter.create(model="member", data=member)
    return member


async def _require_role(auth: Auth, org_id: str, user_id: str, minimum: str) -> Row:
    member = await _member(auth, org_id, user_id)
    if member is None or _rank(member["role"]) < _rank(minimum):
        raise APIError(403, "forbidden", "Insufficient organization role.")
    return member


def _rank(role: str) -> int:
    return _ROLES.index(role) if role in _ROLES else -1


def _require(body: dict[str, Any], key: str) -> str:
    value = body.get(key)
    if not isinstance(value, str) or not value:
        raise APIError(400, "invalid_request", f"Missing or invalid field: {key}.")
    return value
