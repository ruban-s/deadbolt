"""Organizations with configurable role-based access control and teams.

Roles are defined by an :class:`AccessControl` that maps each role to a set of
``resource -> actions`` permissions plus a low-to-high hierarchy. The default
mirrors owner > admin > member; pass a custom one to ``organization()`` to define
your own roles and permissions (Better Auth's access-control model).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from functools import partial
from typing import TYPE_CHECKING, Any

from .._util import new_id, utcnow
from ..db.types import FieldSpec, Row, TableSpec, Where
from ..endpoints import _service as svc
from ..endpoints.context import EndpointResult
from ..endpoints.registry import Endpoint
from ..errors import APIError
from . import Plugin

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

    from ..core.auth import Auth
    from ..endpoints.context import EndpointRequest

_INVITATION_TTL = 7 * 24 * 60 * 60


@dataclass(frozen=True)
class AccessControl:
    """Role definitions: permissions per role plus a low-to-high hierarchy."""

    roles: dict[str, dict[str, frozenset[str]]]
    hierarchy: tuple[str, ...]
    creator_role: str = "owner"
    invite_default: str = "member"

    def rank(self, role: str) -> int:
        return self.hierarchy.index(role) if role in self.hierarchy else -1

    def allows(self, role: str, required: Mapping[str, Iterable[str]]) -> bool:
        granted = self.roles.get(role, {})
        return all(
            set(actions) <= granted.get(resource, frozenset())
            for resource, actions in required.items()
        )


def access_control(
    *,
    roles: Mapping[str, Mapping[str, Iterable[str]]],
    hierarchy: Sequence[str],
    creator_role: str = "owner",
    invite_default: str = "member",
) -> AccessControl:
    """Build an :class:`AccessControl` from a role -> resource -> actions map."""
    normalized = {
        role: {resource: frozenset(actions) for resource, actions in perms.items()}
        for role, perms in roles.items()
    }
    return AccessControl(
        roles=normalized,
        hierarchy=tuple(hierarchy),
        creator_role=creator_role,
        invite_default=invite_default,
    )


DEFAULT_ACCESS_CONTROL = access_control(
    roles={
        "owner": {
            "organization": ["update", "delete"],
            "member": ["create", "update", "delete"],
            "invitation": ["create", "cancel"],
            "team": ["create", "update", "delete"],
        },
        "admin": {
            "member": ["create", "update", "delete"],
            "invitation": ["create", "cancel"],
            "team": ["create", "update", "delete"],
        },
        "member": {},
    },
    hierarchy=("member", "admin", "owner"),
)

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

ACTIVE_ORGANIZATION_TABLE = TableSpec(
    model="active_organization",
    fields={
        "id": FieldSpec(type="string", required=True, unique=True, input=False),
        "user_id": FieldSpec(type="string", required=True, unique=True, references="user.id"),
        "organization_id": FieldSpec(type="string", required=True, references="organization.id"),
        "updated_at": FieldSpec(type="date", required=True, input=False),
    },
)

TEAM_TABLE = TableSpec(
    model="team",
    fields={
        "id": FieldSpec(type="string", required=True, unique=True, input=False),
        "organization_id": FieldSpec(type="string", required=True, references="organization.id"),
        "name": FieldSpec(type="string", required=True),
        "created_at": FieldSpec(type="date", required=True, input=False),
    },
)

TEAM_MEMBER_TABLE = TableSpec(
    model="team_member",
    fields={
        "id": FieldSpec(type="string", required=True, unique=True, input=False),
        "team_id": FieldSpec(type="string", required=True, references="team.id"),
        "user_id": FieldSpec(type="string", required=True, references="user.id"),
        "created_at": FieldSpec(type="date", required=True, input=False),
    },
)

_TABLES = (
    ORGANIZATION_TABLE,
    MEMBER_TABLE,
    INVITATION_TABLE,
    ACTIVE_ORGANIZATION_TABLE,
    TEAM_TABLE,
    TEAM_MEMBER_TABLE,
)


def organization(*, access: AccessControl | None = None) -> Plugin:
    """Return the organizations plugin. Pass ``access`` to define custom roles."""
    ac = access or DEFAULT_ACCESS_CONTROL

    def endpoint(method: str, path: str, handler: Any, name: str) -> Endpoint:
        return Endpoint(method, path, partial(handler, ac=ac), name)

    return Plugin(
        id="organization",
        schema=_TABLES,
        endpoints=(
            endpoint("POST", "/organization/create", _create, "organization_create"),
            endpoint("POST", "/organization/update", _update, "organization_update"),
            endpoint("POST", "/organization/delete", _delete, "organization_delete"),
            endpoint("GET", "/organization/list", _list, "organization_list"),
            endpoint("GET", "/organization/get-full", _get_full, "organization_get_full"),
            endpoint("POST", "/organization/set-active", _set_active, "organization_set_active"),
            endpoint("GET", "/organization/get-active", _get_active, "organization_get_active"),
            endpoint("GET", "/organization/list-members", _members, "organization_members"),
            endpoint("POST", "/organization/remove-member", _remove, "organization_remove"),
            endpoint("POST", "/organization/update-role", _update_role, "organization_update_role"),
            endpoint("POST", "/organization/leave", _leave, "organization_leave"),
            endpoint("POST", "/organization/has-permission", _has_perm, "organization_has_perm"),
            endpoint("POST", "/organization/invite", _invite, "organization_invite"),
            endpoint("POST", "/organization/accept-invitation", _accept, "organization_accept"),
            endpoint("POST", "/organization/reject-invitation", _reject, "organization_reject"),
            endpoint("POST", "/organization/cancel-invitation", _cancel, "organization_cancel"),
            endpoint(
                "GET", "/organization/list-invitations", _list_invites, "organization_invites"
            ),
            endpoint("POST", "/organization/create-team", _create_team, "org_create_team"),
            endpoint("GET", "/organization/list-teams", _list_teams, "org_list_teams"),
            endpoint("POST", "/organization/update-team", _update_team, "org_update_team"),
            endpoint("POST", "/organization/remove-team", _remove_team, "org_remove_team"),
            endpoint(
                "POST", "/organization/add-team-member", _add_team_member, "org_add_team_member"
            ),
            endpoint(
                "POST",
                "/organization/remove-team-member",
                _remove_team_member,
                "org_remove_team_member",
            ),
            endpoint(
                "GET", "/organization/list-team-members", _team_members, "org_team_members"
            ),
        ),
    )


async def _create(auth: Auth, req: EndpointRequest, *, ac: AccessControl) -> EndpointResult:
    user = await _session_user(auth, req)
    name = _require(req.body, "name")
    slug = _require(req.body, "slug").lower()
    if await _org_by_slug(auth, slug) is not None:
        raise APIError(409, "slug_taken", "That organization slug is already in use.")
    now = utcnow()
    org: Row = {"id": new_id(), "name": name, "slug": slug, "created_at": now}
    await auth.adapter.create(model="organization", data=org)
    await _add_member(auth, org["id"], user["id"], ac.creator_role)
    return EndpointResult(data={"organization": org})


async def _update(auth: Auth, req: EndpointRequest, *, ac: AccessControl) -> EndpointResult:
    user = await _session_user(auth, req)
    org_id = _require(req.body, "organization_id")
    await _authorize(auth, ac, org_id, user["id"], "organization", "update")
    update: Row = {}
    if isinstance(req.body.get("name"), str):
        update["name"] = req.body["name"]
    if isinstance(req.body.get("slug"), str):
        slug = req.body["slug"].lower()
        existing = await _org_by_slug(auth, slug)
        if existing is not None and existing["id"] != org_id:
            raise APIError(409, "slug_taken", "That organization slug is already in use.")
        update["slug"] = slug
    org = await auth.adapter.update(
        model="organization", where=[Where("id", org_id)], update=update
    )
    return EndpointResult(data={"organization": org})


async def _delete(auth: Auth, req: EndpointRequest, *, ac: AccessControl) -> EndpointResult:
    user = await _session_user(auth, req)
    org_id = _require(req.body, "organization_id")
    await _authorize(auth, ac, org_id, user["id"], "organization", "delete")
    org_teams = await auth.adapter.find_many(model="team", where=[Where("organization_id", org_id)])
    for team in org_teams:
        await auth.adapter.delete_many(model="team_member", where=[Where("team_id", team["id"])])
    for model in ("member", "invitation", "active_organization", "team"):
        await auth.adapter.delete_many(model=model, where=[Where("organization_id", org_id)])
    await auth.adapter.delete(model="organization", where=[Where("id", org_id)])
    return EndpointResult(data={"success": True})


async def _list(auth: Auth, req: EndpointRequest, *, ac: AccessControl) -> EndpointResult:
    user = await _session_user(auth, req)
    memberships = await auth.adapter.find_many(
        model="member", where=[Where("user_id", user["id"])]
    )
    organizations = []
    for membership in memberships:
        org = await _organization(auth, membership["organization_id"])
        if org is not None:
            organizations.append({**org, "role": membership["role"]})
    return EndpointResult(data={"organizations": organizations})


async def _get_full(auth: Auth, req: EndpointRequest, *, ac: AccessControl) -> EndpointResult:
    user = await _session_user(auth, req)
    org_id = _query_org(req) or await _active_org_id(auth, user["id"])
    if not org_id:
        raise APIError(400, "invalid_request", "No organization specified or active.")
    await _authorize_member(auth, org_id, user["id"])
    org = await _organization(auth, org_id)
    members = await _member_list(auth, org_id)
    invitations = await _pending_invitations(auth, org_id)
    teams = await auth.adapter.find_many(model="team", where=[Where("organization_id", org_id)])
    return EndpointResult(
        data={"organization": org, "members": members, "invitations": invitations, "teams": teams}
    )


async def _set_active(auth: Auth, req: EndpointRequest, *, ac: AccessControl) -> EndpointResult:
    user = await _session_user(auth, req)
    org_id = _require(req.body, "organization_id")
    await _authorize_member(auth, org_id, user["id"])
    now = utcnow()
    existing = await auth.adapter.find_one(
        model="active_organization", where=[Where("user_id", user["id"])]
    )
    if existing is None:
        await auth.adapter.create(
            model="active_organization",
            data={
                "id": new_id(),
                "user_id": user["id"],
                "organization_id": org_id,
                "updated_at": now,
            },
        )
    else:
        await auth.adapter.update(
            model="active_organization",
            where=[Where("user_id", user["id"])],
            update={"organization_id": org_id, "updated_at": now},
        )
    return EndpointResult(data={"active_organization_id": org_id})


async def _get_active(auth: Auth, req: EndpointRequest, *, ac: AccessControl) -> EndpointResult:
    user = await _session_user(auth, req)
    org_id = await _active_org_id(auth, user["id"])
    org = await _organization(auth, org_id) if org_id else None
    return EndpointResult(data={"active_organization_id": org_id, "organization": org})


async def _members(auth: Auth, req: EndpointRequest, *, ac: AccessControl) -> EndpointResult:
    user = await _session_user(auth, req)
    org_id = _require_query_org(req)
    await _authorize_member(auth, org_id, user["id"])
    return EndpointResult(data={"members": await _member_list(auth, org_id)})


async def _remove(auth: Auth, req: EndpointRequest, *, ac: AccessControl) -> EndpointResult:
    user = await _session_user(auth, req)
    org_id = _require(req.body, "organization_id")
    target_id = _require(req.body, "user_id")
    caller = await _authorize(auth, ac, org_id, user["id"], "member", "delete")
    target = await _member(auth, org_id, target_id)
    if target is None:
        raise APIError(404, "not_a_member", "That user is not a member.")
    if ac.rank(target["role"]) >= ac.rank(caller["role"]):
        raise APIError(403, "forbidden", "Cannot remove an equal or higher role.")
    await auth.adapter.delete(
        model="member", where=[Where("organization_id", org_id), Where("user_id", target_id)]
    )
    return EndpointResult(data={"success": True})


async def _update_role(auth: Auth, req: EndpointRequest, *, ac: AccessControl) -> EndpointResult:
    user = await _session_user(auth, req)
    org_id = _require(req.body, "organization_id")
    target_id = _require(req.body, "user_id")
    role = _require(req.body, "role")
    if role not in ac.roles:
        raise APIError(400, "invalid_role", "Unknown role.")
    caller = await _authorize(auth, ac, org_id, user["id"], "member", "update")
    if ac.rank(role) > ac.rank(caller["role"]):
        raise APIError(403, "forbidden", "Cannot grant a role above your own.")
    if await _member(auth, org_id, target_id) is None:
        raise APIError(404, "not_a_member", "That user is not a member.")
    await auth.adapter.update(
        model="member",
        where=[Where("organization_id", org_id), Where("user_id", target_id)],
        update={"role": role},
    )
    return EndpointResult(data={"success": True})


async def _leave(auth: Auth, req: EndpointRequest, *, ac: AccessControl) -> EndpointResult:
    user = await _session_user(auth, req)
    org_id = _require(req.body, "organization_id")
    member = await _member(auth, org_id, user["id"])
    if member is None:
        raise APIError(404, "not_a_member", "You are not a member.")
    if member["role"] == ac.creator_role and await _count_role(auth, org_id, ac.creator_role) <= 1:
        raise APIError(400, "sole_owner", "Transfer ownership or delete the organization first.")
    await auth.adapter.delete(
        model="member", where=[Where("organization_id", org_id), Where("user_id", user["id"])]
    )
    return EndpointResult(data={"success": True})


async def _has_perm(auth: Auth, req: EndpointRequest, *, ac: AccessControl) -> EndpointResult:
    user = await _session_user(auth, req)
    org_id = _require(req.body, "organization_id")
    required = req.body.get("permissions")
    if not isinstance(required, dict):
        raise APIError(400, "invalid_request", "permissions must be an object.")
    member = await _member(auth, org_id, user["id"])
    allowed = member is not None and ac.allows(member["role"], required)
    return EndpointResult(data={"allowed": allowed})


async def _invite(auth: Auth, req: EndpointRequest, *, ac: AccessControl) -> EndpointResult:
    user = await _session_user(auth, req)
    org_id = _require(req.body, "organization_id")
    email = _require(req.body, "email").lower()
    role = req.body.get("role", ac.invite_default)
    if role not in ac.roles:
        raise APIError(400, "invalid_role", "Unknown role.")
    caller = await _authorize(auth, ac, org_id, user["id"], "invitation", "create")
    if ac.rank(role) > ac.rank(caller["role"]):
        raise APIError(403, "forbidden", "Cannot invite at a role above your own.")

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


async def _accept(auth: Auth, req: EndpointRequest, *, ac: AccessControl) -> EndpointResult:
    user = await _session_user(auth, req)
    invitation = await _pending_invitation(auth, _require(req.body, "invitation_id"))
    if invitation["email"] != user["email"]:
        raise APIError(403, "forbidden", "This invitation is for another email.")
    member = await _add_member(auth, invitation["organization_id"], user["id"], invitation["role"])
    await _set_invitation_status(auth, invitation["id"], "accepted")
    return EndpointResult(data={"member": member})


async def _reject(auth: Auth, req: EndpointRequest, *, ac: AccessControl) -> EndpointResult:
    user = await _session_user(auth, req)
    invitation = await _pending_invitation(auth, _require(req.body, "invitation_id"))
    if invitation["email"] != user["email"]:
        raise APIError(403, "forbidden", "This invitation is for another email.")
    await _set_invitation_status(auth, invitation["id"], "rejected")
    return EndpointResult(data={"success": True})


async def _cancel(auth: Auth, req: EndpointRequest, *, ac: AccessControl) -> EndpointResult:
    user = await _session_user(auth, req)
    invitation = await _pending_invitation(auth, _require(req.body, "invitation_id"))
    await _authorize(auth, ac, invitation["organization_id"], user["id"], "invitation", "cancel")
    await _set_invitation_status(auth, invitation["id"], "canceled")
    return EndpointResult(data={"success": True})


async def _list_invites(auth: Auth, req: EndpointRequest, *, ac: AccessControl) -> EndpointResult:
    user = await _session_user(auth, req)
    org_id = _require_query_org(req)
    await _authorize_member(auth, org_id, user["id"])
    return EndpointResult(data={"invitations": await _pending_invitations(auth, org_id)})


async def _create_team(auth: Auth, req: EndpointRequest, *, ac: AccessControl) -> EndpointResult:
    user = await _session_user(auth, req)
    org_id = _require(req.body, "organization_id")
    name = _require(req.body, "name")
    await _authorize(auth, ac, org_id, user["id"], "team", "create")
    team: Row = {
        "id": new_id(),
        "organization_id": org_id,
        "name": name,
        "created_at": utcnow(),
    }
    await auth.adapter.create(model="team", data=team)
    return EndpointResult(data={"team": team})


async def _list_teams(auth: Auth, req: EndpointRequest, *, ac: AccessControl) -> EndpointResult:
    user = await _session_user(auth, req)
    org_id = _require_query_org(req)
    await _authorize_member(auth, org_id, user["id"])
    teams = await auth.adapter.find_many(model="team", where=[Where("organization_id", org_id)])
    return EndpointResult(data={"teams": teams})


async def _update_team(auth: Auth, req: EndpointRequest, *, ac: AccessControl) -> EndpointResult:
    user = await _session_user(auth, req)
    team = await _team(auth, _require(req.body, "team_id"))
    await _authorize(auth, ac, team["organization_id"], user["id"], "team", "update")
    updated = await auth.adapter.update(
        model="team", where=[Where("id", team["id"])], update={"name": _require(req.body, "name")}
    )
    return EndpointResult(data={"team": updated})


async def _remove_team(auth: Auth, req: EndpointRequest, *, ac: AccessControl) -> EndpointResult:
    user = await _session_user(auth, req)
    team = await _team(auth, _require(req.body, "team_id"))
    await _authorize(auth, ac, team["organization_id"], user["id"], "team", "delete")
    await auth.adapter.delete_many(model="team_member", where=[Where("team_id", team["id"])])
    await auth.adapter.delete(model="team", where=[Where("id", team["id"])])
    return EndpointResult(data={"success": True})


async def _add_team_member(
    auth: Auth, req: EndpointRequest, *, ac: AccessControl
) -> EndpointResult:
    user = await _session_user(auth, req)
    team = await _team(auth, _require(req.body, "team_id"))
    target_id = _require(req.body, "user_id")
    await _authorize(auth, ac, team["organization_id"], user["id"], "team", "update")
    if await _member(auth, team["organization_id"], target_id) is None:
        raise APIError(400, "not_a_member", "The user must be an organization member first.")
    if await _team_member(auth, team["id"], target_id) is not None:
        return EndpointResult(data={"success": True})
    await auth.adapter.create(
        model="team_member",
        data={"id": new_id(), "team_id": team["id"], "user_id": target_id, "created_at": utcnow()},
    )
    return EndpointResult(data={"success": True})


async def _remove_team_member(
    auth: Auth, req: EndpointRequest, *, ac: AccessControl
) -> EndpointResult:
    user = await _session_user(auth, req)
    team = await _team(auth, _require(req.body, "team_id"))
    target_id = _require(req.body, "user_id")
    await _authorize(auth, ac, team["organization_id"], user["id"], "team", "update")
    await auth.adapter.delete(
        model="team_member", where=[Where("team_id", team["id"]), Where("user_id", target_id)]
    )
    return EndpointResult(data={"success": True})


async def _team_members(auth: Auth, req: EndpointRequest, *, ac: AccessControl) -> EndpointResult:
    user = await _session_user(auth, req)
    team = await _team(auth, _require_query(req, "team_id"))
    await _authorize_member(auth, team["organization_id"], user["id"])
    rows = await auth.adapter.find_many(model="team_member", where=[Where("team_id", team["id"])])
    members = [{"user_id": row["user_id"]} for row in rows]
    return EndpointResult(data={"members": members})


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


async def _org_by_slug(auth: Auth, slug: str) -> Row | None:
    return await auth.adapter.find_one(model="organization", where=[Where("slug", slug)])


async def _member(auth: Auth, org_id: str, user_id: str) -> Row | None:
    return await auth.adapter.find_one(
        model="member", where=[Where("organization_id", org_id), Where("user_id", user_id)]
    )


async def _member_list(auth: Auth, org_id: str) -> list[Row]:
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
    return members


async def _count_role(auth: Auth, org_id: str, role: str) -> int:
    return await auth.adapter.count(
        model="member", where=[Where("organization_id", org_id), Where("role", role)]
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


async def _active_org_id(auth: Auth, user_id: str) -> str | None:
    row = await auth.adapter.find_one(
        model="active_organization", where=[Where("user_id", user_id)]
    )
    return row["organization_id"] if row is not None else None


async def _team(auth: Auth, team_id: str) -> Row:
    team = await auth.adapter.find_one(model="team", where=[Where("id", team_id)])
    if team is None:
        raise APIError(404, "team_not_found", "No such team.")
    return team


async def _team_member(auth: Auth, team_id: str, user_id: str) -> Row | None:
    return await auth.adapter.find_one(
        model="team_member", where=[Where("team_id", team_id), Where("user_id", user_id)]
    )


async def _pending_invitations(auth: Auth, org_id: str) -> list[Row]:
    return await auth.adapter.find_many(
        model="invitation",
        where=[Where("organization_id", org_id), Where("status", "pending")],
    )


async def _pending_invitation(auth: Auth, invitation_id: str) -> Row:
    invitation = await auth.adapter.find_one(
        model="invitation", where=[Where("id", invitation_id)]
    )
    if (
        invitation is None
        or invitation["status"] != "pending"
        or invitation["expires_at"] <= utcnow()
    ):
        raise APIError(400, "invalid_invitation", "The invitation is invalid or expired.")
    return invitation


async def _set_invitation_status(auth: Auth, invitation_id: str, status: str) -> None:
    await auth.adapter.update(
        model="invitation", where=[Where("id", invitation_id)], update={"status": status}
    )


async def _authorize(
    auth: Auth, ac: AccessControl, org_id: str, user_id: str, resource: str, action: str
) -> Row:
    member = await _member(auth, org_id, user_id)
    if member is None or not ac.allows(member["role"], {resource: [action]}):
        raise APIError(403, "forbidden", "Insufficient permissions.")
    return member


async def _authorize_member(auth: Auth, org_id: str, user_id: str) -> Row:
    member = await _member(auth, org_id, user_id)
    if member is None:
        raise APIError(403, "forbidden", "You are not a member of this organization.")
    return member


def _query_org(req: EndpointRequest) -> str | None:
    return req.query.get("organization_id") if req.query else None


def _require_query_org(req: EndpointRequest) -> str:
    org_id = _query_org(req)
    if not org_id:
        raise APIError(400, "invalid_request", "Missing organization_id.")
    return org_id


def _require_query(req: EndpointRequest, key: str) -> str:
    value = req.query.get(key) if req.query else None
    if not value:
        raise APIError(400, "invalid_request", f"Missing {key}.")
    return value


def _require(body: dict[str, Any], key: str) -> str:
    value = body.get(key)
    if not isinstance(value, str) or not value:
        raise APIError(400, "invalid_request", f"Missing or invalid field: {key}.")
    return value
