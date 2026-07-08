from __future__ import annotations

import json

import pytest

import deadbolt as db
from _helpers import fast_hasher
from deadbolt.http import MultiDict
from deadbolt.plugins.organization import access_control, organization

pytestmark = pytest.mark.anyio


def build_auth() -> db.Auth:
    return db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=fast_hasher(),
        plugins=[organization()],
    )


def post(path: str, body: object, cookies: dict[str, str]) -> db.AuthRequest:
    return db.AuthRequest(method="POST", path=path, body=json.dumps(body).encode(), cookies=cookies)


async def signup(auth: db.Auth, email: str) -> dict[str, str]:
    resp = await auth.handle(
        db.AuthRequest(
            method="POST",
            path="/sign-up/email",
            body=json.dumps({"email": email, "password": "hunter2pw"}).encode(),
        )
    )
    return {c.name: c.value for c in resp.cookies if c.value}


async def create_org(auth: db.Auth, cookies: dict[str, str], slug: str = "acme") -> str:
    resp = await auth.handle(post("/organization/create", {"name": "Acme", "slug": slug}, cookies))
    assert resp.status == 200
    return str(json.loads(resp.body)["organization"]["id"])


async def test_create_makes_creator_owner() -> None:
    auth = build_auth()
    owner = await signup(auth, "owner@b.com")
    await create_org(auth, owner)
    listed = await auth.handle(
        db.AuthRequest(method="GET", path="/organization/list", cookies=owner)
    )
    orgs = json.loads(listed.body)["organizations"]
    assert len(orgs) == 1
    assert orgs[0]["role"] == "owner"


async def test_duplicate_slug_rejected() -> None:
    auth = build_auth()
    owner = await signup(auth, "owner@b.com")
    await create_org(auth, owner, slug="acme")
    resp = await auth.handle(post("/organization/create", {"name": "Other", "slug": "acme"}, owner))
    assert resp.status == 409


async def test_create_requires_session() -> None:
    auth = build_auth()
    resp = await auth.handle(
        db.AuthRequest(
            method="POST",
            path="/organization/create",
            body=json.dumps({"name": "X", "slug": "x"}).encode(),
        )
    )
    assert resp.status == 401


async def test_invite_accept_flow() -> None:
    auth = build_auth()
    owner = await signup(auth, "owner@b.com")
    invitee = await signup(auth, "invitee@b.com")
    org_id = await create_org(auth, owner)

    invited = await auth.handle(
        post(
            "/organization/invite",
            {"organization_id": org_id, "email": "invitee@b.com", "role": "admin"},
            owner,
        )
    )
    assert invited.status == 200
    invitation_id = json.loads(invited.body)["invitation"]["id"]

    accepted = await auth.handle(
        post("/organization/accept-invitation", {"invitation_id": invitation_id}, invitee)
    )
    assert accepted.status == 200
    assert json.loads(accepted.body)["member"]["role"] == "admin"

    listed = await auth.handle(
        db.AuthRequest(method="GET", path="/organization/list", cookies=invitee)
    )
    assert json.loads(listed.body)["organizations"][0]["role"] == "admin"


async def test_invite_requires_admin() -> None:
    auth = build_auth()
    owner = await signup(auth, "owner@b.com")
    member = await signup(auth, "member@b.com")
    org_id = await create_org(auth, owner)
    invited = await auth.handle(
        post("/organization/invite", {"organization_id": org_id, "email": "member@b.com"}, owner)
    )
    invitation_id = json.loads(invited.body)["invitation"]["id"]
    await auth.handle(
        post("/organization/accept-invitation", {"invitation_id": invitation_id}, member)
    )

    # the plain member tries to invite someone -> forbidden
    resp = await auth.handle(
        post("/organization/invite", {"organization_id": org_id, "email": "x@b.com"}, member)
    )
    assert resp.status == 403


async def test_accept_wrong_email_forbidden() -> None:
    auth = build_auth()
    owner = await signup(auth, "owner@b.com")
    other = await signup(auth, "other@b.com")
    org_id = await create_org(auth, owner)
    invited = await auth.handle(
        post("/organization/invite", {"organization_id": org_id, "email": "invitee@b.com"}, owner)
    )
    invitation_id = json.loads(invited.body)["invitation"]["id"]
    resp = await auth.handle(
        post("/organization/accept-invitation", {"invitation_id": invitation_id}, other)
    )
    assert resp.status == 403


async def test_members_list_and_update_role() -> None:
    auth = build_auth()
    owner = await signup(auth, "owner@b.com")
    member = await signup(auth, "member@b.com")
    org_id = await create_org(auth, owner)
    invited = await auth.handle(
        post("/organization/invite", {"organization_id": org_id, "email": "member@b.com"}, owner)
    )
    invitation_id = json.loads(invited.body)["invitation"]["id"]
    accepted = await auth.handle(
        post("/organization/accept-invitation", {"invitation_id": invitation_id}, member)
    )
    member_user_id = json.loads(accepted.body)["member"]["user_id"]

    members_req = db.AuthRequest(
        method="GET",
        path="/organization/list-members",
        query=MultiDict([("organization_id", org_id)]),
        cookies=owner,
    )
    members = json.loads((await auth.handle(members_req)).body)["members"]
    assert {m["email"] for m in members} == {"owner@b.com", "member@b.com"}

    promoted = await auth.handle(
        post(
            "/organization/update-role",
            {"organization_id": org_id, "user_id": member_user_id, "role": "admin"},
            owner,
        )
    )
    assert promoted.status == 200


async def test_invite_invalid_role() -> None:
    auth = build_auth()
    owner = await signup(auth, "owner@b.com")
    org_id = await create_org(auth, owner)
    body = {"organization_id": org_id, "email": "x@b.com", "role": "god"}
    resp = await auth.handle(post("/organization/invite", body, owner))
    assert resp.status == 400
    assert json.loads(resp.body)["error"]["code"] == "invalid_role"


async def test_members_requires_org_id() -> None:
    auth = build_auth()
    owner = await signup(auth, "owner@b.com")
    resp = await auth.handle(
        db.AuthRequest(method="GET", path="/organization/list-members", cookies=owner)
    )
    assert resp.status == 400


async def test_accept_invalid_invitation() -> None:
    auth = build_auth()
    user = await signup(auth, "u@b.com")
    resp = await auth.handle(
        post("/organization/accept-invitation", {"invitation_id": "nope"}, user)
    )
    assert resp.status == 400
    assert json.loads(resp.body)["error"]["code"] == "invalid_invitation"


async def test_update_role_requires_owner_and_membership() -> None:
    auth = build_auth()
    owner = await signup(auth, "owner@b.com")
    org_id = await create_org(auth, owner)
    resp = await auth.handle(
        post(
            "/organization/update-role",
            {"organization_id": org_id, "user_id": "ghost", "role": "admin"},
            owner,
        )
    )
    assert resp.status == 404


async def test_remove_member_permissions() -> None:
    auth = build_auth()
    owner = await signup(auth, "owner@b.com")
    member = await signup(auth, "member@b.com")
    org_id = await create_org(auth, owner)
    invited = await auth.handle(
        post("/organization/invite", {"organization_id": org_id, "email": "member@b.com"}, owner)
    )
    invitation_id = json.loads(invited.body)["invitation"]["id"]
    accepted = await auth.handle(
        post("/organization/accept-invitation", {"invitation_id": invitation_id}, member)
    )
    member_user_id = json.loads(accepted.body)["member"]["user_id"]

    # member cannot remove the owner
    owner_user = await auth.adapter.find_one(model="user", where=[db.Where("email", "owner@b.com")])
    assert owner_user is not None
    denied = await auth.handle(
        post(
            "/organization/remove-member",
            {"organization_id": org_id, "user_id": owner_user["id"]},
            member,
        )
    )
    assert denied.status == 403

    removed = await auth.handle(
        post(
            "/organization/remove-member",
            {"organization_id": org_id, "user_id": member_user_id},
            owner,
        )
    )
    assert removed.status == 200


async def _member_setup(auth: db.Auth) -> tuple[dict[str, str], dict[str, str], str, str]:
    owner = await signup(auth, "owner@b.com")
    member = await signup(auth, "member@b.com")
    org_id = await create_org(auth, owner)
    invited = await auth.handle(
        post("/organization/invite", {"organization_id": org_id, "email": "member@b.com"}, owner)
    )
    invitation_id = json.loads(invited.body)["invitation"]["id"]
    accepted = await auth.handle(
        post("/organization/accept-invitation", {"invitation_id": invitation_id}, member)
    )
    member_id = json.loads(accepted.body)["member"]["user_id"]
    return owner, member, org_id, member_id


async def test_has_permission() -> None:
    auth = build_auth()
    owner, member, org_id, _ = await _member_setup(auth)
    allowed = await auth.handle(
        post(
            "/organization/has-permission",
            {"organization_id": org_id, "permissions": {"organization": ["delete"]}},
            owner,
        )
    )
    assert json.loads(allowed.body)["allowed"] is True
    denied = await auth.handle(
        post(
            "/organization/has-permission",
            {"organization_id": org_id, "permissions": {"organization": ["delete"]}},
            member,
        )
    )
    assert json.loads(denied.body)["allowed"] is False


async def test_update_and_delete_organization() -> None:
    auth = build_auth()
    owner, member, org_id, _ = await _member_setup(auth)

    denied = await auth.handle(
        post("/organization/update", {"organization_id": org_id, "name": "Nope"}, member)
    )
    assert denied.status == 403

    updated = await auth.handle(
        post("/organization/update", {"organization_id": org_id, "name": "Renamed"}, owner)
    )
    assert json.loads(updated.body)["organization"]["name"] == "Renamed"

    deleted = await auth.handle(post("/organization/delete", {"organization_id": org_id}, owner))
    assert deleted.status == 200
    listed = await auth.handle(
        db.AuthRequest(method="GET", path="/organization/list", cookies=owner)
    )
    assert json.loads(listed.body)["organizations"] == []


async def test_leave_and_sole_owner_guard() -> None:
    auth = build_auth()
    owner, member, org_id, _ = await _member_setup(auth)

    sole = await auth.handle(post("/organization/leave", {"organization_id": org_id}, owner))
    assert sole.status == 400
    assert json.loads(sole.body)["error"]["code"] == "sole_owner"

    left = await auth.handle(post("/organization/leave", {"organization_id": org_id}, member))
    assert left.status == 200


async def test_reject_and_cancel_invitation() -> None:
    auth = build_auth()
    owner = await signup(auth, "owner@b.com")
    invitee = await signup(auth, "invitee@b.com")
    org_id = await create_org(auth, owner)

    inv1 = json.loads(
        (
            await auth.handle(
                post(
                    "/organization/invite",
                    {"organization_id": org_id, "email": "invitee@b.com"},
                    owner,
                )
            )
        ).body
    )["invitation"]["id"]
    rejected = await auth.handle(
        post("/organization/reject-invitation", {"invitation_id": inv1}, invitee)
    )
    assert rejected.status == 200

    inv2 = json.loads(
        (
            await auth.handle(
                post(
                    "/organization/invite",
                    {"organization_id": org_id, "email": "invitee@b.com"},
                    owner,
                )
            )
        ).body
    )["invitation"]["id"]
    canceled = await auth.handle(
        post("/organization/cancel-invitation", {"invitation_id": inv2}, owner)
    )
    assert canceled.status == 200

    listed = db.AuthRequest(
        method="GET",
        path="/organization/list-invitations",
        query=MultiDict([("organization_id", org_id)]),
        cookies=owner,
    )
    assert json.loads((await auth.handle(listed)).body)["invitations"] == []


async def test_active_organization() -> None:
    auth = build_auth()
    owner = await signup(auth, "owner@b.com")
    org_id = await create_org(auth, owner)
    set_resp = await auth.handle(
        post("/organization/set-active", {"organization_id": org_id}, owner)
    )
    assert json.loads(set_resp.body)["active_organization_id"] == org_id

    got = await auth.handle(
        db.AuthRequest(method="GET", path="/organization/get-active", cookies=owner)
    )
    assert json.loads(got.body)["organization"]["id"] == org_id


async def test_get_full_organization_uses_active() -> None:
    auth = build_auth()
    owner = await signup(auth, "owner@b.com")
    org_id = await create_org(auth, owner)
    await auth.handle(post("/organization/set-active", {"organization_id": org_id}, owner))
    full = await auth.handle(
        db.AuthRequest(method="GET", path="/organization/get-full", cookies=owner)
    )
    body = json.loads(full.body)
    assert body["organization"]["id"] == org_id
    assert len(body["members"]) == 1


async def test_has_permission_requires_object() -> None:
    auth = build_auth()
    owner = await signup(auth, "owner@b.com")
    org_id = await create_org(auth, owner)
    resp = await auth.handle(
        post(
            "/organization/has-permission", {"organization_id": org_id, "permissions": "bad"}, owner
        )
    )
    assert resp.status == 400


async def test_update_org_slug_conflict() -> None:
    auth = build_auth()
    owner = await signup(auth, "owner@b.com")
    first = await create_org(auth, owner, slug="acme")
    await create_org(auth, owner, slug="beta")
    resp = await auth.handle(
        post("/organization/update", {"organization_id": first, "slug": "beta"}, owner)
    )
    assert resp.status == 409


async def test_leave_when_not_member() -> None:
    auth = build_auth()
    owner = await signup(auth, "owner@b.com")
    stranger = await signup(auth, "stranger@b.com")
    org_id = await create_org(auth, owner)
    resp = await auth.handle(post("/organization/leave", {"organization_id": org_id}, stranger))
    assert resp.status == 404


def build_custom_auth() -> db.Auth:
    ac = access_control(
        roles={
            "owner": {
                "organization": ["update", "delete"],
                "invitation": ["create", "cancel"],
                "billing": ["manage"],
            },
            "billing": {"billing": ["manage"]},
            "viewer": {},
        },
        hierarchy=("viewer", "billing", "owner"),
        creator_role="owner",
        invite_default="viewer",
    )
    return db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=fast_hasher(),
        plugins=[organization(access=ac)],
    )


async def test_custom_roles_and_permissions() -> None:
    auth = build_custom_auth()
    owner = await signup(auth, "owner@b.com")
    org_id = await create_org(auth, owner)

    can_bill = await auth.handle(
        post(
            "/organization/has-permission",
            {"organization_id": org_id, "permissions": {"billing": ["manage"]}},
            owner,
        )
    )
    assert json.loads(can_bill.body)["allowed"] is True

    invited = await auth.handle(
        post(
            "/organization/invite",
            {"organization_id": org_id, "email": "v@b.com", "role": "viewer"},
            owner,
        )
    )
    assert invited.status == 200
    assert json.loads(invited.body)["invitation"]["role"] == "viewer"


async def test_custom_role_unknown_rejected() -> None:
    auth = build_custom_auth()
    owner = await signup(auth, "owner@b.com")
    org_id = await create_org(auth, owner)
    resp = await auth.handle(
        post(
            "/organization/invite",
            {"organization_id": org_id, "email": "x@b.com", "role": "admin"},
            owner,
        )
    )
    assert resp.status == 400
    assert json.loads(resp.body)["error"]["code"] == "invalid_role"


async def _team_setup(auth: db.Auth) -> tuple[dict[str, str], dict[str, str], str, str, str]:
    owner, member, org_id, member_id = await _member_setup(auth)
    created = await auth.handle(
        post("/organization/create-team", {"organization_id": org_id, "name": "Eng"}, owner)
    )
    team_id = json.loads(created.body)["team"]["id"]
    return owner, member, org_id, member_id, team_id


async def test_team_lifecycle() -> None:
    auth = build_auth()
    owner, _member, org_id, member_id, team_id = await _team_setup(auth)

    listed = db.AuthRequest(
        method="GET",
        path="/organization/list-teams",
        query=MultiDict([("organization_id", org_id)]),
        cookies=owner,
    )
    teams = json.loads((await auth.handle(listed)).body)["teams"]
    assert [t["name"] for t in teams] == ["Eng"]

    renamed = await auth.handle(
        post("/organization/update-team", {"team_id": team_id, "name": "Platform"}, owner)
    )
    assert json.loads(renamed.body)["team"]["name"] == "Platform"

    added = await auth.handle(
        post("/organization/add-team-member", {"team_id": team_id, "user_id": member_id}, owner)
    )
    assert added.status == 200
    members_req = db.AuthRequest(
        method="GET",
        path="/organization/list-team-members",
        query=MultiDict([("team_id", team_id)]),
        cookies=owner,
    )
    assert len(json.loads((await auth.handle(members_req)).body)["members"]) == 1

    await auth.handle(
        post("/organization/remove-team-member", {"team_id": team_id, "user_id": member_id}, owner)
    )
    removed = await auth.handle(post("/organization/remove-team", {"team_id": team_id}, owner))
    assert removed.status == 200


async def test_team_create_requires_permission() -> None:
    auth = build_auth()
    _owner, member, org_id, _ = await _member_setup(auth)
    resp = await auth.handle(
        post("/organization/create-team", {"organization_id": org_id, "name": "X"}, member)
    )
    assert resp.status == 403


async def test_add_team_member_requires_org_member() -> None:
    auth = build_auth()
    owner, _m, _org_id, _mid, team_id = await _team_setup(auth)
    resp = await auth.handle(
        post("/organization/add-team-member", {"team_id": team_id, "user_id": "ghost"}, owner)
    )
    assert resp.status == 400
