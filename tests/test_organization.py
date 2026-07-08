from __future__ import annotations

import json

import pytest

import deadbolt as db
from _helpers import fast_hasher
from deadbolt.http import MultiDict
from deadbolt.plugins.organization import organization

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
        path="/organization/members",
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
        db.AuthRequest(method="GET", path="/organization/members", cookies=owner)
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
