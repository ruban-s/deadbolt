from __future__ import annotations

import json

import pytest

import deadbolt as db
from _helpers import fast_hasher

pytestmark = pytest.mark.anyio


class CapturingEmail:
    def __init__(self) -> None:
        self.token: str | None = None

    async def send(self, *, to: str, subject: str, body: str) -> None:
        self.token = body.rsplit(":", 1)[1].strip()


def build_auth(
    *, require_verification: bool = False, email: CapturingEmail | None = None
) -> db.Auth:
    return db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(
            enabled=True, require_email_verification=require_verification
        ),
        hasher=fast_hasher(),
        email_sender=email,
    )


def post(path: str, body: object, cookies: dict[str, str] | None = None) -> db.AuthRequest:
    return db.AuthRequest(
        method="POST", path=path, body=json.dumps(body).encode(), cookies=cookies or {}
    )


async def signup(auth: db.Auth, email: str = "a@b.com") -> dict[str, str]:
    resp = await auth.handle(post("/sign-up/email", {"email": email, "password": "hunter2pw"}))
    return {c.name: c.value for c in resp.cookies if c.value}


async def test_email_verification_flow_and_gate() -> None:
    mail = CapturingEmail()
    auth = build_auth(require_verification=True, email=mail)
    await signup(auth)

    blocked = await auth.handle(
        post("/sign-in/email", {"email": "a@b.com", "password": "hunter2pw"})
    )
    assert blocked.status == 403
    assert json.loads(blocked.body)["error"]["code"] == "email_not_verified"

    await auth.handle(post("/send-verification-email", {"email": "a@b.com"}))
    assert mail.token is not None
    verified = await auth.handle(post("/verify-email", {"token": mail.token}))
    assert verified.status == 200

    ok = await auth.handle(post("/sign-in/email", {"email": "a@b.com", "password": "hunter2pw"}))
    assert ok.status == 200


async def test_update_user() -> None:
    auth = build_auth()
    cookies = await signup(auth)
    resp = await auth.handle(
        post("/update-user", {"name": "Alice", "image": "http://x/a.png"}, cookies)
    )
    user = json.loads(resp.body)["user"]
    assert user["name"] == "Alice"
    assert user["image"] == "http://x/a.png"


async def test_change_email_immediate() -> None:
    auth = build_auth()
    cookies = await signup(auth)
    resp = await auth.handle(post("/change-email", {"new_email": "new@b.com"}, cookies))
    assert json.loads(resp.body)["user"]["email"] == "new@b.com"


async def test_change_email_with_verification() -> None:
    mail = CapturingEmail()
    auth = build_auth(require_verification=True, email=mail)
    cookies = await signup(auth)
    resp = await auth.handle(post("/change-email", {"new_email": "new@b.com"}, cookies))
    assert json.loads(resp.body)["status"] == "verification_sent"
    confirmed = await auth.handle(post("/verify-email", {"token": mail.token}))
    assert confirmed.status == 200
    session = await auth.handle(db.AuthRequest(method="GET", path="/get-session", cookies=cookies))
    assert json.loads(session.body)["user"]["email"] == "new@b.com"


async def test_change_email_conflict() -> None:
    auth = build_auth()
    cookies = await signup(auth, "a@b.com")
    await signup(auth, "taken@b.com")
    resp = await auth.handle(post("/change-email", {"new_email": "taken@b.com"}, cookies))
    assert resp.status == 409


async def test_delete_user() -> None:
    auth = build_auth()
    cookies = await signup(auth)
    resp = await auth.handle(post("/delete-user", {"password": "hunter2pw"}, cookies))
    assert resp.status == 200
    gone = await auth.handle(post("/sign-in/email", {"email": "a@b.com", "password": "hunter2pw"}))
    assert gone.status == 401


async def test_delete_user_wrong_password() -> None:
    auth = build_auth()
    cookies = await signup(auth)
    resp = await auth.handle(post("/delete-user", {"password": "wrongpass"}, cookies))
    assert resp.status == 401


async def test_session_management() -> None:
    auth = build_auth()
    first = await signup(auth)
    # a second session for the same user
    second_resp = await auth.handle(
        post("/sign-in/email", {"email": "a@b.com", "password": "hunter2pw"})
    )
    second = {c.name: c.value for c in second_resp.cookies if c.value}

    listed = await auth.handle(db.AuthRequest(method="GET", path="/list-sessions", cookies=first))
    sessions = json.loads(listed.body)["sessions"]
    assert len(sessions) == 2
    assert all("token" not in s for s in sessions)

    revoked = await auth.handle(post("/revoke-other-sessions", {}, first))
    assert json.loads(revoked.body)["revoked"] == 1
    # the second session is now invalid
    check = await auth.handle(db.AuthRequest(method="GET", path="/get-session", cookies=second))
    assert json.loads(check.body)["user"] is None


async def test_revoke_specific_session() -> None:
    auth = build_auth()
    cookies = await signup(auth)
    listed = await auth.handle(db.AuthRequest(method="GET", path="/list-sessions", cookies=cookies))
    session_id = json.loads(listed.body)["sessions"][0]["id"]
    revoked = await auth.handle(post("/revoke-session", {"session_id": session_id}, cookies))
    assert json.loads(revoked.body)["success"] is True


async def test_list_and_unlink_accounts() -> None:
    auth = build_auth()
    cookies = await signup(auth)
    listed = await auth.handle(db.AuthRequest(method="GET", path="/list-accounts", cookies=cookies))
    accounts = json.loads(listed.body)["accounts"]
    assert len(accounts) == 1
    assert accounts[0]["provider_id"] == "credential"
    assert "password" not in accounts[0]

    # cannot unlink the only account
    resp = await auth.handle(post("/unlink-account", {"provider_id": "credential"}, cookies))
    assert resp.status == 400
    assert json.loads(resp.body)["error"]["code"] == "last_account"


async def test_endpoints_require_session() -> None:
    auth = build_auth()
    for path in ("/update-user", "/delete-user", "/revoke-session", "/unlink-account"):
        resp = await auth.handle(post(path, {}))
        assert resp.status == 401, path
    for path in ("/list-sessions", "/list-accounts"):
        resp = await auth.handle(db.AuthRequest(method="GET", path=path))
        assert resp.status == 401, path


async def test_unlink_secondary_account() -> None:
    auth = build_auth()
    cookies = await signup(auth)
    user = await auth.adapter.find_one(model="user", where=[db.Where("email", "a@b.com")])
    assert user is not None
    for provider in ("google", "github"):
        await auth.adapter.create(
            model="account",
            data={
                "id": f"acc-{provider}",
                "user_id": user["id"],
                "provider_id": provider,
                "account_id": f"{provider}-1",
                "password": None,
                "created_at": user["created_at"],
                "updated_at": user["created_at"],
            },
        )
    missing = await auth.handle(post("/unlink-account", {"provider_id": "facebook"}, cookies))
    assert missing.status == 404
    ok = await auth.handle(post("/unlink-account", {"provider_id": "google"}, cookies))
    assert ok.status == 200


async def test_revoke_all_sessions() -> None:
    auth = build_auth()
    first = await signup(auth)
    await auth.handle(post("/sign-in/email", {"email": "a@b.com", "password": "hunter2pw"}))
    resp = await auth.handle(post("/revoke-sessions", {}, first))
    assert json.loads(resp.body)["revoked"] == 2
    check = await auth.handle(db.AuthRequest(method="GET", path="/get-session", cookies=first))
    assert json.loads(check.body)["user"] is None


async def test_verify_email_invalid_token() -> None:
    auth = build_auth()
    resp = await auth.handle(post("/verify-email", {"token": "nope"}))
    assert resp.status == 400
    assert json.loads(resp.body)["error"]["code"] == "invalid_token"


async def test_change_email_same_is_noop() -> None:
    auth = build_auth()
    cookies = await signup(auth, "a@b.com")
    resp = await auth.handle(post("/change-email", {"new_email": "a@b.com"}, cookies))
    assert json.loads(resp.body) == {"success": True}
