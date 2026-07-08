from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

import deadbolt as db
from _helpers import fast_hasher
from deadbolt.endpoints.context import EndpointRequest, EndpointResult
from deadbolt.endpoints.registry import Endpoint

if TYPE_CHECKING:
    from deadbolt.hooks import HookContext

pytestmark = pytest.mark.anyio


def build_auth(hooks: db.Hooks | None = None, plugins: list[db.Plugin] | None = None) -> db.Auth:
    return db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        email_and_password=db.EmailPassword(enabled=True),
        hasher=fast_hasher(),
        hooks=hooks,
        plugins=plugins or [],
    )


def post(path: str, body: object) -> db.AuthRequest:
    return db.AuthRequest(method="POST", path=path, body=json.dumps(body).encode())


async def test_before_hook_can_block() -> None:
    async def only_example(ctx: HookContext) -> None:
        email = ctx.request.body.get("email", "")
        if not email.endswith("@example.com"):
            raise db.errors.APIError(403, "domain_blocked", "Only example.com allowed.")

    auth = build_auth(hooks=db.Hooks(before=(db.Hook(only_example, path="/sign-up/email"),)))
    blocked = await auth.handle(
        post("/sign-up/email", {"email": "a@b.com", "password": "hunter2pw"})
    )
    assert blocked.status == 403
    assert json.loads(blocked.body)["error"]["code"] == "domain_blocked"

    ok = await auth.handle(
        post("/sign-up/email", {"email": "a@example.com", "password": "hunter2pw"})
    )
    assert ok.status == 200


async def test_after_hook_observes_result() -> None:
    seen: list[int] = []

    async def record(ctx: HookContext) -> None:
        assert ctx.result is not None
        seen.append(ctx.result.status)

    auth = build_auth(hooks=db.Hooks(after=(db.Hook(record),)))
    await auth.handle(post("/sign-up/email", {"email": "a@b.com", "password": "hunter2pw"}))
    assert seen == [200]


async def test_after_hook_can_replace_result() -> None:
    async def rewrite(ctx: HookContext) -> None:
        ctx.result = EndpointResult(data={"intercepted": True}, status=418)

    auth = build_auth(hooks=db.Hooks(after=(db.Hook(rewrite, path="/get-session"),)))
    resp = await auth.handle(db.AuthRequest(method="GET", path="/get-session"))
    assert resp.status == 418
    assert json.loads(resp.body) == {"intercepted": True}


async def test_hook_path_scoping() -> None:
    calls: list[str] = []

    async def track(ctx: HookContext) -> None:
        calls.append(ctx.path)

    auth = build_auth(hooks=db.Hooks(before=(db.Hook(track, path="/sign-out"),)))
    await auth.handle(post("/sign-up/email", {"email": "a@b.com", "password": "hunter2pw"}))
    await auth.handle(db.AuthRequest(method="POST", path="/sign-out"))
    assert calls == ["/sign-out"]


async def test_plugin_can_register_hooks() -> None:
    events: list[str] = []

    async def note(ctx: HookContext) -> None:
        events.append("after")

    async def hello(auth: db.Auth, req: EndpointRequest) -> EndpointResult:
        return EndpointResult(data={"ok": True})

    plugin = db.Plugin(
        id="greeter",
        endpoints=(Endpoint("GET", "/hello", hello, "hello"),),
        after=(db.Hook(note, path="/hello"),),
    )
    auth = build_auth(plugins=[plugin])
    resp = await auth.handle(db.AuthRequest(method="GET", path="/hello"))
    assert resp.status == 200
    assert events == ["after"]
