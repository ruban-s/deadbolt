from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

import deadbolt as db
from _helpers import fast_hasher
from deadbolt.plugins.siwe import siwe

if TYPE_CHECKING:
    from collections.abc import Callable

pytestmark = pytest.mark.anyio

DOMAIN = "example.com"
ADDRESS = "0x" + "a" * 40
OTHER = "0x" + "b" * 40


def stub(recovered: str | None) -> Callable[[str, str], str | None]:
    """A verifier that returns ``recovered`` for a 'good' signature, else None."""

    def verify(message: str, signature: str) -> str | None:
        return recovered if signature == "good" else None

    return verify


def build_auth(verify: Callable[[str, str], str | None] | None) -> db.Auth:
    return db.Auth(
        adapter=db.MemoryAdapter(),
        secret="x" * 32,
        hasher=fast_hasher(),
        plugins=[siwe(domain=DOMAIN, verify=verify)],
    )


def message(
    *, nonce: str, address: str = ADDRESS, domain: str = DOMAIN, expiration: str | None = None
) -> str:
    lines = [
        f"{domain} wants you to sign in with your Ethereum account:",
        address,
        "",
        "Sign in to Example",
        "",
        "URI: https://example.com",
        "Version: 1",
        "Chain ID: 1",
        f"Nonce: {nonce}",
        "Issued At: 2026-07-09T00:00:00Z",
    ]
    if expiration:
        lines.append(f"Expiration Time: {expiration}")
    return "\n".join(lines)


async def get_nonce(auth: db.Auth) -> str:
    resp = await auth.handle(db.AuthRequest(method="GET", path="/siwe/nonce"))
    return str(json.loads(resp.body)["nonce"])


def verify_req(msg: str, signature: str = "good") -> db.AuthRequest:
    return db.AuthRequest(
        method="POST",
        path="/siwe/verify",
        body=json.dumps({"message": msg, "signature": signature}).encode(),
    )


async def test_full_flow_signs_in() -> None:
    auth = build_auth(stub(ADDRESS))
    nonce = await get_nonce(auth)
    resp = await auth.handle(verify_req(message(nonce=nonce)))
    assert resp.status == 200
    body = json.loads(resp.body)
    assert body["address"] == ADDRESS
    cookie = next(c for c in resp.cookies if c.value)

    who = await auth.handle(
        db.AuthRequest(method="GET", path="/get-session", cookies={cookie.name: cookie.value})
    )
    assert json.loads(who.body)["user"]["email"] == f"{ADDRESS}@siwe.local"


async def test_nonce_is_single_use() -> None:
    auth = build_auth(stub(ADDRESS))
    msg = message(nonce=await get_nonce(auth))
    assert (await auth.handle(verify_req(msg))).status == 200
    replay = await auth.handle(verify_req(msg))
    assert replay.status == 401
    assert json.loads(replay.body)["error"]["code"] == "invalid_nonce"


async def test_untrusted_domain_rejected() -> None:
    auth = build_auth(stub(ADDRESS))
    nonce = await get_nonce(auth)
    resp = await auth.handle(verify_req(message(nonce=nonce, domain="evil.com")))
    assert resp.status == 401
    assert json.loads(resp.body)["error"]["code"] == "invalid_message"


async def test_bad_signature_rejected() -> None:
    auth = build_auth(stub(ADDRESS))
    nonce = await get_nonce(auth)
    resp = await auth.handle(verify_req(message(nonce=nonce), signature="wrong"))
    assert json.loads(resp.body)["error"]["code"] == "invalid_signature"


async def test_signature_for_other_address_rejected() -> None:
    auth = build_auth(stub(OTHER))  # recovers a different address than the message claims
    nonce = await get_nonce(auth)
    resp = await auth.handle(verify_req(message(nonce=nonce)))
    assert json.loads(resp.body)["error"]["code"] == "invalid_signature"


async def test_unknown_nonce_rejected() -> None:
    auth = build_auth(stub(ADDRESS))
    resp = await auth.handle(verify_req(message(nonce="never-issued-nonce")))
    assert json.loads(resp.body)["error"]["code"] == "invalid_nonce"


async def test_expired_message_rejected() -> None:
    auth = build_auth(stub(ADDRESS))
    nonce = await get_nonce(auth)
    msg = message(nonce=nonce, expiration="2000-01-01T00:00:00Z")
    resp = await auth.handle(verify_req(msg))
    assert json.loads(resp.body)["error"]["code"] == "expired_message"


async def test_returning_wallet_maps_to_same_user() -> None:
    auth = build_auth(stub(ADDRESS))
    first = json.loads((await auth.handle(verify_req(message(nonce=await get_nonce(auth))))).body)
    second = json.loads((await auth.handle(verify_req(message(nonce=await get_nonce(auth))))).body)
    assert first["user"]["id"] == second["user"]["id"]


async def test_default_verifier_rejects_garbage_signature() -> None:
    # The default eth-account verifier must fail closed on an unparseable signature.
    auth = build_auth(None)
    nonce = await get_nonce(auth)
    resp = await auth.handle(verify_req(message(nonce=nonce), signature="0xdeadbeef"))
    assert resp.status == 401
    assert json.loads(resp.body)["error"]["code"] == "invalid_signature"


async def test_real_ethereum_signature() -> None:
    pytest.importorskip("eth_account")
    from eth_account import Account  # noqa: PLC0415
    from eth_account.messages import encode_defunct  # noqa: PLC0415

    account = Account.create()
    auth = build_auth(None)  # default eth-account verifier
    msg = message(nonce=await get_nonce(auth), address=account.address)
    signed = Account.sign_message(encode_defunct(text=msg), account.key)
    sig = signed.signature.hex()
    sig = sig if sig.startswith("0x") else f"0x{sig}"

    resp = await auth.handle(verify_req(msg, signature=sig))
    assert resp.status == 200
    assert json.loads(resp.body)["address"] == account.address.lower()
