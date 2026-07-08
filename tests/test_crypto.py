from __future__ import annotations

import pytest

from _helpers import fast_hasher
from deadbolt.crypto import (
    CookieSigner,
    derive_key,
    generate_token,
    hash_token,
    tokens_equal,
)

pytestmark = pytest.mark.anyio


async def test_hash_and_verify_roundtrip() -> None:
    hasher = fast_hasher()
    hashed = await hasher.hash("correct horse")
    assert hashed != "correct horse"
    assert await hasher.verify(hashed, "correct horse")
    assert not await hasher.verify(hashed, "wrong")


async def test_verify_rejects_garbage_hash() -> None:
    hasher = fast_hasher()
    assert not await hasher.verify("not-a-hash", "whatever")


def test_tokens_are_unique_and_high_entropy() -> None:
    tokens = {generate_token() for _ in range(100)}
    assert len(tokens) == 100
    assert all(len(t) >= 40 for t in tokens)


def test_hash_token_is_stable_and_hex() -> None:
    token = generate_token()
    assert hash_token(token) == hash_token(token)
    assert len(hash_token(token)) == 64
    assert tokens_equal(hash_token(token), hash_token(token))


def test_derive_key_domain_separation() -> None:
    master = "x" * 32
    a = derive_key(master, b"purpose-a")
    b = derive_key(master, b"purpose-b")
    assert a != b
    assert len(a) == 32
    assert derive_key(master, b"purpose-a") == a


def test_cookie_signer_rejects_tampering() -> None:
    signer = CookieSigner("s" * 32)
    signed = signer.sign("token-value")
    assert signer.unsign(signed) == "token-value"
    assert signer.unsign(signed + "x") is None
    assert signer.unsign("garbage") is None


def test_cookie_signer_key_isolation() -> None:
    signed = CookieSigner("a" * 32).sign("v")
    assert CookieSigner("b" * 32).unsign(signed) is None
