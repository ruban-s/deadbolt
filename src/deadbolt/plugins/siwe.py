"""Sign-In with Ethereum (EIP-4361). Requires ``deadbolt[siwe]``.

A user proves control of an Ethereum address by signing a structured message with
their wallet — no password, no email. The flow is nonce-challenge based:

1. ``GET /siwe/nonce`` — the client fetches a single-use nonce and embeds it in an
   EIP-4361 message it builds locally.
2. The wallet signs that message (EIP-191 ``personal_sign``).
3. ``POST /siwe/verify`` — the client sends ``{message, signature}``; the server
   recovers the signer, checks it matches the message's address, validates the
   nonce/domain/expiry, then signs the user in (creating a wallet-backed user on
   first sight).

Signature recovery is injectable via ``verify`` so it can be stubbed in tests.
"""

from __future__ import annotations

import re
import secrets
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from .._util import new_id, utcnow
from ..db.types import FieldSpec, TableSpec, Where
from ..endpoints import _service as svc
from ..endpoints.context import EndpointResult
from ..endpoints.registry import Endpoint
from ..errors import APIError
from . import Plugin

if TYPE_CHECKING:
    from collections.abc import Callable

    from ..core.auth import Auth
    from ..db.types import Row
    from ..endpoints.context import EndpointRequest

    Verify = Callable[[str, str], str | None]

_NONCE_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_ADDRESS = re.compile(r"^0x[a-fA-F0-9]{40}$")

NONCE_TABLE = TableSpec(
    model="siwe_nonce",
    fields={
        "id": FieldSpec(type="string", required=True, unique=True, input=False),
        "nonce": FieldSpec(type="string", required=True, unique=True, input=False),
        "expires_at": FieldSpec(type="date", required=True, input=False),
        "created_at": FieldSpec(type="date", required=True, input=False),
    },
)

WALLET_TABLE = TableSpec(
    model="wallet_address",
    fields={
        "id": FieldSpec(type="string", required=True, unique=True, input=False),
        "address": FieldSpec(type="string", required=True, unique=True, input=False),
        "user_id": FieldSpec(type="string", required=True, references="user.id", input=False),
        "created_at": FieldSpec(type="date", required=True, input=False),
    },
)


def siwe(
    *,
    domain: str,
    chain_id: int = 1,
    nonce_ttl: int = 600,
    verify: Verify | None = None,
) -> Plugin:
    """Return the Sign-In with Ethereum plugin.

    ``domain`` is the domain the message must be bound to (checked against the
    message). ``chain_id`` is advertised on the nonce response. ``nonce_ttl`` is the
    nonce lifetime in seconds. ``verify`` overrides signature recovery with
    ``(message, signature) -> address | None``; the default uses ``eth-account``.
    """
    recover = verify or _eth_verifier()

    async def nonce(auth: Auth, req: EndpointRequest) -> EndpointResult:
        value = "".join(secrets.choice(_NONCE_ALPHABET) for _ in range(17))
        now = utcnow()
        await auth.adapter.create(
            model="siwe_nonce",
            data={
                "id": new_id(),
                "nonce": value,
                "expires_at": now + timedelta(seconds=nonce_ttl),
                "created_at": now,
            },
        )
        return EndpointResult(data={"nonce": value, "chain_id": chain_id})

    async def verify_message(auth: Auth, req: EndpointRequest) -> EndpointResult:
        message = svc.require_str(req.body, "message")
        signature = svc.require_str(req.body, "signature")
        fields = _parse(message)
        address = fields.get("address")
        if address is None or fields.get("domain") != domain:
            raise APIError(401, "invalid_message", "Malformed or untrusted SIWE message.")

        recovered = recover(message, signature)
        if recovered is None or recovered.lower() != address.lower():
            raise APIError(401, "invalid_signature", "Signature does not match the address.")

        await _consume_nonce(auth, fields.get("nonce"))
        expiry = _parse_time(fields.get("expiration"))
        if expiry is not None and expiry <= utcnow():
            raise APIError(401, "expired_message", "The SIWE message has expired.")

        user = await _user_for(auth, address.lower())
        token, _ = await auth.sessions.create(user["id"], ip=req.client_ip)
        return EndpointResult(
            data={"user": svc.public_user(user), "address": address.lower()},
            cookies=[auth.sessions.build_cookie(token)],
        )

    return Plugin(
        id="siwe",
        schema=(NONCE_TABLE, WALLET_TABLE),
        endpoints=(
            Endpoint("GET", "/siwe/nonce", nonce, "siwe_nonce"),
            Endpoint("POST", "/siwe/verify", verify_message, "siwe_verify"),
        ),
    )


async def _consume_nonce(auth: Auth, value: str | None) -> None:
    row = None
    if value:
        row = await auth.adapter.find_one(model="siwe_nonce", where=[Where("nonce", value)])
    if row is None:
        raise APIError(401, "invalid_nonce", "Unknown or already-used nonce.")
    await auth.adapter.delete(model="siwe_nonce", where=[Where("nonce", value)])
    if row["expires_at"] <= utcnow():
        raise APIError(401, "invalid_nonce", "The nonce has expired.")


async def _user_for(auth: Auth, address: str) -> Row:
    wallet = await auth.adapter.find_one(model="wallet_address", where=[Where("address", address)])
    if wallet is not None:
        existing = await svc.find_user_by_id(auth.adapter, wallet["user_id"])
        if existing is not None:
            return existing
    now = utcnow()
    user_id = new_id()
    user: Row = {
        "id": user_id,
        "email": f"{address}@siwe.local",
        "email_verified": False,
        "name": None,
        "image": None,
        "created_at": now,
        "updated_at": now,
    }
    await auth.adapter.create(model="user", data=user)
    await auth.adapter.create(
        model="wallet_address",
        data={"id": new_id(), "address": address, "user_id": user_id, "created_at": now},
    )
    return user


def _parse(message: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    lines = message.splitlines()
    if lines:
        header = re.match(r"^(.*?) wants you to sign in", lines[0])
        if header:
            fields["domain"] = header.group(1)
    for raw in lines:
        line = raw.strip()
        if _ADDRESS.fullmatch(line):
            fields["address"] = line
        elif line.startswith("Nonce:"):
            fields["nonce"] = line[len("Nonce:") :].strip()
        elif line.startswith("Expiration Time:"):
            fields["expiration"] = line[len("Expiration Time:") :].strip()
    return fields


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=utcnow().tzinfo)


def _eth_verifier() -> Verify:
    def verify(message: str, signature: str) -> str | None:
        from eth_account import Account  # noqa: PLC0415 — optional dependency
        from eth_account.messages import encode_defunct  # noqa: PLC0415

        try:
            recovered = Account.recover_message(encode_defunct(text=message), signature=signature)
        except Exception:  # noqa: BLE001 — recovery raises varied crypto/validation errors
            return None
        return str(recovered)

    return verify
