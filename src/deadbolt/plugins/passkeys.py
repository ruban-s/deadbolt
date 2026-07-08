"""Passkeys (WebAuthn) registration and authentication. Requires ``deadbolt[passkeys]``.

Two ceremonies: registration (enroll a passkey for the signed-in user) and
authentication (sign in with a passkey). Each is a two-step options -> verify flow;
the server-issued challenge is stored keyed by a returned ``challenge_token``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import timedelta
from functools import partial
from typing import TYPE_CHECKING, Any

from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.structs import PublicKeyCredentialDescriptor

from .._util import new_id, utcnow
from ..crypto import generate_token
from ..db.types import FieldSpec, Row, TableSpec, Where
from ..endpoints import _service as svc
from ..endpoints.context import EndpointResult
from ..endpoints.registry import Endpoint
from ..errors import APIError
from . import Plugin

if TYPE_CHECKING:
    from ..core.auth import Auth
    from ..endpoints.context import EndpointRequest

_REG_PREFIX = "passkey-reg"
_AUTH_PREFIX = "passkey-auth"
_CHALLENGE_TTL = 300

PASSKEY_TABLE = TableSpec(
    model="passkey",
    fields={
        "id": FieldSpec(type="string", required=True, unique=True, input=False),
        "user_id": FieldSpec(type="string", required=True, references="user.id", input=False),
        "name": FieldSpec(type="string", input=False),
        "credential_id": FieldSpec(type="string", required=True, unique=True, input=False),
        "public_key": FieldSpec(type="string", required=True, input=False),
        "sign_count": FieldSpec(type="number", required=True, default_value=0, input=False),
        "created_at": FieldSpec(type="date", required=True, input=False),
    },
)


@dataclass(frozen=True)
class PasskeyConfig:
    rp_id: str
    rp_name: str
    origin: str


def passkeys(*, rp_id: str, rp_name: str, origin: str) -> Plugin:
    """Return the passkeys plugin for a relying party (``rp_id``/``origin``)."""
    cfg = PasskeyConfig(rp_id=rp_id, rp_name=rp_name, origin=origin)

    def ep(method: str, path: str, handler: Any, name: str) -> Endpoint:
        return Endpoint(method, path, partial(handler, cfg=cfg), name)

    return Plugin(
        id="passkeys",
        schema=(PASSKEY_TABLE,),
        endpoints=(
            ep("POST", "/passkey/register-options", _register_options, "passkey_reg_options"),
            ep("POST", "/passkey/register-verify", _register_verify, "passkey_reg_verify"),
            ep("POST", "/passkey/authenticate-options", _auth_options, "passkey_auth_options"),
            ep("POST", "/passkey/authenticate-verify", _auth_verify, "passkey_auth_verify"),
            ep("GET", "/passkey/list", _list, "passkey_list"),
            ep("POST", "/passkey/delete", _delete, "passkey_delete"),
        ),
    )


async def _register_options(
    auth: Auth, req: EndpointRequest, *, cfg: PasskeyConfig
) -> EndpointResult:
    _, user = await svc.require_session(auth, req)
    existing = await auth.adapter.find_many(model="passkey", where=[Where("user_id", user["id"])])
    options = generate_registration_options(
        rp_id=cfg.rp_id,
        rp_name=cfg.rp_name,
        user_name=user["email"],
        user_id=user["id"].encode(),
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(row["credential_id"]))
            for row in existing
        ],
    )
    token = await _store_challenge(auth, f"{_REG_PREFIX}:{user['id']}", options.challenge)
    return EndpointResult(
        data={"options": json.loads(options_to_json(options)), "challenge_token": token}
    )


async def _register_verify(
    auth: Auth, req: EndpointRequest, *, cfg: PasskeyConfig
) -> EndpointResult:
    _, user = await svc.require_session(auth, req)
    token = svc.require_str(req.body, "challenge_token")
    credential = _require_credential(req)
    challenge = await _take_challenge(auth, f"{_REG_PREFIX}:{user['id']}:{token}")

    result = _verify_registration(json.dumps(credential), challenge, cfg)
    await auth.adapter.create(
        model="passkey",
        data={
            "id": new_id(),
            "user_id": user["id"],
            "name": req.body.get("name"),
            "credential_id": bytes_to_base64url(result.credential_id),
            "public_key": bytes_to_base64url(result.credential_public_key),
            "sign_count": result.sign_count,
            "created_at": utcnow(),
        },
    )
    return EndpointResult(data={"success": True})


async def _auth_options(auth: Auth, req: EndpointRequest, *, cfg: PasskeyConfig) -> EndpointResult:
    allow: list[PublicKeyCredentialDescriptor] = []
    email = req.body.get("email")
    if isinstance(email, str) and email:
        user = await svc.find_user_by_email(auth.adapter, email.lower())
        if user is not None:
            rows = await auth.adapter.find_many(
                model="passkey", where=[Where("user_id", user["id"])]
            )
            allow = [
                PublicKeyCredentialDescriptor(id=base64url_to_bytes(row["credential_id"]))
                for row in rows
            ]
    options = generate_authentication_options(rp_id=cfg.rp_id, allow_credentials=allow)
    token = await _store_challenge(auth, _AUTH_PREFIX, options.challenge)
    return EndpointResult(
        data={"options": json.loads(options_to_json(options)), "challenge_token": token}
    )


async def _auth_verify(auth: Auth, req: EndpointRequest, *, cfg: PasskeyConfig) -> EndpointResult:
    token = svc.require_str(req.body, "challenge_token")
    credential = _require_credential(req)
    challenge = await _take_challenge(auth, f"{_AUTH_PREFIX}:{token}")

    credential_id = credential.get("id")
    passkey = await auth.adapter.find_one(
        model="passkey", where=[Where("credential_id", credential_id)]
    )
    if passkey is None:
        raise APIError(400, "unknown_passkey", "No matching passkey.")

    result = _verify_authentication(json.dumps(credential), challenge, cfg, passkey)
    await auth.adapter.update(
        model="passkey",
        where=[Where("id", passkey["id"])],
        update={"sign_count": result.new_sign_count},
    )
    user = await svc.find_user_by_id(auth.adapter, passkey["user_id"])
    if user is None:
        raise APIError(400, "unknown_passkey", "No matching passkey.")
    session_token, _ = await auth.sessions.create(user["id"], ip=req.client_ip)
    return EndpointResult(
        data={"user": svc.public_user(user)}, cookies=[auth.sessions.build_cookie(session_token)]
    )


async def _list(auth: Auth, req: EndpointRequest, *, cfg: PasskeyConfig) -> EndpointResult:
    _, user = await svc.require_session(auth, req)
    rows = await auth.adapter.find_many(model="passkey", where=[Where("user_id", user["id"])])
    passkeys_out = [
        {"id": row["id"], "name": row["name"], "created_at": row["created_at"]} for row in rows
    ]
    return EndpointResult(data={"passkeys": passkeys_out})


async def _delete(auth: Auth, req: EndpointRequest, *, cfg: PasskeyConfig) -> EndpointResult:
    _, user = await svc.require_session(auth, req)
    passkey_id = svc.require_str(req.body, "id")
    existing = await auth.adapter.find_one(
        model="passkey", where=[Where("id", passkey_id), Where("user_id", user["id"])]
    )
    if existing is None:
        raise APIError(404, "not_found", "No such passkey.")
    await auth.adapter.delete(model="passkey", where=[Where("id", passkey_id)])
    return EndpointResult(data={"success": True})


def _verify_registration(credential_json: str, challenge: bytes, cfg: PasskeyConfig) -> Any:
    return verify_registration_response(
        credential=credential_json,
        expected_challenge=challenge,
        expected_rp_id=cfg.rp_id,
        expected_origin=cfg.origin,
    )


def _verify_authentication(
    credential_json: str, challenge: bytes, cfg: PasskeyConfig, passkey: Row
) -> Any:
    return verify_authentication_response(
        credential=credential_json,
        expected_challenge=challenge,
        expected_rp_id=cfg.rp_id,
        expected_origin=cfg.origin,
        credential_public_key=base64url_to_bytes(passkey["public_key"]),
        credential_current_sign_count=passkey["sign_count"],
    )


def _require_credential(req: EndpointRequest) -> dict[str, Any]:
    credential = req.body.get("credential")
    if not isinstance(credential, dict):
        raise APIError(400, "invalid_request", "Missing credential.")
    return credential


async def _store_challenge(auth: Auth, prefix: str, challenge: bytes) -> str:
    token = generate_token()
    now = utcnow()
    await auth.adapter.create(
        model="verification",
        data={
            "id": new_id(),
            "identifier": f"{prefix}:{token}",
            "value": bytes_to_base64url(challenge),
            "expires_at": now + timedelta(seconds=_CHALLENGE_TTL),
            "created_at": now,
        },
    )
    return token


async def _take_challenge(auth: Auth, identifier: str) -> bytes:
    record = await auth.adapter.find_one(
        model="verification", where=[Where("identifier", identifier)]
    )
    if record is None or record["expires_at"] <= utcnow():
        raise APIError(400, "invalid_challenge", "The challenge is invalid or expired.")
    await auth.adapter.delete(model="verification", where=[Where("identifier", identifier)])
    return base64url_to_bytes(record["value"])
