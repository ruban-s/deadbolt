"""The endpoint table and lookups by route and by name."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .accounts import list_accounts, unlink_account
from .email_password import (
    change_password,
    get_session,
    request_password_reset,
    reset_password,
    sign_in_email,
    sign_out,
    sign_up_email,
)
from .sessions import (
    list_sessions,
    revoke_other_sessions,
    revoke_session,
    revoke_sessions,
)
from .user import delete_user, update_user
from .verification import change_email, send_verification_email, verify_email

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from ..core.auth import Auth
    from .context import EndpointRequest, EndpointResult

    Handler = Callable[[Auth, EndpointRequest], Awaitable[EndpointResult]]


@dataclass(frozen=True)
class Endpoint:
    method: str
    path: str
    handler: Handler
    name: str


ENDPOINTS: tuple[Endpoint, ...] = (
    Endpoint("POST", "/sign-up/email", sign_up_email, "sign_up_email"),
    Endpoint("POST", "/sign-in/email", sign_in_email, "sign_in_email"),
    Endpoint("POST", "/sign-out", sign_out, "sign_out"),
    Endpoint("GET", "/get-session", get_session, "get_session"),
    Endpoint("POST", "/change-password", change_password, "change_password"),
    Endpoint("POST", "/request-password-reset", request_password_reset, "request_password_reset"),
    Endpoint("POST", "/reset-password", reset_password, "reset_password"),
    Endpoint(
        "POST", "/send-verification-email", send_verification_email, "send_verification_email"
    ),
    Endpoint("POST", "/verify-email", verify_email, "verify_email"),
    Endpoint("POST", "/change-email", change_email, "change_email"),
    Endpoint("POST", "/update-user", update_user, "update_user"),
    Endpoint("POST", "/delete-user", delete_user, "delete_user"),
    Endpoint("GET", "/list-sessions", list_sessions, "list_sessions"),
    Endpoint("POST", "/revoke-session", revoke_session, "revoke_session"),
    Endpoint("POST", "/revoke-sessions", revoke_sessions, "revoke_sessions"),
    Endpoint("POST", "/revoke-other-sessions", revoke_other_sessions, "revoke_other_sessions"),
    Endpoint("GET", "/list-accounts", list_accounts, "list_accounts"),
    Endpoint("POST", "/unlink-account", unlink_account, "unlink_account"),
)


class Registry:
    def __init__(self, endpoints: tuple[Endpoint, ...] = ENDPOINTS) -> None:
        self.by_route = {(e.method, e.path): e for e in endpoints}
        self.by_name = {e.name: e for e in endpoints}
