"""The ``Auth`` object: the single hub the whole public API hangs off."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..errors import ConfigError
from .config import CookieConfig, EmailPassword, SessionConfig

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ..http import AuthRequest, AuthResponse
    from ..protocols import AsyncDatabaseAdapter, EmailSender, Hasher


class Auth:
    """Configures deadbolt and exposes the request handler and direct-call API.

    A single instance is the entire mental model: ``auth.handle`` serves HTTP,
    ``auth.api`` calls endpoints directly, and ``auth.asgi_app`` / ``auth.wsgi_app``
    return mountable apps.
    """

    def __init__(
        self,
        *,
        adapter: AsyncDatabaseAdapter,
        secret: str | bytes,
        base_path: str = "/api/auth",
        email_and_password: EmailPassword | None = None,
        session: SessionConfig | None = None,
        cookie: CookieConfig | None = None,
        trusted_origins: Sequence[str] = (),
        hasher: Hasher | None = None,
        email_sender: EmailSender | None = None,
    ) -> None:
        if not secret:
            raise ConfigError("Auth requires a non-empty secret of at least 32 bytes.")
        self.adapter = adapter
        self.secret = secret
        self.base_path = base_path
        self.email_and_password = email_and_password or EmailPassword()
        self.session = session or SessionConfig()
        self.cookie = cookie or CookieConfig()
        self.trusted_origins = tuple(trusted_origins)
        self.hasher = hasher
        self.email_sender = email_sender

    async def handle(self, request: AuthRequest) -> AuthResponse:
        """Route ``request`` to an endpoint and return the response."""
        raise NotImplementedError("Endpoint routing lands in Phase 1.")

    @property
    def api(self) -> object:
        """Namespace of endpoints callable directly, without HTTP."""
        raise NotImplementedError("Direct-call API lands in Phase 1.")

    def asgi_app(self) -> object:
        """Return a mountable ASGI application."""
        raise NotImplementedError("ASGI mount lands in Phase 2.")

    def wsgi_app(self) -> object:
        """Return a mountable WSGI application."""
        raise NotImplementedError("WSGI mount lands in Phase 2.")
