"""The ``Auth`` object: the single hub the whole public API hangs off."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..crypto import Argon2Hasher, CookieSigner
from ..endpoints import Registry
from ..errors import ConfigError
from ..session import SessionManager
from .api import Api
from .config import CookieConfig, EmailPassword, SessionConfig
from .router import Router

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ..http import AuthRequest, AuthResponse
    from ..protocols import AsyncDatabaseAdapter, EmailSender, Hasher

_MIN_SECRET_BYTES = 32


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
        if not secret or len(secret) < _MIN_SECRET_BYTES:
            raise ConfigError("Auth requires a secret of at least 32 bytes.")
        self.adapter = adapter
        self.secret = secret
        self.base_path = base_path
        self.email_and_password = email_and_password or EmailPassword()
        self.session = session or SessionConfig()
        self.cookie = cookie or CookieConfig()
        self.trusted_origins = tuple(trusted_origins)
        self.hasher: Hasher = hasher or Argon2Hasher()
        self.email_sender = email_sender

        self.sessions = SessionManager(
            adapter=adapter,
            signer=CookieSigner(secret),
            config=self.session,
            cookie=self.cookie,
        )
        self._router = Router(self, Registry())
        self._api = Api(self, Registry())

    async def handle(self, request: AuthRequest) -> AuthResponse:
        """Route ``request`` to an endpoint and return the response."""
        return await self._router.handle(request)

    @property
    def api(self) -> Api:
        """Namespace of endpoints callable directly, without HTTP."""
        return self._api

    def asgi_app(self) -> object:
        """Return a mountable ASGI application."""
        raise NotImplementedError("ASGI mount lands in Phase 2.")

    def wsgi_app(self) -> object:
        """Return a mountable WSGI application."""
        raise NotImplementedError("WSGI mount lands in Phase 2.")
