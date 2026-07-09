"""The ``Auth`` object: the single hub the whole public API hangs off."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .._sync import SyncBridge
from .._util import utcnow
from ..crypto import Argon2Hasher, CookieSigner
from ..db.types import Where
from ..endpoints import ENDPOINTS, Registry
from ..errors import ConfigError
from ..integrations.asgi import create_asgi_app
from ..integrations.wsgi import create_wsgi_app
from ..models import CORE_TABLES
from ..ratelimit import RateLimit, RateLimiter
from ..session import SessionManager
from .api import Api
from .config import CookieConfig, EmailPassword, SessionConfig
from .router import Router

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ..hooks import Hook, Hooks
    from ..http import AuthRequest, AuthResponse
    from ..integrations.asgi import ASGIApp
    from ..integrations.wsgi import WSGIApp
    from ..plugins import Plugin
    from ..protocols import AsyncDatabaseAdapter, EmailSender, Hasher
    from ..ratelimit import RateLimitStore

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
        plugins: Sequence[Plugin] = (),
        rate_limit: RateLimit | None = None,
        rate_limit_store: RateLimitStore | None = None,
        max_body_bytes: int = 1_048_576,
        hooks: Hooks | None = None,
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
        self.max_body_bytes = max_body_bytes
        self.hasher: Hasher = hasher or Argon2Hasher()
        self.email_sender = email_sender

        self.sessions = SessionManager(
            adapter=adapter,
            signer=CookieSigner(secret),
            config=self.session,
            cookie=self.cookie,
        )
        self.plugins = tuple(plugins)
        self.schema = tuple(CORE_TABLES) + tuple(t for p in self.plugins for t in p.schema)
        self.before_hooks: list[Hook] = [
            *(hooks.before if hooks else ()),
            *(h for p in self.plugins for h in p.before),
        ]
        self.after_hooks: list[Hook] = [
            *(hooks.after if hooks else ()),
            *(h for p in self.plugins for h in p.after),
        ]
        plugin_endpoints = tuple(e for p in self.plugins for e in p.endpoints)
        registry = Registry(ENDPOINTS + plugin_endpoints)
        self.rate_limiter = RateLimiter(rate_limit or RateLimit(), rate_limit_store)
        self._router = Router(self, registry)
        self._api = Api(self, registry)
        self._bridge = SyncBridge()

    async def handle(self, request: AuthRequest) -> AuthResponse:
        """Route ``request`` to an endpoint and return the response."""
        return await self._router.handle(request)

    def handle_sync(self, request: AuthRequest) -> AuthResponse:
        """Serve ``request`` from synchronous (WSGI) code via the sync bridge."""
        return self._bridge.run(self.handle, request)

    def close(self) -> None:
        """Shut down the background loop backing the sync bridge, if started."""
        self._bridge.close()

    async def cleanup_expired(self) -> dict[str, int]:
        """Delete expired sessions and verifications; run periodically in production."""
        now = utcnow()
        sessions = await self.adapter.delete_many(
            model="session", where=[Where("expires_at", now, "lte")]
        )
        verifications = await self.adapter.delete_many(
            model="verification", where=[Where("expires_at", now, "lte")]
        )
        return {"sessions": sessions, "verifications": verifications}

    @property
    def api(self) -> Api:
        """Namespace of endpoints callable directly, without HTTP."""
        return self._api

    def asgi_app(self) -> ASGIApp:
        """Return a mountable ASGI application; mount it at ``base_path``."""
        return create_asgi_app(self)

    def wsgi_app(self) -> WSGIApp:
        """Return a mountable WSGI application; mount it at ``base_path``."""
        return create_wsgi_app(self)
