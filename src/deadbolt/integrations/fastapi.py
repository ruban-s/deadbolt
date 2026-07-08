"""FastAPI / Starlette mount adapter. Requires ``deadbolt[fastapi]``. (Phase 2)"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..core.auth import Auth


def mount(app: Any, auth: Auth, *, prefix: str = "/api/auth") -> None:
    """Mount ``auth`` on a FastAPI/Starlette ``app`` under ``prefix``."""
    raise NotImplementedError("FastAPI integration lands in Phase 2.")
