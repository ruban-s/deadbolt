"""Session lifecycle: create, validate, refresh, rotate, revoke, and cookies."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

from .._util import new_id, utcnow
from ..crypto import generate_token, hash_token
from ..db.types import Row, Where
from ..http import Cookie

if TYPE_CHECKING:
    from collections.abc import Callable
    from datetime import datetime

    from ..core.config import CookieConfig, SessionConfig
    from ..crypto import CookieSigner
    from ..protocols import AsyncDatabaseAdapter


class SessionManager:
    def __init__(
        self,
        *,
        adapter: AsyncDatabaseAdapter,
        signer: CookieSigner,
        config: SessionConfig,
        cookie: CookieConfig,
        now: Callable[[], datetime] = utcnow,
    ) -> None:
        self._adapter = adapter
        self._signer = signer
        self._config = config
        self._cookie = cookie
        self._now = now

    @property
    def cookie_name(self) -> str:
        if self._cookie.host_prefix and self._cookie.secure:
            return f"__Host-{self._cookie.name}"
        return self._cookie.name

    async def create(
        self, user_id: str, *, ip: str | None = None, user_agent: str | None = None
    ) -> tuple[str, Row]:
        token = generate_token()
        moment = self._now()
        row: Row = {
            "id": new_id(),
            "user_id": user_id,
            "token": hash_token(token),
            "expires_at": moment + timedelta(seconds=self._config.expires_in),
            "created_at": moment,
            "updated_at": moment,
            "ip_address": ip,
            "user_agent": user_agent,
        }
        await self._adapter.create(model="session", data=row)
        return token, row

    async def validate(self, token: str) -> Row | None:
        row = await self._adapter.find_one(
            model="session", where=[Where("token", hash_token(token))]
        )
        if row is None:
            return None
        moment = self._now()
        absolute_end = row["created_at"] + timedelta(seconds=self._config.max_lifetime)
        if row["expires_at"] <= moment or moment >= absolute_end:
            await self._delete(row["token"])
            return None
        return await self._maybe_refresh(row, moment, absolute_end)

    async def _maybe_refresh(self, row: Row, moment: datetime, absolute_end: datetime) -> Row:
        due = row["updated_at"] + timedelta(seconds=self._config.update_age)
        if moment < due:
            return row
        update = {
            "expires_at": min(moment + timedelta(seconds=self._config.expires_in), absolute_end),
            "updated_at": moment,
        }
        refreshed = await self._adapter.update(
            model="session", where=[Where("token", row["token"])], update=update
        )
        return refreshed if refreshed is not None else row

    def is_fresh(self, session: Row, now: datetime | None = None) -> bool:
        """Whether ``session`` was created within ``fresh_age`` (for sensitive ops)."""
        moment = now or self._now()
        return bool(moment - session["created_at"] < timedelta(seconds=self._config.fresh_age))

    async def revoke(self, token: str) -> None:
        await self._delete(hash_token(token))

    async def revoke_all(self, user_id: str) -> int:
        return await self._adapter.delete_many(model="session", where=[Where("user_id", user_id)])

    async def list_for(self, user_id: str) -> list[Row]:
        return await self._adapter.find_many(model="session", where=[Where("user_id", user_id)])

    async def revoke_by_id(self, session_id: str, user_id: str) -> bool:
        row = await self._adapter.find_one(
            model="session", where=[Where("id", session_id), Where("user_id", user_id)]
        )
        if row is None:
            return False
        await self._delete(row["token"])
        return True

    async def revoke_others(self, user_id: str, keep_token: str) -> int:
        keep_hash = hash_token(keep_token)
        revoked = 0
        for row in await self.list_for(user_id):
            if row["token"] != keep_hash:
                await self._delete(row["token"])
                revoked += 1
        return revoked

    async def _delete(self, token_hash: str) -> None:
        await self._adapter.delete(model="session", where=[Where("token", token_hash)])

    def build_cookie(self, token: str) -> Cookie:
        return Cookie(
            name=self.cookie_name,
            value=self._signer.sign(token),
            max_age=self._config.expires_in,
            path=self._cookie.path,
            domain=None if self._cookie.host_prefix else self._cookie.domain,
            secure=self._cookie.secure,
            http_only=self._cookie.http_only,
            same_site=self._cookie.same_site,
        )

    def clear_cookie(self) -> Cookie:
        cookie = self.build_cookie("")
        cookie.value = ""
        cookie.max_age = 0
        return cookie

    def read_token(self, cookies: dict[str, str]) -> str | None:
        signed = cookies.get(self.cookie_name)
        if signed is None:
            return None
        return self._signer.unsign(signed)
