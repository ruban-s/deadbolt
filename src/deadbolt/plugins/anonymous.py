"""Anonymous sessions: grant a guest a real session with no credentials.

A visitor calls ``POST /sign-in/anonymous`` and immediately receives a session, so
your app can persist state (carts, drafts, preferences) against a stable user id
before they ever register. Guest users are recorded in an ``anonymous`` table; when
one later signs up, your application decides how to migrate their data.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .._util import new_id, utcnow
from ..db.types import FieldSpec, TableSpec
from ..endpoints import _service as svc
from ..endpoints.context import EndpointResult
from ..endpoints.registry import Endpoint
from . import Plugin

if TYPE_CHECKING:
    from ..core.auth import Auth
    from ..db.types import Row
    from ..endpoints.context import EndpointRequest

ANONYMOUS_TABLE = TableSpec(
    model="anonymous",
    fields={
        "id": FieldSpec(type="string", required=True, unique=True, input=False),
        "user_id": FieldSpec(
            type="string", required=True, unique=True, references="user.id", input=False
        ),
        "created_at": FieldSpec(type="date", required=True, input=False),
    },
)


def anonymous(*, email_domain: str = "anonymous.deadbolt") -> Plugin:
    """Return a plugin adding ``POST /sign-in/anonymous``.

    ``email_domain`` seeds the synthetic, unique placeholder email each guest user
    is created with (``anon-<id>@<email_domain>``).
    """

    async def sign_in(auth: Auth, req: EndpointRequest) -> EndpointResult:
        now = utcnow()
        user_id = new_id()
        user: Row = {
            "id": user_id,
            "email": f"anon-{user_id}@{email_domain}",
            "email_verified": False,
            "name": None,
            "image": None,
            "created_at": now,
            "updated_at": now,
        }
        await auth.adapter.create(model="user", data=user)
        await auth.adapter.create(
            model="anonymous", data={"id": new_id(), "user_id": user_id, "created_at": now}
        )
        token, _ = await auth.sessions.create(user_id, ip=req.client_ip)
        return EndpointResult(
            data={"user": svc.public_user(user), "is_anonymous": True},
            cookies=[auth.sessions.build_cookie(token)],
        )

    return Plugin(
        id="anonymous",
        schema=(ANONYMOUS_TABLE,),
        endpoints=(Endpoint("POST", "/sign-in/anonymous", sign_in, "sign_in_anonymous"),),
    )
