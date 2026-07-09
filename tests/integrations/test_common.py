from __future__ import annotations

from deadbolt.http import Cookie
from deadbolt.integrations._common import endpoint_path, parse_cookies, render_set_cookie


def test_endpoint_path_strips_prefix_and_defaults() -> None:
    assert endpoint_path("/api/auth/sign-in", "/api/auth") == "/sign-in"
    assert endpoint_path("/api/auth", "/api/auth") == "/"  # exact prefix → root
    assert endpoint_path("/other/thing", "/api/auth") == "/other/thing"  # unrelated path
    assert endpoint_path("/api/authorize", "/api/auth") == "/api/authorize"  # not a segment match
    assert endpoint_path("", "/api/auth") == "/"


def test_parse_cookies() -> None:
    assert parse_cookies(None) == {}
    assert parse_cookies("") == {}
    assert parse_cookies("a=1; b=2") == {"a": "1", "b": "2"}


def test_render_set_cookie_full_and_minimal() -> None:
    full = render_set_cookie(
        Cookie(
            name="s",
            value="v",
            max_age=60,
            domain="x.com",
            secure=True,
            http_only=True,
            same_site="Lax",
        )
    )
    for part in (
        "s=v",
        "Path=/",
        "Max-Age=60",
        "Domain=x.com",
        "Secure",
        "HttpOnly",
        "SameSite=Lax",
    ):
        assert part in full

    minimal = render_set_cookie(
        Cookie(name="s", value="", max_age=None, secure=False, http_only=False, same_site="")
    )
    assert "Secure" not in minimal
    assert "HttpOnly" not in minimal
    assert "SameSite" not in minimal
    assert "Max-Age" not in minimal
