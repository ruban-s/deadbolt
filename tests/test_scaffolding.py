from __future__ import annotations

import pytest

import deadbolt as db
from deadbolt import errors, models
from deadbolt.http import MultiDict

pytestmark = pytest.mark.anyio


def test_multidict_api() -> None:
    md = MultiDict([("A", "1"), ("a", "2"), ("B", "3")])
    assert md.get("a") == "1"
    assert md.get_all("A") == ["1", "2"]
    assert md.get("missing", "default") == "default"
    assert "b" in md
    assert "z" not in md
    assert len(md) == 3
    assert list(md) == ["A", "a", "B"]
    assert list(md.items()) == [("A", "1"), ("a", "2"), ("B", "3")]
    md.add("c", "4")
    assert md.get("C") == "4"


def test_multidict_from_mapping() -> None:
    md = MultiDict.from_mapping({"x": "1"})
    assert md.get("x") == "1"


def test_error_hierarchy() -> None:
    err = errors.APIError(400, "bad", "nope")
    assert isinstance(err, errors.AuthError)
    assert errors.is_api_error(err)
    assert not errors.is_api_error(ValueError())
    assert err.status == 400 and err.code == "bad"


def test_core_tables() -> None:
    names = {t.model for t in models.CORE_TABLES}
    assert names == {"user", "session", "account", "verification"}
    assert models.USER.fields["email"].unique


def test_lazy_sqlalchemy_adapter_access() -> None:
    assert db.SQLAlchemyAdapter is db.db.SQLAlchemyAdapter
    with pytest.raises(NotImplementedError):
        db.SQLAlchemyAdapter(engine=None)


def test_unknown_top_level_attribute() -> None:
    with pytest.raises(AttributeError):
        db.DoesNotExist  # noqa: B018


def test_unknown_db_attribute() -> None:
    with pytest.raises(AttributeError):
        db.db.DoesNotExist  # noqa: B018


def test_mount_app_stubs() -> None:
    auth = db.Auth(adapter=db.MemoryAdapter(), secret="x" * 32)
    with pytest.raises(NotImplementedError):
        auth.asgi_app()
    with pytest.raises(NotImplementedError):
        auth.wsgi_app()
