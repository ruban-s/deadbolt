from __future__ import annotations

import pytest

import deadbolt as db


def test_alias_exposes_core_surface() -> None:
    assert hasattr(db, "Auth")
    assert hasattr(db, "EmailPassword")
    assert hasattr(db, "AuthRequest")
    assert hasattr(db, "Where")


def test_version_is_a_string() -> None:
    assert isinstance(db.__version__, str)


def test_auth_rejects_empty_secret() -> None:
    with pytest.raises(db.errors.ConfigError):
        db.Auth(adapter=db.MemoryAdapter(), secret="")


def test_sqlalchemy_adapter_is_lazy() -> None:
    assert "SQLAlchemyAdapter" in db.__all__
