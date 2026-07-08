from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from deadbolt.cli import load_config, main, render_ddl

if TYPE_CHECKING:
    from pathlib import Path

CONFIG = "_fixture_app:auth"


def test_render_ddl_includes_core_and_plugin_tables() -> None:
    auth = load_config(CONFIG)
    ddl = render_ddl(auth.schema, "sqlite")
    assert "CREATE TABLE user" in ddl
    assert "CREATE TABLE session" in ddl
    assert "CREATE TABLE two_factor" in ddl


def test_render_ddl_dialect_specific() -> None:
    auth = load_config(CONFIG)
    pg = render_ddl(auth.schema, "postgresql")
    assert "CREATE TABLE" in pg


def test_main_generate_to_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["generate", "--config", CONFIG, "--dialect", "sqlite"])
    assert code == 0
    out = capsys.readouterr().out
    assert "CREATE TABLE user" in out


def test_main_generate_to_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    target = tmp_path / "schema.sql"
    code = main(["generate", "--config", CONFIG, "--output", str(target)])
    assert code == 0
    assert "CREATE TABLE" in target.read_text()
    assert "Wrote" in capsys.readouterr().out


def test_load_config_rejects_bad_reference() -> None:
    with pytest.raises(SystemExit):
        load_config("no-colon")
