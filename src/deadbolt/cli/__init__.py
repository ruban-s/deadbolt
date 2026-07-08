"""The deadbolt command-line interface: generate SQL schema from an Auth config."""

from __future__ import annotations

import argparse
import importlib
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ..core.auth import Auth
    from ..db.types import TableSpec

_DIALECTS = ("postgresql", "mysql", "sqlite")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="deadbolt", description="deadbolt CLI")
    sub = parser.add_subparsers(dest="command", required=True)
    generate = sub.add_parser("generate", help="Generate SQL schema from an Auth config.")
    generate.add_argument("--config", required=True, help="module:attr of your Auth instance")
    generate.add_argument("--dialect", default="postgresql", choices=_DIALECTS)
    generate.add_argument("--output", default=None, help="write DDL to a file instead of stdout")
    args = parser.parse_args(argv)

    auth = load_config(args.config)
    ddl = render_ddl(auth.schema, args.dialect)
    if args.output is not None:
        Path(args.output).write_text(ddl)
        print(f"Wrote {len(auth.schema)} tables to {args.output}")
    else:
        print(ddl, end="")
    return 0


def load_config(ref: str) -> Auth:
    module_name, separator, attribute = ref.partition(":")
    if not separator or not attribute:
        raise SystemExit("--config must be in 'module:attr' form")
    module = importlib.import_module(module_name)
    auth: Auth = getattr(module, attribute)
    return auth


def render_ddl(schema: Sequence[TableSpec], dialect_name: str) -> str:
    from sqlalchemy.dialects.mysql.base import MySQLDialect  # noqa: PLC0415
    from sqlalchemy.dialects.postgresql.base import PGDialect  # noqa: PLC0415
    from sqlalchemy.dialects.sqlite.base import SQLiteDialect  # noqa: PLC0415
    from sqlalchemy.schema import CreateTable  # noqa: PLC0415

    from ..db.sqlalchemy_async import build_metadata  # noqa: PLC0415

    dialects = {
        "postgresql": PGDialect(),
        "mysql": MySQLDialect(),
        "sqlite": SQLiteDialect(),
    }
    dialect = dialects[dialect_name]
    metadata = build_metadata(schema)
    statements = [
        str(CreateTable(table).compile(dialect=dialect)).strip() + ";"
        for table in metadata.sorted_tables
    ]
    return "\n\n".join(statements) + "\n"
