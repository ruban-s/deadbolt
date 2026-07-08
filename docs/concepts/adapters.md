# Database adapters

Every database in deadbolt sits behind a single async interface. The core, the session manager, and
every plugin speak only that interface — they never touch SQL or an ORM directly. Swapping Postgres
for SQLite, or a real database for an in-memory dict, is a one-line change at construction time.

## The `AsyncDatabaseAdapter` protocol

An adapter is anything that satisfies the `AsyncDatabaseAdapter` [`Protocol`](https://docs.python.org/3/library/typing.html#typing.Protocol).
It is `@runtime_checkable` and defined structurally, so implementers conform by shape — no base class,
no inheritance. It carries one attribute, `config: AdapterConfig`, and the following methods. Every
call is keyword-only and every `model` argument is the logical table name (for example `"session"`).

```python
class AsyncDatabaseAdapter(Protocol):
    config: AdapterConfig

    async def create(
        self, *, model: str, data: Row, select: Sequence[str] | None = None
    ) -> Row: ...

    async def find_one(
        self, *, model: str, where: Sequence[Where], select: Sequence[str] | None = None
    ) -> Row | None: ...

    async def find_many(
        self,
        *,
        model: str,
        where: Sequence[Where] = (),
        limit: int | None = None,
        offset: int | None = None,
        sort_by: SortBy | None = None,
        select: Sequence[str] | None = None,
    ) -> list[Row]: ...

    async def update(self, *, model: str, where: Sequence[Where], update: Row) -> Row | None: ...

    async def update_many(self, *, model: str, where: Sequence[Where], update: Row) -> int: ...

    async def delete(self, *, model: str, where: Sequence[Where]) -> None: ...

    async def delete_many(self, *, model: str, where: Sequence[Where]) -> int: ...

    async def count(self, *, model: str, where: Sequence[Where] = ()) -> int: ...

    async def create_schema(
        self, *, tables: Sequence[TableSpec], file: str | None = None
    ) -> str: ...
```

A `Row` is just `dict[str, Any]`. The method semantics are:

| Method | Returns | Notes |
| --- | --- | --- |
| `create` | the created row | `select` optionally narrows the returned columns |
| `find_one` | the first match, or `None` | |
| `find_many` | a list of matching rows | supports `limit`, `offset`, and `sort_by` |
| `update` | the updated row, or `None` if nothing matched | updates the first match |
| `update_many` | the number of rows updated | |
| `delete` | `None` | deletes the first match |
| `delete_many` | the number of rows deleted | |
| `count` | the number of matching rows | |
| `create_schema` | a string (DDL or empty) | provisions tables from `TableSpec`s |

## Query and schema primitives

The same portable value objects flow through every adapter. They live in `deadbolt.db` and are
re-exported at the package root.

### `Where`

A single filter condition. Multiple conditions in a sequence are combined by their `connector`:
all `AND` conditions must match, and if any `OR` conditions are present at least one of them must
also match.

```python
import deadbolt as db

# user_id == "u1" AND created_at >= cutoff
where = [
    db.Where("user_id", "u1"),
    db.Where("created_at", cutoff, operator="gte"),
]
```

| Field | Type | Default |
| --- | --- | --- |
| `field` | `str` | required |
| `value` | `Any` | required |
| `operator` | `Operator` | `"eq"` |
| `connector` | `"AND"` or `"OR"` | `"AND"` |

The supported operators are a fixed `Literal`, and every adapter implements the same set:

| Operator | Meaning |
| --- | --- |
| `eq` | equal |
| `ne` | not equal |
| `lt` | less than |
| `lte` | less than or equal |
| `gt` | greater than |
| `gte` | greater than or equal |
| `in` | value is in a collection |
| `contains` | substring / membership match |
| `starts_with` | string prefix match |
| `ends_with` | string suffix match |

### `SortBy`

Orders a `find_many` result by one field.

```python
import deadbolt as db

sort = db.SortBy("created_at", direction="desc")   # direction defaults to "asc"
```

### `FieldSpec` and `TableSpec`

A `TableSpec` is a logical table — a `model` name plus a mapping of field name to `FieldSpec`. A
`FieldSpec` describes one column: its `type` (`"string"`, `"number"`, `"boolean"`, `"date"`, or
`"json"`) plus deadbolt's custom-field attributes.

| `FieldSpec` field | Type | Default | Purpose |
| --- | --- | --- | --- |
| `type` | `FieldType` | required | column data type |
| `required` | `bool` | `False` | `NOT NULL` when true |
| `unique` | `bool` | `False` | unique constraint (never applied to `id`) |
| `default_value` | `Any` | `None` | default when omitted |
| `input` | `bool` | `True` | whether the field is accepted from user input |
| `references` | `str | None` | `None` | foreign-key target |
| `field_name` | `str | None` | `None` | physical column name if it differs from the key |

These specs are how the core and every plugin declare their tables. `Auth` assembles them into
`Auth.schema`, which an adapter turns into real tables via `create_schema`.

## `MemoryAdapter` — tests and local dev

The in-memory adapter backs each `model` with a plain list of row dicts and implements the full
protocol in pure Python. It takes no arguments and needs no external service, which makes it the
default choice for tests, examples, and local development.

```python
import deadbolt as db

auth = db.Auth(
    adapter=db.MemoryAdapter(),
    secret="a-32-byte-or-longer-random-secret-please",
    email_and_password=db.EmailPassword(enabled=True),
)
```

Its `create_schema` is a no-op (tables materialize on first write), and all data lives only for the
lifetime of the process.

## `SQLAlchemyAdapter` — Postgres, MySQL, SQLite

The production adapter is built on SQLAlchemy 2.0 Core in async mode and covers Postgres, MySQL, and
SQLite through their async drivers. It ships behind the `sqlalchemy` extra, and importing
`deadbolt` never pulls SQLAlchemy in eagerly — the adapter is loaded lazily on first access.

You construct it from an `AsyncEngine`. By default it builds its metadata from deadbolt's core
tables; pass `schema=` to include your plugins' tables (`Auth.schema` is the full set).

```python
import deadbolt as db
from sqlalchemy.ext.asyncio import create_async_engine

engine = create_async_engine("postgresql+asyncpg://localhost/app")

auth = db.Auth(
    adapter=db.SQLAlchemyAdapter(engine, schema=...),   # schema defaults to the core tables
    secret="a-32-byte-or-longer-random-secret-please",
    email_and_password=db.EmailPassword(enabled=True),
)
```

Under the hood the adapter calls `build_metadata`, a standalone function that turns a sequence of
`TableSpec`s into SQLAlchemy `MetaData`. It maps each `FieldType` to a column type (`string` and
`date` to `Text`, `number` to `Integer`, `boolean` to `Boolean`, `json` to `JSON`), marks the `id`
field as the primary key, and applies uniqueness and nullability from the `FieldSpec`. The same
function is shared by the CLI, so the schema the CLI emits and the schema the adapter runs against
are always identical.

```python
from deadbolt.db.sqlalchemy_async import build_metadata

metadata = build_metadata(auth.schema)
```

!!! note
    Dates are stored as ISO-8601 strings, not native datetime columns. The adapter encodes
    `datetime` values with `isoformat()` on the way in and parses them back with
    `datetime.fromisoformat()` on the way out. This keeps timezone-aware values round-tripping
    identically across every dialect, sidestepping the differences in how Postgres, MySQL, and
    SQLite handle date and time types.

## Writing a custom adapter

Because `AsyncDatabaseAdapter` is a structural `Protocol`, a custom adapter is any class that
implements the methods above and exposes a `config`. There is nothing to subclass and nothing to
register — if the shape matches, it works, and `isinstance(obj, AsyncDatabaseAdapter)` even confirms
it at runtime.

```python
import deadbolt as db
from deadbolt.db.types import AdapterConfig, Row, SortBy, TableSpec, Where


class MyAdapter:
    def __init__(self) -> None:
        self.config = AdapterConfig(adapter_id="mine", adapter_name="Mine")

    async def create(self, *, model: str, data: Row, select=None) -> Row:
        ...

    async def find_one(self, *, model: str, where, select=None) -> Row | None:
        ...

    # ...find_many, update, update_many, delete, delete_many, count, create_schema


auth = db.Auth(
    adapter=MyAdapter(),
    secret="a-32-byte-or-longer-random-secret-please",
)
```

Implement every method the core uses, honour the `Where` / `SortBy` semantics described above, and
your backend is a first-class citizen — the core, the session manager, and every plugin will drive
it without knowing anything about how it stores rows.
