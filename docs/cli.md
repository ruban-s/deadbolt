# CLI

Installing `deadbolt` provides a `deadbolt` console command (entry point `deadbolt.cli:main`). Its
job is to turn an `Auth` configuration into SQL schema, so you can create the tables `deadbolt`
needs with your own migration tooling.

```bash
deadbolt --help
```

## `deadbolt generate`

Generate `CREATE TABLE` DDL from an `Auth` instance. The schema is derived from the core tables
plus every table contributed by the plugins you enabled on that `Auth`.

```bash
deadbolt generate --config myapp.auth:auth
```

| Flag | Required | Default | Description |
| --- | --- | --- | --- |
| `--config` | yes | — | `module:attr` reference to your `Auth` instance, e.g. `myapp.auth:auth`. |
| `--dialect` | no | `postgresql` | SQL dialect: `postgresql`, `mysql`, or `sqlite`. |
| `--output` | no | *(stdout)* | Write the DDL to a file instead of printing it. |

`--config` imports the given module and reads the named attribute, which must be a configured
`Auth`. A reference without both a module and an attribute (no `:`) exits with an error.

### Choosing a dialect

The DDL is compiled with SQLAlchemy for the chosen backend, so column types match the target
database:

```bash
deadbolt generate --config myapp.auth:auth --dialect postgresql
deadbolt generate --config myapp.auth:auth --dialect mysql
deadbolt generate --config myapp.auth:auth --dialect sqlite
```

### Output

Without `--output`, the DDL is written to stdout, tables ordered by dependency:

```bash
deadbolt generate --config myapp.auth:auth --dialect postgresql
```

```text
CREATE TABLE "user" (
    id VARCHAR NOT NULL,
    email VARCHAR NOT NULL,
    ...
    PRIMARY KEY (id)
);

CREATE TABLE session (
    id VARCHAR NOT NULL,
    user_id VARCHAR NOT NULL,
    ...
    PRIMARY KEY (id)
);
```

With `--output`, the DDL is written to the file and a one-line summary is printed:

```bash
deadbolt generate --config myapp.auth:auth --output schema.sql
```

```text
Wrote 4 tables to schema.sql
```

!!! note
    Enable your plugins on the `Auth` you point `--config` at. Plugins such as organizations,
    passkeys, and API keys add their own tables, and only tables present on that instance appear in
    the generated schema.
