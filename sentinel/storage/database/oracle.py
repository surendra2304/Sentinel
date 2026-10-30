"""Oracle-specific SQL helpers shared by Sentinel's persistence layer.

Everything here exists to keep Sentinel's SQL legal on Oracle Autonomous Database
(23.26):

* identifiers are unqualified and validated against Oracle's reserved words
  (``MODE``, ``LEVEL``, ``SIZE``, ``COMMENT``, ``SESSION``, ``ACCESS``,
  ``NUMBER``, ``DATE``, ``START``, ``END``, ...);
* upserts are expressed as ``MERGE`` statements with named ``:bind`` parameters
  -- never ``INSERT OR REPLACE``, ``ON CONFLICT`` or positional ``?`` markers;
* empty strings are normalised to ``NULL`` because Oracle cannot store ``''``.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

#: Oracle reserved words that must never be used as unquoted identifiers.
ORACLE_RESERVED_WORDS: frozenset[str] = frozenset(
    {
        "ACCESS",
        "ADD",
        "ALL",
        "ALTER",
        "AND",
        "ANY",
        "AS",
        "ASC",
        "AUDIT",
        "BETWEEN",
        "BY",
        "CHAR",
        "CHECK",
        "CLUSTER",
        "COLUMN",
        "COMMENT",
        "COMPRESS",
        "CONNECT",
        "CREATE",
        "CURRENT",
        "DATE",
        "DECIMAL",
        "DEFAULT",
        "DELETE",
        "DESC",
        "DISTINCT",
        "DROP",
        "ELSE",
        "END",
        "EXCLUSIVE",
        "EXISTS",
        "FILE",
        "FLOAT",
        "FOR",
        "FROM",
        "GRANT",
        "GROUP",
        "HAVING",
        "IDENTIFIED",
        "IMMEDIATE",
        "IN",
        "INCREMENT",
        "INDEX",
        "INITIAL",
        "INSERT",
        "INTEGER",
        "INTERSECT",
        "INTO",
        "IS",
        "LEVEL",
        "LIKE",
        "LOCK",
        "LONG",
        "MAXEXTENTS",
        "MINUS",
        "MLSLABEL",
        "MODE",
        "MODIFY",
        "NOAUDIT",
        "NOCOMPRESS",
        "NOT",
        "NOWAIT",
        "NULL",
        "NUMBER",
        "OF",
        "OFFLINE",
        "ON",
        "ONLINE",
        "OPTION",
        "OR",
        "ORDER",
        "PCTFREE",
        "PRIOR",
        "PRIVILEGES",
        "PUBLIC",
        "RAW",
        "RENAME",
        "RESOURCE",
        "REVOKE",
        "ROW",
        "ROWID",
        "ROWNUM",
        "ROWS",
        "SELECT",
        "SESSION",
        "SET",
        "SHARE",
        "SIZE",
        "SMALLINT",
        "START",
        "SUCCESSFUL",
        "SYNONYM",
        "SYSDATE",
        "TABLE",
        "THEN",
        "TO",
        "TRIGGER",
        "UID",
        "UNION",
        "UNIQUE",
        "UPDATE",
        "USER",
        "VALIDATE",
        "VALUES",
        "VARCHAR",
        "VARCHAR2",
        "VIEW",
        "WHENEVER",
        "WHERE",
        "WITH",
    }
)

_IDENTIFIER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,127}$")


class UnsafeIdentifierError(ValueError):
    """Raised when an identifier would be illegal or unsafe on Oracle."""


def validate_identifier(name: str) -> str:
    """Return ``name`` if it is a safe, non-reserved, unqualified Oracle identifier."""
    if not _IDENTIFIER_RE.match(name or ""):
        raise UnsafeIdentifierError(f"Invalid Oracle identifier: {name!r}")
    if name.upper() in ORACLE_RESERVED_WORDS:
        raise UnsafeIdentifierError(
            f"'{name}' is an Oracle reserved word; map it to a different column name."
        )
    return name


def normalise_empty(value: Any) -> Any:
    """Return ``None`` for an empty string (Oracle stores ``''`` as NULL)."""
    if isinstance(value, str) and value == "":
        return None
    return value


def normalise_row(values: Mapping[str, Any]) -> dict[str, Any]:
    """Normalise every empty string in a row mapping to ``None``."""
    return {key: normalise_empty(value) for key, value in values.items()}


def build_merge_sql(
    table_name: str,
    key_columns: Iterable[str],
    value_columns: Iterable[str],
    *,
    alias: str = "t",
    source_alias: str = "s",
) -> str:
    """Build an Oracle ``MERGE`` statement with named bind parameters.

    The source row is projected from ``dual``, which is how Oracle accepts bind
    variables without a table. Every bind appears as ``:name``; no positional
    ``?`` markers are produced.
    """
    table = validate_identifier(table_name)
    keys = [validate_identifier(column) for column in key_columns]
    values = [validate_identifier(column) for column in value_columns]
    if not keys:
        raise ValueError("MERGE requires at least one key column")

    using = ", ".join(f":{column} AS {column}" for column in keys)
    on_clause = " AND ".join(f"{alias}.{column} = {source_alias}.{column}" for column in keys)
    insert_columns = ", ".join([*keys, *values])
    insert_values = ", ".join(f":{column}" for column in [*keys, *values])

    sql = (
        f"MERGE INTO {table} {alias} "
        f"USING (SELECT {using} FROM dual) {source_alias} "
        f"ON ({on_clause})"
    )
    if values:
        update_set = ", ".join(f"{alias}.{column} = :{column}" for column in values)
        sql += f" WHEN MATCHED THEN UPDATE SET {update_set}"
    sql += f" WHEN NOT MATCHED THEN INSERT ({insert_columns}) VALUES ({insert_values})"
    return sql


def build_insert_returning_sql(
    table_name: str,
    columns: list[str],
    values_bind: list[str],
    returning_column: str = "audit_id",
) -> str:
    """Oracle INSERT with RETURNING clause (single-row identity retrieval).

    Translation: SQLAlchemy INSERT does not always emit RETURNING; this
    explicit form lets the security layer retrieve the generated identity
    (e.g. audit_id) in one round-trip without a second SELECT.
    """
    table = validate_identifier(table_name)
    col_list = ", ".join(validate_identifier(c) for c in columns)
    val_list = ", ".join(f":{b}" for b in values_bind)
    return (
        f"INSERT INTO {table} ({col_list}) VALUES ({val_list}) "
        f"RETURNING {validate_identifier(returning_column)} INTO :{returning_column}"
    )
