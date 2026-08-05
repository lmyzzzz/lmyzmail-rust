from __future__ import annotations

import re
from dataclasses import dataclass

import sqlglot

from .errors import HarnessError

_FAILED_DDL = re.compile(r'Error executing DDL "([^"\r\n]+)" via JDBC')
_OUTBOUND_DDL_PATTERNS = (
    re.compile(r"^create table outbound_mail_queue\b", re.IGNORECASE),
    re.compile(
        r"^create index idx_queue_status_retry on outbound_mail_queue\b",
        re.IGNORECASE,
    ),
    re.compile(r"^create index idx_queue_sender on outbound_mail_queue\b", re.IGNORECASE),
    re.compile(r"^create index idx_queue_created on outbound_mail_queue\b", re.IGNORECASE),
    re.compile(r"^create index idx_queue_sent_file on outbound_mail_queue\b", re.IGNORECASE),
)
_LONGTEXT_COLUMNS = ("attachments_json", "body_html", "body_text")


@dataclass(frozen=True, slots=True)
class OracleLongTextCompatibility:
    source_sql: str
    postgres_sql: str
    postgres_statements: tuple[str, ...]


def normalize_postgres_schema_dump(value: bytes) -> bytes:
    """Remove only pg_dump's per-run psql safety tokens."""

    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError as error:
        raise HarnessError("PostgreSQL schema dump was not UTF-8") from error
    text = re.sub(r"^\\restrict [^\n]+\n", "", text, flags=re.MULTILINE)
    text = re.sub(r"^\\unrestrict [^\n]+\n", "", text, flags=re.MULTILINE)
    return text.encode("utf-8")


def mysql_fixture_to_postgres(sql: str) -> str:
    """Translate fixture DDL with an actual SQL parser, including LONGTEXT."""

    try:
        statements = sqlglot.transpile(sql, read="mysql", write="postgres", pretty=True)
    except sqlglot.errors.SqlglotError as error:
        raise HarnessError(f"fixture SQL is not valid MySQL: {error}") from error
    if not statements:
        raise HarnessError("fixture SQL contained no statements")
    return ";\n".join(statements) + ";\n"


def extract_oracle_outbound_queue_compatibility(
    log_text: str,
) -> OracleLongTextCompatibility:
    """Recover and safely translate the one known frozen-oracle DDL incompatibility."""

    if 'type "longtext" does not exist' not in log_text.lower():
        raise HarnessError("oracle log did not contain the expected LONGTEXT failure")

    failed_statements = {match.group(1).strip() for match in _FAILED_DDL.finditer(log_text)}
    outbound_statements = {
        statement for statement in failed_statements if "outbound_mail_queue" in statement.lower()
    }
    selected: list[str] = []
    for pattern in _OUTBOUND_DDL_PATTERNS:
        matches = sorted(statement for statement in outbound_statements if pattern.match(statement))
        if len(matches) != 1:
            raise HarnessError(
                "oracle outbound queue DDL did not match the frozen contract: "
                f"{pattern.pattern!r} matched {matches!r}"
            )
        selected.append(matches[0])
    if outbound_statements != set(selected):
        unexpected = sorted(outbound_statements - set(selected))
        raise HarnessError(f"oracle emitted unexpected outbound queue DDL: {unexpected!r}")

    longtext_columns = tuple(
        sorted(
            match.group(1).lower()
            for match in re.finditer(
                r"\b([a-z_][a-z0-9_]*)\s+LONGTEXT\b",
                selected[0],
                flags=re.IGNORECASE,
            )
        )
    )
    if longtext_columns != _LONGTEXT_COLUMNS:
        raise HarnessError(
            "oracle LONGTEXT column set changed: "
            f"{longtext_columns!r}; expected {_LONGTEXT_COLUMNS!r}"
        )

    source_sql = ";\n".join(selected) + ";\n"
    translated_create = mysql_fixture_to_postgres(selected[0] + ";\n").rstrip()
    try:
        translated_indexes = tuple(
            sqlglot.parse_one(statement, read="postgres").sql(dialect="postgres", pretty=True)
            for statement in selected[1:]
        )
    except sqlglot.errors.SqlglotError as error:
        raise HarnessError(f"oracle index DDL is not valid PostgreSQL: {error}") from error
    postgres_sql = translated_create + "\n" + ";\n".join(translated_indexes) + ";\n"
    if "longtext" in postgres_sql.lower():
        raise HarnessError("translated oracle DDL still contains LONGTEXT")
    if "nulls first" in postgres_sql.lower() or "nulls last" in postgres_sql.lower():
        raise HarnessError("oracle index compatibility repair changed NULL ordering")
    try:
        parsed = sqlglot.parse(postgres_sql, read="postgres")
    except sqlglot.errors.SqlglotError as error:
        raise HarnessError(f"translated oracle DDL is not valid PostgreSQL: {error}") from error
    parsed_statements = tuple(statement for statement in parsed if statement is not None)
    if len(parsed_statements) != len(_OUTBOUND_DDL_PATTERNS):
        raise HarnessError(
            "translated oracle DDL statement count changed: "
            f"{len(parsed_statements)} != {len(_OUTBOUND_DDL_PATTERNS)}"
        )
    postgres_statements = tuple(
        statement.sql(dialect="postgres") for statement in parsed_statements
    )
    return OracleLongTextCompatibility(
        source_sql=source_sql,
        postgres_sql=postgres_sql,
        postgres_statements=postgres_statements,
    )
