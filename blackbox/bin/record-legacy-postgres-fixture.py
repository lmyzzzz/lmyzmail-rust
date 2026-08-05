#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import psycopg

from lmyzmail_blackbox.errors import HarnessError
from lmyzmail_blackbox.golden import canonical_json
from lmyzmail_blackbox.runtime import JavaOracleRuntime
from lmyzmail_blackbox.sql_fixture import (
    extract_oracle_outbound_queue_compatibility,
    normalize_postgres_schema_dump,
)

EXPECTED_TABLES = (
    "contact",
    "email_index",
    "email_label",
    "email_label_assignment",
    "inbound_dmarc_log",
    "mailbox",
    "outbound_mail_queue",
    "outbound_tls_log",
    "skibidi_cringe_ip",
    "skibidi_cringe_ip_activity",
    "starred_email",
    "user_preference",
    "user_session",
)
EXPECTED_INITIAL_TABLES = tuple(
    table for table in EXPECTED_TABLES if table != "outbound_mail_queue"
)


def _capture() -> tuple[bytes, dict[str, Any], bytes, bytes]:
    with JavaOracleRuntime() as oracle:
        if oracle.workspace is None or oracle.ports is None:
            raise HarnessError("oracle did not expose its isolated runtime state")
        log_text = "\n".join(
            (oracle.workspace / name).read_text(encoding="utf-8", errors="replace")
            for name in ("java-oracle.log", "java-application.log")
            if (oracle.workspace / name).is_file()
        )

        with psycopg.connect(
            host="127.0.0.1",
            port=oracle.ports.postgres,
            user="lmyzmail_test",
            dbname="lmyzmail",
            connect_timeout=5,
        ) as connection:
            initial_table_rows = connection.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'public' AND table_type = 'BASE TABLE' "
                "ORDER BY table_name"
            ).fetchall()
            initial_tables = tuple(str(row[0]) for row in initial_table_rows)
            if initial_tables != EXPECTED_INITIAL_TABLES:
                raise HarnessError(
                    "oracle initial PostgreSQL table set changed: "
                    f"{initial_tables!r}; expected {EXPECTED_INITIAL_TABLES!r}"
                )

            compatibility = extract_oracle_outbound_queue_compatibility(log_text)
            for statement in compatibility.postgres_statements:
                connection.execute(statement)

            table_rows = connection.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'public' AND table_type = 'BASE TABLE' "
                "ORDER BY table_name"
            ).fetchall()
            column_rows = connection.execute(
                "SELECT table_name, column_name, data_type, udt_name, is_nullable, "
                "character_maximum_length "
                "FROM information_schema.columns WHERE table_schema = 'public' "
                "ORDER BY table_name, ordinal_position"
            ).fetchall()

        tables = tuple(str(row[0]) for row in table_rows)
        if tables != EXPECTED_TABLES:
            raise HarnessError(f"oracle PostgreSQL table set mismatch: {tables!r}")

        pg_dump = oracle.paths.runtime / "postgres-root/usr/lib/postgresql/16/bin/pg_dump"
        environment = oracle._postgres_env()
        result = subprocess.run(  # noqa: S603
            [
                str(pg_dump),
                "--host=127.0.0.1",
                f"--port={oracle.ports.postgres}",
                "--username=lmyzmail_test",
                "--dbname=lmyzmail",
                "--schema=public",
                "--schema-only",
                "--no-owner",
                "--no-privileges",
                "--no-comments",
                "--quote-all-identifiers",
            ],
            check=False,
            capture_output=True,
            env=environment,
        )
        if result.returncode != 0:
            raise HarnessError(
                "pg_dump failed: " + result.stderr.decode("utf-8", errors="replace")[-4000:]
            )
        dump = normalize_postgres_schema_dump(result.stdout)

        with psycopg.connect(
            host="127.0.0.1",
            port=oracle.ports.postgres,
            user="lmyzmail_test",
            dbname="postgres",
            connect_timeout=5,
            autocommit=True,
        ) as connection:
            connection.execute('CREATE DATABASE "lmyzmail_roundtrip"')

        psql = oracle.paths.runtime / "postgres-root/usr/lib/postgresql/16/bin/psql"
        imported = subprocess.run(  # noqa: S603
            [
                str(psql),
                "--host=127.0.0.1",
                f"--port={oracle.ports.postgres}",
                "--username=lmyzmail_test",
                "--dbname=lmyzmail_roundtrip",
                "--single-transaction",
                "--set=ON_ERROR_STOP=1",
                '--command=DROP SCHEMA "public";',
                "--file=-",
            ],
            input=dump,
            check=False,
            capture_output=True,
            env=environment,
        )
        if imported.returncode != 0:
            raise HarnessError(
                "schema round-trip import failed: "
                + imported.stderr.decode("utf-8", errors="replace")[-4000:]
            )

        roundtrip = subprocess.run(  # noqa: S603
            [
                str(pg_dump),
                "--host=127.0.0.1",
                f"--port={oracle.ports.postgres}",
                "--username=lmyzmail_test",
                "--dbname=lmyzmail_roundtrip",
                "--schema=public",
                "--schema-only",
                "--no-owner",
                "--no-privileges",
                "--no-comments",
                "--quote-all-identifiers",
            ],
            check=False,
            capture_output=True,
            env=environment,
        )
        if roundtrip.returncode != 0:
            raise HarnessError(
                "schema round-trip pg_dump failed: "
                + roundtrip.stderr.decode("utf-8", errors="replace")[-4000:]
            )
        roundtrip_dump = normalize_postgres_schema_dump(roundtrip.stdout)

    columns = [
        {
            "table": str(row[0]),
            "column": str(row[1]),
            "data_type": str(row[2]),
            "udt_name": str(row[3]),
            "nullable": row[4] == "YES",
            "character_maximum_length": row[5],
        }
        for row in column_rows
    ]
    long_text_columns = {
        (column["table"], column["column"]): column["data_type"]
        for column in columns
        if (column["table"], column["column"])
        in {
            ("outbound_mail_queue", "body_text"),
            ("outbound_mail_queue", "body_html"),
            ("outbound_mail_queue", "attachments_json"),
        }
    }
    if long_text_columns != {
        ("outbound_mail_queue", "body_text"): "text",
        ("outbound_mail_queue", "body_html"): "text",
        ("outbound_mail_queue", "attachments_json"): "text",
    }:
        raise HarnessError(f"LONGTEXT compatibility mismatch: {long_text_columns!r}")

    metadata: dict[str, Any] = {
        "schema_version": 1,
        "oracle_profile": "managed-basic",
        "tables": list(tables),
        "columns": columns,
        "compatibility_repairs": [
            {
                "kind": "hibernate-longtext-to-postgres-text",
                "table": "outbound_mail_queue",
                "initial_tables": list(initial_tables),
                "source_statement_count": len(compatibility.postgres_statements),
                "source_sha256": hashlib.sha256(
                    compatibility.source_sql.encode("utf-8")
                ).hexdigest(),
                "postgres_sha256": hashlib.sha256(
                    compatibility.postgres_sql.encode("utf-8")
                ).hexdigest(),
            }
        ],
        "roundtrip_schema_sha256": hashlib.sha256(roundtrip_dump).hexdigest(),
        "schema_sha256": hashlib.sha256(dump).hexdigest(),
    }
    return (
        dump,
        metadata,
        compatibility.source_sql.encode("utf-8"),
        compatibility.postgres_sql.encode("utf-8"),
    )


def _write_create_once(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            if path.read_bytes() != value:
                raise HarnessError(f"refusing to overwrite existing fixture: {path}") from None
            return
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> None:
    if os.environ.get("LMYZMAIL_RECORD_LEGACY_POSTGRES_FIXTURE") != "1":
        raise SystemExit(
            "set LMYZMAIL_RECORD_LEGACY_POSTGRES_FIXTURE=1 for an explicit fixture refresh"
        )
    repository = Path(__file__).resolve().parents[2]
    first_capture = _capture()
    second_capture = _capture()
    if first_capture != second_capture:
        raise HarnessError("isolated oracle schema capture was not repeatable")
    first_dump, first_metadata, first_source, first_compatibility = first_capture
    fixture_root = repository / "blackbox/fixtures/legacy"
    _write_create_once(fixture_root / "postgres-schema.sql", first_dump)
    _write_create_once(fixture_root / "postgres-schema.json", canonical_json(first_metadata))
    _write_create_once(fixture_root / "postgres-longtext-oracle.sql", first_source)
    _write_create_once(fixture_root / "postgres-longtext-compat.sql", first_compatibility)
    print(f"Recorded repeatable legacy PostgreSQL fixture: {first_metadata['schema_sha256']}")


if __name__ == "__main__":
    main()
