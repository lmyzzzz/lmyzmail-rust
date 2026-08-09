from __future__ import annotations

import base64
import gzip
import io
import json
import re
import time
import xml.parsers.expat as expat
from email import policy
from email.message import Message
from email.parser import BytesParser
from pathlib import Path
from typing import Any, cast

import psycopg
import redis

from .differential import RuntimeTarget, Scenario
from .protocols import RawHttpResponse, http_exchange
from .runtime import API_KEY
from .scripted_dns import DnsAnswer, DnsQuery, ScriptedDnsServer, TxtAnswer
from .snapshots import http_json_snapshot

_HOST = "127.0.0.1"
_DATABASE = "lmyzmail"
_DATABASE_USER = "lmyzmail_test"
_REPORT_DATE = "2024-01-01"
_NO_DATA_DATE = "2024-01-02"
_DMARC_DOMAIN = "sender.example"
_TLS_DOMAIN = "recipient.example"
_NO_DATA_DOMAIN = "no-data.example"
_ADDRESS_DOMAIN = "MiXeD.Example"
_AMBIGUOUS_DOMAIN = "ambiguous.example"
_LOOKALIKE_DOMAIN = "lookalike.example"
_LIMIT_DOMAIN = "limit.example"
_REPORT_SENDER = "qa@example.test"
_API_HEADERS = (("X-API-Key", API_KEY),)
_NORMALIZERS = (
    "header:date:http-date",
    "json-object-order:reports-contract",
)

_TXT = 16
_UUID_V4 = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
_REPORT_PERIOD = re.compile(r"(?m)^Report Period: \d{4}-\d{2}-\d{2}(?=\r?$)")
_RFC3339_INSTANT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z")
_REDIS_QUEUE_PREFIX = "botmail:mail:queue:"
_MAX_DECOMPRESSED_REPORT_BYTES = 4 * 1024 * 1024


def _txt_answer(value: str) -> TxtAnswer:
    value.encode("ascii")
    return TxtAnswer(tuple(value[offset : offset + 200] for offset in range(0, len(value), 200)))


_REPORT_DNS_ANSWERS = {
    ("_dmarc.mixed.example", _TXT): DnsAnswer(
        txt=(
            TxtAnswer(
                (
                    "v=DMARC1; p=none; rua=mailto:local@mixed.example!10m, "
                    "mailto:external@reports.example,mailto:external@reports.example, "
                    "https://mixed.example/dmarc,https://collector.ext.example/dmarc",
                )
            ),
        )
    ),
    ("mixed.example._report._dmarc.reports.example", _TXT): DnsAnswer(
        txt=(TxtAnswer(("v=DMARC1",)),)
    ),
    ("mixed.example._report._dmarc.collector.ext.example", _TXT): DnsAnswer(
        txt=(TxtAnswer(("v=DMARC1",)),)
    ),
    ("_smtp._tls.mixed.example", _TXT): DnsAnswer(
        txt=(TxtAnswer(("v=TLSRPTv1; rua=mailto:tls@mixed.example,https://mixed.example/tls",)),)
    ),
    ("_dmarc.ambiguous.example", _TXT): DnsAnswer(
        txt=(
            TxtAnswer(("v=DMARC1; rua=mailto:first@ambiguous.example",)),
            TxtAnswer(("v=DMARC1; rua=mailto:second@ambiguous.example",)),
        )
    ),
    ("_smtp._tls.ambiguous.example", _TXT): DnsAnswer(
        txt=(
            TxtAnswer(("v=TLSRPTv1; rua=mailto:first@ambiguous.example",)),
            TxtAnswer(("v=TLSRPTv1; rua=mailto:second@ambiguous.example",)),
        )
    ),
    ("_dmarc.lookalike.example", _TXT): DnsAnswer(
        txt=(TxtAnswer(("v=DMARC10; rua=mailto:nope@lookalike.example",)),)
    ),
    ("_smtp._tls.lookalike.example", _TXT): DnsAnswer(
        txt=(TxtAnswer(("v=TLSRPTv10; rua=mailto=nope@lookalike.example",)),)
    ),
    ("_dmarc.limit.example", _TXT): DnsAnswer(
        txt=(
            _txt_answer(
                "v=DMARC1; rua="
                + ",".join(f"mailto:limit-{index}@limit.example" for index in range(12))
                + ",https://limit.example/too-late"
            ),
        )
    ),
    ("_smtp._tls.limit.example", _TXT): DnsAnswer(
        txt=(TxtAnswer(("v=TLSRPTv1; rua=mailto:tls@limit.example",)),)
    ),
    ("_dmarc.sender.example", _TXT): DnsAnswer(
        txt=(TxtAnswer(("v=DMARC1; p=none; rua=mailto:qa@example.test",)),)
    ),
    ("sender.example._report._dmarc.example.test", _TXT): DnsAnswer(
        txt=(TxtAnswer(("v=DMARC1",)),)
    ),
    ("_smtp._tls.recipient.example", _TXT): DnsAnswer(
        txt=(TxtAnswer(("v=TLSRPTv1; rua=mailto:qa@example.test",)),)
    ),
}


def report_dns_server() -> ScriptedDnsServer:
    return ScriptedDnsServer(_REPORT_DNS_ANSWERS)


def _ports(target: RuntimeTarget) -> tuple[str, int]:
    if target.ports is None:
        raise AssertionError("reports target is not started")
    return _HOST, target.ports.http


def _connect_postgres(
    target: RuntimeTarget,
) -> psycopg.Connection[tuple[Any, ...]]:
    if target.ports is None:
        raise AssertionError("reports target is not started")
    connection = psycopg.connect(
        host=_HOST,
        port=target.ports.postgres,
        user=_DATABASE_USER,
        dbname=_DATABASE,
        connect_timeout=5,
        autocommit=False,
    )
    connection.execute("SET statement_timeout = '5s'")
    connection.execute("SET lock_timeout = '5s'")
    return connection


def _request(target: RuntimeTarget, method: str, path: str) -> RawHttpResponse:
    host, port = _ports(target)
    return http_exchange(
        host,
        port,
        method,
        path,
        headers=_API_HEADERS,
        timeout=10.0,
        max_response=1 * 1024 * 1024,
    )


def _parse_json_object(response: RawHttpResponse) -> dict[str, Any]:
    def object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise AssertionError(f"duplicate JSON object key in reports response: {key!r}")
            value[key] = item
        return value

    try:
        value = json.loads(response.body, object_pairs_hook=object_without_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AssertionError("reports response was not strict UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise AssertionError(f"reports response was not a JSON object: {value!r}")
    return cast(dict[str, Any], value)


def _expect_json(
    response: RawHttpResponse,
    *,
    status: int,
    body: dict[str, Any],
) -> dict[str, Any]:
    if response.status_code != status:
        raise AssertionError(
            f"reports response status changed: {response.status_line!r}, body={response.body!r}"
        )
    actual = _parse_json_object(response)
    if actual != body:
        raise AssertionError(f"reports response changed: actual={actual!r}, expected={body!r}")
    return http_json_snapshot(response, canonicalize_object_order=True)


def _report_database_state(target: RuntimeTarget) -> dict[str, Any]:
    with _connect_postgres(target) as connection:
        dmarc_count_row = connection.execute("SELECT count(*) FROM inbound_dmarc_log").fetchone()
        tls_count_row = connection.execute("SELECT count(*) FROM outbound_tls_log").fetchone()
        dmarc_rows = connection.execute(
            """
            SELECT id, source_ip, header_from_domain, envelope_from_domain,
                   spf_result, dkim_result, dmarc_result, disposition,
                   message_count, report_date::text
            FROM inbound_dmarc_log
            ORDER BY id
            """
        ).fetchall()
        tls_rows = connection.execute(
            """
            SELECT id, recipient_domain, mx_host, target_ip, target_port,
                   tls_success, tls_protocol, cipher_suite, failure_type,
                   connection_count, report_date::text
            FROM outbound_tls_log
            ORDER BY id
            """
        ).fetchall()
    if dmarc_count_row is None or tls_count_row is None:
        raise AssertionError("reports table count query returned no row")
    return {
        "dmarc": {
            "rowCount": cast(int, dmarc_count_row[0]),
            "rows": [
                {
                    "id": row[0],
                    "sourceIp": row[1],
                    "headerFromDomain": row[2],
                    "envelopeFromDomain": row[3],
                    "spfResult": row[4],
                    "dkimResult": row[5],
                    "dmarcResult": row[6],
                    "disposition": row[7],
                    "messageCount": row[8],
                    "reportDate": row[9],
                }
                for row in dmarc_rows
            ],
        },
        "tls": {
            "rowCount": cast(int, tls_count_row[0]),
            "rows": [
                {
                    "id": row[0],
                    "recipientDomain": row[1],
                    "mxHost": row[2],
                    "targetIp": row[3],
                    "targetPort": row[4],
                    "tlsSuccess": row[5],
                    "tlsProtocol": row[6],
                    "cipherSuite": row[7],
                    "failureType": row[8],
                    "connectionCount": row[9],
                    "reportDate": row[10],
                }
                for row in tls_rows
            ],
        },
    }


def capture_reporting_status(target: RuntimeTarget) -> dict[str, Any]:
    response = _request(target, "GET", "/api/reports/status")
    return _expect_json(
        response,
        status=200,
        body={
            "enabled": True,
            "autoSendEnabled": False,
            "minVolumeForReport": 10,
            "dmarcReportSenderAddress": _REPORT_SENDER,
            "tlsReportSenderAddress": _REPORT_SENDER,
            "organizationName": "Blackbox Reports",
            "httpDeliveryEnabled": False,
        },
    )


cast(Any, capture_reporting_status).__lmyzmail_contract__ = {
    "protocol": "http/raw-socket",
    "method": "GET",
    "target": "/api/reports/status",
    "authentication": "admin API key",
    "json_object_order": "canonicalized recursively by key",
}


def _seed_volume_threshold(target: RuntimeTarget) -> tuple[int, int]:
    with _connect_postgres(target) as connection:
        dmarc_row = connection.execute(
            """
            SELECT message_count
            FROM inbound_dmarc_log
            WHERE header_from_domain = %s AND report_date = %s
            FOR UPDATE
            """,
            (_DMARC_DOMAIN, _REPORT_DATE),
        ).fetchone()
        tls_row = connection.execute(
            """
            SELECT connection_count
            FROM outbound_tls_log
            WHERE recipient_domain = %s AND report_date = %s
            FOR UPDATE
            """,
            (_TLS_DOMAIN, _REPORT_DATE),
        ).fetchone()
        if dmarc_row is None or tls_row is None:
            raise AssertionError("legacy reports seed rows are missing")
        original = (cast(int, dmarc_row[0]), cast(int, tls_row[0]))
        dmarc_update = connection.execute(
            """
            UPDATE inbound_dmarc_log
            SET message_count = 10
            WHERE header_from_domain = %s AND report_date = %s
            """,
            (_DMARC_DOMAIN, _REPORT_DATE),
        )
        tls_update = connection.execute(
            """
            UPDATE outbound_tls_log
            SET connection_count = 10
            WHERE recipient_domain = %s AND report_date = %s
            """,
            (_TLS_DOMAIN, _REPORT_DATE),
        )
        if dmarc_update.rowcount != 1 or tls_update.rowcount != 1:
            raise AssertionError("legacy reports threshold update was not one row per table")
    return original


def _restore_volume_threshold(target: RuntimeTarget, original: tuple[int, int]) -> None:
    with _connect_postgres(target) as connection:
        dmarc_update = connection.execute(
            """
            UPDATE inbound_dmarc_log
            SET message_count = %s
            WHERE header_from_domain = %s AND report_date = %s
            """,
            (original[0], _DMARC_DOMAIN, _REPORT_DATE),
        )
        tls_update = connection.execute(
            """
            UPDATE outbound_tls_log
            SET connection_count = %s
            WHERE recipient_domain = %s AND report_date = %s
            """,
            (original[1], _TLS_DOMAIN, _REPORT_DATE),
        )
        if dmarc_update.rowcount != 1 or tls_update.rowcount != 1:
            raise AssertionError("legacy reports threshold restore was not one row per table")


def capture_seeded_report_domains(target: RuntimeTarget) -> dict[str, Any]:
    original = _seed_volume_threshold(target)
    try:
        response = _request(target, "GET", f"/api/reports/domains?date={_REPORT_DATE}")
        snapshot = _expect_json(
            response,
            status=200,
            body={
                "date": _REPORT_DATE,
                "minVolume": 10,
                "dmarcDomains": [_DMARC_DOMAIN],
                "tlsDomains": [_TLS_DOMAIN],
            },
        )
    finally:
        _restore_volume_threshold(target, original)

    restored = _report_database_state(target)
    dmarc_rows = cast(list[dict[str, Any]], cast(dict[str, Any], restored["dmarc"])["rows"])
    tls_rows = cast(list[dict[str, Any]], cast(dict[str, Any], restored["tls"])["rows"])
    if [row["messageCount"] for row in dmarc_rows] != [original[0]]:
        raise AssertionError("DMARC threshold fixture was not restored")
    if [row["connectionCount"] for row in tls_rows] != [original[1]]:
        raise AssertionError("TLS threshold fixture was not restored")
    return {"response": snapshot, "restoredCounts": list(original)}


cast(Any, capture_seeded_report_domains).__lmyzmail_contract__ = {
    "protocol": "http/raw-socket+postgresql",
    "method": "GET",
    "target": f"/api/reports/domains?date={_REPORT_DATE}",
    "fixture": "transactionally set both frozen seed volumes to the inclusive threshold 10",
    "cleanup": "restore both original volumes in finally and verify exact restoration",
    "json_object_order": "canonicalized recursively by key",
}


def capture_invalid_report_dates(target: RuntimeTarget) -> dict[str, Any]:
    cases = (
        (
            "GET",
            "/api/reports/domains?date=not-a-date",
            {"error": "Invalid date format"},
        ),
        (
            "POST",
            "/api/reports/trigger?date=not-a-date",
            {
                "error": "Invalid date format",
                "message": "Use ISO format: YYYY-MM-DD",
            },
        ),
        (
            "POST",
            f"/api/reports/domain/{_NO_DATA_DOMAIN}?date=not-a-date",
            {"error": "Invalid date format"},
        ),
    )
    observations: list[dict[str, Any]] = []
    for method, path, expected in cases:
        observations.append(
            {
                "method": method,
                "target": path,
                "response": _expect_json(
                    _request(target, method, path),
                    status=400,
                    body=expected,
                ),
            }
        )
    return {"cases": observations}


cast(Any, capture_invalid_report_dates).__lmyzmail_contract__ = {
    "protocol": "http/raw-socket",
    "requests": [
        "GET /api/reports/domains?date=not-a-date",
        "POST /api/reports/trigger?date=not-a-date",
        f"POST /api/reports/domain/{_NO_DATA_DOMAIN}?date=not-a-date",
    ],
    "authentication": "admin API key",
    "json_object_order": "canonicalized recursively by key",
}


def capture_no_data_report_trigger(target: RuntimeTarget) -> dict[str, Any]:
    before = _report_database_state(target)
    response = _request(target, "POST", f"/api/reports/trigger?date={_NO_DATA_DATE}")
    snapshot = _expect_json(
        response,
        status=200,
        body={
            "date": _NO_DATA_DATE,
            "dmarcSent": 0,
            "dmarcFailed": 0,
            "tlsSent": 0,
            "tlsFailed": 0,
            "error": "none",
        },
    )
    after = _report_database_state(target)
    if after != before:
        raise AssertionError(f"no-data report trigger mutated report logs: {before!r} != {after!r}")
    return {
        "response": snapshot,
        "database": {
            "before": before,
            "after": after,
            "unchanged": True,
        },
    }


cast(Any, capture_no_data_report_trigger).__lmyzmail_contract__ = {
    "protocol": "http/raw-socket+postgresql",
    "method": "POST",
    "target": f"/api/reports/trigger?date={_NO_DATA_DATE}",
    "database_invariant": (
        "inbound_dmarc_log and outbound_tls_log row counts and core fields remain exact"
    ),
    "json_object_order": "canonicalized recursively by key",
}


def capture_no_data_domain_report(target: RuntimeTarget) -> dict[str, Any]:
    path = f"/api/reports/domain/{_NO_DATA_DOMAIN}?date={_NO_DATA_DATE}"
    response = _request(target, "POST", path)
    return _expect_json(
        response,
        status=200,
        body={
            "domain": _NO_DATA_DOMAIN,
            "date": _NO_DATA_DATE,
            "dmarc": {
                "results": [],
                "error": "No DMARC data for this domain/date",
            },
            "tls": {
                "results": [],
                "error": "No TLS data for this domain/date",
            },
        },
    )


cast(Any, capture_no_data_domain_report).__lmyzmail_contract__ = {
    "protocol": "http/raw-socket",
    "method": "POST",
    "target": f"/api/reports/domain/{_NO_DATA_DOMAIN}?date={_NO_DATA_DATE}",
    "dns_invariant": "no report data means address discovery is not invoked",
    "json_object_order": "canonicalized recursively by key",
}


def _drain_report_dns_queries(target: RuntimeTarget) -> tuple[DnsQuery, ...]:
    drain = getattr(target, "drain_report_dns_queries", None)
    if not callable(drain):
        raise AssertionError("reports target does not expose the scripted DNS query trace")
    value = drain()
    if not isinstance(value, tuple) or not all(isinstance(item, DnsQuery) for item in value):
        raise AssertionError("reports target returned an invalid DNS query trace")
    return cast(tuple[DnsQuery, ...], value)


def _address_body(
    domain: str,
    *,
    dmarc_mailto: list[str] | None = None,
    dmarc_https: list[str] | None = None,
    tls_mailto: list[str] | None = None,
    tls_https: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "domain": domain,
        "dmarc": {
            "mailto": dmarc_mailto or [],
            "https": dmarc_https or [],
        },
        "tlsrpt": {
            "mailto": tls_mailto or [],
            "https": tls_https or [],
        },
    }


def capture_report_addresses(target: RuntimeTarget) -> dict[str, Any]:
    if _drain_report_dns_queries(target):
        raise AssertionError("scripted report DNS trace was not empty before address discovery")
    cases = (
        (
            _ADDRESS_DOMAIN,
            _address_body(
                _ADDRESS_DOMAIN,
                dmarc_mailto=["local@mixed.example", "external@reports.example"],
                dmarc_https=[
                    "https://mixed.example/dmarc",
                    "https://collector.ext.example/dmarc",
                ],
                tls_mailto=["tls@mixed.example"],
                tls_https=["https://mixed.example/tls"],
            ),
        ),
        (_AMBIGUOUS_DOMAIN, _address_body(_AMBIGUOUS_DOMAIN)),
        (_LOOKALIKE_DOMAIN, _address_body(_LOOKALIKE_DOMAIN)),
        ("missing.example", _address_body("missing.example")),
        (
            _LIMIT_DOMAIN,
            _address_body(
                _LIMIT_DOMAIN,
                dmarc_mailto=[f"limit-{index}@limit.example" for index in range(10)],
                tls_mailto=["tls@limit.example"],
            ),
        ),
    )
    observations: list[dict[str, Any]] = []
    for domain, expected in cases:
        observations.append(
            {
                "domain": domain,
                "response": _expect_json(
                    _request(target, "GET", f"/api/reports/addresses/{domain}"),
                    status=200,
                    body=expected,
                ),
            }
        )

    queries = _drain_report_dns_queries(target)
    expected_queries = (
        "_dmarc.mixed.example",
        "mixed.example._report._dmarc.reports.example",
        "mixed.example._report._dmarc.collector.ext.example",
        "_smtp._tls.mixed.example",
        "_dmarc.ambiguous.example",
        "_smtp._tls.ambiguous.example",
        "_dmarc.lookalike.example",
        "_smtp._tls.lookalike.example",
        "_dmarc.missing.example",
        "_dmarc.missing.example",
        "_smtp._tls.missing.example",
        "_smtp._tls.missing.example",
        "_dmarc.limit.example",
        "_smtp._tls.limit.example",
    )
    if tuple(query.qname for query in queries) != expected_queries:
        raise AssertionError(f"report address DNS query order changed: {queries!r}")
    if any(query.qtype != _TXT or query.qclass != 1 for query in queries):
        raise AssertionError(f"report address discovery issued a non-TXT/IN query: {queries!r}")
    return {
        "cases": observations,
        "dnsQueries": [
            {"qname": query.qname, "qtype": query.qtype, "qclass": query.qclass}
            for query in queries
        ],
    }


cast(Any, capture_report_addresses).__lmyzmail_contract__ = {
    "protocol": "http/raw-socket+scripted-udp-dns",
    "method": "GET",
    "target": "/api/reports/addresses/{domain}",
    "authentication": "admin API key",
    "dns": "isolated TXT fixture with exact query trace",
    "coverage": [
        "mixed mailto and HTTPS RUA with same-domain and external DMARC authorization",
        "deduplication and one authorization query per external destination domain",
        "multiple valid policy records rejected",
        "lookalike non-first version tags rejected",
        "NXDOMAIN downgraded to empty address lists",
        "mailto-first combined RUA limit of 10",
    ],
    "json_object_order": "canonicalized recursively by key",
}


def _workspace(target: RuntimeTarget) -> Path:
    if target.workspace is None:
        raise AssertionError("reports target workspace is unavailable")
    return target.workspace


def _sent_files(target: RuntimeTarget) -> dict[str, Path]:
    root = _workspace(target) / "maildir" / _REPORT_SENDER / "sent"
    if not root.exists():
        return {}
    if root.is_symlink() or not root.is_dir():
        raise AssertionError("report sender Sent folder is not a real directory")
    files: dict[str, Path] = {}
    for path in root.rglob("*"):
        if path.is_symlink():
            raise AssertionError(f"report Sent folder contains a symlink: {path}")
        if path.is_file():
            files[path.relative_to(root).as_posix()] = path
    return files


def _decode_part(part: Message) -> bytes:
    value = part.get_payload(decode=True)
    if not isinstance(value, bytes):
        raise AssertionError("report MIME part did not contain decoded bytes")
    return value


def _replace_report_id(value: str, *, location: str) -> str:
    normalized, count = _UUID_V4.subn("<report-id>", value)
    if count != 1:
        raise AssertionError(f"{location} contained {count} UUIDv4 report ids")
    return normalized


def _report_attachment(filename: str, payload: bytes) -> dict[str, Any]:
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(payload)) as stream:
            decompressed = stream.read(_MAX_DECOMPRESSED_REPORT_BYTES + 1)
        if len(decompressed) > _MAX_DECOMPRESSED_REPORT_BYTES:
            raise AssertionError("report attachment exceeded the decompressed byte ceiling")
        text = decompressed.decode("utf-8")
    except (EOFError, OSError, UnicodeDecodeError) as error:
        raise AssertionError("report attachment was not UTF-8 gzip content") from error
    normalized = _replace_report_id(text, location=f"attachment {filename}")
    if filename.endswith(".xml.gz"):
        upper = text.upper()
        if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
            raise AssertionError("DMARC report attachment contained forbidden XML declarations")
        try:
            expat.ParserCreate(namespace_separator=" ").Parse(text, True)
        except expat.ExpatError as error:
            raise AssertionError("DMARC report attachment was not well-formed XML") from error
        report_format = "dmarc-xml"
    elif filename.endswith(".json.gz"):
        try:
            value = json.loads(text)
        except json.JSONDecodeError as error:
            raise AssertionError("TLS report attachment was not strict JSON") from error
        if not isinstance(value, dict) or not isinstance(value.get("report-id"), str):
            raise AssertionError("TLS report attachment omitted its report-id")
        report_format = "tlsrpt-json"
    else:
        raise AssertionError(f"unexpected report attachment filename: {filename!r}")
    return {
        "format": report_format,
        "decompressedText": normalized,
        "compressedBytesPositive": len(payload) > 0,
    }


def _report_message_snapshot(raw: bytes) -> dict[str, Any]:
    message = BytesParser(policy=policy.default).parsebytes(raw)
    plain_parts: list[Message] = []
    attachments: list[Message] = []
    for part in message.walk():
        if part.is_multipart():
            continue
        if part.get_content_disposition() == "attachment":
            attachments.append(part)
        elif part.get_content_type() == "text/plain":
            plain_parts.append(part)
    if len(plain_parts) != 1 or len(attachments) != 1:
        raise AssertionError(
            f"report message MIME shape changed: plain={len(plain_parts)}, "
            f"attachments={len(attachments)}"
        )
    body_part = plain_parts[0]
    body_charset = body_part.get_content_charset() or "utf-8"
    try:
        body = _decode_part(body_part).decode(body_charset)
    except (LookupError, UnicodeDecodeError) as error:
        raise AssertionError("report body was not decodable text") from error
    body, period_count = _REPORT_PERIOD.subn("Report Period: <report-period>", body)
    if period_count != 1:
        raise AssertionError(f"report body contained {period_count} wall-clock periods")
    body = _replace_report_id(body, location="report body")

    attachment = attachments[0]
    filename = attachment.get_filename()
    if not isinstance(filename, str) or not filename:
        raise AssertionError("report attachment omitted its filename")
    subject = str(message.get("Subject", ""))
    return {
        "from": str(message.get("From", "")),
        "to": str(message.get("To", "")),
        "subject": _replace_report_id(subject, location="report subject"),
        "body": body,
        "attachment": {
            "filename": filename,
            "contentType": attachment.get_content_type(),
            **_report_attachment(filename, _decode_part(attachment)),
        },
    }


def _redis_pending(client: redis.Redis) -> list[int]:
    raw = cast(list[bytes], client.lrange(_REDIS_QUEUE_PREFIX + "pending", 0, -1))
    try:
        return [int(value.decode("ascii")) for value in raw]
    except (UnicodeDecodeError, ValueError) as error:
        raise AssertionError("report queue pending list contained a non-numeric task id") from error


def _wait_for_report_side_effects(
    target: RuntimeTarget,
    client: redis.Redis,
    before_pending: list[int],
    before_files: dict[str, Path],
) -> tuple[list[int], dict[str, Path]]:
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        pending = _redis_pending(client)
        files = _sent_files(target)
        if len(pending) == len(before_pending) + 2 and len(files) == len(before_files) + 2:
            if pending[: len(before_pending)] != before_pending:
                raise AssertionError("report queue mutated the pre-existing pending prefix")
            return pending[len(before_pending) :], {
                key: path for key, path in files.items() if key not in before_files
            }
        time.sleep(0.05)
    raise AssertionError("timed out waiting for two report queue and Maildir publications")


def _task_snapshot(client: redis.Redis, task_id: int) -> tuple[str, dict[str, Any]]:
    key = f"{_REDIS_QUEUE_PREFIX}task:{task_id}"
    raw = cast(bytes | None, client.get(key))
    if raw is None:
        raise AssertionError(f"report queue task disappeared before observation: {task_id}")
    try:
        detail = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AssertionError("report queue task was not strict UTF-8 JSON") from error
    if not isinstance(detail, dict):
        raise AssertionError("report queue task was not a JSON object")
    encoded = detail.get("signedContentBase64")
    if not isinstance(encoded, str) or not encoded:
        raise AssertionError("seeded report message did not use frozen in-memory queue mode")
    try:
        message = base64.b64decode(encoded, validate=True)
    except ValueError as error:
        raise AssertionError("report queue content was not canonical Base64") from error
    snapshot = _report_message_snapshot(message)
    report_format = cast(str, cast(dict[str, Any], snapshot["attachment"])["format"])
    label = {"dmarc-xml": "dmarc", "tlsrpt-json": "tls"}.get(report_format)
    if label is None:
        raise AssertionError(f"unknown report queue format: {report_format!r}")
    recipients_raw = detail.get("recipientsJson")
    if not isinstance(recipients_raw, str):
        raise AssertionError("report queue task omitted recipientsJson")
    recipients = json.loads(recipients_raw)
    domains_raw = cast(
        dict[bytes, bytes],
        client.hgetall(f"{_REDIS_QUEUE_PREFIX}domains:{task_id}"),
    )
    if not domains_raw:
        raise AssertionError("report queue task omitted domain status state")
    domains: dict[str, Any] = {}
    for raw_domain, raw_status in domains_raw.items():
        try:
            domain = raw_domain.decode("utf-8")
            status = raw_status.decode("utf-8")
        except UnicodeDecodeError as error:
            raise AssertionError("report queue domain state was not strict UTF-8") from error
        try:
            domain_detail = json.loads(status)
        except json.JSONDecodeError as error:
            raise AssertionError("report queue domain state was not strict JSON") from error
        if not isinstance(domain_detail, dict) or domain_detail.get("domain") != domain:
            raise AssertionError("report queue domain state key and payload disagreed")
        updated_at = domain_detail.get("updatedAt")
        if not isinstance(updated_at, str) or _RFC3339_INSTANT.fullmatch(updated_at) is None:
            raise AssertionError("report queue domain state omitted its RFC3339 updatedAt")
        domain_detail["updatedAt"] = "<updated-at>"
        domains[domain] = domain_detail
    ttl = cast(int, client.ttl(key))
    if ttl <= 0:
        raise AssertionError("report queue task did not retain a positive TTL")
    return label, {
        "senderAddress": detail.get("senderAddress"),
        "recipients": recipients,
        "status": detail.get("status"),
        "retryCount": detail.get("retryCount"),
        "maxRetries": detail.get("maxRetries"),
        "messageIdPresent": isinstance(detail.get("messageId"), str),
        "sentFilePresent": isinstance(detail.get("sentFileName"), str),
        "sentSubdirectory": detail.get("sentSubdirectory"),
        "inMemory": True,
        "taskTtlPositive": True,
        "domains": domains,
        "message": snapshot,
    }


def _capture_report_publications(
    target: RuntimeTarget,
    client: redis.Redis,
    before_pending: list[int],
    before_files: dict[str, Path],
) -> tuple[list[str], dict[str, dict[str, Any]], dict[str, dict[str, Any]], dict[str, Path]]:
    new_ids, added_files = _wait_for_report_side_effects(
        target,
        client,
        before_pending,
        before_files,
    )
    tasks: dict[str, dict[str, Any]] = {}
    pending_order: list[str] = []
    for task_id in new_ids:
        label, snapshot = _task_snapshot(client, task_id)
        if label in tasks:
            raise AssertionError(f"duplicate generated report task: {label}")
        tasks[label] = snapshot
        pending_order.append(label)

    maildir_messages: dict[str, dict[str, Any]] = {}
    for path in added_files.values():
        snapshot = _report_message_snapshot(path.read_bytes())
        report_format = cast(str, cast(dict[str, Any], snapshot["attachment"])["format"])
        maildir_label = {"dmarc-xml": "dmarc", "tlsrpt-json": "tls"}.get(report_format)
        if maildir_label is None or maildir_label in maildir_messages:
            raise AssertionError("report Maildir publication had an unexpected format")
        maildir_messages[maildir_label] = snapshot
    if set(tasks) != {"dmarc", "tls"} or maildir_messages != {
        label: snapshot["message"] for label, snapshot in tasks.items()
    }:
        raise AssertionError("report Redis and Maildir publications were not byte-equivalent")
    return pending_order, tasks, maildir_messages, added_files


def capture_seeded_report_delivery(target: RuntimeTarget) -> dict[str, Any]:
    if _drain_report_dns_queries(target):
        raise AssertionError("scripted report DNS trace was not empty before delivery")
    before_database = _report_database_state(target)
    before_files = _sent_files(target)
    if target.ports is None:
        raise AssertionError("reports target is not started")
    client: redis.Redis = redis.Redis(
        host=_HOST,
        port=target.ports.redis,
        decode_responses=False,
    )
    try:
        before_pending = _redis_pending(client)
        dmarc_response = _expect_json(
            _request(
                target,
                "POST",
                f"/api/reports/domain/{_DMARC_DOMAIN}?date={_REPORT_DATE}",
            ),
            status=200,
            body={
                "domain": _DMARC_DOMAIN,
                "date": _REPORT_DATE,
                "dmarc": {
                    "results": [{"success": True, "method": "email", "target": _REPORT_SENDER}],
                    "error": "none",
                },
                "tls": {"results": [], "error": "No TLS data for this domain/date"},
            },
        )
        tls_response = _expect_json(
            _request(
                target,
                "POST",
                f"/api/reports/domain/{_TLS_DOMAIN}?date={_REPORT_DATE}",
            ),
            status=200,
            body={
                "domain": _TLS_DOMAIN,
                "date": _REPORT_DATE,
                "dmarc": {"results": [], "error": "No DMARC data for this domain/date"},
                "tls": {
                    "results": [{"success": True, "method": "email", "target": _REPORT_SENDER}],
                    "error": "none",
                },
            },
        )
        pending_order, tasks, maildir_messages, added_files = _capture_report_publications(
            target,
            client,
            before_pending,
            before_files,
        )
    finally:
        client.close()

    after_database = _report_database_state(target)
    if after_database != before_database:
        raise AssertionError("report delivery mutated the source DMARC/TLS log rows")
    queries = _drain_report_dns_queries(target)
    expected_queries = (
        "_dmarc.sender.example",
        "sender.example._report._dmarc.example.test",
        "_smtp._tls.recipient.example",
    )
    if tuple(query.qname for query in queries) != expected_queries:
        raise AssertionError(f"seeded report delivery DNS query order changed: {queries!r}")
    return {
        "responses": {"dmarc": dmarc_response, "tls": tls_response},
        "dnsQueries": [query.qname for query in queries],
        "queue": {
            "pendingOrder": pending_order,
            "tasks": tasks,
        },
        "maildir": {
            "addedCount": len(added_files),
            "messages": maildir_messages,
            "noTemporaryFiles": not any(".tmp" in key for key in added_files),
        },
        "sourceDatabaseUnchanged": True,
    }


cast(Any, capture_seeded_report_delivery).__lmyzmail_contract__ = {
    "protocol": "http/raw-socket+scripted-udp-dns+redis+maildir+mime",
    "method": "POST",
    "targets": [
        f"/api/reports/domain/{_DMARC_DOMAIN}?date={_REPORT_DATE}",
        f"/api/reports/domain/{_TLS_DOMAIN}?date={_REPORT_DATE}",
    ],
    "authentication": "admin API key",
    "coverage": [
        "DMARC aggregate XML gzip generation and email queue publication",
        "TLSRPT aggregate JSON gzip generation and email queue publication",
        "external DMARC destination authorization",
        "Redis task/domain state and Maildir byte equivalence",
        "source report rows remain unchanged",
    ],
    "normalized_fields": [
        "UUIDv4 report id",
        "message Date and Message-ID headers excluded after MIME parsing",
        "wall-clock report body period",
        "Redis domain status updatedAt",
        "MIME boundary and generated Maildir filename excluded after MIME parsing",
    ],
    "json_object_order": "canonicalized recursively by key",
}


def capture_seeded_report_trigger(target: RuntimeTarget) -> dict[str, Any]:
    if _drain_report_dns_queries(target):
        raise AssertionError("scripted report DNS trace was not empty before trigger")
    baseline_database = _report_database_state(target)
    original = _seed_volume_threshold(target)
    try:
        before_database = _report_database_state(target)
        before_files = _sent_files(target)
        if target.ports is None:
            raise AssertionError("reports target is not started")
        client: redis.Redis = redis.Redis(
            host=_HOST,
            port=target.ports.redis,
            decode_responses=False,
        )
        try:
            before_pending = _redis_pending(client)
            response = _expect_json(
                _request(target, "POST", f"/api/reports/trigger?date={_REPORT_DATE}"),
                status=200,
                body={
                    "date": _REPORT_DATE,
                    "dmarcSent": 1,
                    "dmarcFailed": 0,
                    "tlsSent": 1,
                    "tlsFailed": 0,
                    "error": "none",
                },
            )
            pending_order, tasks, maildir_messages, added_files = _capture_report_publications(
                target,
                client,
                before_pending,
                before_files,
            )
        finally:
            client.close()

        after_database = _report_database_state(target)
        if after_database != before_database:
            raise AssertionError("report trigger mutated the source DMARC/TLS log rows")
        queries = _drain_report_dns_queries(target)
        # The prior seeded-delivery scenario warms the JVM resolver cache.
        expected_queries: tuple[str, ...] = ()
        if tuple(query.qname for query in queries) != expected_queries:
            raise AssertionError(
                f"seeded report trigger unexpectedly bypassed the warm DNS cache: {queries!r}"
            )
    finally:
        _restore_volume_threshold(target, original)

    restored_database = _report_database_state(target)
    if restored_database != baseline_database:
        raise AssertionError("report trigger threshold fixture was not restored exactly")
    return {
        "response": response,
        "dnsQueries": [query.qname for query in queries],
        "queue": {
            "pendingOrder": pending_order,
            "tasks": tasks,
        },
        "maildir": {
            "addedCount": len(added_files),
            "messages": maildir_messages,
            "noTemporaryFiles": not any(".tmp" in key for key in added_files),
        },
        "sourceDatabaseUnchanged": True,
        "thresholdCountsRestored": True,
    }


cast(Any, capture_seeded_report_trigger).__lmyzmail_contract__ = {
    "protocol": "http/raw-socket+scripted-udp-dns+postgresql+redis+maildir+mime",
    "method": "POST",
    "target": f"/api/reports/trigger?date={_REPORT_DATE}",
    "authentication": "admin API key",
    "fixture": "transactionally set both frozen seed volumes to the inclusive threshold 10",
    "cleanup": "restore both original volumes in finally and verify exact database restoration",
    "coverage": [
        "multi-domain DMARC and TLSRPT generation in one trigger",
        "warm resolver cache reuse without duplicate DNS traffic",
        "delivery success and failure summary counters",
        "external DMARC destination authorization",
        "Redis task/domain state and Maildir byte equivalence",
        "source report rows remain unchanged",
    ],
    "normalized_fields": [
        "UUIDv4 report id",
        "message Date and Message-ID headers excluded after MIME parsing",
        "wall-clock report body period",
        "Redis domain status updatedAt",
        "MIME boundary and generated Maildir filename excluded after MIME parsing",
    ],
    "json_object_order": "canonicalized recursively by key",
}


REPORT_SCENARIOS = (
    Scenario(
        "http/reports/status",
        capture_reporting_status,
        normalizers=_NORMALIZERS,
    ),
    Scenario(
        "http/reports/seeded-domains",
        capture_seeded_report_domains,
        normalizers=_NORMALIZERS,
    ),
    Scenario(
        "http/reports/invalid-dates",
        capture_invalid_report_dates,
        normalizers=_NORMALIZERS,
    ),
    Scenario(
        "http/reports/no-data-trigger",
        capture_no_data_report_trigger,
        normalizers=_NORMALIZERS,
    ),
    Scenario(
        "http/reports/no-data-domain",
        capture_no_data_domain_report,
        normalizers=_NORMALIZERS,
    ),
    Scenario(
        "http/reports/addresses",
        capture_report_addresses,
        normalizers=_NORMALIZERS,
    ),
    Scenario(
        "http/reports/seeded-delivery",
        capture_seeded_report_delivery,
        normalizers=(
            *_NORMALIZERS,
            "report-id:uuid-v4",
            "rfc5322:parsed-message",
            "report-body:wall-clock-period",
            "redis-domain-status:updated-at",
            "maildir:generated-filename",
        ),
    ),
    Scenario(
        "http/reports/seeded-trigger",
        capture_seeded_report_trigger,
        normalizers=(
            *_NORMALIZERS,
            "report-id:uuid-v4",
            "rfc5322:parsed-message",
            "report-body:wall-clock-period",
            "redis-domain-status:updated-at",
            "maildir:generated-filename",
        ),
    ),
)
