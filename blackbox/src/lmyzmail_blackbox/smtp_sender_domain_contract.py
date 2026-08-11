from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any, cast

import psycopg

from .differential import RuntimeTarget, Scenario
from .smtp_contract import (
    open_smtp_client,
    smtp_ehlo,
    smtp_greeting_snapshot,
    smtp_reply_snapshot,
)

_PERSISTENCE_TIMEOUT_SECONDS = 8.0


@dataclass(frozen=True, slots=True)
class SenderDomainCase:
    name: str
    source: str
    domain: str
    reason: str | None

    @property
    def mail_from(self) -> str:
        return f"sender@{self.domain}"


_CASES = (
    SenderDomainCase(
        "reserved-domain",
        "127.0.0.2",
        "example.com",
        "Reserved domain 'example.com' is not allowed",
    ),
    SenderDomainCase(
        "reserved-tld",
        "127.0.0.3",
        "mx.test",
        "Reserved TLD '.test' is not allowed",
    ),
    SenderDomainCase(
        "missing-dot",
        "127.0.0.4",
        "localhost",
        "Domain must contain at least one dot",
    ),
    SenderDomainCase(
        "ipv4",
        "127.0.0.5",
        "192.0.2.1",
        "IP address is not allowed as sender domain",
    ),
    SenderDomainCase(
        "ipv6",
        "127.0.0.6",
        "2001:db8::1",
        "IP address is not allowed as sender domain",
    ),
    SenderDomainCase(
        "address-literal",
        "127.0.0.7",
        "[192.0.2.1]",
        "IP address is not allowed as sender domain",
    ),
    SenderDomainCase(
        "leading-dot",
        "127.0.0.8",
        ".mail.com",
        "Domain cannot start or end with a dot",
    ),
    SenderDomainCase(
        "trailing-dot",
        "127.0.0.9",
        "mail.com.",
        "Domain cannot start or end with a dot",
    ),
    SenderDomainCase(
        "consecutive-dots",
        "127.0.0.10",
        "bad..com",
        "Domain cannot contain consecutive dots",
    ),
    SenderDomainCase(
        "leading-hyphen",
        "127.0.0.11",
        "-mail.com",
        "Label '-mail' cannot start or end with hyphen",
    ),
    SenderDomainCase(
        "trailing-hyphen",
        "127.0.0.12",
        "mail-.com",
        "Label 'mail-' cannot start or end with hyphen",
    ),
    SenderDomainCase(
        "invalid-ascii-character",
        "127.0.0.13",
        "bad_name.com",
        "Invalid characters in label 'bad_name'",
    ),
    SenderDomainCase(
        "label-too-long",
        "127.0.0.14",
        f"{'a' * 64}.com",
        f"Label '{'a' * 64}' exceeds 63 characters",
    ),
    SenderDomainCase(
        "domain-too-long",
        "127.0.0.15",
        ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 63, "com")),
        "Domain name too long (max 255 characters)",
    ),
    SenderDomainCase(
        "short-tld",
        "127.0.0.16",
        "mail.c",
        "TLD must be at least 2 characters",
    ),
    SenderDomainCase(
        "numeric-tld",
        "127.0.0.17",
        "mail.123",
        "TLD cannot be all numeric",
    ),
    SenderDomainCase(
        "frozen-invalid-tld",
        "127.0.0.18",
        "mail.testing",
        "Invalid or non-existent TLD 'testing'",
    ),
    SenderDomainCase(
        "invalid-punycode",
        "127.0.0.19",
        "xn--a_.de",
        "Invalid Punycode label: xn--a_",
    ),
    SenderDomainCase(
        "unicode-private-use",
        "127.0.0.20",
        "\ue000.de",
        "Label contains invalid Unicode character",
    ),
    SenderDomainCase(
        "unicode-label-too-long",
        "127.0.0.21",
        f"{'é' * 64}.de",
        "Label too long (max 63 characters)",
    ),
    SenderDomainCase("valid-ascii", "127.0.0.22", "real-domain.com", None),
    SenderDomainCase("valid-punycode", "127.0.0.23", "xn--bcher-kva.de", None),
    SenderDomainCase("valid-unicode", "127.0.0.24", "bücher.de", None),
)


def _check(condition: bool, details: object) -> None:
    if not condition:
        raise AssertionError(f"SMTP sender-domain contract violation: {details!r}")


def _connect_postgres(target: RuntimeTarget) -> psycopg.Connection[tuple[Any, ...]]:
    ports = target.ports
    if ports is None:
        raise AssertionError("SMTP sender-domain target is not started")
    connection = psycopg.connect(
        host="127.0.0.1",
        port=ports.postgres,
        user="lmyzmail_test",
        dbname="lmyzmail",
        connect_timeout=5,
        autocommit=True,
    )
    connection.execute("SET statement_timeout = '2s'")
    return connection


def _wait_for_rejection_persistence(
    target: RuntimeTarget,
    case: SenderDomainCase,
) -> dict[str, Any]:
    reason = case.reason
    _check(reason is not None, case)
    deadline = time.monotonic() + _PERSISTENCE_TIMEOUT_SECONDS
    latest: tuple[tuple[Any, ...] | None, list[tuple[Any, ...]]] = (None, [])
    with _connect_postgres(target) as connection:
        while True:
            ip_row = connection.execute(
                "SELECT total_score,current_score,activity_count,illegal_domain_count,"
                "other_count FROM skibidi_cringe_ip WHERE ip_address = %s",
                (case.source,),
            ).fetchone()
            activity_rows = connection.execute(
                "SELECT activity_type,score,mail_from,response_message,metadata,"
                "helo_name,session_id,rcpt_to FROM skibidi_cringe_ip_activity "
                "WHERE ip_address = %s ORDER BY id",
                (case.source,),
            ).fetchall()
            latest = (ip_row, list(activity_rows))
            if ip_row == (5, 5, 2, 1, 1) and len(activity_rows) == 2:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(
                    "SMTP sender-domain activities were not persisted within "
                    f"{_PERSISTENCE_TIMEOUT_SECONDS:g} seconds for {case.name}: {latest!r}"
                )
            time.sleep(min(0.025, remaining))

    ip_row, activity_rows = latest
    _check(ip_row == (5, 5, 2, 1, 1), ip_row)
    _check(len(activity_rows) == 2, activity_rows)
    ip = cast(tuple[Any, ...], ip_row)
    by_type = {cast(str, row[0]): row for row in activity_rows}
    _check(set(by_type) == {"ILLEGAL_SENDER_DOMAIN", "PROTOCOL_VIOLATION"}, activity_rows)

    illegal = by_type["ILLEGAL_SENDER_DOMAIN"]
    expected_metadata = f"Invalid domain: {case.domain} - {reason}"
    _check(illegal[1] == 4, illegal)
    _check(illegal[2] == case.mail_from[:255], illegal)
    _check(illegal[3] is None, illegal)
    _check(illegal[4] == expected_metadata[:1024], illegal)
    _check(illegal[5:] == (None, None, None), illegal)

    protocol = by_type["PROTOCOL_VIOLATION"]
    _check(protocol[1] == 1, protocol)
    _check(protocol[2:4] == (None, None), protocol)
    _check(protocol[4] == "Bad sequence: RCPT in state HELO", protocol)
    _check(protocol[5] == "blackbox.example", protocol)
    _check(
        isinstance(protocol[6], str)
        and re.fullmatch(r"[0-9a-f]{8}", protocol[6]) is not None,
        protocol,
    )
    _check(protocol[7] is None, protocol)

    return {
        "ip": {
            "total_score": ip[0],
            "current_score": ip[1],
            "activity_count": ip[2],
            "illegal_domain_count": ip[3],
            "other_count": ip[4],
        },
        "illegal_sender_domain_activity": {
            "type": illegal[0],
            "score": illegal[1],
            "mail_from": illegal[2],
            "response_message": illegal[3],
            "metadata": illegal[4],
            "helo_name": illegal[5],
            "session_id": illegal[6],
            "rcpt_to": illegal[7],
        },
        "post_rejection_protocol_activity": {
            "type": protocol[0],
            "score": protocol[1],
            "mail_from": protocol[2],
            "response_message": protocol[3],
            "metadata": protocol[4],
            "helo_name": protocol[5],
            "session_id": "<session-id>",
            "rcpt_to": protocol[7],
        },
    }


def _assert_no_persistence(target: RuntimeTarget, case: SenderDomainCase) -> None:
    with _connect_postgres(target) as connection:
        ip_row = connection.execute(
            "SELECT total_score FROM skibidi_cringe_ip WHERE ip_address = %s",
            (case.source,),
        ).fetchone()
        activity_count = connection.execute(
            "SELECT count(*) FROM skibidi_cringe_ip_activity WHERE ip_address = %s",
            (case.source,),
        ).fetchone()
    _check(ip_row is None, {case.name: ip_row})
    _check(activity_count == (0,), {case.name: activity_count})


def capture_sender_domain_matrix(target: RuntimeTarget) -> dict[str, Any]:
    observations: list[dict[str, Any]] = []
    for case in _CASES:
        client, hostname = open_smtp_client(target, source=case.source)
        with client:
            ehlo = smtp_ehlo(client, hostname)
            started = time.monotonic()
            reply = client.command(f"MAIL FROM:<{case.mail_from}>".encode())
            elapsed = time.monotonic() - started
            _check(elapsed <= 10.0, {case.name: elapsed})

            if case.reason is None:
                _check(reply == (b"250 2.1.0 Sender OK\r\n",), {case.name: reply})
                quit_reply = client.quit()
                _assert_no_persistence(target, case)
                observations.append(
                    {
                        "name": case.name,
                        "source": case.source,
                        "mail_from": case.mail_from,
                        "decision": "accepted",
                        "wire": {
                            "greeting": smtp_greeting_snapshot(),
                            "ehlo": smtp_reply_snapshot(ehlo, hostname),
                            "mail_from": smtp_reply_snapshot(reply, hostname),
                            "quit": smtp_reply_snapshot(quit_reply, hostname),
                        },
                        "persistence": None,
                    }
                )
                continue

            expected = f"550 5.1.8 Sender address rejected: {case.reason}\r\n".encode()
            _check(reply == (expected,), {case.name: reply})
            rcpt = client.command(b"RCPT TO:<qa@blackbox.example.com>")
            _check(rcpt == (b"503 5.5.1 Bad sequence of commands\r\n",), rcpt)
            quit_reply = client.quit()

        observations.append(
            {
                "name": case.name,
                "source": case.source,
                "mail_from": case.mail_from,
                "decision": "rejected",
                "reason": case.reason,
                "wire": {
                    "greeting": smtp_greeting_snapshot(),
                    "ehlo": smtp_reply_snapshot(ehlo, hostname),
                    "mail_from": [expected.decode("utf-8")],
                    "rcpt_after_rejection": smtp_reply_snapshot(rcpt, hostname),
                    "quit": smtp_reply_snapshot(quit_reply, hostname),
                },
                "persistence": _wait_for_rejection_persistence(target, case),
            }
        )

    return {"cases": observations}


SMTP_SENDER_DOMAIN_SCENARIOS = (
    Scenario(
        "smtp/sender-domain/matrix",
        capture_sender_domain_matrix,
        normalizers=(
            "smtp:greeting-skibidi-grammar",
            "smtp:server-hostname",
            "postgres:async-activity-observation-window",
        ),
        contract={
            "protocol": "SMTP MAIL FROM sender-domain validation",
            "case_count": len(_CASES),
            "invalid_case_count": sum(case.reason is not None for case in _CASES),
            "valid_case_count": sum(case.reason is None for case in _CASES),
            "invalid_response": "550 5.1.8 Sender address rejected: <exact reason>",
            "post_rejection_state": "HELO without an accepted sender",
            "invalid_persistence": (
                "one ILLEGAL_SENDER_DOMAIN score-4 write plus the RCPT bad-sequence "
                "PROTOCOL_VIOLATION score-1 write"
            ),
            "valid_persistence": "no cringe IP or activity row",
        },
    ),
)
