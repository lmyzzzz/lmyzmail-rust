from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any, Protocol, cast

import psycopg

from .differential import RuntimeTarget, Scenario
from .scripted_dns import AAnswer, DnsAnswer, DnsQuery
from .smtp_contract import (
    open_smtp_client,
    smtp_ehlo,
    smtp_greeting_snapshot,
    smtp_reply_snapshot,
)

DNS_A_TYPE = 1
SPAMHAUS_DBL_ZONE = "dbl.blackbox.invalid"
_PERSISTENCE_TIMEOUT_SECONDS = 8.0
_SMTP_COMMAND_TIMEOUT_SECONDS = 10.0


class SpamhausDnsTarget(Protocol):
    def drain_spamhaus_dns_queries(self) -> tuple[DnsQuery, ...]: ...


@dataclass(frozen=True, slots=True)
class SpamhausCase:
    name: str
    source: str
    domain: str
    decision: str
    return_code: str | None = None
    description: str | None = None
    variable_dns_retries: bool = False

    @property
    def mail_from(self) -> str:
        return f"sender@{self.domain}"

    @property
    def ascii_domain(self) -> str:
        return self.domain.encode("idna").decode("ascii").lower()

    @property
    def query_name(self) -> str:
        return f"{self.ascii_domain}.{SPAMHAUS_DBL_ZONE}"


_REJECT_CASES = (
    SpamhausCase(
        "known-dbl-code",
        "127.0.0.31",
        "KnOwN-DbL.CoM",
        "rejected",
        "127.0.1.4",
        "DBL (phish domain)",
    ),
    SpamhausCase(
        "unknown-dbl-code",
        "127.0.0.32",
        "unknown-dbl.net",
        "rejected",
        "127.42.42.42",
        f"Listed in {SPAMHAUS_DBL_ZONE}",
    ),
    SpamhausCase("nxdomain", "127.0.0.33", "clear-domain.org", "accepted"),
    SpamhausCase("nodata", "127.0.0.34", "nodata-domain.com", "accepted"),
    SpamhausCase(
        "servfail",
        "127.0.0.35",
        "servfail-domain.net",
        "accepted",
        variable_dns_retries=True,
    ),
    SpamhausCase(
        "timeout",
        "127.0.0.36",
        "timeout-domain.org",
        "accepted",
        variable_dns_retries=True,
    ),
    SpamhausCase(
        "unicode-idna",
        "127.0.0.37",
        "bücher.de",
        "rejected",
        "127.0.1.2",
        "DBL (spam domain)",
    ),
)

_REJECT_DISABLED_CASE = SpamhausCase(
    "reject-disabled",
    "127.0.0.41",
    "known-dbl.com",
    "accepted",
    "127.0.1.4",
    "DBL (phish domain)",
)
_DISABLED_CASE = SpamhausCase(
    "spamhaus-disabled",
    "127.0.0.42",
    "known-dbl.com",
    "accepted",
    "127.0.1.4",
    "DBL (phish domain)",
)
_CACHE_CASE = SpamhausCase(
    "cache-hit",
    "127.0.0.38",
    "cache-dbl.com",
    "rejected",
    "127.0.1.5",
    "DBL (malware domain)",
)


def spamhaus_dns_answers() -> dict[tuple[str, int], DnsAnswer]:
    answers: dict[tuple[str, int], DnsAnswer] = {}
    for case in (*_REJECT_CASES, _REJECT_DISABLED_CASE, _CACHE_CASE):
        if case.return_code is not None:
            answers[(case.query_name, DNS_A_TYPE)] = DnsAnswer(
                a=(AAnswer(case.return_code, ttl=0 if case is _CACHE_CASE else 60),)
            )
    nodata = next(case for case in _REJECT_CASES if case.name == "nodata")
    servfail = next(case for case in _REJECT_CASES if case.name == "servfail")
    timeout_case = next(case for case in _REJECT_CASES if case.name == "timeout")
    answers[(nodata.query_name, DNS_A_TYPE)] = DnsAnswer()
    answers[(servfail.query_name, DNS_A_TYPE)] = DnsAnswer(rcode=2)
    answers[(timeout_case.query_name, DNS_A_TYPE)] = DnsAnswer(drop=True)
    return answers


def _check(condition: bool, details: object) -> None:
    if not condition:
        raise AssertionError(f"SMTP Spamhaus contract violation: {details!r}")


def _drain_dns_queries(target: RuntimeTarget) -> tuple[DnsQuery, ...]:
    return cast(SpamhausDnsTarget, target).drain_spamhaus_dns_queries()


def _matching_dbl_queries(queries: tuple[DnsQuery, ...], case: SpamhausCase) -> list[DnsQuery]:
    return [
        query
        for query in queries
        if query.qtype == DNS_A_TYPE and query.qname == case.query_name
    ]


def _latin1_reply_snapshot(reply: tuple[bytes, ...], hostname: bytes) -> list[str]:
    normalized = tuple(line.replace(hostname, b"<hostname>") for line in reply)
    return [line.decode("latin-1") for line in normalized]


def _connect_postgres(target: RuntimeTarget) -> psycopg.Connection[tuple[Any, ...]]:
    ports = target.ports
    if ports is None:
        raise AssertionError("SMTP Spamhaus target is not started")
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


def _wait_for_activity_count(
    target: RuntimeTarget,
    source: str,
    expected_count: int,
) -> tuple[tuple[Any, ...] | None, list[tuple[Any, ...]]]:
    deadline = time.monotonic() + _PERSISTENCE_TIMEOUT_SECONDS
    latest: tuple[tuple[Any, ...] | None, list[tuple[Any, ...]]] = (None, [])
    with _connect_postgres(target) as connection:
        while True:
            ip_row = connection.execute(
                "SELECT total_score,current_score,activity_count,spamhaus_count,"
                "other_count FROM skibidi_cringe_ip WHERE ip_address = %s",
                (source,),
            ).fetchone()
            activities = connection.execute(
                "SELECT activity_type,score,mail_from,response_message,metadata,"
                "helo_name,session_id,rcpt_to FROM skibidi_cringe_ip_activity "
                "WHERE ip_address = %s ORDER BY id",
                (source,),
            ).fetchall()
            latest = (ip_row, list(activities))
            if (
                ip_row is not None
                and cast(int, ip_row[2]) == expected_count
                and len(activities) == expected_count
            ):
                return latest
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(
                    "SMTP Spamhaus activities were not persisted within "
                    f"{_PERSISTENCE_TIMEOUT_SECONDS:g} seconds: {latest!r}"
                )
            time.sleep(min(0.025, remaining))


def _assert_no_persistence(target: RuntimeTarget, case: SpamhausCase) -> None:
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


def _persistence_snapshot(target: RuntimeTarget, case: SpamhausCase) -> dict[str, Any]:
    ip_row, activity_rows = _wait_for_activity_count(target, case.source, 2)
    _check(ip_row == (4, 4, 2, 1, 1), ip_row)
    by_type = {cast(str, row[0]): row for row in activity_rows}
    _check(set(by_type) == {"SPAMHAUS_LISTED", "PROTOCOL_VIOLATION"}, activity_rows)

    spamhaus = by_type["SPAMHAUS_LISTED"]
    _check(spamhaus[1] == 3, spamhaus)
    _check(spamhaus[2] == case.mail_from[:255], spamhaus)
    _check(spamhaus[3] is None, spamhaus)
    _check(spamhaus[4] == f"Listed in: , {SPAMHAUS_DBL_ZONE}", spamhaus)
    _check(spamhaus[5:] == (None, None, None), spamhaus)

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
    ip = cast(tuple[Any, ...], ip_row)
    return {
        "ip": {
            "total_score": ip[0],
            "current_score": ip[1],
            "activity_count": ip[2],
            "spamhaus_count": ip[3],
            "other_count": ip[4],
        },
        "spamhaus_activity": {
            "type": spamhaus[0],
            "score": spamhaus[1],
            "mail_from": spamhaus[2],
            "response_message": spamhaus[3],
            "metadata": spamhaus[4],
            "helo_name": spamhaus[5],
            "session_id": spamhaus[6],
            "rcpt_to": spamhaus[7],
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


def _attempt(target: RuntimeTarget, case: SpamhausCase) -> dict[str, Any]:
    _drain_dns_queries(target)
    client, hostname = open_smtp_client(target, source=case.source)
    with client:
        ehlo = smtp_ehlo(client, hostname)
        started = time.monotonic()
        mail_reply = client.command(f"MAIL FROM:<{case.mail_from}>".encode())
        elapsed = time.monotonic() - started
        _check(elapsed <= _SMTP_COMMAND_TIMEOUT_SECONDS, {case.name: elapsed})
        if case.decision == "rejected":
            description = cast(str, case.description)
            expected = (
                "550 5.7.1 Service unavailable; sender domain "
                f"[{case.domain}] blocked using {SPAMHAUS_DBL_ZONE}; {description}; "
                f"see https://www.spamhaus.org/query/ip/{case.source}\r\n"
            ).encode("latin-1")
            _check(mail_reply == (expected,), {case.name: mail_reply})
            rcpt = client.command(b"RCPT TO:<qa@blackbox.example.com>")
            _check(rcpt == (b"503 5.5.1 Bad sequence of commands\r\n",), rcpt)
            quit_reply = client.quit()
        else:
            _check(mail_reply == (b"250 2.1.0 Sender OK\r\n",), {case.name: mail_reply})
            rcpt = None
            quit_reply = client.quit()

    matches = _matching_dbl_queries(_drain_dns_queries(target), case)
    if case.variable_dns_retries:
        _check(bool(matches), {case.name: matches})
        normalized_query_count: int | str = "at-least-one"
    else:
        _check(1 <= len(matches) <= 4, {case.name: matches})
        normalized_query_count = len(matches)

    wire: dict[str, Any] = {
        "greeting": smtp_greeting_snapshot(),
        "ehlo": smtp_reply_snapshot(ehlo, hostname),
        "mail_from": _latin1_reply_snapshot(mail_reply, hostname),
        "quit": smtp_reply_snapshot(quit_reply, hostname),
    }
    if rcpt is not None:
        wire["rcpt_after_rejection"] = smtp_reply_snapshot(rcpt, hostname)
    if case.decision == "rejected":
        persistence = _persistence_snapshot(target, case)
    else:
        _assert_no_persistence(target, case)
        persistence = None
    return {
        "name": case.name,
        "source": case.source,
        "mail_from": case.mail_from,
        "decision": case.decision,
        "dns": {
            "query_name": case.query_name,
            "qtype": DNS_A_TYPE,
            "query_count": normalized_query_count,
        },
        "wire": wire,
        "persistence": persistence,
    }


def capture_spamhaus_reject_matrix(target: RuntimeTarget) -> dict[str, Any]:
    return {"cases": [_attempt(target, case) for case in _REJECT_CASES]}


def capture_spamhaus_reject_disabled(target: RuntimeTarget) -> dict[str, Any]:
    return {"cases": [_attempt(target, _REJECT_DISABLED_CASE)]}


def capture_spamhaus_disabled(target: RuntimeTarget) -> dict[str, Any]:
    case = _DISABLED_CASE
    _drain_dns_queries(target)
    client, hostname = open_smtp_client(target, source=case.source)
    with client:
        ehlo = smtp_ehlo(client, hostname)
        mail_reply = client.command(f"MAIL FROM:<{case.mail_from}>".encode())
        _check(mail_reply == (b"250 2.1.0 Sender OK\r\n",), mail_reply)
        quit_reply = client.quit()
    matches = _matching_dbl_queries(_drain_dns_queries(target), case)
    _check(matches == [], matches)
    _assert_no_persistence(target, case)
    return {
        "cases": [
            {
                "name": case.name,
                "source": case.source,
                "mail_from": case.mail_from,
                "decision": case.decision,
                "dns": {"query_name": case.query_name, "qtype": DNS_A_TYPE, "query_count": 0},
                "wire": {
                    "greeting": smtp_greeting_snapshot(),
                    "ehlo": smtp_reply_snapshot(ehlo, hostname),
                    "mail_from": _latin1_reply_snapshot(mail_reply, hostname),
                    "quit": smtp_reply_snapshot(quit_reply, hostname),
                },
                "persistence": None,
            }
        ]
    }


def _cache_attempt(target: RuntimeTarget, case: SpamhausCase) -> None:
    client, hostname = open_smtp_client(target, source=case.source)
    with client:
        smtp_ehlo(client, hostname)
        reply = client.command(f"MAIL FROM:<{case.mail_from}>".encode())
        _check(bool(reply) and reply[0].startswith(b"550 5.7.1 Service unavailable;"), reply)
        client.quit()


def capture_spamhaus_cache(target: RuntimeTarget) -> dict[str, Any]:
    case = _CACHE_CASE
    _drain_dns_queries(target)
    _cache_attempt(target, case)
    first_ip, _ = _wait_for_activity_count(target, case.source, 1)
    first_queries = _matching_dbl_queries(_drain_dns_queries(target), case)
    _check(len(first_queries) == 1, first_queries)

    _cache_attempt(target, case)
    second_ip, _ = _wait_for_activity_count(target, case.source, 2)
    cached_queries = _matching_dbl_queries(_drain_dns_queries(target), case)
    _check(cached_queries == [], cached_queries)

    time.sleep(1.2)
    _cache_attempt(target, case)
    third_ip, activities = _wait_for_activity_count(target, case.source, 3)
    expired_queries = _matching_dbl_queries(_drain_dns_queries(target), case)
    _check(len(expired_queries) == 1, expired_queries)
    _check(first_ip == (3, 3, 1, 1, 0), first_ip)
    _check(second_ip == (6, 6, 2, 2, 0), second_ip)
    _check(third_ip == (9, 9, 3, 3, 0), third_ip)
    _check(all(row[0] == "SPAMHAUS_LISTED" and row[1] == 3 for row in activities), activities)
    return {
        "source": case.source,
        "mail_from": case.mail_from,
        "dns_query_name": case.query_name,
        "first_lookup_query_count": 1,
        "immediate_cache_hit_query_count": 0,
        "post_ttl_lookup_query_count": 1,
        "cache_ttl_seconds": 1,
        "persistence": {
            "total_score": 9,
            "current_score": 9,
            "activity_count": 3,
            "spamhaus_count": 3,
            "other_count": 0,
        },
    }


SMTP_SPAMHAUS_REJECT_SCENARIOS = (
    Scenario(
        "smtp/spamhaus/domain-dbl-matrix",
        capture_spamhaus_reject_matrix,
        normalizers=(
            "smtp:greeting-skibidi-grammar",
            "smtp:server-hostname",
            "postgres:async-activity-observation-window",
            "dns:servfail-retry-count",
            "dns:timeout-retry-count",
        ),
        contract={
            "protocol": "SMTP MAIL FROM Spamhaus domain DBL early rejection",
            "case_count": len(_REJECT_CASES),
            "dns_query": "<lowercase IDNA sender domain>.<configured DBL zone> A",
            "listed_response": "550 5.7.1 Service unavailable; sender domain [...]",
            "failure_policy": "NXDOMAIN, NODATA, SERVFAIL, and deadline expiry fail open",
            "listed_persistence": "SPAMHAUS_LISTED score 3; post-reject RCPT violation score 1",
        },
    ),
    Scenario(
        "smtp/spamhaus/cache",
        capture_spamhaus_cache,
        normalizers=("postgres:async-activity-observation-window",),
        contract={
            "cache_key": "client IP plus ASCII sender domain",
            "cache_ttl_seconds": 1,
            "fixture_dns_ttl_seconds": 0,
            "immediate_reuse": "no second DNS A query",
            "expiry": "a new DNS A query occurs after TTL",
        },
    ),
)

SMTP_SPAMHAUS_REJECT_DISABLED_SCENARIOS = (
    Scenario(
        "smtp/spamhaus/reject-disabled",
        capture_spamhaus_reject_disabled,
        normalizers=("smtp:greeting-skibidi-grammar", "smtp:server-hostname"),
        contract={
            "configuration": "Spamhaus and DBL enabled, reject-on-listed disabled",
            "behavior": "listed sender is accepted and no cringe activity is written",
        },
    ),
)

SMTP_SPAMHAUS_DISABLED_SCENARIOS = (
    Scenario(
        "smtp/spamhaus/disabled",
        capture_spamhaus_disabled,
        normalizers=("smtp:greeting-skibidi-grammar", "smtp:server-hostname"),
        contract={
            "configuration": "Spamhaus disabled while DBL remains configured",
            "behavior": "sender is accepted without a DBL query or cringe activity",
        },
    ),
)
