from __future__ import annotations

import ssl
import time
from typing import Any, cast

import psycopg

from .differential import RuntimeTarget, Scenario
from .protocols import RawSmtpClient, read_smtp_reply
from .smtp_contract import (
    open_smtp_client,
    smtp_ehlo,
    smtp_greeting_snapshot,
    smtp_reply_snapshot,
)

_SERVER_NAME = "smtp.example.test"
_AUTH_FAILURE_LIMIT = 20
_AUTH_PROBE_OBSERVATION_SECONDS = 8.0
_BAD_SEQUENCE = (b"503 5.5.1 Bad sequence of commands\r\n",)
_AUTH_NOT_IMPLEMENTED = (
    b"502 5.5.1 AUTH command not implemented. "
    b"Blud is yapping about AUTH but nobody is listening. "
    b"We don't do that here. Take your L and go back to the lobby.\r\n",
)
_UNKNOWN_CONTINUATION = (b"500 5.5.1 Command not recognized: DXNLCG==\r\n",)
_MAIL_OK = (b"250 2.1.0 Sender OK\r\n",)
_MAIL_BLOCKED = (b"550 5.7.1 Access denied\r\n",)
_RESET_OK = (b"250 2.0.0 Reset OK\r\n",)
_NOOP_OK = (b"250 OK\r\n",)
_READY_FOR_TLS = (b"220 2.0.0 Ready to start TLS\r\n",)
_LINE_TOO_LONG = (b"500 5.5.2 Line too long\r\n",)

_AUTH_CASES = (
    ("no_mechanism", b"AUTH"),
    ("arbitrary_mechanism", b"AUTH XOAUTH2"),
    ("plain", b"AUTH PLAIN"),
    ("login", b"AUTH LOGIN"),
    ("initial_response", b"AUTH PLAIN AHVzZXIAcGFzcw=="),
    ("malformed_base64", b"AUTH PLAIN !!!not-base64!!!"),
    ("mixed_case", b"aUtH pLaIn"),
    ("mixed_case_and_tabs", b"AuTh \tLoGiN\tZHVtbXk="),
)

_SMTP_NORMALIZERS = (
    "smtp:greeting-skibidi-grammar",
    "smtp:server-hostname",
)
_AUTH_PROBE_NORMALIZERS = ("postgres:bounded-async-auth-probe-observation-window",)


def _check(condition: bool, details: object) -> None:
    if not condition:
        raise AssertionError(f"SMTP AUTH contract violation: {details!r}")


def _snapshot_command(
    client: RawSmtpClient,
    hostname: bytes,
    command: bytes,
    expected: tuple[bytes, ...],
) -> list[str]:
    reply = client.command(command)
    _check(reply == expected, {"command": command, "reply": reply})
    return smtp_reply_snapshot(reply, hostname)


def _assert_auth_not_advertised(reply: tuple[bytes, ...]) -> None:
    for line in reply:
        capability = line[4:].strip().split(maxsplit=1)[0].upper()
        _check(capability != b"AUTH", reply)


def _connect_postgres(
    target: RuntimeTarget,
) -> psycopg.Connection[tuple[Any, ...]]:
    ports = target.ports
    if ports is None:
        raise AssertionError("SMTP AUTH target is not started")
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


def _auth_probe_counts(
    connection: psycopg.Connection[tuple[Any, ...]],
) -> tuple[int, int]:
    activity_row = connection.execute(
        "SELECT count(*) FROM skibidi_cringe_ip_activity WHERE activity_type = 'AUTH_PROBE'"
    ).fetchone()
    aggregate_row = connection.execute(
        "SELECT COALESCE(sum(auth_probe_count), 0) FROM skibidi_cringe_ip"
    ).fetchone()
    if activity_row is None or not isinstance(activity_row[0], int):
        raise AssertionError(f"SMTP AUTH contract violation: {activity_row!r}")
    if aggregate_row is None or not isinstance(aggregate_row[0], int):
        raise AssertionError(f"SMTP AUTH contract violation: {aggregate_row!r}")
    return activity_row[0], aggregate_row[0]


def _observe_missing_auth_probe_persistence(
    connection: psycopg.Connection[tuple[Any, ...]],
    baseline: tuple[int, int],
) -> dict[str, int]:
    deadline = time.monotonic() + _AUTH_PROBE_OBSERVATION_SECONDS
    latest = baseline
    while True:
        latest = _auth_probe_counts(connection)
        deltas = (latest[0] - baseline[0], latest[1] - baseline[1])
        _check(deltas == (0, 0), {"baseline": baseline, "latest": latest})
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return {
                "observation_window_ms": int(_AUTH_PROBE_OBSERVATION_SECONDS * 1000),
                "activity_rows_delta": deltas[0],
                "aggregate_auth_probe_delta": deltas[1],
            }
        time.sleep(min(0.1, remaining))


def _client_context(target: RuntimeTarget) -> ssl.SSLContext:
    certificate = getattr(target, "tls_certificate_pem", None)
    _check(isinstance(certificate, bytes), "target did not expose a TLS certificate")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cadata=cast(bytes, certificate).decode("ascii"))
    return context


def _capture_plaintext_auth(target: RuntimeTarget) -> dict[str, Any]:
    with _connect_postgres(target) as connection:
        database_baseline = _auth_probe_counts(connection)
        client, hostname = open_smtp_client(target)
        with client:
            pre_ehlo = _snapshot_command(client, hostname, b"AUTH PLAIN", _BAD_SEQUENCE)
            ehlo = smtp_ehlo(client, hostname)
            _assert_auth_not_advertised(ehlo)

            handler_cases: list[dict[str, Any]] = []
            continuation: dict[str, Any] | None = None
            for name, command in _AUTH_CASES:
                handler_cases.append(
                    {
                        "case": name,
                        "command": command.decode("ascii"),
                        "reply": _snapshot_command(
                            client,
                            hostname,
                            command,
                            _AUTH_NOT_IMPLEMENTED,
                        ),
                    }
                )
                if name == "login":
                    continuation = {
                        "command": "dXNlcg==",
                        "reply": _snapshot_command(
                            client,
                            hostname,
                            b"dXNlcg==",
                            _UNKNOWN_CONTINUATION,
                        ),
                    }
            _check(continuation is not None, handler_cases)

            overlong_command = b"AUTH PLAIN " + (b"A" * 1000)
            client.stream.sendall(overlong_command + b"\r\n")
            overlong_wire_reply = read_smtp_reply(client.stream)
            _check(overlong_wire_reply == _LINE_TOO_LONG, overlong_wire_reply)
            overlong_reply = smtp_reply_snapshot(overlong_wire_reply, hostname)
            after_overlong = _snapshot_command(
                client,
                hostname,
                b"NOOP",
                _NOOP_OK,
            )

            noop_after_variants = _snapshot_command(
                client,
                hostname,
                b"NOOP",
                _NOOP_OK,
            )
            transaction_mail = _snapshot_command(
                client,
                hostname,
                b"MAIL FROM:<>",
                _MAIL_OK,
            )
            transaction_auth = _snapshot_command(
                client,
                hostname,
                b"AUTH PLAIN",
                _BAD_SEQUENCE,
            )
            transaction_reset = _snapshot_command(
                client,
                hostname,
                b"RSET",
                _RESET_OK,
            )

            filler_attempts = _AUTH_FAILURE_LIMIT - len(_AUTH_CASES) - 1
            _check(filler_attempts > 0, filler_attempts)
            for _ in range(filler_attempts):
                _snapshot_command(
                    client,
                    hostname,
                    b"AUTH PLAIN",
                    _AUTH_NOT_IMPLEMENTED,
                )

            mail_before_threshold = _snapshot_command(
                client,
                hostname,
                b"MAIL FROM:<>",
                _MAIL_OK,
            )
            reset_before_threshold = _snapshot_command(
                client,
                hostname,
                b"RSET",
                _RESET_OK,
            )
            threshold_auth = _snapshot_command(
                client,
                hostname,
                b"AUTH PLAIN",
                _AUTH_NOT_IMPLEMENTED,
            )
            mail_after_threshold = _snapshot_command(
                client,
                hostname,
                b"MAIL FROM:<>",
                _MAIL_BLOCKED,
            )
            final_noop = _snapshot_command(client, hostname, b"NOOP", _NOOP_OK)
            quit_reply = client.quit()

        partial_client, _partial_hostname = open_smtp_client(target)
        with partial_client:
            partial_client.stream.sendall(b"AUTH LOGIN")

        recovery_client, recovery_hostname = open_smtp_client(target)
        with recovery_client:
            recovery_ehlo = smtp_ehlo(recovery_client, recovery_hostname)
            recovery_noop = _snapshot_command(
                recovery_client,
                recovery_hostname,
                b"NOOP",
                _NOOP_OK,
            )
            recovery_quit = recovery_client.quit()

        database = _observe_missing_auth_probe_persistence(
            connection,
            database_baseline,
        )

    return {
        "greeting": smtp_greeting_snapshot(),
        "pre_ehlo_auth": pre_ehlo,
        "ehlo": smtp_reply_snapshot(ehlo, hostname),
        "auth_advertised": False,
        "handler_cases": handler_cases,
        "extra_base64_continuation": continuation,
        "line_length": {
            "command_length": len(overlong_command),
            "reply": overlong_reply,
            "session_recovery": after_overlong,
        },
        "transaction_rejection": {
            "noop_after_auth_variants": noop_after_variants,
            "mail_from": transaction_mail,
            "auth": transaction_auth,
            "rset": transaction_reset,
        },
        "rate_limit": {
            "auth_failure_limit": _AUTH_FAILURE_LIMIT,
            "filler_attempts": filler_attempts,
            "mail_before_threshold": mail_before_threshold,
            "reset_before_threshold": reset_before_threshold,
            "threshold_auth": threshold_auth,
            "mail_after_threshold": mail_after_threshold,
        },
        "session_usable_after_block": {
            "noop": final_noop,
            "quit": smtp_reply_snapshot(quit_reply, hostname),
        },
        "partial_disconnect_recovery": {
            "sent_without_crlf_length": len(b"AUTH LOGIN"),
            "recovery_ehlo": smtp_reply_snapshot(recovery_ehlo, recovery_hostname),
            "recovery_noop": recovery_noop,
            "recovery_quit": smtp_reply_snapshot(recovery_quit, recovery_hostname),
        },
        "auth_probe_database": database,
    }


def _capture_starttls_auth(target: RuntimeTarget) -> dict[str, Any]:
    with _connect_postgres(target) as connection:
        database_baseline = _auth_probe_counts(connection)
        client, hostname = open_smtp_client(target)
        with client:
            pre_ehlo = _snapshot_command(client, hostname, b"AUTH PLAIN", _BAD_SEQUENCE)
            ehlo_before_tls = smtp_ehlo(client, hostname, advertise_starttls=True)
            _assert_auth_not_advertised(ehlo_before_tls)
            auth_before_tls = _snapshot_command(
                client,
                hostname,
                b"AUTH PLAIN",
                _AUTH_NOT_IMPLEMENTED,
            )
            ready = client.start_tls(
                _client_context(target),
                server_hostname=_SERVER_NAME,
            )
            _check(ready == _READY_FOR_TLS, ready)
            auth_before_post_tls_ehlo = _snapshot_command(
                client,
                hostname,
                b"AUTH LOGIN",
                _BAD_SEQUENCE,
            )
            ehlo_after_tls = smtp_ehlo(client, hostname)
            _assert_auth_not_advertised(ehlo_after_tls)
            auth_after_tls = _snapshot_command(
                client,
                hostname,
                b"AUTH LOGIN",
                _AUTH_NOT_IMPLEMENTED,
            )
            noop = _snapshot_command(client, hostname, b"NOOP", _NOOP_OK)
            quit_reply = client.quit()

        database = _observe_missing_auth_probe_persistence(
            connection,
            database_baseline,
        )

    return {
        "greeting": smtp_greeting_snapshot(),
        "pre_ehlo_auth": pre_ehlo,
        "ehlo_before_tls": smtp_reply_snapshot(ehlo_before_tls, hostname),
        "auth_advertised_before_tls": False,
        "auth_before_tls": auth_before_tls,
        "starttls": smtp_reply_snapshot(ready, hostname),
        "auth_before_post_tls_ehlo": auth_before_post_tls_ehlo,
        "ehlo_after_tls": smtp_reply_snapshot(ehlo_after_tls, hostname),
        "auth_advertised_after_tls": False,
        "auth_after_tls": auth_after_tls,
        "session_usable": {
            "noop": noop,
            "quit": smtp_reply_snapshot(quit_reply, hostname),
        },
        "auth_probe_database": database,
    }


SMTP_AUTH_SCENARIOS = (
    Scenario(
        "smtp/auth/state-rate-limit-and-side-effects",
        _capture_plaintext_auth,
        _SMTP_NORMALIZERS + _AUTH_PROBE_NORMALIZERS,
        {
            "protocol": "smtp",
            "operation": "auth-state-rate-limit-and-side-effects",
            "auth_advertised": False,
            "handler_reply": _AUTH_NOT_IMPLEMENTED[0].decode("ascii"),
            "handler_state": "HELO",
            "bad_sequence_states": ["CONNECT", "MAIL"],
            "arguments_are_not_parsed": True,
            "base64_continuation_is_a_new_command": True,
            "overlong_line_reply": _LINE_TOO_LONG[0].decode("ascii"),
            "partial_line_disconnect": "close-without-response-and-new-session-recovers",
            "command_matching": "case-insensitive",
            "auth_failure_limit": _AUTH_FAILURE_LIMIT,
            "blocked_command": "MAIL",
            "blocked_reply": _MAIL_BLOCKED[0].decode("ascii"),
            "session_remains_usable": True,
            "auth_probe_persistence_observation_seconds": (_AUTH_PROBE_OBSERVATION_SECONDS),
            "auth_probe_persistence_observed": False,
        },
    ),
)

SMTP_AUTH_TLS_SCENARIOS = (
    Scenario(
        "smtp/auth/starttls-state",
        _capture_starttls_auth,
        _SMTP_NORMALIZERS + _AUTH_PROBE_NORMALIZERS,
        {
            "protocol": "smtp",
            "operation": "auth-starttls-state",
            "auth_advertised_before_tls": False,
            "auth_advertised_after_tls": False,
            "pre_tls_ehlo_required": True,
            "post_tls_ehlo_required": True,
            "handler_reply_before_tls": _AUTH_NOT_IMPLEMENTED[0].decode("ascii"),
            "handler_reply_after_tls": _AUTH_NOT_IMPLEMENTED[0].decode("ascii"),
            "session_remains_usable": True,
            "auth_probe_persistence_observation_seconds": (_AUTH_PROBE_OBSERVATION_SECONDS),
            "auth_probe_persistence_observed": False,
        },
    ),
)
