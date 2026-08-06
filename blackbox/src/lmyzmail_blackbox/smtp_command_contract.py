from __future__ import annotations

from typing import Any

from .differential import RuntimeTarget, Scenario
from .protocols import RawSmtpClient, read_smtp_reply
from .smtp_contract import (
    open_smtp_client,
    smtp_ehlo,
    smtp_greeting_snapshot,
    smtp_reply_snapshot,
)
from .snapshots import bytes_snapshot

_MAX_LINE_LENGTH = 1000
_MAX_ERRORS_PER_CONNECTION = 10

_SMTP_NORMALIZERS = (
    "smtp:greeting-skibidi-grammar",
    "smtp:server-hostname",
)

_OK = (b"250 OK\r\n",)
_RESET_OK = (b"250 2.0.0 Reset OK\r\n",)
_SENDER_OK = (b"250 2.1.0 Sender OK\r\n",)
_RECIPIENT_OK = (b"250 2.1.5 Recipient OK\r\n",)
_BAD_SEQUENCE = (b"503 5.5.1 Bad sequence of commands\r\n",)
_SYNTAX_PARAMETERS = (b"501 5.5.4 Syntax error in parameters\r\n",)
_LINE_TOO_LONG = (b"500 5.5.2 Line too long\r\n",)
_VRFY_NEUTRAL = (b"252 2.5.2 Cannot verify user, but will accept message and attempt delivery\r\n",)
_HELP = (
    b"214-Supported commands:\r\n",
    b"214-HELO EHLO MAIL RCPT DATA BDAT\r\n",
    b"214-RSET NOOP QUIT VRFY HELP STARTTLS\r\n",
    b"214 For more information, see RFC 5321\r\n",
)
_MESSAGE_TOO_LARGE = (b"552 5.3.4 Message size exceeds limit of 15728640 bytes\r\n",)
_MISSING_MAILBOX = (b"550 5.1.1 Mailbox not found: missing@example.test\r\n",)
_UNACCEPTED_DOMAIN = (b"550 5.1.2 Domain not accepted: invalid.test\r\n",)


def _check(condition: bool, details: object) -> None:
    if not condition:
        raise AssertionError(f"SMTP command contract violation: {details!r}")


def _snapshot_command(
    client: RawSmtpClient,
    hostname: bytes,
    command: bytes,
    expected: tuple[bytes, ...],
) -> list[str]:
    reply = client.command(command)
    _check(reply == expected, {"command": command, "reply": reply})
    return smtp_reply_snapshot(reply, hostname)


def _snapshot_raw(
    client: RawSmtpClient,
    hostname: bytes,
    payload: bytes,
    expected: tuple[bytes, ...],
) -> dict[str, Any]:
    client.stream.sendall(payload)
    reply = read_smtp_reply(client.stream)
    _check(reply == expected, {"payload": payload, "reply": reply})
    return {
        "payload": bytes_snapshot(payload),
        "reply": smtp_reply_snapshot(reply, hostname),
    }


def _snapshot_unframed_raw(
    client: RawSmtpClient,
    payload: bytes,
    expected_wire: bytes,
) -> dict[str, Any]:
    client.stream.sendall(payload)
    reply = client.stream.read_exact(len(expected_wire))
    _check(reply == expected_wire, {"payload": payload, "reply": reply})
    return {
        "payload": bytes_snapshot(payload),
        "reply": bytes_snapshot(reply),
    }


def _quit_snapshot(client: RawSmtpClient, hostname: bytes) -> list[str]:
    return smtp_reply_snapshot(client.quit(), hostname)


def _assert_server_eof(client: RawSmtpClient) -> bool:
    _check(not client.stream.buffer, client.stream.buffer)
    client.stream.sock.settimeout(2.0)
    trailing = client.stream.sock.recv(1)
    _check(trailing == b"", trailing)
    return True


def _capture_utility_and_transaction_state(target: RuntimeTarget) -> dict[str, Any]:
    client, hostname = open_smtp_client(target)
    with client:
        pre_helo = {
            "noop_without_argument": _snapshot_command(client, hostname, b"NOOP", _OK),
            "noop_with_argument": _snapshot_command(
                client,
                hostname,
                b"NOOP arbitrary text",
                _OK,
            ),
            "vrfy_without_argument": _snapshot_command(
                client,
                hostname,
                b"VRFY",
                _VRFY_NEUTRAL,
            ),
            "vrfy_with_argument": _snapshot_command(
                client,
                hostname,
                b"VRFY qa@example.test",
                _VRFY_NEUTRAL,
            ),
            "help_without_argument": _snapshot_command(
                client,
                hostname,
                b"HELP",
                _HELP,
            ),
            "help_with_argument": _snapshot_command(
                client,
                hostname,
                b"HELP NOOP",
                _HELP,
            ),
            "rset": _snapshot_command(client, hostname, b"RSET", _RESET_OK),
            "mail_after_connect_rset": _snapshot_command(
                client,
                hostname,
                b"MAIL FROM:<>",
                _BAD_SEQUENCE,
            ),
        }

        ehlo = smtp_ehlo(client, hostname)
        mail_syntax_cases = []
        for name, command, expected in (
            ("missing_argument", b"MAIL", _SYNTAX_PARAMETERS),
            ("missing_from_colon", b"MAIL FROM", _SYNTAX_PARAMETERS),
            ("wrong_prefix", b"MAIL TO:<>", _SYNTAX_PARAMETERS),
            ("empty_reverse_path", b"MAIL FROM:", _SYNTAX_PARAMETERS),
            ("negative_size", b"MAIL FROM:<> SIZE=-1", _SYNTAX_PARAMETERS),
            ("nonnumeric_size", b"MAIL FROM:<> SIZE=abc", _SYNTAX_PARAMETERS),
            ("over_limit_size", b"MAIL FROM:<> SIZE=15728641", _MESSAGE_TOO_LARGE),
        ):
            mail_syntax_cases.append(
                {
                    "case": name,
                    "command": command.decode("ascii"),
                    "reply": _snapshot_command(client, hostname, command, expected),
                }
            )

        max_size_mail = _snapshot_command(
            client,
            hostname,
            b"MAIL FROM:<> SIZE=15728640",
            _SENDER_OK,
        )
        max_size_reset = _snapshot_command(client, hostname, b"RSET", _RESET_OK)
        unknown_parameter_mail = _snapshot_command(
            client,
            hostname,
            b"MAIL FROM:<> FOO",
            _SENDER_OK,
        )
        unknown_parameter_reset = _snapshot_command(client, hostname, b"RSET", _RESET_OK)
        spaced_null_sender = _snapshot_command(
            client,
            hostname,
            b"MAIL FROM: <>",
            _SENDER_OK,
        )

        rcpt_cases = []
        for name, command, expected in (
            ("wrong_prefix", b"RCPT FROM:<qa@example.test>", _SYNTAX_PARAMETERS),
            ("empty_argument", b"RCPT TO:", _SYNTAX_PARAMETERS),
            ("empty_forward_path", b"RCPT TO:<>", _SYNTAX_PARAMETERS),
            ("missing_mailbox", b"RCPT TO:<missing@example.test>", _MISSING_MAILBOX),
            ("unaccepted_domain", b"RCPT TO:<other@invalid.test>", _UNACCEPTED_DOMAIN),
            ("loose_address", b"RCPT TO:qa@example.test", _RECIPIENT_OK),
            ("angle_address", b"RCPT TO:<qa@example.test>", _RECIPIENT_OK),
        ):
            rcpt_cases.append(
                {
                    "case": name,
                    "command": command.decode("ascii"),
                    "reply": _snapshot_command(client, hostname, command, expected),
                }
            )

        transaction_utility = {
            "noop": _snapshot_command(client, hostname, b"NOOP still-open", _OK),
            "vrfy": _snapshot_command(client, hostname, b"VRFY postmaster", _VRFY_NEUTRAL),
            "help": _snapshot_command(client, hostname, b"HELP RCPT", _HELP),
            "second_mail": _snapshot_command(
                client,
                hostname,
                b"MAIL FROM:<>",
                _BAD_SEQUENCE,
            ),
        }

        ehlo_reset = client.command(b"EHLO reset.example")
        expected_reset = (
            b"250-" + hostname + b" Hello reset.example\r\n",
            b"250-PIPELINING\r\n",
            b"250-SIZE 15728640\r\n",
            b"250-8BITMIME\r\n",
            b"250-CHUNKING\r\n",
            b"250-ENHANCEDSTATUSCODES\r\n",
            b"250-SMTPUTF8\r\n",
            b"250 SKIBIDITOILET\r\n",
        )
        _check(ehlo_reset == expected_reset, ehlo_reset)
        mail_after_ehlo_reset = _snapshot_command(
            client,
            hostname,
            b"MAIL FROM:<>",
            _SENDER_OK,
        )
        rset_after_mail = _snapshot_command(client, hostname, b"RSET", _RESET_OK)
        quit_reply = _quit_snapshot(client, hostname)

    return {
        "greeting": smtp_greeting_snapshot(),
        "pre_helo": pre_helo,
        "ehlo": smtp_reply_snapshot(ehlo, hostname),
        "mail_syntax_cases": mail_syntax_cases,
        "mail_parameter_cases": {
            "maximum_size": max_size_mail,
            "reset_after_maximum_size": max_size_reset,
            "unknown_parameter": unknown_parameter_mail,
            "reset_after_unknown_parameter": unknown_parameter_reset,
            "space_after_from_colon": spaced_null_sender,
        },
        "rcpt_cases": rcpt_cases,
        "transaction_utility": transaction_utility,
        "ehlo_resets_transaction": {
            "ehlo": smtp_reply_snapshot(ehlo_reset, hostname),
            "mail_after_reset": mail_after_ehlo_reset,
            "rset": rset_after_mail,
        },
        "quit": quit_reply,
    }


def _capture_parser_and_line_limits(target: RuntimeTarget) -> dict[str, Any]:
    client, hostname = open_smtp_client(target)
    with client:
        malformed = []
        for name, payload, expected in (
            ("empty_line", b"\r\n", (b"500 5.5.1 Command not recognized: \r\n",)),
            ("space_only", b"   \r\n", (b"500 5.5.1 Command not recognized: \r\n",)),
            ("trimmed_tabs", b"\tNOOP\t\r\n", _OK),
        ):
            malformed.append(
                {
                    "case": name,
                    **_snapshot_raw(client, hostname, payload, expected),
                }
            )

        exact_command = b"X" * _MAX_LINE_LENGTH
        exact_reply = (b"500 5.5.1 Command not recognized: " + exact_command + b"\r\n",)
        exact_limit = _snapshot_raw(
            client,
            hostname,
            exact_command + b"\r\n",
            exact_reply,
        )

        overlong_command = b"Y" * (_MAX_LINE_LENGTH + 1)
        over_limit = _snapshot_raw(
            client,
            hostname,
            overlong_command + b"\r\n",
            _LINE_TOO_LONG,
        )
        recovery = _snapshot_command(client, hostname, b"NOOP", _OK)
        quit_reply = _quit_snapshot(client, hostname)

    partial_client, _partial_hostname = open_smtp_client(target)
    with partial_client:
        partial_client.stream.sendall(b"FROBULATE")

    recovery_client, recovery_hostname = open_smtp_client(target)
    with recovery_client:
        recovery_ehlo = smtp_ehlo(recovery_client, recovery_hostname)
        recovery_noop = _snapshot_command(recovery_client, recovery_hostname, b"NOOP", _OK)
        recovery_quit = _quit_snapshot(recovery_client, recovery_hostname)

    return {
        "greeting": smtp_greeting_snapshot(),
        "malformed_lines": malformed,
        "line_length": {
            "maximum_command_bytes": _MAX_LINE_LENGTH,
            "at_limit": exact_limit,
            "over_limit": over_limit,
            "session_recovery": recovery,
            "quit": quit_reply,
        },
        "partial_disconnect_recovery": {
            "sent_without_crlf": bytes_snapshot(b"FROBULATE"),
            "new_session_ehlo": smtp_reply_snapshot(recovery_ehlo, recovery_hostname),
            "new_session_noop": recovery_noop,
            "new_session_quit": recovery_quit,
        },
    }


def _capture_control_byte_reflection_evidence(target: RuntimeTarget) -> dict[str, Any]:
    client, hostname = open_smtp_client(target)
    with client:
        cases = []
        for name, payload, expected_wire in (
            (
                "tab_in_command",
                b"NOOP\tfoo\r\n",
                b"500 5.5.1 Command not recognized: NOOP\tFOO\r\n",
            ),
            (
                "nul_in_command",
                b"NOOP\x00ARG\r\n",
                b"500 5.5.1 Command not recognized: NOOP\x00ARG\r\n",
            ),
            (
                "invalid_utf8_replaced_then_ascii_encoded",
                b"X\xffY\r\n",
                b"500 5.5.1 Command not recognized: X?Y\r\n",
            ),
            (
                "bare_cr_reflected",
                b"NOOP\rX\r\n",
                b"500 5.5.1 Command not recognized: NOOP\rX\r\n",
            ),
            (
                "bare_lf_reflected",
                b"NOOP\nX\r\n",
                b"500 5.5.1 Command not recognized: NOOP\nX\r\n",
            ),
        ):
            cases.append(
                {
                    "case": name,
                    **_snapshot_unframed_raw(client, payload, expected_wire),
                }
            )
        recovery = _snapshot_command(client, hostname, b"NOOP", _OK)
        quit_reply = _quit_snapshot(client, hostname)

    return {
        "greeting": smtp_greeting_snapshot(),
        "cases": cases,
        "session_recovery": recovery,
        "quit": quit_reply,
    }


def _capture_fragmented_overlong_evidence(target: RuntimeTarget) -> dict[str, Any]:
    client, hostname = open_smtp_client(target)
    with client:
        payload = b"Z" * (_MAX_LINE_LENGTH + 1)
        client.stream.sendall(payload)
        first_reply = read_smtp_reply(client.stream)
        _check(first_reply == _LINE_TOO_LONG, first_reply)
        client.stream.sendall(b"\r\n")
        terminator_reply = read_smtp_reply(client.stream)
        _check(terminator_reply == _LINE_TOO_LONG, terminator_reply)
        recovery = _snapshot_command(client, hostname, b"NOOP", _OK)
        quit_reply = _quit_snapshot(client, hostname)

    return {
        "greeting": smtp_greeting_snapshot(),
        "payload": bytes_snapshot(payload),
        "reply_before_terminator": smtp_reply_snapshot(first_reply, hostname),
        "reply_for_terminator": smtp_reply_snapshot(terminator_reply, hostname),
        "session_recovery": recovery,
        "quit": quit_reply,
    }


def _capture_error_budget_and_recovery(target: RuntimeTarget) -> dict[str, Any]:
    syntax_client, syntax_hostname = open_smtp_client(target)
    with syntax_client:
        syntax_replies = [
            _snapshot_command(syntax_client, syntax_hostname, b"EHLO", _SYNTAX_PARAMETERS)
            for _ in range(_MAX_ERRORS_PER_CONNECTION + 2)
        ]
        noop_after_syntax = _snapshot_command(syntax_client, syntax_hostname, b"NOOP", _OK)
        syntax_quit = _quit_snapshot(syntax_client, syntax_hostname)

    error_client, error_hostname = open_smtp_client(target)
    with error_client:
        error_replies = []
        for index in range(1, _MAX_ERRORS_PER_CONNECTION + 1):
            command = f"UNKNOWN{index}".encode("ascii")
            reply = error_client.command(command)
            expected = (
                (b"421 4.3.2 " + error_hostname + b" Service not available\r\n")
                if index == _MAX_ERRORS_PER_CONNECTION
                else (b"500 5.5.1 Command not recognized: " + command + b"\r\n")
            )
            _check(reply == (expected,), {"index": index, "reply": reply})
            error_replies.append(
                {
                    "index": index,
                    "command": command.decode("ascii"),
                    "reply": smtp_reply_snapshot(reply, error_hostname),
                }
            )
        threshold_eof = _assert_server_eof(error_client)

    recovery_client, recovery_hostname = open_smtp_client(target)
    with recovery_client:
        recovery_noop = _snapshot_command(recovery_client, recovery_hostname, b"NOOP", _OK)
        recovery_quit = _quit_snapshot(recovery_client, recovery_hostname)

    return {
        "greeting": smtp_greeting_snapshot(),
        "handler_syntax_errors": {
            "attempts": len(syntax_replies),
            "replies": syntax_replies,
            "session_recovery": noop_after_syntax,
            "quit": syntax_quit,
        },
        "dispatcher_error_budget": {
            "maximum_errors": _MAX_ERRORS_PER_CONNECTION,
            "replies": error_replies,
            "threshold_closes_connection": threshold_eof,
        },
        "new_connection_recovery": {
            "noop": recovery_noop,
            "quit": recovery_quit,
        },
    }


SMTP_COMMAND_SCENARIOS = (
    Scenario(
        "smtp/commands/utility-and-transaction-state",
        _capture_utility_and_transaction_state,
        _SMTP_NORMALIZERS,
        {
            "protocol": "smtp",
            "operation": "utility-and-transaction-state",
            "utility_commands_allowed_before_helo": ["RSET", "NOOP", "VRFY", "HELP"],
            "utility_arguments_ignored": ["NOOP", "VRFY", "HELP"],
            "rset_preserves_connect_state_before_helo": True,
            "mail_from_prefix_required": True,
            "mail_size_limit_bytes": 15_728_640,
            "unknown_mail_parameters_ignored": True,
            "loose_rcpt_address_accepted": True,
            "ehlo_resets_transaction": True,
        },
    ),
    Scenario(
        "smtp/commands/parser-and-line-limits",
        _capture_parser_and_line_limits,
        _SMTP_NORMALIZERS,
        {
            "protocol": "smtp",
            "operation": "parser-and-line-limits",
            "command_terminator": "CRLF",
            "maximum_command_bytes_excluding_crlf": _MAX_LINE_LENGTH,
            "command_argument_separator": "ASCII space only",
            "overlong_session_recovers": True,
            "partial_line_disconnect": "close-without-response-and-new-session-recovers",
        },
    ),
    Scenario(
        "smtp/commands/error-budget-and-recovery",
        _capture_error_budget_and_recovery,
        _SMTP_NORMALIZERS,
        {
            "protocol": "smtp",
            "operation": "error-budget-and-recovery",
            "maximum_dispatcher_or_decoder_errors": _MAX_ERRORS_PER_CONNECTION,
            "threshold_reply_code": 421,
            "threshold_closes_connection": True,
            "handler_syntax_errors_consume_budget": False,
            "error_budget_scope": "connection",
        },
    ),
)

SMTP_COMMAND_ORACLE_EVIDENCE_SCENARIOS = (
    Scenario(
        "smtp/commands/oracle-control-byte-reflection",
        _capture_control_byte_reflection_evidence,
        _SMTP_NORMALIZERS,
        {
            "protocol": "smtp",
            "operation": "command-control-byte-reflection-evidence",
            "difference_id": "smtp-command-control-byte-reflection",
            "candidate_requirement": "fixed-non-reflective-syntax-error",
        },
    ),
    Scenario(
        "smtp/commands/oracle-fragmented-overlong-line",
        _capture_fragmented_overlong_evidence,
        _SMTP_NORMALIZERS,
        {
            "protocol": "smtp",
            "operation": "fragmented-overlong-double-error-evidence",
            "difference_id": "smtp-fragmented-overlong-double-error",
            "oracle_replies_for_one_logical_line": 2,
            "candidate_requirement": "one-error-per-logical-line",
        },
    ),
)
