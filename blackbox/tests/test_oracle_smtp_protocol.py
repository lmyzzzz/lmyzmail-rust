from __future__ import annotations

import re
import time
from collections.abc import Iterator

import psycopg
import pytest

from lmyzmail_blackbox.protocols import BoundedSocket, connect_bounded, read_smtp_reply
from lmyzmail_blackbox.runtime import JavaOracleRuntime
from lmyzmail_blackbox.smtp_contract import SMTP_SCENARIOS, _index_count


@pytest.fixture(scope="module")
def smtp_oracle() -> Iterator[JavaOracleRuntime]:
    with JavaOracleRuntime() as oracle:
        yield oracle


def _reply(stream: BoundedSocket) -> tuple[bytes, ...]:
    """Read one complete SMTP reply while retaining CRLF for wire assertions."""

    return read_smtp_reply(stream)


def _send(stream: BoundedSocket, command: bytes) -> tuple[bytes, ...]:
    stream.sendall(command + b"\r\n")
    return _reply(stream)


def _connect(oracle: JavaOracleRuntime) -> BoundedSocket:
    assert oracle.ports is not None
    return connect_bounded("127.0.0.1", oracle.ports.smtp, timeout=10.0)


def _assert_greeting(greeting: tuple[bytes, ...]) -> bytes:
    assert len(greeting) == 1
    assert re.fullmatch(
        rb"220 [^\s]+ ESMTP lmyzmail SMTP Server 2\.8\.0 - "
        rb"(?:Brrrrr )?Skibidi (?:[dD][oO][pPmM] ){1,5}"
        rb"(?:(?:[yY][eE][sS] [yY][eE][sS])|(?:[nN][oO] [nN][oO]))!\r\n",
        greeting[0],
    )
    return greeting[0].split(b" ", 2)[1]


def _assert_quit(stream: BoundedSocket, hostname: bytes) -> None:
    assert _send(stream, b"QUIT") == (b"221 2.0.0 " + hostname + b" closing connection\r\n",)
    # QUIT is a response-and-close command; the peer must not leave the session open.
    assert not stream.buffer
    stream.sock.settimeout(2.0)
    assert stream.sock.recv(1) == b""


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(180)
def test_managed_java_smtp_greeting_extensions_and_quit(
    smtp_oracle: JavaOracleRuntime,
) -> None:
    stream = _connect(smtp_oracle)
    try:
        hostname = _assert_greeting(_reply(stream))
        assert _send(stream, b"EHLO blackbox.example") == (
            b"250-" + hostname + b" Hello blackbox.example\r\n",
            b"250-PIPELINING\r\n",
            b"250-SIZE 15728640\r\n",
            b"250-8BITMIME\r\n",
            b"250-CHUNKING\r\n",
            b"250-ENHANCEDSTATUSCODES\r\n",
            b"250-SMTPUTF8\r\n",
            b"250 SKIBIDITOILET\r\n",
        )
        assert _send(stream, b"HELO blackbox.example") == (
            b"250 " + hostname + b" Hello blackbox.example\r\n",
        )
        _assert_quit(stream, hostname)
    finally:
        stream.sock.close()


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(180)
def test_managed_java_smtp_sequencing_syntax_auth_and_starttls(
    smtp_oracle: JavaOracleRuntime,
) -> None:
    stream = _connect(smtp_oracle)
    try:
        hostname = _assert_greeting(_reply(stream))

        # MAIL/RCPT/DATA are transaction commands and cannot run before HELO.
        assert _send(stream, b"MAIL FROM:<>") == (b"503 5.5.1 Bad sequence of commands\r\n",)
        assert _send(stream, b"RCPT TO:<qa@example.test>") == (
            b"503 5.5.1 Bad sequence of commands\r\n",
        )
        assert _send(stream, b"DATA") == (b"503 5.5.1 Bad sequence of commands\r\n",)

        # Missing arguments are parameter syntax errors, while an unknown verb is
        # a command-recognition error. These responses are distinct on the oracle.
        assert _send(stream, b"EHLO") == (b"501 5.5.4 Syntax error in parameters\r\n",)
        assert _send(stream, b"FROBULATE") == (b"500 5.5.1 Command not recognized: FROBULATE\r\n",)
        assert _send(stream, b"HELO") == (b"501 5.5.4 Syntax error in parameters\r\n",)

        assert _send(stream, b"HELO blackbox.example") == (
            b"250 " + hostname + b" Hello blackbox.example\r\n",
        )
        assert _send(stream, b"AUTH PLAIN") == (
            b"502 5.5.1 AUTH command not implemented. "
            b"Blud is yapping about AUTH but nobody is listening. "
            b"We don't do that here. Take your L and go back to the lobby.\r\n",
        )
        # Managed oracle starts without its optional certificate, so STARTTLS is
        # intentionally absent from EHLO and is not registered by the dispatcher.
        assert _send(stream, b"STARTTLS") == (b"500 5.5.1 Command not recognized: STARTTLS\r\n",)
        assert _send(stream, b"RSET") == (b"250 2.0.0 Reset OK\r\n",)
        assert _send(stream, b"NOOP") == (b"250 OK\r\n",)
        _assert_quit(stream, hostname)
    finally:
        stream.sock.close()


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(180)
def test_managed_java_smtp_data_pipeline_bdat_storage_contracts(
    smtp_oracle: JavaOracleRuntime,
) -> None:
    observations = [scenario.capture(smtp_oracle) for scenario in SMTP_SCENARIOS]
    assert [observation["mode"] for observation in observations] == [
        "data",
        "pipeline",
        "bdat",
    ]


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(180)
def test_smtp_storage_deadline_cancels_postgres_table_lock(
    smtp_oracle: JavaOracleRuntime,
) -> None:
    assert smtp_oracle.ports is not None
    with psycopg.connect(
        host="127.0.0.1",
        port=smtp_oracle.ports.postgres,
        user="lmyzmail_test",
        dbname="lmyzmail",
        connect_timeout=5,
    ) as blocker:
        blocker.execute("LOCK TABLE email_index IN ACCESS EXCLUSIVE MODE")
        started = time.monotonic()
        with pytest.raises(AssertionError, match="deadline expired during PostgreSQL"):
            _index_count(
                smtp_oracle,
                "<locked-deadline@example.test>",
                deadline=started + 0.25,
            )
        assert time.monotonic() - started < 1.0
