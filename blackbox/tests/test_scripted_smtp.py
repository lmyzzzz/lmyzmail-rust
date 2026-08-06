from __future__ import annotations

import socket
import ssl
import time
from itertools import pairwise
from pathlib import Path

import pytest

from lmyzmail_blackbox.errors import HarnessError, ProtocolError
from lmyzmail_blackbox.protocols import RawSmtpClient, read_smtp_reply
from lmyzmail_blackbox.scripted_smtp import (
    DisconnectPoint,
    RecipientReply,
    ScriptedSmtpServer,
    SmtpScenario,
)
from lmyzmail_blackbox.tls_fixture import (
    create_server_ssl_context,
    provision_ephemeral_tls_material,
)


def _prepare_transaction(client: RawSmtpClient) -> None:
    assert client.command(b"EHLO outbound.example.test")[-1].startswith(b"250 ")
    assert client.command(b"MAIL FROM:<sender@example.test>") == (b"250 2.1.0 sender accepted\r\n",)
    assert client.command(b"RCPT TO:<qa@example.test>") == (b"250 2.1.5 recipient accepted\r\n",)


def test_scripted_server_captures_exact_transaction_and_dot_unstuffs() -> None:
    server = ScriptedSmtpServer()
    message = b"Subject: exact\r\n\r\nbody\r\n.dot-prefixed\r\n"

    with server:
        with RawSmtpClient.connect(server.host, server.port) as client:
            assert client.greeting == (b"220 smtp.example.test ESMTP lmyzmail fixture\r\n",)
            _prepare_transaction(client)
            assert client.data(message) == (
                (b"354 end data with <CRLF>.<CRLF>\r\n",),
                (b"250 2.0.0 message accepted\r\n",),
            )
            assert client.quit() == (b"221 2.0.0 bye\r\n",)

    assert len(server.messages()) == 1
    attempt = server.messages()[0]
    assert attempt.sender == b"sender@example.test"
    assert attempt.recipients == (b"qa@example.test",)
    assert attempt.data == message
    assert attempt.wire_data == (b"Subject: exact\r\n\r\nbody\r\n..dot-prefixed\r\n.\r\n")
    assert attempt.accepted

    transcript = tuple((event.direction, event.kind, event.payload) for event in server.events())
    assert transcript == (
        ("fixture", "connected", b""),
        ("server", "reply", b"220 smtp.example.test ESMTP lmyzmail fixture\r\n"),
        ("client", "command", b"EHLO outbound.example.test\r\n"),
        (
            "server",
            "reply",
            b"250-smtp.example.test\r\n250-PIPELINING\r\n250-8BITMIME\r\n250 SIZE 8388608\r\n",
        ),
        ("client", "command", b"MAIL FROM:<sender@example.test>\r\n"),
        ("server", "reply", b"250 2.1.0 sender accepted\r\n"),
        ("client", "command", b"RCPT TO:<qa@example.test>\r\n"),
        ("server", "reply", b"250 2.1.5 recipient accepted\r\n"),
        ("client", "command", b"DATA\r\n"),
        ("server", "reply", b"354 end data with <CRLF>.<CRLF>\r\n"),
        ("client", "data", b"Subject: exact\r\n"),
        ("client", "data", b"\r\n"),
        ("client", "data", b"body\r\n"),
        ("client", "data", b"..dot-prefixed\r\n"),
        ("client", "data", b".\r\n"),
        ("server", "reply", b"250 2.0.0 message accepted\r\n"),
        ("fixture", "message-accepted", b""),
        ("client", "command", b"QUIT\r\n"),
        ("server", "reply", b"221 2.0.0 bye\r\n"),
        ("fixture", "closed", b""),
    )
    assert [event.sequence for event in server.events()] == list(range(1, 21))
    assert all(
        earlier.monotonic_ns <= later.monotonic_ns for earlier, later in pairwise(server.events())
    )


def test_scripted_server_pipelines_per_recipient_temporary_and_permanent_failures() -> None:
    scenario = SmtpScenario(
        recipient_replies=(
            RecipientReply("temporary@example.test", b"451 4.2.0 mailbox busy\r\n"),
            RecipientReply("permanent@example.test", b"550 5.1.1 mailbox missing\r\n"),
        )
    )
    server = ScriptedSmtpServer(scenario)

    with server:
        with RawSmtpClient.connect(server.host, server.port) as client:
            assert client.command(b"EHLO outbound.example.test")[-1].startswith(b"250 ")
            assert client.command(b"MAIL FROM:<sender@example.test>")[0].startswith(b"250 ")
            replies = client.pipeline(
                (
                    b"RCPT TO:<temporary@example.test>",
                    b"RCPT TO:<permanent@example.test>",
                    b"RCPT TO:<accepted@example.test>",
                )
            )
            assert replies == (
                (b"451 4.2.0 mailbox busy\r\n",),
                (b"550 5.1.1 mailbox missing\r\n",),
                (b"250 2.1.5 recipient accepted\r\n",),
            )
            assert client.data(b"Subject: recipients\r\n\r\nbody\r\n")[1][0].startswith(b"250 ")
            client.quit()

    assert server.messages()[0].recipients == (b"accepted@example.test",)
    commands = [event.payload for event in server.events() if event.kind == "command"]
    assert commands[2:5] == [
        b"RCPT TO:<temporary@example.test>\r\n",
        b"RCPT TO:<permanent@example.test>\r\n",
        b"RCPT TO:<accepted@example.test>\r\n",
    ]


def test_scripted_server_upgrades_starttls_and_resets_greeting_state(tmp_path: Path) -> None:
    material = provision_ephemeral_tls_material(tmp_path)
    server_context = create_server_ssl_context(material)
    client_context = ssl.create_default_context()
    client_context.load_verify_locations(cadata=material.certificate_pem.decode("ascii"))
    server = ScriptedSmtpServer(SmtpScenario(tls_context=server_context))

    with server:
        with RawSmtpClient.connect(server.host, server.port) as client:
            plaintext_ehlo = client.command(b"EHLO outbound.example.test")
            assert b"250 STARTTLS\r\n" in plaintext_ehlo
            assert client.start_tls(
                client_context,
                server_hostname="smtp.example.test",
            ) == (b"220 2.0.0 ready to start TLS\r\n",)
            assert client.command(b"MAIL FROM:<sender@example.test>") == (
                b"503 5.5.1 send EHLO first\r\n",
            )
            tls_ehlo = client.command(b"EHLO outbound.example.test")
            assert all(b"STARTTLS" not in line for line in tls_ehlo)
            client.quit()

    assert len([event for event in server.events() if event.kind == "tls-established"]) == 1
    assert tuple(material.keystore_path.parent.iterdir()) == (material.keystore_path,)


@pytest.mark.parametrize(
    ("point", "reply_received", "message_count", "accepted"),
    (
        (DisconnectPoint.BEFORE_DATA_READY, False, 0, None),
        (DisconnectPoint.BEFORE_DATA_ACCEPT, False, 1, False),
        (DisconnectPoint.AFTER_DATA_ACCEPT, True, 1, True),
    ),
)
def test_scripted_disconnect_points_distinguish_remote_acceptance(
    point: DisconnectPoint,
    reply_received: bool,
    message_count: int,
    accepted: bool | None,
) -> None:
    server = ScriptedSmtpServer(SmtpScenario(disconnect_at=point))

    with server:
        with RawSmtpClient.connect(server.host, server.port) as client:
            _prepare_transaction(client)
            if point is DisconnectPoint.BEFORE_DATA_READY:
                with pytest.raises(ProtocolError, match="disconnected"):
                    client.command(b"DATA")
            else:
                assert client.command(b"DATA")[0].startswith(b"354 ")
                if reply_received:
                    assert client.data_body(b"Subject: disconnect\r\n\r\nbody\r\n")[0].startswith(
                        b"250 "
                    )
                else:
                    with pytest.raises(ProtocolError, match="disconnected"):
                        client.data_body(b"Subject: disconnect\r\n\r\nbody\r\n")

    assert len(server.messages()) == message_count
    if accepted is not None:
        assert server.messages()[0].accepted is accepted
    disconnects = [event for event in server.events() if event.kind == "scripted-disconnect"]
    assert len(disconnects) == 1
    assert disconnects[0].payload == point.value.encode("ascii")


def test_connection_timestamps_capture_retry_delay() -> None:
    server = ScriptedSmtpServer(
        SmtpScenario(
            disconnect_at=DisconnectPoint.BEFORE_DATA_READY,
            max_connections=2,
            max_concurrent_connections=1,
        )
    )

    with server:
        for attempt in range(2):
            with RawSmtpClient.connect(server.host, server.port) as client:
                _prepare_transaction(client)
                with pytest.raises(ProtocolError, match="disconnected"):
                    client.command(b"DATA")
            if attempt == 0:
                time.sleep(0.03)

    connections = [event for event in server.events() if event.kind == "connected"]
    assert len(connections) == 2
    retry_delay_ns = connections[1].monotonic_ns - connections[0].monotonic_ns
    assert retry_delay_ns >= 30_000_000


def test_slow_reader_applies_sender_visible_backpressure() -> None:
    scenario = SmtpScenario(
        read_chunk_bytes=256,
        read_delay_seconds=0.002,
        max_data_line_bytes=1024,
        connection_timeout_seconds=10.0,
    )
    server = ScriptedSmtpServer(scenario)
    message = (b"x" * 998 + b"\r\n") * 128

    with server:
        with RawSmtpClient.connect(server.host, server.port, timeout=10.0) as client:
            _prepare_transaction(client)
            assert client.command(b"DATA")[0].startswith(b"354 ")
            client.stream.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
            started = time.monotonic()
            client.stream.sendall(message + b".\r\n")
            assert read_smtp_reply(client.stream)[0].startswith(b"250 ")
            data_elapsed = time.monotonic() - started
            client.quit()

    assert data_elapsed >= 0.2
    assert server.messages()[0].data == message


def test_fixture_enforces_message_and_transcript_budgets() -> None:
    server = ScriptedSmtpServer(SmtpScenario(max_message_bytes=32, max_session_bytes=1024))
    with server:
        with RawSmtpClient.connect(server.host, server.port) as client:
            _prepare_transaction(client)
            assert client.command(b"DATA")[0].startswith(b"354 ")
            assert client.data_body(b"x" * 64 + b"\r\n") == (
                b"421 4.3.2 fixture protocol limit\r\n",
            )
    assert server.messages() == ()
    assert any(event.kind == "protocol-error" for event in server.events())

    overflow = ScriptedSmtpServer(SmtpScenario(max_transcript_bytes=8))
    overflow.start()
    try:
        with socket.create_connection((overflow.host, overflow.port), timeout=1.0) as connection:
            assert connection.recv(1) == b"2"
    finally:
        overflow.stop()
    with pytest.raises(HarnessError, match="transcript byte budget"):
        overflow.assert_no_errors()

    event_overflow = ScriptedSmtpServer(SmtpScenario(max_transcript_events=1))
    event_overflow.start()
    try:
        with socket.create_connection(
            (event_overflow.host, event_overflow.port), timeout=1.0
        ) as connection:
            assert connection.recv(1) == b"2"
    finally:
        event_overflow.stop()
    with pytest.raises(HarnessError, match="transcript event count budget"):
        event_overflow.assert_no_errors()


def test_stop_cancels_a_long_scripted_read_delay() -> None:
    server = ScriptedSmtpServer(
        SmtpScenario(
            read_delay_seconds=30.0,
            connection_timeout_seconds=60.0,
        )
    )
    server.start()
    connection = socket.create_connection((server.host, server.port), timeout=1.0)
    try:
        assert connection.recv(1024).startswith(b"220 ")
        started = time.monotonic()
        server.stop(timeout=1.0)
        assert time.monotonic() - started < 1.0
    finally:
        connection.close()
    server.assert_no_errors()


@pytest.mark.parametrize(
    "scenario",
    (
        SmtpScenario(max_connections=1, max_concurrent_connections=1),
        SmtpScenario(max_message_bytes=1, max_session_bytes=1),
    ),
)
def test_valid_bounded_scenarios_construct(scenario: SmtpScenario) -> None:
    assert ScriptedSmtpServer(scenario).scenario is scenario


def test_invalid_scenarios_fail_before_listening() -> None:
    with pytest.raises(ValueError, match="unique"):
        SmtpScenario(
            recipient_replies=(
                RecipientReply("QA@example.test", b"250 accepted\r\n"),
                RecipientReply("qa@example.test", b"550 rejected\r\n"),
            )
        )
    with pytest.raises(ValueError, match="message limit"):
        SmtpScenario(max_message_bytes=2, max_session_bytes=1)
    with pytest.raises(ValueError, match="finite and positive"):
        SmtpScenario(connection_timeout_seconds=float("inf"))
