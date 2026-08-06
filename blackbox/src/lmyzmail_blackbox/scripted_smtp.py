from __future__ import annotations

import ipaddress
import math
import re
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal

from .errors import HarnessError

_REPLY = re.compile(rb"^[2345][0-9][0-9] [^\r\n]*\r\n$")
_MAIL_FROM = re.compile(rb"^MAIL FROM:\s*<([^>]*)>(?:\s+.*)?\r\n$", re.IGNORECASE)
_RCPT_TO = re.compile(rb"^RCPT TO:\s*<([^>]*)>(?:\s+.*)?\r\n$", re.IGNORECASE)


class DisconnectPoint(StrEnum):
    BEFORE_DATA_READY = "before-data-ready"
    BEFORE_DATA_ACCEPT = "before-data-accept"
    AFTER_DATA_ACCEPT = "after-data-accept"


@dataclass(frozen=True, slots=True)
class RecipientReply:
    recipient: str
    reply: bytes

    def __post_init__(self) -> None:
        if not self.recipient or any(value in self.recipient for value in "\r\n<>\x00"):
            raise ValueError("recipient rule must contain one bare mailbox")
        _validate_reply(self.reply, field_name="recipient reply")

    @property
    def normalized_recipient(self) -> str:
        return self.recipient.casefold()


@dataclass(frozen=True, slots=True)
class SmtpScenario:
    hostname: str = "smtp.example.test"
    ehlo_extensions: tuple[bytes, ...] = (
        b"PIPELINING",
        b"8BITMIME",
        b"SIZE 8388608",
    )
    recipient_replies: tuple[RecipientReply, ...] = ()
    default_recipient_reply: bytes = b"250 2.1.5 recipient accepted\r\n"
    data_ready_reply: bytes = b"354 end data with <CRLF>.<CRLF>\r\n"
    data_result_reply: bytes = b"250 2.0.0 message accepted\r\n"
    tls_context: ssl.SSLContext | None = field(default=None, repr=False, compare=False)
    disconnect_at: DisconnectPoint | None = None
    read_chunk_bytes: int = 4096
    read_delay_seconds: float = 0.0
    max_line_bytes: int = 512
    max_data_line_bytes: int = 65_536
    max_message_bytes: int = 8 * 1024 * 1024
    max_session_bytes: int = 16 * 1024 * 1024
    max_transcript_bytes: int = 64 * 1024 * 1024
    max_transcript_events: int = 100_000
    max_commands: int = 1000
    max_connections: int = 32
    max_concurrent_connections: int = 8
    connection_timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        if (
            not self.hostname
            or len(self.hostname.encode("ascii", errors="strict")) > 200
            or any(value in self.hostname for value in "\r\n\x00")
        ):
            raise ValueError("SMTP fixture hostname is invalid")
        for extension in self.ehlo_extensions:
            if (
                not extension
                or len(extension) > 500
                or b"\r" in extension
                or b"\n" in extension
                or b"\x00" in extension
                or extension.upper() == b"STARTTLS"
            ):
                raise ValueError("EHLO extensions must be bounded single lines")
        _validate_reply(self.default_recipient_reply, field_name="default recipient reply")
        _validate_reply(
            self.data_ready_reply,
            field_name="DATA ready reply",
            expected_prefix=b"354 ",
        )
        _validate_reply(self.data_result_reply, field_name="DATA result reply")
        normalized = [value.normalized_recipient for value in self.recipient_replies]
        if len(normalized) != len(set(normalized)):
            raise ValueError("recipient rules must be unique case-insensitively")
        _validate_positive_integer(self.read_chunk_bytes, "read chunk")
        _validate_positive_integer(self.max_line_bytes, "command line")
        _validate_positive_integer(self.max_data_line_bytes, "DATA line")
        _validate_positive_integer(self.max_message_bytes, "message")
        _validate_positive_integer(self.max_session_bytes, "session")
        _validate_positive_integer(self.max_transcript_bytes, "transcript")
        _validate_positive_integer(self.max_transcript_events, "transcript event count")
        _validate_positive_integer(self.max_commands, "command count")
        _validate_positive_integer(self.max_connections, "connection count")
        _validate_positive_integer(self.max_concurrent_connections, "concurrent connection")
        if self.max_concurrent_connections > self.max_connections:
            raise ValueError("concurrent connection limit exceeds total connection limit")
        if self.max_message_bytes > self.max_session_bytes:
            raise ValueError("message limit exceeds session byte limit")
        if not math.isfinite(self.read_delay_seconds) or self.read_delay_seconds < 0:
            raise ValueError("read delay must be finite and non-negative")
        if (
            not math.isfinite(self.connection_timeout_seconds)
            or self.connection_timeout_seconds <= 0
        ):
            raise ValueError("connection timeout must be finite and positive")

    def reply_for_recipient(self, recipient: str) -> bytes:
        normalized = recipient.casefold()
        for rule in self.recipient_replies:
            if rule.normalized_recipient == normalized:
                return rule.reply
        return self.default_recipient_reply


@dataclass(frozen=True, slots=True)
class SmtpEvent:
    sequence: int
    connection_id: int
    monotonic_ns: int
    direction: Literal["client", "server", "fixture"]
    kind: str
    payload: bytes


@dataclass(frozen=True, slots=True)
class SmtpMessageAttempt:
    connection_id: int
    sender: bytes
    recipients: tuple[bytes, ...]
    data: bytes
    wire_data: bytes
    received_at_ns: int
    accepted: bool


class _PeerClosed(Exception):
    pass


class _PeerProtocolError(Exception):
    pass


@dataclass(slots=True)
class _ConnectionOwner:
    connection: socket.socket | ssl.SSLSocket


class _BoundedReader:
    def __init__(
        self,
        connection: socket.socket | ssl.SSLSocket,
        *,
        deadline: float,
        chunk_bytes: int,
        read_delay_seconds: float,
        max_session_bytes: int,
        stop_event: threading.Event,
    ) -> None:
        self.connection = connection
        self.deadline = deadline
        self.chunk_bytes = chunk_bytes
        self.read_delay_seconds = read_delay_seconds
        self.max_session_bytes = max_session_bytes
        self.stop_event = stop_event
        self.received = 0
        self.buffer = bytearray()

    def replace_connection(self, connection: ssl.SSLSocket) -> None:
        if self.buffer:
            raise _PeerProtocolError("plaintext remained buffered before STARTTLS")
        self.connection = connection

    def read_line(self, *, max_bytes: int) -> bytes:
        while True:
            end = self.buffer.find(b"\n")
            if end >= 0:
                if end + 1 > max_bytes:
                    raise _PeerProtocolError(f"line exceeded {max_bytes} bytes")
                value = bytes(self.buffer[: end + 1])
                del self.buffer[: end + 1]
                if not value.endswith(b"\r\n"):
                    raise _PeerProtocolError("line did not use CRLF")
                return value
            if len(self.buffer) >= max_bytes:
                raise _PeerProtocolError(f"line exceeded {max_bytes} bytes")
            self.buffer.extend(self._recv(max_bytes - len(self.buffer)))

    def _recv(self, remaining_line_bytes: int) -> bytes:
        remaining_seconds = self.deadline - time.monotonic()
        if remaining_seconds <= 0:
            raise _PeerProtocolError("connection deadline exceeded")
        if self.read_delay_seconds:
            if self.stop_event.wait(min(self.read_delay_seconds, remaining_seconds)):
                raise _PeerClosed
            remaining_seconds = self.deadline - time.monotonic()
            if remaining_seconds <= 0:
                raise _PeerProtocolError("connection deadline exceeded")
        self.connection.settimeout(remaining_seconds)
        budget = self.max_session_bytes - self.received
        if budget <= 0:
            raise _PeerProtocolError("session byte budget exceeded")
        try:
            value = self.connection.recv(min(self.chunk_bytes, remaining_line_bytes, budget + 1))
        except TimeoutError as error:
            raise _PeerProtocolError("connection deadline exceeded") from error
        if not value:
            raise _PeerClosed
        self.received += len(value)
        if self.received > self.max_session_bytes:
            raise _PeerProtocolError("session byte budget exceeded")
        return value


class ScriptedSmtpServer:
    def __init__(
        self,
        scenario: SmtpScenario | None = None,
        *,
        bind_host: str = "127.0.0.1",
        bind_port: int = 0,
    ) -> None:
        self.scenario = scenario if scenario is not None else SmtpScenario()
        try:
            parsed_bind_host = ipaddress.ip_address(bind_host)
        except ValueError as error:
            raise ValueError("scripted SMTP bind host must be a numeric IP address") from error
        if parsed_bind_host.is_unspecified or parsed_bind_host.is_multicast:
            raise ValueError("scripted SMTP bind host must be a specific unicast address")
        if parsed_bind_host.version != 4:
            raise ValueError("scripted SMTP bind host must be an IPv4 address")
        if isinstance(bind_port, bool) or not 0 <= bind_port <= 65_535:
            raise ValueError("scripted SMTP bind port must be between 0 and 65535")
        self._bind_host = bind_host
        self._bind_port = bind_port
        self._state_lock = threading.RLock()
        self._condition = threading.Condition(self._state_lock)
        self._stop_event = threading.Event()
        self._connection_slots = threading.BoundedSemaphore(
            self.scenario.max_concurrent_connections
        )
        self._listener: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None
        self._worker_threads: set[threading.Thread] = set()
        self._active_connections: set[socket.socket | ssl.SSLSocket] = set()
        self._events: list[SmtpEvent] = []
        self._messages: list[SmtpMessageAttempt] = []
        self._errors: list[Exception] = []
        self._sequence = 0
        self._connections_accepted = 0
        self._transcript_bytes = 0
        self._transcript_overflow = False
        self._transcript_overflow_reason: str | None = None
        self._port: int | None = None
        self._started = False
        self._stopped = False

    @property
    def host(self) -> str:
        return self._bind_host

    @property
    def port(self) -> int:
        with self._state_lock:
            if self._port is None:
                raise HarnessError("scripted SMTP server has not started")
            return self._port

    def start(self) -> ScriptedSmtpServer:
        with self._state_lock:
            if self._started:
                raise HarnessError("scripted SMTP server instances may only start once")
            self._started = True
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((self.host, self._bind_port))
            listener.listen(min(self.scenario.max_connections, 128))
            listener.settimeout(0.1)
            with self._state_lock:
                self._listener = listener
                self._port = int(listener.getsockname()[1])
            thread = threading.Thread(
                target=self._accept_loop,
                name="lmyzmail-scripted-smtp-accept",
                daemon=False,
            )
            self._accept_thread = thread
            thread.start()
            return self
        except BaseException:
            listener.close()
            with self._state_lock:
                self._stopped = True
            raise

    def stop(self, *, timeout: float = 5.0) -> None:
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("stop timeout must be finite and positive")
        with self._state_lock:
            if not self._started:
                raise HarnessError("scripted SMTP server has not started")
            if self._stopped:
                return
            self._stopped = True
            listener = self._listener
            connections = tuple(self._active_connections)
        self._stop_event.set()
        if listener is not None:
            listener.close()
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()

        deadline = time.monotonic() + timeout
        accept_thread = self._accept_thread
        if accept_thread is not None:
            accept_thread.join(max(0.0, deadline - time.monotonic()))
        while True:
            with self._state_lock:
                workers = tuple(self._worker_threads)
            if not workers:
                break
            for worker in workers:
                worker.join(max(0.0, deadline - time.monotonic()))
            if time.monotonic() >= deadline:
                break
        with self._state_lock:
            alive = [thread.name for thread in self._worker_threads if thread.is_alive()]
            if accept_thread is not None and accept_thread.is_alive():
                alive.append(accept_thread.name)
        if alive:
            raise HarnessError(f"scripted SMTP threads did not stop: {alive!r}")

    def events(self) -> tuple[SmtpEvent, ...]:
        with self._state_lock:
            return tuple(self._events)

    def messages(self) -> tuple[SmtpMessageAttempt, ...]:
        with self._state_lock:
            return tuple(self._messages)

    def wait_for_events(
        self,
        kind: str,
        count: int,
        *,
        timeout: float = 5.0,
    ) -> tuple[SmtpEvent, ...]:
        if not kind:
            raise ValueError("event kind must not be empty")
        _validate_positive_integer(count, "event count")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("wait timeout must be finite and positive")
        deadline = time.monotonic() + timeout
        with self._condition:
            while True:
                matches = tuple(value for value in self._events if value.kind == kind)
                if len(matches) >= count:
                    return matches
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(f"timed out waiting for {count} {kind!r} SMTP events")
                self._condition.wait(remaining)

    def assert_no_errors(self) -> None:
        with self._state_lock:
            errors = tuple(self._errors)
            overflow_reason = self._transcript_overflow_reason
        if overflow_reason is not None:
            raise HarnessError(f"scripted SMTP transcript {overflow_reason} budget was exceeded")
        if errors:
            raise ExceptionGroup("scripted SMTP server errors", errors)

    def __enter__(self) -> ScriptedSmtpServer:
        return self.start()

    def __exit__(self, exception_type: object, *_: object) -> None:
        self.stop()
        if exception_type is None:
            self.assert_no_errors()

    def _accept_loop(self) -> None:
        try:
            while not self._stop_event.is_set():
                with self._state_lock:
                    if self._connections_accepted >= self.scenario.max_connections:
                        listener = self._listener
                        self._listener = None
                        if listener is not None:
                            listener.close()
                        return
                    listener = self._listener
                if listener is None:
                    return
                if not self._connection_slots.acquire(timeout=0.1):
                    continue
                try:
                    connection, _ = listener.accept()
                except TimeoutError:
                    self._connection_slots.release()
                    continue
                except OSError:
                    self._connection_slots.release()
                    if self._stop_event.is_set():
                        return
                    raise
                with self._state_lock:
                    self._connections_accepted += 1
                    connection_id = self._connections_accepted
                    self._active_connections.add(connection)
                self._record(connection_id, "fixture", "connected")
                worker = threading.Thread(
                    target=self._run_connection,
                    args=(connection_id, connection),
                    name=f"lmyzmail-scripted-smtp-{connection_id}",
                    daemon=False,
                )
                with self._state_lock:
                    self._worker_threads.add(worker)
                worker.start()
        except BaseException as error:
            self._add_error(error)

    def _run_connection(self, connection_id: int, connection: socket.socket) -> None:
        owner = _ConnectionOwner(connection)
        try:
            self._handle_connection(connection_id, owner)
        except _PeerClosed:
            self._record(connection_id, "fixture", "peer-closed")
        except _PeerProtocolError as error:
            self._record(connection_id, "fixture", "protocol-error", str(error).encode("utf-8"))
            self._try_send(
                connection_id,
                owner.connection,
                b"421 4.3.2 fixture protocol limit\r\n",
            )
        except (ConnectionError, OSError, ssl.SSLError) as error:
            self._record(connection_id, "fixture", "peer-disconnected", str(error).encode("utf-8"))
        except BaseException as error:
            self._add_error(error)
        finally:
            current = owner.connection
            try:
                current.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            current.close()
            with self._state_lock:
                self._active_connections.discard(connection)
                self._active_connections.discard(current)
                self._worker_threads.discard(threading.current_thread())
                self._condition.notify_all()
            self._record(connection_id, "fixture", "closed")
            self._connection_slots.release()

    def _handle_connection(
        self,
        connection_id: int,
        owner: _ConnectionOwner,
    ) -> None:
        connection = owner.connection
        deadline = time.monotonic() + self.scenario.connection_timeout_seconds
        reader = _BoundedReader(
            connection,
            deadline=deadline,
            chunk_bytes=self.scenario.read_chunk_bytes,
            read_delay_seconds=self.scenario.read_delay_seconds,
            max_session_bytes=self.scenario.max_session_bytes,
            stop_event=self._stop_event,
        )
        greeting = f"220 {self.scenario.hostname} ESMTP lmyzmail fixture\r\n".encode("ascii")
        self._send(connection_id, connection, greeting)
        greeted = False
        tls_active = False
        sender: bytes | None = None
        recipients: list[bytes] = []

        for _ in range(self.scenario.max_commands):
            command = reader.read_line(max_bytes=self.scenario.max_line_bytes)
            self._record(connection_id, "client", "command", command)
            verb = command[:-2].split(maxsplit=1)[0].upper() if command[:-2] else b""

            if verb == b"EHLO":
                greeted = True
                sender = None
                recipients.clear()
                self._send(connection_id, connection, self._ehlo_reply(tls_active=tls_active))
            elif verb == b"HELO":
                greeted = True
                sender = None
                recipients.clear()
                self._send(
                    connection_id,
                    connection,
                    f"250 {self.scenario.hostname}\r\n".encode("ascii"),
                )
            elif verb == b"STARTTLS":
                if self.scenario.tls_context is None or tls_active or not greeted:
                    self._send(connection_id, connection, b"454 4.7.0 TLS unavailable\r\n")
                    continue
                if reader.buffer:
                    raise _PeerProtocolError("plaintext remained buffered before STARTTLS")
                self._send(connection_id, connection, b"220 2.0.0 ready to start TLS\r\n")
                connection.settimeout(max(0.001, deadline - time.monotonic()))
                connection = self.scenario.tls_context.wrap_socket(connection, server_side=True)
                owner.connection = connection
                with self._state_lock:
                    self._active_connections.discard(reader.connection)
                    self._active_connections.add(connection)
                reader.replace_connection(connection)
                tls_active = True
                greeted = False
                sender = None
                recipients.clear()
                self._record(connection_id, "fixture", "tls-established")
            elif verb == b"MAIL":
                match = _MAIL_FROM.fullmatch(command)
                if not greeted:
                    self._send(connection_id, connection, b"503 5.5.1 send EHLO first\r\n")
                elif match is None:
                    self._send(connection_id, connection, b"501 5.5.2 malformed MAIL FROM\r\n")
                else:
                    sender = match.group(1)
                    recipients.clear()
                    self._send(connection_id, connection, b"250 2.1.0 sender accepted\r\n")
            elif verb == b"RCPT":
                match = _RCPT_TO.fullmatch(command)
                if sender is None:
                    self._send(connection_id, connection, b"503 5.5.1 send MAIL first\r\n")
                elif match is None:
                    self._send(connection_id, connection, b"501 5.5.2 malformed RCPT TO\r\n")
                else:
                    recipient = match.group(1)
                    try:
                        mailbox = recipient.decode("ascii")
                    except UnicodeDecodeError:
                        self._send(
                            connection_id,
                            connection,
                            b"553 5.1.3 mailbox must be ASCII\r\n",
                        )
                        continue
                    reply = self.scenario.reply_for_recipient(mailbox)
                    if reply.startswith(b"2"):
                        recipients.append(recipient)
                    self._send(connection_id, connection, reply)
            elif verb == b"DATA":
                if sender is None or not recipients:
                    self._send(
                        connection_id,
                        connection,
                        b"503 5.5.1 need sender and recipient\r\n",
                    )
                    continue
                if self.scenario.disconnect_at is DisconnectPoint.BEFORE_DATA_READY:
                    self._record(
                        connection_id,
                        "fixture",
                        "scripted-disconnect",
                        b"before-data-ready",
                    )
                    return
                self._send(connection_id, connection, self.scenario.data_ready_reply)
                data, wire_data = self._read_data(connection_id, reader)
                if self.scenario.disconnect_at is DisconnectPoint.BEFORE_DATA_ACCEPT:
                    self._append_message(
                        connection_id,
                        sender,
                        tuple(recipients),
                        data,
                        wire_data,
                        accepted=False,
                    )
                    self._record(
                        connection_id,
                        "fixture",
                        "scripted-disconnect",
                        b"before-data-accept",
                    )
                    return
                accepted = self.scenario.data_result_reply.startswith(b"2")
                self._send(connection_id, connection, self.scenario.data_result_reply)
                self._append_message(
                    connection_id,
                    sender,
                    tuple(recipients),
                    data,
                    wire_data,
                    accepted=accepted,
                )
                sender = None
                recipients.clear()
                if self.scenario.disconnect_at is DisconnectPoint.AFTER_DATA_ACCEPT:
                    self._record(
                        connection_id,
                        "fixture",
                        "scripted-disconnect",
                        b"after-data-accept",
                    )
                    return
            elif verb == b"RSET":
                sender = None
                recipients.clear()
                self._send(connection_id, connection, b"250 2.0.0 reset\r\n")
            elif verb == b"NOOP":
                self._send(connection_id, connection, b"250 2.0.0 noop\r\n")
            elif verb == b"QUIT":
                self._send(connection_id, connection, b"221 2.0.0 bye\r\n")
                return
            else:
                self._send(connection_id, connection, b"502 5.5.1 command not implemented\r\n")
        raise _PeerProtocolError("command count budget exceeded")

    def _read_data(
        self,
        connection_id: int,
        reader: _BoundedReader,
    ) -> tuple[bytes, bytes]:
        message = bytearray()
        wire = bytearray()
        while True:
            line = reader.read_line(max_bytes=self.scenario.max_data_line_bytes)
            wire.extend(line)
            self._record(connection_id, "client", "data", line)
            if len(wire) > self.scenario.max_message_bytes + 3:
                raise _PeerProtocolError("message byte budget exceeded")
            if line == b".\r\n":
                return bytes(message), bytes(wire)
            if line.startswith(b".."):
                line = line[1:]
            message.extend(line)
            if len(message) > self.scenario.max_message_bytes:
                raise _PeerProtocolError("message byte budget exceeded")

    def _ehlo_reply(self, *, tls_active: bool) -> bytes:
        extensions = list(self.scenario.ehlo_extensions)
        if self.scenario.tls_context is not None and not tls_active:
            extensions.append(b"STARTTLS")
        hostname = self.scenario.hostname.encode("ascii")
        if not extensions:
            return b"250 " + hostname + b"\r\n"
        lines = [b"250-" + hostname + b"\r\n"]
        for index, extension in enumerate(extensions):
            separator = b" " if index == len(extensions) - 1 else b"-"
            lines.append(b"250" + separator + extension + b"\r\n")
        return b"".join(lines)

    def _send(
        self,
        connection_id: int,
        connection: socket.socket | ssl.SSLSocket,
        value: bytes,
    ) -> None:
        connection.sendall(value)
        self._record(connection_id, "server", "reply", value)

    def _try_send(
        self,
        connection_id: int,
        connection: socket.socket | ssl.SSLSocket,
        value: bytes,
    ) -> None:
        try:
            self._send(connection_id, connection, value)
        except OSError:
            pass

    def _append_message(
        self,
        connection_id: int,
        sender: bytes,
        recipients: tuple[bytes, ...],
        data: bytes,
        wire_data: bytes,
        *,
        accepted: bool,
    ) -> None:
        message = SmtpMessageAttempt(
            connection_id=connection_id,
            sender=sender,
            recipients=recipients,
            data=data,
            wire_data=wire_data,
            received_at_ns=time.monotonic_ns(),
            accepted=accepted,
        )
        with self._condition:
            self._messages.append(message)
            self._condition.notify_all()
        self._record(
            connection_id,
            "fixture",
            "message-accepted" if accepted else "message-not-accepted",
        )

    def _record(
        self,
        connection_id: int,
        direction: Literal["client", "server", "fixture"],
        kind: str,
        payload: bytes = b"",
    ) -> None:
        with self._condition:
            if self._transcript_overflow:
                return
            if len(self._events) >= self.scenario.max_transcript_events:
                self._transcript_overflow = True
                self._transcript_overflow_reason = "event count"
                self._condition.notify_all()
                return
            if self._transcript_bytes + len(payload) > self.scenario.max_transcript_bytes:
                self._transcript_overflow = True
                self._transcript_overflow_reason = "byte"
                self._condition.notify_all()
                return
            self._sequence += 1
            self._transcript_bytes += len(payload)
            self._events.append(
                SmtpEvent(
                    sequence=self._sequence,
                    connection_id=connection_id,
                    monotonic_ns=time.monotonic_ns(),
                    direction=direction,
                    kind=kind,
                    payload=payload,
                )
            )
            self._condition.notify_all()

    def _add_error(self, error: BaseException) -> None:
        with self._condition:
            if isinstance(error, Exception):
                self._errors.append(error)
            else:
                self._errors.append(HarnessError(f"non-Exception server failure: {error!r}"))
            self._condition.notify_all()


def _validate_reply(
    value: bytes,
    *,
    field_name: str,
    expected_prefix: bytes | None = None,
) -> None:
    if not _REPLY.fullmatch(value):
        raise ValueError(f"{field_name} must be one complete SMTP reply line")
    if expected_prefix is not None and not value.startswith(expected_prefix):
        raise ValueError(f"{field_name} must start with {expected_prefix!r}")


def _validate_positive_integer(value: int, field_name: str) -> None:
    if isinstance(value, bool) or value < 1:
        raise ValueError(f"{field_name} limit must be a positive integer")
