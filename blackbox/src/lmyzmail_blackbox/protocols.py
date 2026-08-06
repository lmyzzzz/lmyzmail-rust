from __future__ import annotations

import json
import math
import re
import socket
import ssl
import struct
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Never

from .errors import ProtocolError


class BoundedSocket:
    def __init__(
        self,
        sock: socket.socket,
        *,
        deadline: float,
        max_received: int = 8 * 1024 * 1024,
    ) -> None:
        if max_received < 1:
            raise ValueError("receive budget must be positive")
        self.sock = sock
        self.deadline = deadline
        self.max_received = max_received
        self.received = 0
        self.buffer = bytearray()

    def _remaining(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ProtocolError("protocol deadline exceeded")
        return remaining

    def recv_some(self, max_bytes: int = 65_536) -> bytes:
        if max_bytes < 1:
            raise ValueError("receive size must be positive")
        self.sock.settimeout(self._remaining())
        chunk = self.sock.recv(min(max_bytes, self.max_received - self.received + 1))
        if not chunk:
            return b""
        self.received += len(chunk)
        if self.received > self.max_received:
            raise ProtocolError("response exceeded receive budget")
        return chunk

    def read_line(self, *, max_line: int = 65_536) -> bytes:
        if max_line < 1:
            raise ValueError("line budget must be positive")
        while True:
            end = self.buffer.find(b"\n")
            if end >= 0:
                line = bytes(self.buffer[: end + 1])
                del self.buffer[: end + 1]
                return line
            if len(self.buffer) >= max_line:
                raise ProtocolError(f"line exceeded {max_line} bytes")
            chunk = self.recv_some(min(4096, max_line - len(self.buffer)))
            if not chunk:
                raise ProtocolError("peer disconnected before line terminator")
            self.buffer.extend(chunk)

    def read_exact(self, size: int) -> bytes:
        if size < 0 or size > self.max_received:
            raise ProtocolError(f"invalid exact read size: {size}")
        while len(self.buffer) < size:
            chunk = self.recv_some(size - len(self.buffer))
            if not chunk:
                raise ProtocolError("peer disconnected during exact read")
            self.buffer.extend(chunk)
        value = bytes(self.buffer[:size])
        del self.buffer[:size]
        return value

    def read_until(self, delimiter: bytes, *, max_bytes: int) -> bytes:
        if not delimiter:
            raise ValueError("delimiter must not be empty")
        if max_bytes < 1:
            raise ValueError("delimiter search budget must be positive")
        while True:
            end = self.buffer.find(delimiter)
            if end >= 0:
                size = end + len(delimiter)
                value = bytes(self.buffer[:size])
                del self.buffer[:size]
                return value
            if len(self.buffer) >= max_bytes:
                raise ProtocolError(f"delimiter was not found within {max_bytes} bytes")
            chunk = self.recv_some(min(4096, max_bytes - len(self.buffer)))
            if not chunk:
                raise ProtocolError("peer disconnected before delimiter")
            self.buffer.extend(chunk)

    def sendall(self, data: bytes) -> None:
        self.sock.settimeout(self._remaining())
        self.sock.sendall(data)


def connect_bounded(
    host: str,
    port: int,
    *,
    timeout: float,
    max_received: int = 8 * 1024 * 1024,
) -> BoundedSocket:
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("protocol timeout must be finite and positive")
    if max_received < 1:
        raise ValueError("receive budget must be positive")
    deadline = time.monotonic() + timeout
    sock = socket.create_connection((host, port), timeout=timeout)
    return BoundedSocket(sock, deadline=deadline, max_received=max_received)


def read_smtp_reply(
    stream: BoundedSocket,
    *,
    max_lines: int = 100,
) -> tuple[bytes, ...]:
    if max_lines < 1:
        raise ValueError("SMTP reply line budget must be positive")
    first = stream.read_line()
    if (
        not first.endswith(b"\r\n")
        or len(first) < 5
        or not first[:3].isdigit()
        or first[3:4] not in (b" ", b"-")
    ):
        raise ProtocolError(f"invalid SMTP reply: {first!r}")
    code = first[:3]
    if code[:1] not in (b"2", b"3", b"4", b"5"):
        raise ProtocolError(f"invalid SMTP reply code: {first!r}")
    lines = [first]
    if first[3:4] == b"-":
        while len(lines) < max_lines:
            line = stream.read_line()
            if not line.endswith(b"\r\n") or len(line) < 5:
                raise ProtocolError(f"invalid SMTP continuation: {line!r}")
            lines.append(line)
            if line.startswith(code + b" "):
                break
            if not line.startswith(code + b"-"):
                raise ProtocolError(f"SMTP continuation changed reply code or separator: {line!r}")
        else:
            raise ProtocolError(f"SMTP reply exceeded {max_lines} lines")
    return tuple(lines)


def _validate_smtp_message(message: bytes) -> None:
    without_crlf = message.replace(b"\r\n", b"")
    if b"\r" in without_crlf or b"\n" in without_crlf:
        raise ValueError("SMTP message must use CRLF line endings")


def _encode_smtp_data(message: bytes) -> bytes:
    _validate_smtp_message(message)
    if not message:
        return b".\r\n"
    encoded = b"\r\n".join(
        b"." + line if line.startswith(b".") else line for line in message.split(b"\r\n")
    )
    if not encoded.endswith(b"\r\n"):
        encoded += b"\r\n"
    return encoded + b".\r\n"


@dataclass(slots=True)
class RawSmtpClient:
    stream: BoundedSocket
    greeting: tuple[bytes, ...]
    _closed: bool = False

    @classmethod
    def connect(
        cls,
        host: str,
        port: int,
        *,
        timeout: float = 10.0,
        max_received: int = 8 * 1024 * 1024,
    ) -> RawSmtpClient:
        stream = connect_bounded(
            host,
            port,
            timeout=timeout,
            max_received=max_received,
        )
        try:
            greeting = read_smtp_reply(stream)
            if greeting[0][:3] != b"220":
                raise ProtocolError(f"SMTP server did not greet with 220: {greeting!r}")
            return cls(stream=stream, greeting=greeting)
        except BaseException:
            stream.sock.close()
            raise

    @staticmethod
    def _command_bytes(command: bytes) -> bytes:
        if not command or b"\r" in command or b"\n" in command or b"\x00" in command:
            raise ValueError("SMTP command must be one non-empty line without CR, LF, or NUL")
        if len(command) > 510:
            raise ValueError("SMTP command exceeds the 512-octet line limit")
        return command + b"\r\n"

    def _require_open(self) -> None:
        if self._closed:
            raise ProtocolError("SMTP client is closed")

    def command(self, command: bytes) -> tuple[bytes, ...]:
        self._require_open()
        self.stream.sendall(self._command_bytes(command))
        return read_smtp_reply(self.stream)

    def pipeline(self, commands: Sequence[bytes]) -> tuple[tuple[bytes, ...], ...]:
        self._require_open()
        if not commands:
            raise ValueError("SMTP pipeline must contain at least one command")
        if len(commands) > 100:
            raise ValueError("SMTP pipeline exceeds the 100-command budget")
        payload = b"".join(self._command_bytes(command) for command in commands)
        self.stream.sendall(payload)
        return tuple(read_smtp_reply(self.stream) for _ in commands)

    def data(self, message: bytes) -> tuple[tuple[bytes, ...], tuple[bytes, ...]]:
        data_ready = self.command(b"DATA")
        if not data_ready[0].startswith(b"354 "):
            raise ProtocolError(f"SMTP DATA was not accepted: {data_ready!r}")
        return data_ready, self.data_body(message)

    def data_body(self, message: bytes) -> tuple[bytes, ...]:
        self._require_open()
        self.stream.sendall(_encode_smtp_data(message))
        return read_smtp_reply(self.stream)

    def bdat(self, chunk: bytes, *, last: bool = False) -> tuple[bytes, ...]:
        self._require_open()
        suffix = b" LAST" if last else b""
        command = b"BDAT " + str(len(chunk)).encode("ascii") + suffix
        self.stream.sendall(self._command_bytes(command) + chunk)
        return read_smtp_reply(self.stream)

    def start_tls(
        self,
        context: ssl.SSLContext,
        *,
        server_hostname: str,
    ) -> tuple[bytes, ...]:
        response = self.command(b"STARTTLS")
        if not response[0].startswith(b"220 "):
            raise ProtocolError(f"SMTP STARTTLS was not accepted: {response!r}")
        if self.stream.buffer:
            self.close()
            raise ProtocolError("SMTP plaintext bytes remained buffered before TLS")
        try:
            self.stream.sock.settimeout(self.stream._remaining())
            self.stream.sock = context.wrap_socket(
                self.stream.sock,
                server_hostname=server_hostname,
            )
        except BaseException:
            self.close()
            raise
        return response

    def quit(self) -> tuple[bytes, ...]:
        try:
            response = self.command(b"QUIT")
            if response[0][:3] != b"221":
                raise ProtocolError(f"SMTP QUIT was not accepted: {response!r}")
            if self.stream.buffer:
                raise ProtocolError("SMTP server sent bytes after the 221 reply")
            try:
                trailing = self.stream.recv_some()
            except TimeoutError as error:
                raise ProtocolError("SMTP server did not close after the 221 reply") from error
            if trailing:
                raise ProtocolError("SMTP server sent bytes after the 221 reply")
            return response
        finally:
            self.close()

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self.stream.sock.close()

    def __enter__(self) -> RawSmtpClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


@dataclass(frozen=True, slots=True)
class SmtpTranscript:
    greeting: tuple[bytes, ...]
    ehlo: tuple[bytes, ...]
    mail_from: tuple[bytes, ...]
    rcpt_to: tuple[bytes, ...]
    data_ready: tuple[bytes, ...]
    accepted: tuple[bytes, ...]
    quit: tuple[bytes, ...]


def smtp_data_transaction(
    host: str,
    port: int,
    *,
    sender: str,
    recipient: str,
    message: bytes,
    timeout: float = 10.0,
) -> SmtpTranscript:
    _validate_smtp_message(message)
    with RawSmtpClient.connect(host, port, timeout=timeout) as client:
        ehlo = client.command(b"EHLO blackbox.example")
        mail_from = client.command(f"MAIL FROM:<{sender}>".encode("ascii"))
        rcpt_to = client.command(f"RCPT TO:<{recipient}>".encode("ascii"))
        data_ready, accepted = client.data(message)
        quit_reply = client.quit()
        return SmtpTranscript(
            greeting=client.greeting,
            ehlo=ehlo,
            mail_from=mail_from,
            rcpt_to=rcpt_to,
            data_ready=data_ready,
            accepted=accepted,
            quit=quit_reply,
        )


def raw_exchange(
    host: str,
    port: int,
    request: bytes,
    *,
    timeout: float = 5.0,
    max_response: int = 8 * 1024 * 1024,
    tls_context: ssl.SSLContext | None = None,
    server_hostname: str | None = None,
) -> bytes:
    deadline = time.monotonic() + timeout
    sock = socket.create_connection((host, port), timeout=timeout)
    if tls_context is not None:
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProtocolError("TLS deadline exceeded before handshake")
            sock.settimeout(remaining)
            sock = tls_context.wrap_socket(
                sock,
                server_hostname=server_hostname or host,
            )
        except BaseException:
            sock.close()
            raise
    stream = BoundedSocket(
        sock,
        deadline=deadline,
        max_received=max_response,
    )
    try:
        stream.sendall(request)
        chunks: list[bytes] = []
        while True:
            chunk = stream.recv_some()
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
    finally:
        sock.close()


_HTTP_METHOD = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_HTTP_HEADER_NAME = re.compile(rb"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


@dataclass(frozen=True, slots=True)
class RawHttpResponse:
    status_line: bytes
    status_code: int
    headers: tuple[tuple[bytes, bytes], ...]
    body: bytes
    raw: bytes

    def header_values(self, name: bytes) -> tuple[bytes, ...]:
        lowered = name.lower()
        return tuple(value for key, value in self.headers if key.lower() == lowered)


def build_http_request(
    method: str,
    target: str,
    *,
    host: str,
    headers: Iterable[tuple[str, str]] = (),
    body: bytes = b"",
) -> bytes:
    if not _HTTP_METHOD.fullmatch(method):
        raise ValueError(f"invalid HTTP method: {method!r}")
    if not target.startswith("/") or "\r" in target or "\n" in target:
        raise ValueError("HTTP target must be an origin-form path without CR or LF")
    if "\r" in host or "\n" in host:
        raise ValueError("HTTP Host value contains CR or LF")

    normalized_headers: list[tuple[str, str]] = []
    names: set[str] = set()
    content_lengths: list[str] = []
    has_transfer_encoding = False
    for name, value in headers:
        encoded_name = name.encode("ascii", errors="strict")
        if not _HTTP_HEADER_NAME.fullmatch(encoded_name):
            raise ValueError(f"invalid HTTP header name: {name!r}")
        if "\r" in value or "\n" in value:
            raise ValueError(f"HTTP header {name!r} contains CR or LF")
        normalized_headers.append((name, value))
        names.add(name.lower())
        if name.lower() == "content-length":
            content_lengths.append(value)
        elif name.lower() == "transfer-encoding":
            has_transfer_encoding = True

    if has_transfer_encoding and content_lengths:
        raise ValueError("HTTP request cannot contain both Transfer-Encoding and Content-Length")
    if content_lengths:
        if len(content_lengths) != 1 or not content_lengths[0].isdigit():
            raise ValueError("HTTP request Content-Length must be one decimal value")
        if int(content_lengths[0]) != len(body):
            raise ValueError("HTTP request Content-Length does not match the body")

    if "host" not in names:
        normalized_headers.append(("Host", host))
    if "connection" not in names:
        normalized_headers.append(("Connection", "close"))
    if body and "content-length" not in names:
        normalized_headers.append(("Content-Length", str(len(body))))

    head = [f"{method} {target} HTTP/1.1\r\n".encode("ascii")]
    head.extend(f"{name}: {value}\r\n".encode("latin-1") for name, value in normalized_headers)
    head.append(b"\r\n")
    return b"".join(head) + body


def _decode_chunked_body(payload: bytes) -> bytes:
    cursor = 0
    decoded = bytearray()
    while True:
        line_end = payload.find(b"\r\n", cursor)
        if line_end < 0:
            raise ProtocolError("chunk size line was not terminated")
        size_field = payload[cursor:line_end].split(b";", 1)[0].strip()
        if not size_field:
            raise ProtocolError("empty chunk size")
        try:
            size = int(size_field, 16)
        except ValueError as error:
            raise ProtocolError(f"invalid chunk size: {size_field!r}") from error
        cursor = line_end + 2
        if size == 0:
            if payload[cursor : cursor + 2] == b"\r\n":
                cursor += 2
            else:
                trailer_end = payload.find(b"\r\n\r\n", cursor)
                if trailer_end < 0:
                    raise ProtocolError("chunk trailers were not terminated")
                cursor = trailer_end + 4
            if cursor != len(payload):
                raise ProtocolError("bytes followed the final HTTP chunk")
            return bytes(decoded)
        end = cursor + size
        if end > len(payload) or payload[end : end + 2] != b"\r\n":
            raise ProtocolError("chunk data was truncated or lacked CRLF")
        decoded.extend(payload[cursor:end])
        cursor = end + 2


def parse_http_response(raw: bytes, *, request_method: str = "GET") -> RawHttpResponse:
    separator = raw.find(b"\r\n\r\n")
    if separator < 0:
        raise ProtocolError("HTTP response headers were not terminated")
    head = raw[:separator]
    wire_body = raw[separator + 4 :]
    lines = head.split(b"\r\n")
    status_parts = lines[0].split(b" ", 2)
    if (
        len(status_parts) < 2
        or status_parts[0] not in (b"HTTP/1.0", b"HTTP/1.1")
        or len(status_parts[1]) != 3
        or not status_parts[1].isdigit()
    ):
        raise ProtocolError(f"invalid HTTP status line: {lines[0]!r}")
    status_code = int(status_parts[1])

    parsed_headers: list[tuple[bytes, bytes]] = []
    for line in lines[1:]:
        if line[:1] in (b" ", b"\t") or b":" not in line:
            raise ProtocolError(f"invalid HTTP response header: {line!r}")
        name, value = line.split(b":", 1)
        if not _HTTP_HEADER_NAME.fullmatch(name):
            raise ProtocolError(f"invalid HTTP response header name: {name!r}")
        parsed_headers.append((name, value.strip(b" \t")))

    response = RawHttpResponse(
        status_line=lines[0],
        status_code=status_code,
        headers=tuple(parsed_headers),
        body=b"",
        raw=raw,
    )
    no_body = (
        request_method.upper() == "HEAD" or status_code in {204, 304} or 100 <= status_code < 200
    )
    if no_body:
        if wire_body:
            raise ProtocolError("HTTP response included a forbidden message body")
        return response

    transfer_encoding = response.header_values(b"transfer-encoding")
    content_length = response.header_values(b"content-length")
    if transfer_encoding:
        codings = [part.strip().lower() for part in transfer_encoding[-1].split(b",")]
        if not codings or codings[-1] != b"chunked":
            body = wire_body
        else:
            body = _decode_chunked_body(wire_body)
    elif content_length:
        if len(content_length) != 1 or not content_length[0].isdigit():
            raise ProtocolError("invalid or conflicting HTTP Content-Length")
        expected = int(content_length[0])
        if len(wire_body) != expected:
            raise ProtocolError(
                f"HTTP body length mismatch: expected {expected}, received {len(wire_body)}"
            )
        body = wire_body
    else:
        body = wire_body
    return RawHttpResponse(
        status_line=response.status_line,
        status_code=response.status_code,
        headers=response.headers,
        body=body,
        raw=raw,
    )


def http_exchange(
    host: str,
    port: int,
    method: str,
    target: str,
    *,
    headers: Iterable[tuple[str, str]] = (),
    body: bytes = b"",
    timeout: float = 5.0,
    max_response: int = 8 * 1024 * 1024,
) -> RawHttpResponse:
    request = build_http_request(
        method,
        target,
        host=f"{host}:{port}",
        headers=headers,
        body=body,
    )
    raw = raw_exchange(
        host,
        port,
        request,
        timeout=timeout,
        max_response=max_response,
    )
    return parse_http_response(raw, request_method=method)


def json_http_exchange(
    host: str,
    port: int,
    method: str,
    target: str,
    *,
    value: object,
    headers: Iterable[tuple[str, str]] = (),
    timeout: float = 5.0,
    max_request: int = 1 * 1024 * 1024,
    max_response: int = 8 * 1024 * 1024,
) -> RawHttpResponse:
    """Send one compact, finite JSON request with an explicit body bound."""

    try:
        body = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ValueError("JSON request value is not finite and serializable") from error
    if len(body) > max_request:
        raise ValueError("JSON request body exceeds the configured bound")
    return http_exchange(
        host,
        port,
        method,
        target,
        headers=(("Content-Type", "application/json"), *tuple(headers)),
        body=body,
        timeout=timeout,
        max_response=max_response,
    )


def encode_varint(value: int) -> bytes:
    if value < 0 or value > 0x7FFFFFFF:
        raise ValueError("Minecraft VarInt value out of supported range")
    result = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        result.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(result)


def decode_varint(stream: BoundedSocket) -> int:
    result = 0
    for index in range(5):
        byte = stream.read_exact(1)[0]
        result |= (byte & 0x7F) << (7 * index)
        if not byte & 0x80:
            return result
    raise ProtocolError("Minecraft VarInt exceeded five bytes")


def _decode_varint_buffer(value: bytes, cursor: int) -> tuple[int, int]:
    result = 0
    for index in range(5):
        if cursor >= len(value):
            raise ProtocolError("Minecraft packet ended during VarInt")
        byte = value[cursor]
        cursor += 1
        result |= (byte & 0x7F) << (7 * index)
        if not byte & 0x80:
            return result, cursor
    raise ProtocolError("Minecraft VarInt exceeded five bytes")


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Never:
    raise ProtocolError(f"non-standard JSON constant: {value}")


def minecraft_status(
    host: str,
    port: int,
    *,
    protocol_version: int = 47,
    timeout: float = 5.0,
) -> dict[str, object]:
    encoded_host = host.encode("utf-8")
    handshake = b"".join(
        (
            encode_varint(0),
            encode_varint(protocol_version),
            encode_varint(len(encoded_host)),
            encoded_host,
            struct.pack(">H", port),
            encode_varint(1),
        )
    )
    stream = connect_bounded(host, port, timeout=timeout)
    try:
        stream.sendall(encode_varint(len(handshake)) + handshake)
        stream.sendall(b"\x01\x00")
        packet_size = decode_varint(stream)
        if packet_size <= 0 or packet_size > 1_048_576:
            raise ProtocolError(f"Minecraft status packet too large: {packet_size}")
        packet = stream.read_exact(packet_size)
        packet_id, cursor = _decode_varint_buffer(packet, 0)
        if packet_id != 0:
            raise ProtocolError(f"unexpected Minecraft status packet id: {packet_id}")
        json_size, cursor = _decode_varint_buffer(packet, cursor)
        if json_size > 1_048_576 or cursor + json_size != len(packet):
            raise ProtocolError(f"invalid Minecraft JSON length: {json_size}")
        payload = packet[cursor : cursor + json_size]
        try:
            value = json.loads(
                payload,
                object_pairs_hook=_strict_json_object,
                parse_constant=_reject_json_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ProtocolError("Minecraft status payload was not strict UTF-8 JSON") from error
        if not isinstance(value, dict):
            raise ProtocolError("Minecraft status payload was not an object")
        return value
    finally:
        stream.sock.close()


def lines_without_crlf(lines: Iterable[bytes]) -> list[str]:
    return [line.rstrip(b"\r\n").decode("utf-8", errors="strict") for line in lines]
