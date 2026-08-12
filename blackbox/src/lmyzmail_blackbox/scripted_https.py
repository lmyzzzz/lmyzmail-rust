from __future__ import annotations

import contextlib
import ipaddress
import math
import socket
import ssl
import threading
from dataclasses import dataclass

from .errors import HarnessError

_MAX_HEADER_BYTES = 16 * 1024
_MAX_RESPONSE_BYTES = 128 * 1024
_MAX_CONNECTIONS = 32
_MAX_CONCURRENT_CONNECTIONS = 8
_CONNECTION_TIMEOUT_SECONDS = 15.0


@dataclass(frozen=True, slots=True)
class HttpsScenario:
    status: int = 200
    reason: str = "OK"
    headers: tuple[tuple[str, str], ...] = (("Content-Type", "text/plain"),)
    body: bytes = b""
    response_delay_seconds: float = 0.0
    response_chunk_bytes: int = 16 * 1024
    response_chunk_delay_seconds: float = 0.0
    close_without_response: bool = False

    def __post_init__(self) -> None:
        if isinstance(self.status, bool) or not 100 <= self.status <= 599:
            raise ValueError("HTTPS fixture status must be between 100 and 599")
        if (
            not self.reason
            or len(self.reason.encode("ascii", errors="strict")) > 80
            or any(value in self.reason for value in "\r\n\x00")
        ):
            raise ValueError("HTTPS fixture reason is invalid")
        if len(self.body) > _MAX_RESPONSE_BYTES:
            raise ValueError("HTTPS fixture response exceeds its byte budget")
        if (
            isinstance(self.response_chunk_bytes, bool)
            or self.response_chunk_bytes <= 0
            or self.response_chunk_bytes > _MAX_RESPONSE_BYTES
        ):
            raise ValueError("HTTPS fixture response chunk is out of range")
        for name, value in self.headers:
            if (
                not name
                or len(name.encode("ascii", errors="strict")) > 128
                or not all(character.isalnum() or character == "-" for character in name)
                or len(value.encode("latin-1", errors="strict")) > 4096
                or any(character in value for character in "\r\n\x00")
            ):
                raise ValueError("HTTPS fixture header is invalid")
        for delay in (self.response_delay_seconds, self.response_chunk_delay_seconds):
            if not math.isfinite(delay) or delay < 0 or delay > 60:
                raise ValueError("HTTPS fixture delay must be finite and at most 60 seconds")


@dataclass(frozen=True, slots=True)
class HttpsRequest:
    connection_id: int
    method: str
    target: str
    version: str
    headers: tuple[tuple[str, str], ...]
    sni: str | None
    tls_protocol: str
    tls_cipher: str
    tls_secret_bits: int


class ScriptedHttpsServer:
    """Bounded HTTPS/1.1 fixture for externally observing MTA-STS fetches."""

    def __init__(
        self,
        scenario: HttpsScenario,
        *,
        tls_context: ssl.SSLContext,
        bind_host: str = "127.0.0.1",
        bind_port: int = 0,
    ) -> None:
        try:
            parsed = ipaddress.ip_address(bind_host)
        except ValueError as error:
            raise ValueError("HTTPS fixture bind host must be a numeric IP address") from error
        if parsed.version != 4 or parsed.is_unspecified or parsed.is_multicast:
            raise ValueError("HTTPS fixture bind host must be a specific IPv4 address")
        if isinstance(bind_port, bool) or not 0 <= bind_port <= 65_535:
            raise ValueError("HTTPS fixture bind port must be between 0 and 65535")
        self._scenario = scenario
        self._tls_context = tls_context
        self._bind_host = bind_host
        self._bind_port = bind_port
        self._state_lock = threading.RLock()
        self._stop_event = threading.Event()
        self._listener: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None
        self._workers: list[threading.Thread] = []
        self._active: set[socket.socket] = set()
        self._requests: list[HttpsRequest] = []
        self._errors: list[Exception] = []
        self._handshake_failures = 0
        self._connections = 0
        self._concurrent = threading.BoundedSemaphore(_MAX_CONCURRENT_CONNECTIONS)
        self._sni: dict[int, str | None] = {}
        self._tls_context.set_servername_callback(self._record_sni)

    @property
    def host(self) -> str:
        return self._bind_host

    @property
    def port(self) -> int:
        listener = self._listener
        if listener is None:
            raise HarnessError("scripted HTTPS server is not running")
        return int(listener.getsockname()[1])

    def start(self) -> None:
        if self._listener is not None:
            raise RuntimeError("scripted HTTPS server is already running")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((self._bind_host, self._bind_port))
            listener.listen(_MAX_CONCURRENT_CONNECTIONS)
            listener.settimeout(0.2)
        except BaseException:
            listener.close()
            raise
        self._listener = listener
        self._stop_event.clear()
        self._accept_thread = threading.Thread(
            target=self._accept,
            name="lmyzmail-scripted-https",
            daemon=True,
        )
        self._accept_thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        listener = self._listener
        if listener is not None:
            with contextlib.suppress(OSError):
                listener.close()
        with self._state_lock:
            active = tuple(self._active)
        for connection in active:
            with contextlib.suppress(OSError):
                connection.shutdown(socket.SHUT_RDWR)
            with contextlib.suppress(OSError):
                connection.close()
        accept_thread = self._accept_thread
        if accept_thread is not None:
            accept_thread.join(timeout=2.0)
            if accept_thread.is_alive():
                raise HarnessError("scripted HTTPS accept thread did not stop")
        for worker in tuple(self._workers):
            worker.join(timeout=2.0)
            if worker.is_alive():
                raise HarnessError("scripted HTTPS worker did not stop")
        self._accept_thread = None
        self._listener = None
        self._workers.clear()
        self.raise_if_errors()

    def requests(self) -> tuple[HttpsRequest, ...]:
        with self._state_lock:
            return tuple(self._requests)

    def errors(self) -> tuple[Exception, ...]:
        with self._state_lock:
            return tuple(self._errors)

    def handshake_failures(self) -> int:
        with self._state_lock:
            return self._handshake_failures

    def raise_if_errors(self) -> None:
        errors = self.errors()
        if errors:
            raise HarnessError(f"scripted HTTPS server failed: {errors[0]}")

    def __enter__(self) -> ScriptedHttpsServer:
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()

    def _record_sni(
        self,
        connection: ssl.SSLSocket | ssl.SSLObject,
        server_name: str | None,
        _context: ssl.SSLSocket,
    ) -> int | None:
        with self._state_lock:
            self._sni[id(connection)] = server_name
        return None

    def _accept(self) -> None:
        listener = self._listener
        if listener is None:
            return
        while not self._stop_event.is_set():
            try:
                connection, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                if not self._stop_event.is_set():
                    self._record_error(HarnessError("scripted HTTPS listener failed"))
                return
            with self._state_lock:
                self._connections += 1
                connection_id = self._connections
            if connection_id > _MAX_CONNECTIONS or not self._concurrent.acquire(blocking=False):
                connection.close()
                self._record_error(HarnessError("scripted HTTPS connection budget exceeded"))
                continue
            worker = threading.Thread(
                target=self._serve_connection,
                args=(connection_id, connection),
                name=f"lmyzmail-scripted-https-{connection_id}",
                daemon=True,
            )
            self._workers.append(worker)
            worker.start()

    def _serve_connection(self, connection_id: int, plain: socket.socket) -> None:
        connection: socket.socket | ssl.SSLSocket = plain
        with self._state_lock:
            self._active.add(plain)
        try:
            plain.settimeout(_CONNECTION_TIMEOUT_SECONDS)
            try:
                tls = self._tls_context.wrap_socket(plain, server_side=True)
            except ssl.SSLError:
                with self._state_lock:
                    self._handshake_failures += 1
                return
            connection = tls
            with self._state_lock:
                self._active.discard(plain)
                self._active.add(tls)
            request = self._read_request(connection_id, tls)
            with self._state_lock:
                self._requests.append(request)
            self._write_response(tls)
        except (ConnectionError, TimeoutError, ssl.SSLError):
            # A bounded client may intentionally close once its own response limit is hit.
            pass
        except (UnicodeError, ValueError) as error:
            self._record_error(error)
        finally:
            with self._state_lock:
                self._active.discard(plain)
                self._active.discard(connection)
                self._sni.pop(id(connection), None)
            with contextlib.suppress(OSError):
                connection.close()
            if connection is not plain:
                with contextlib.suppress(OSError):
                    plain.close()
            self._concurrent.release()

    def _read_request(self, connection_id: int, connection: ssl.SSLSocket) -> HttpsRequest:
        value = bytearray()
        while b"\r\n\r\n" not in value:
            if len(value) >= _MAX_HEADER_BYTES:
                raise ValueError("HTTPS fixture request headers exceeded their byte budget")
            chunk = connection.recv(min(4096, _MAX_HEADER_BYTES - len(value)))
            if not chunk:
                raise ConnectionError("HTTPS peer disconnected before its request")
            value.extend(chunk)
        head, trailing = bytes(value).split(b"\r\n\r\n", 1)
        if trailing:
            raise ValueError("HTTPS fixture request unexpectedly contained a body")
        lines = head.split(b"\r\n")
        request_line = lines[0].decode("ascii", errors="strict").split(" ")
        if len(request_line) != 3 or any(not item for item in request_line):
            raise ValueError("HTTPS fixture request line is invalid")
        method, target, version = request_line
        headers: list[tuple[str, str]] = []
        for line in lines[1:]:
            if b":" not in line:
                raise ValueError("HTTPS fixture request header is invalid")
            name, raw_value = line.split(b":", 1)
            headers.append(
                (
                    name.decode("ascii", errors="strict"),
                    raw_value.strip(b" \t").decode("latin-1", errors="strict"),
                )
            )
        cipher = connection.cipher()
        if cipher is None:
            raise ValueError("HTTPS fixture TLS session did not negotiate a cipher")
        with self._state_lock:
            sni = self._sni.get(id(connection))
        return HttpsRequest(
            connection_id=connection_id,
            method=method,
            target=target,
            version=version,
            headers=tuple(headers),
            sni=sni,
            tls_protocol=connection.version() or "",
            tls_cipher=cipher[0],
            tls_secret_bits=cipher[2],
        )

    def _write_response(self, connection: ssl.SSLSocket) -> None:
        scenario = self._scenario
        if scenario.response_delay_seconds and self._stop_event.wait(
            scenario.response_delay_seconds
        ):
            return
        if scenario.close_without_response:
            return
        headers = list(scenario.headers)
        names = {name.casefold() for name, _ in headers}
        if "content-length" not in names:
            headers.append(("Content-Length", str(len(scenario.body))))
        if "connection" not in names:
            headers.append(("Connection", "close"))
        head = (
            f"HTTP/1.1 {scenario.status} {scenario.reason}\r\n"
            + "".join(f"{name}: {value}\r\n" for name, value in headers)
            + "\r\n"
        ).encode("latin-1", errors="strict")
        connection.sendall(head)
        for offset in range(0, len(scenario.body), scenario.response_chunk_bytes):
            if offset and scenario.response_chunk_delay_seconds and self._stop_event.wait(
                scenario.response_chunk_delay_seconds
            ):
                return
            connection.sendall(scenario.body[offset : offset + scenario.response_chunk_bytes])

    def _record_error(self, error: Exception) -> None:
        with self._state_lock:
            self._errors.append(error)
