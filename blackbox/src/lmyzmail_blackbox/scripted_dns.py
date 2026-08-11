from __future__ import annotations

import contextlib
import ipaddress
import socket
import struct
import threading
from collections.abc import Mapping
from dataclasses import dataclass

from .errors import HarnessError

_MAX_PACKET_BYTES = 4096
_MAX_QUERIES = 256
_A_TYPE = 1
_TXT_TYPE = 16
_IN_CLASS = 1


@dataclass(frozen=True, slots=True)
class AAnswer:
    address: str
    ttl: int = 60

    def __post_init__(self) -> None:
        try:
            parsed = ipaddress.ip_address(self.address)
        except ValueError as error:
            raise ValueError("A answer must contain a valid IPv4 address") from error
        if parsed.version != 4:
            raise ValueError("A answer must contain a valid IPv4 address")
        if isinstance(self.ttl, bool) or not 0 <= self.ttl <= 2**31 - 1:
            raise ValueError("A answer TTL is out of range")


@dataclass(frozen=True, slots=True)
class TxtAnswer:
    chunks: tuple[str, ...]
    ttl: int = 60

    def __post_init__(self) -> None:
        if not self.chunks:
            raise ValueError("TXT answer must contain at least one chunk")
        if isinstance(self.ttl, bool) or not 0 <= self.ttl <= 2**31 - 1:
            raise ValueError("TXT answer TTL is out of range")
        for chunk in self.chunks:
            encoded = chunk.encode("utf-8")
            if not encoded or len(encoded) > 255:
                raise ValueError("TXT chunks must be between 1 and 255 UTF-8 bytes")


@dataclass(frozen=True, slots=True)
class DnsAnswer:
    a: tuple[AAnswer, ...] = ()
    txt: tuple[TxtAnswer, ...] = ()
    rcode: int = 0
    drop: bool = False

    def __post_init__(self) -> None:
        if isinstance(self.rcode, bool) or not 0 <= self.rcode <= 15:
            raise ValueError("DNS rcode must be between 0 and 15")
        if not isinstance(self.drop, bool):
            raise ValueError("DNS drop flag must be boolean")


@dataclass(frozen=True, slots=True)
class DnsQuery:
    qname: str
    qtype: int
    qclass: int


class ScriptedDnsServer:
    """Bounded UDP DNS fixture for deterministic A and TXT lookups.

    Only one uncompressed question is accepted per datagram. Unknown names return
    NXDOMAIN, while configured names can return records, an explicit rcode, or no
    response for deadline tests.
    """

    def __init__(
        self,
        answers: Mapping[tuple[str, int], DnsAnswer],
        *,
        bind_host: str = "127.0.0.1",
        bind_port: int = 0,
    ) -> None:
        try:
            parsed_host = ipaddress.ip_address(bind_host)
        except ValueError as error:
            raise ValueError("scripted DNS bind host must be a numeric IP address") from error
        if parsed_host.version != 4 or parsed_host.is_unspecified or parsed_host.is_multicast:
            raise ValueError("scripted DNS bind host must be a specific IPv4 address")
        if isinstance(bind_port, bool) or not 0 <= bind_port <= 65_535:
            raise ValueError("scripted DNS bind port must be between 0 and 65535")
        normalized: dict[tuple[str, int], DnsAnswer] = {}
        for (qname, qtype), answer in answers.items():
            normalized_name = _normalize_name(qname)
            if isinstance(qtype, bool) or not 0 <= qtype <= 65_535:
                raise ValueError("DNS query type is out of range")
            if (normalized_name, qtype) in normalized:
                raise ValueError(f"duplicate scripted DNS answer: {qname!r}/{qtype}")
            normalized[(normalized_name, qtype)] = answer
        self._answers = normalized
        self._bind_host = bind_host
        self._bind_port = bind_port
        self._state_lock = threading.RLock()
        self._stop_event = threading.Event()
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._queries: list[DnsQuery] = []
        self._errors: list[Exception] = []

    @property
    def host(self) -> str:
        return self._bind_host

    @property
    def port(self) -> int:
        listener = self._socket
        if listener is None:
            raise HarnessError("scripted DNS server is not running")
        return int(listener.getsockname()[1])

    def start(self) -> None:
        if self._socket is not None:
            raise RuntimeError("scripted DNS server is already running")
        listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((self._bind_host, self._bind_port))
            listener.settimeout(0.2)
        except BaseException:
            listener.close()
            raise
        self._socket = listener
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._serve,
            name="lmyzmail-scripted-dns",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        listener = self._socket
        if listener is not None:
            with contextlib.suppress(OSError):
                listener.close()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=2.0)
            if thread.is_alive():
                raise HarnessError("scripted DNS server thread did not stop")
        self._thread = None
        self._socket = None
        self.raise_if_errors()

    def queries(self) -> tuple[DnsQuery, ...]:
        with self._state_lock:
            return tuple(self._queries)

    def drain_queries(self) -> tuple[DnsQuery, ...]:
        with self._state_lock:
            result = tuple(self._queries)
            self._queries.clear()
            return result

    def errors(self) -> tuple[Exception, ...]:
        with self._state_lock:
            return tuple(self._errors)

    def raise_if_errors(self) -> None:
        errors = self.errors()
        if errors:
            raise HarnessError(f"scripted DNS server failed: {errors[0]}")

    def __enter__(self) -> ScriptedDnsServer:
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()

    def _serve(self) -> None:
        listener = self._socket
        if listener is None:
            return
        while not self._stop_event.is_set():
            try:
                packet, address = listener.recvfrom(_MAX_PACKET_BYTES + 1)
            except TimeoutError:
                continue
            except OSError:
                if not self._stop_event.is_set():
                    self._record_error(HarnessError("scripted DNS listener failed"))
                return
            if len(packet) > _MAX_PACKET_BYTES:
                self._record_error(HarnessError("scripted DNS packet exceeded fixture limit"))
                continue
            try:
                response = self._response(packet)
            except (ValueError, struct.error) as error:
                self._record_error(error)
                continue
            if response is not None:
                with contextlib.suppress(OSError):
                    listener.sendto(response, address)

    def _response(self, packet: bytes) -> bytes | None:
        if len(packet) < 12:
            raise ValueError("DNS packet header is truncated")
        transaction_id, request_flags, question_count, _, _, additional_count = struct.unpack(
            "!HHHHHH", packet[:12]
        )
        if question_count != 1:
            raise ValueError("scripted DNS requires exactly one question")
        qname, offset = _decode_name(packet, 12)
        if offset + 4 > len(packet):
            raise ValueError("DNS question has trailing or truncated bytes")
        qtype, qclass = struct.unpack("!HH", packet[offset : offset + 4])
        if offset + 4 != len(packet) and additional_count == 0:
            raise ValueError("DNS question has trailing or truncated bytes")
        query = DnsQuery(qname, qtype, qclass)
        with self._state_lock:
            if len(self._queries) >= _MAX_QUERIES:
                raise ValueError("scripted DNS query budget exceeded")
            self._queries.append(query)
        answer = self._answers.get((qname, qtype))
        if answer is not None and answer.drop:
            return None
        rcode = 3 if answer is None else answer.rcode
        a_answers = (
            ()
            if answer is None or qclass != _IN_CLASS or rcode != 0 or qtype != _A_TYPE
            else answer.a
        )
        txt_answers = (
            ()
            if answer is None or qclass != _IN_CLASS or rcode != 0 or qtype != _TXT_TYPE
            else answer.txt
        )
        answer_count = len(a_answers) + len(txt_answers)
        flags = 0x8000 | 0x0400 | 0x0080 | (request_flags & 0x0100) | rcode
        header = struct.pack("!HHHHHH", transaction_id, flags, 1, answer_count, 0, 0)
        question = packet[12 : offset + 4]
        records = b"".join(_encode_a_answer(item) for item in a_answers)
        records += b"".join(_encode_txt_answer(item) for item in txt_answers)
        return header + question + records

    def _record_error(self, error: Exception) -> None:
        with self._state_lock:
            self._errors.append(error)


def _normalize_name(value: str) -> str:
    if not value or any(character in value for character in "\r\n\x00"):
        raise ValueError("DNS name is empty or contains a control separator")
    name = value.rstrip(".").casefold()
    if not name or len(name.encode("ascii")) > 253:
        raise ValueError("DNS name is outside the fixture length bound")
    labels = name.split(".")
    if any(not label or len(label.encode("ascii")) > 63 for label in labels):
        raise ValueError("DNS label is outside the fixture length bound")
    return name


def _decode_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    total = 0
    while True:
        if offset >= len(packet):
            raise ValueError("DNS name is truncated")
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0:
            raise ValueError("compressed DNS questions are not supported")
        if length > 63 or offset + length > len(packet):
            raise ValueError("DNS label is truncated or oversized")
        label = packet[offset : offset + length].decode("ascii")
        offset += length
        total += length + 1
        if total > 253:
            raise ValueError("DNS name exceeds 253 bytes")
        labels.append(label.casefold())
    return ".".join(labels), offset


def _encode_txt_answer(answer: TxtAnswer) -> bytes:
    payload = b"".join(
        bytes((len(chunk.encode("utf-8")),)) + chunk.encode("utf-8")
        for chunk in answer.chunks
    )
    if len(payload) > 65_535:
        raise ValueError("DNS TXT answer exceeds 65535 bytes")
    header = struct.pack("!HHIH", _TXT_TYPE, _IN_CLASS, answer.ttl, len(payload))
    return b"\xc0\x0c" + header + payload


def _encode_a_answer(answer: AAnswer) -> bytes:
    payload = ipaddress.ip_address(answer.address).packed
    header = struct.pack("!HHIH", _A_TYPE, _IN_CLASS, answer.ttl, len(payload))
    return b"\xc0\x0c" + header + payload
