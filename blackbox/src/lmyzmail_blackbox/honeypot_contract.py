from __future__ import annotations

import re
import select
import socket
import ssl
import struct
import time
from collections.abc import Callable
from typing import Any, cast

import psycopg
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from .differential import RuntimeTarget, Scenario
from .errors import ProtocolError
from .protocols import BoundedSocket
from .snapshots import bytes_snapshot

_HOST = "127.0.0.1"
_MAX_RESPONSE = 256 * 1024
_HTTP_PROBE = b"GET / HTTP/1.1\r\nHost: honeypot.example\r\nConnection: close\r\n\r\n"
_RDP_REQUEST = bytes.fromhex("0300000b06e00000000000")
_RDP_TLS_RESPONSE = bytes.fromhex("030000130ed000000001000200080001000000")
_RDP_DISCONNECT = bytes.fromhex("0300000902f0802180")


def _contract(value: dict[str, Any]) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def decorate(function: Callable[..., Any]) -> Callable[..., Any]:
        cast(Any, function).__lmyzmail_contract__ = value
        return function

    return decorate


def _port(target: RuntimeTarget, index: int) -> int:
    if target.ports is None or index >= len(target.ports.honeypots):
        raise ProtocolError(f"honeypot trap {index} is unavailable")
    return target.ports.honeypots[index]


def _connect(
    target: RuntimeTarget,
    index: int,
    *,
    timeout: float = 5.0,
    source: str | None = None,
) -> BoundedSocket:
    deadline = time.monotonic() + timeout
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if source is not None:
            sock.bind((source, 0))
        sock.settimeout(timeout)
        sock.connect((_HOST, _port(target, index)))
        return BoundedSocket(sock, deadline=deadline, max_received=_MAX_RESPONSE)
    except BaseException:
        sock.close()
        raise


def _read_to_eof(stream: BoundedSocket) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = stream.recv_some()
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _exchange(
    target: RuntimeTarget,
    index: int,
    request: bytes,
    *,
    timeout: float = 5.0,
    source: str | None = None,
) -> bytes:
    stream = _connect(target, index, timeout=timeout, source=source)
    try:
        stream.sendall(request)
        return _read_to_eof(stream)
    finally:
        stream.sock.close()


def _read_server_banner(target: RuntimeTarget, index: int) -> tuple[BoundedSocket, bytes]:
    stream = _connect(target, index, timeout=2.0)
    try:
        readable, _, _ = select.select([stream.sock], [], [], 0.005)
        if readable:
            raise ProtocolError("honeypot emitted a banner before the configured initial delay")
        if index == 0:
            header = stream.read_exact(4)
            length = int.from_bytes(header[:3], "little")
            return stream, header + stream.read_exact(length)
        return stream, stream.read_line(max_line=4096)
    except BaseException:
        stream.sock.close()
        raise


def _normalized_mysql_greeting(value: bytes) -> dict[str, Any]:
    if len(value) != 103 or value[:5] != b"c\x00\x00\x00\x0a":
        raise ProtocolError(f"unexpected MySQL greeting: {value!r}")
    normalized = bytearray(value)
    for start, end in ((37, 41), (41, 49), (68, 80)):
        normalized[start:end] = b"\x00" * (end - start)
    return cast(dict[str, Any], bytes_snapshot(bytes(normalized)))


def _http_variant_set(exchange: Callable[[], bytes]) -> list[dict[str, Any]]:
    variants: dict[str, dict[str, Any]] = {}
    for _ in range(128):
        response = exchange()
        snapshot = cast(dict[str, Any], bytes_snapshot(response))
        variants[cast(str, snapshot["sha256"])] = snapshot
        if len(variants) == 4:
            break
    if len(variants) != 4:
        raise ProtocolError(f"expected four HTTP mockery variants, observed {len(variants)}")
    return [variants[key] for key in sorted(variants)]


def _certificate_snapshot(der: bytes) -> dict[str, Any]:
    certificate = x509.load_der_x509_certificate(der)
    public_key = certificate.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ProtocolError("honeypot certificate is not an EC certificate")
    sans = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    basic = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
    validity_days = round(
        (certificate.not_valid_after_utc - certificate.not_valid_before_utc).total_seconds()
        / 86_400
    )
    return {
        "serial": certificate.serial_number,
        "subject": certificate.subject.rfc4514_string(),
        "issuer": certificate.issuer.rfc4514_string(),
        "dns_sans": sorted(sans.value.get_values_for_type(x509.DNSName)),
        "curve": public_key.curve.name,
        "signature_hash": certificate.signature_hash_algorithm.name,
        "is_ca": basic.value.ca,
        "basic_constraints_critical": basic.critical,
        "validity_days": validity_days,
    }


def _tls_exchange(target: RuntimeTarget, index: int, prefix: bytes = b"") -> tuple[bytes, bytes]:
    raw = socket.create_connection((_HOST, _port(target, index)), timeout=5.0)
    try:
        raw.settimeout(5.0)
        if prefix:
            raw.sendall(prefix)
            received = bytearray()
            while len(received) < len(_RDP_TLS_RESPONSE):
                chunk = raw.recv(len(_RDP_TLS_RESPONSE) - len(received))
                if not chunk:
                    raise ProtocolError("RDP honeypot closed before TLS negotiation")
                received.extend(chunk)
            if bytes(received) != _RDP_TLS_RESPONSE:
                raise ProtocolError(f"unexpected RDP negotiation response: {bytes(received)!r}")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        tls = context.wrap_socket(raw, server_hostname="not.a.real.server")
        raw = tls
        der = tls.getpeercert(binary_form=True)
        if der is None:
            raise ProtocolError("honeypot TLS peer did not present a certificate")
        chunks: list[bytes] = []
        while True:
            chunk = tls.recv(65_536)
            if not chunk:
                return der, b"".join(chunks)
            chunks.append(chunk)
    finally:
        raw.close()


def _varint(value: int) -> bytes:
    result = bytearray()
    value &= 0xFFFFFFFF
    while True:
        byte = value & 0x7F
        value >>= 7
        result.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(result)


def _minecraft_handshake() -> bytes:
    address = b"honeypot.example"
    body = b"\x00" + _varint(47) + _varint(len(address)) + address + b"\x63\xdd\x01"
    return _varint(len(body)) + body


@_contract(
    {
        "protocol": "honeypot/tcp-raw",
        "profile": "server-first-and-banner-replies",
        "traps": ["MYSQL", "SSH", "VNC", "NONE", "NONE", "NONE", "FTP", "VNC"],
        "normalized": ["MySQL connection id and auth salt"],
    }
)
def capture_server_first(target: RuntimeTarget) -> dict[str, Any]:
    banners: list[dict[str, Any]] = []
    for index in range(8):
        if index in {3, 4, 5}:
            stream = _connect(target, index, timeout=1.0)
            try:
                banners.append({"trap": index, "passive_eof": stream.recv_some(1) == b""})
            finally:
                stream.sock.close()
            continue
        stream, banner = _read_server_banner(target, index)
        try:
            snapshot = _normalized_mysql_greeting(banner) if index == 0 else bytes_snapshot(banner)
            banners.append({"trap": index, "banner": snapshot})
        finally:
            stream.sock.close()

    mysql, _ = _read_server_banner(target, 0)
    try:
        mysql.sendall(b"PING\r\n")
        mysql_reply = _read_to_eof(mysql)
    finally:
        mysql.sock.close()
    ftp, _ = _read_server_banner(target, 6)
    try:
        ftp.sendall(b"USER scanner\r\n")
        ftp_reply = _read_to_eof(ftp)
    finally:
        ftp.sock.close()
    return {
        "banners": banners,
        "cross_protocol_mysql_to_redis": bytes_snapshot(mysql_reply),
        "matching_ftp_reply": bytes_snapshot(ftp_reply),
    }


@_contract(
    {
        "protocol": "honeypot/tcp-raw",
        "profile": "client-first-detector",
        "coverage": [
            "SOCKS4/5",
            "Zabbix binary/text",
            "MongoDB",
            "PostgreSQL",
            "MySQL auth",
            "Minecraft legacy/modern",
            "Redis",
            "Memcached",
            "SSH/SMTP/FTP/POP3/IMAP",
            "UNKNOWN",
        ],
    }
)
def capture_client_first(target: RuntimeTarget) -> dict[str, Any]:
    mongo = struct.pack("<iiii", 17, 1, 0, 2013) + b"\x00"
    mysql_payload = b"\x01\x00\x00\x00" + b"\x00" * 28
    mysql = len(mysql_payload).to_bytes(3, "little") + b"\x01" + mysql_payload
    zabbix = b"ZBXD\x01" + (0).to_bytes(8, "little")
    probes = {
        "socks5": b"\x05\x01\x00",
        "socks4": b"\x04\x01\x00\x50\x7f\x00\x00\x01x\x00",
        "zabbix_binary": zabbix,
        "mongodb": mongo,
        "postgresql": b"\x00\x00\x00\x08\x00\x03\x00\x00",
        "mysql": mysql,
        "minecraft_legacy": b"\xfe\x01",
        "minecraft_modern": _minecraft_handshake(),
        "redis": b"PING\r\n",
        "memcached": b"stats\r\n",
        "ssh": b"SSH-2.0-scanner\r\n",
        "smtp": b"EHLO scanner.example\r\n",
        "ftp": b"USER scanner\r\n",
        "pop3": b"STAT\r\n",
        "imap": b"A001 LOGIN scanner secret\r\n",
        "zabbix_text": b"agent.ping\n",
        "unknown": b"wat even is this\r\n",
    }
    return {
        name: bytes_snapshot(_exchange(target, 3, request))
        for name, request in probes.items()
    }


@_contract(
    {
        "protocol": "honeypot/tcp+tls+rdp+rfb",
        "profile": "special-protocols",
        "coverage": ["HTTP four-way random set", "TLS certificate", "RDP TLS", "VNC 3.8"],
        "normalized": ["TLS key, validity anchors, signature", "HTTP random choice order"],
    }
)
def capture_special_protocols(target: RuntimeTarget) -> dict[str, Any]:
    http_variants = _http_variant_set(lambda: _exchange(target, 3, _HTTP_PROBE))
    tls_certificates: list[dict[str, Any]] = []

    def tls_http() -> bytes:
        der, response = _tls_exchange(target, 5)
        tls_certificates.append(_certificate_snapshot(der))
        return response

    tls_variants = _http_variant_set(tls_http)
    if any(value != tls_certificates[0] for value in tls_certificates[1:]):
        raise ProtocolError("TLS certificate semantics changed within one process")

    rdp_der, rdp_response = _tls_exchange(target, 4, _RDP_REQUEST)
    if rdp_response != _RDP_DISCONNECT:
        raise ProtocolError(f"unexpected RDP TLS response: {rdp_response!r}")

    def vnc(selection: int, *, authenticate: bool = False) -> dict[str, Any]:
        stream, banner = _read_server_banner(target, 7)
        try:
            stream.sendall(b"RFB 003.008\n")
            security_types = stream.read_exact(256)
            stream.sendall(bytes([selection]))
            challenge = stream.read_exact(16) if authenticate else b""
            if authenticate:
                stream.sendall(b"\x00" * 16)
            security_result = stream.read_exact(4)
            stream.sendall(b"\x01")
            server_init = _read_to_eof(stream)
            return {
                "banner": bytes_snapshot(banner),
                "security_types": bytes_snapshot(security_types),
                "challenge": bytes_snapshot(challenge),
                "security_result": bytes_snapshot(security_result),
                "server_init": bytes_snapshot(server_init),
            }
        finally:
            stream.sock.close()

    return {
        "http_variants": http_variants,
        "tls": {"certificate": tls_certificates[0], "http_variants": tls_variants},
        "rdp": {
            "certificate": _certificate_snapshot(rdp_der),
            "negotiation": bytes_snapshot(_RDP_TLS_RESPONSE),
            "disconnect": bytes_snapshot(rdp_response),
        },
        "vnc_none": vnc(1),
        "vnc_auth": vnc(2, authenticate=True),
        "vnc_unknown_type": vnc(42),
    }


@_contract(
    {
        "protocol": "honeypot/tcp-raw",
        "profile": "bounds-timeouts-and-recovery",
        "limits": {"max_read_bytes": 1024, "max_connections_per_trap": 4},
        "coverage": ["post-banner timeout", "maximum read", "disconnect", "overload"],
    }
)
def capture_transport(target: RuntimeTarget) -> dict[str, Any]:
    ssh, banner = _read_server_banner(target, 1)
    try:
        banner_ignored_eof = ssh.recv_some(1) == b""
    finally:
        ssh.sock.close()

    oversized = _exchange(target, 3, b"x" * 4096)
    partial = _connect(target, 3, timeout=1.0)
    partial.sendall(b"GE")
    partial.sock.close()
    recovery = _exchange(target, 3, b"PING\r\n")

    streams = [_connect(target, 1, timeout=2.0) for _ in range(5)]
    outcomes: list[str] = []
    try:
        for stream in streams:
            try:
                value = stream.read_line(max_line=4096)
                outcomes.append("banner" if value == banner else "other")
            except (ConnectionError, OSError, ProtocolError):
                outcomes.append("eof")
    finally:
        for stream in streams:
            stream.sock.close()
    return {
        "banner_ignored_eof": banner_ignored_eof,
        "oversized": bytes_snapshot(oversized),
        "disconnect_recovery": bytes_snapshot(recovery),
        "connection_limit": sorted(outcomes),
    }


@_contract(
    {
        "protocol": "honeypot/postgresql-side-effect",
        "profile": "durable-cringe-record",
        "source": "127.0.0.2",
        "expected": "one HONEYPOT_HIT activity and one atomic score upsert",
        "normalized": ["ephemeral trap port"],
    }
)
def capture_persistence(target: RuntimeTarget) -> dict[str, Any]:
    if target.ports is None:
        raise ProtocolError("runtime ports are unavailable")
    response = _exchange(target, 3, b"PING\r\n", source="127.0.0.2")
    deadline = time.monotonic() + 5.0
    row: tuple[Any, ...] | None = None
    activity: tuple[Any, ...] | None = None
    while time.monotonic() < deadline:
        with psycopg.connect(
            host=_HOST,
            port=target.ports.postgres,
            dbname="lmyzmail",
            user="lmyzmail_test",
        ) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT current_score, total_score, activity_count, honeypot_hit_count
                    FROM skibidi_cringe_ip WHERE ip_address = '127.0.0.2'
                    """
                )
                row = cursor.fetchone()
                cursor.execute(
                    """
                    SELECT activity_type, score, metadata, response_message,
                           helo_name, mail_from, rcpt_to
                    FROM skibidi_cringe_ip_activity
                    WHERE ip_address = '127.0.0.2'
                    ORDER BY id DESC LIMIT 1
                    """
                )
                activity = cursor.fetchone()
        if row is not None and activity is not None:
            break
        time.sleep(0.025)
    if row is None or activity is None:
        log_tail = "<application log unavailable>"
        if target.workspace is not None:
            log_path = target.workspace / f"{target.target_kind}.log"
            if log_path.is_file():
                log_tail = log_path.read_bytes()[-16_384:].decode("utf-8", errors="replace")
        raise ProtocolError(
            "honeypot activity was not persisted within five seconds; "
            f"application log tail:\n{log_tail}"
        )
    metadata = re.sub(r"Honeypot\[trap-3:\d+\]", "Honeypot[trap-3:<port>]", activity[2])
    return {
        "response": bytes_snapshot(response),
        "ip": {
            "current_score": row[0],
            "total_score": row[1],
            "activity_count": row[2],
            "honeypot_hit_count": row[3],
        },
        "activity": {
            "type": activity[0],
            "score": activity[1],
            "metadata": metadata,
            "response_message": activity[3],
            "helo_name": activity[4],
            "mail_from": activity[5],
            "rcpt_to": activity[6],
        },
    }


@_contract(
    {
        "protocol": "honeypot/tcp-raw",
        "profile": "oracle-first-read-fragmentation-evidence",
        "request": "fragment PING into P then ING CRLF",
        "candidate_requirement": "classify incrementally within a bounded buffer",
    }
)
def capture_oracle_fragmentation(target: RuntimeTarget) -> dict[str, Any]:
    stream = _connect(target, 3, timeout=2.0)
    try:
        stream.sendall(b"P")
        time.sleep(0.05)
        try:
            stream.sendall(b"ING\r\n")
        except OSError:
            pass
        return {"response": bytes_snapshot(_read_to_eof(stream))}
    finally:
        stream.sock.close()


HONEYPOT_SCENARIOS = (
    Scenario("server-first", capture_server_first, normalizers=("mysql:greeting-random",)),
    Scenario("client-first", capture_client_first),
    Scenario(
        "special-protocols",
        capture_special_protocols,
        normalizers=("http:four-variant-set", "x509:dynamic-fields"),
    ),
    Scenario("transport", capture_transport),
    Scenario("persistence", capture_persistence, normalizers=("metadata:ephemeral-port",)),
)

HONEYPOT_ORACLE_EVIDENCE_SCENARIOS = (
    Scenario("first-read-fragmentation", capture_oracle_fragmentation),
)


__all__ = ["HONEYPOT_ORACLE_EVIDENCE_SCENARIOS", "HONEYPOT_SCENARIOS"]
