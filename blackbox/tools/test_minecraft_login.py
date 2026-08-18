from __future__ import annotations

import hashlib
import os
import socket
import struct
import sys
import uuid
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import pytest

from lmyzmail_blackbox.differential import DifferentialRunner, RuntimeTarget, Scenario
from lmyzmail_blackbox.errors import ProtocolError
from lmyzmail_blackbox.persistent_runtime import PersistentJavaOracleRuntime
from lmyzmail_blackbox.ports import PortSet
from lmyzmail_blackbox.runtime import CandidateRuntime
from lmyzmail_blackbox.snapshots import bytes_snapshot

_GOLDEN = "managed-minecraft-login-v14"
_MAX_FRAME = 2 * 1024 * 1024
_MAX_REJECTION_DRAIN = 32 * 1024 * 1024
_LOGIN_READ_TIMEOUT_SECONDS = 60.0
_PACKET_READ_TIMEOUT_SECONDS = 5.0
_USERNAME = "BlackboxLogin"
_REPLACEMENT_USERNAME_BYTES = b"\xed\xa0\x80"


@dataclass(frozen=True, slots=True)
class _OracleTarget:
    runtime: PersistentJavaOracleRuntime

    @property
    def target_kind(self) -> str:
        return "java-oracle"

    @property
    def workspace(self) -> Path | None:
        return self.runtime.workspace

    @property
    def ports(self) -> PortSet | None:
        return self.runtime.ports


class _LoginJavaOracleRuntime(PersistentJavaOracleRuntime):
    def _application_arguments(self) -> list[str]:
        return [
            *super()._application_arguments(),
            "--botmail.minecraft.spawn.x=-12.75",
            "--botmail.minecraft.spawn.y=70.9",
            "--botmail.minecraft.spawn.z=34.5",
            "--botmail.minecraft.spawn.yaw=45.0",
            "--botmail.minecraft.spawn.pitch=-15.0",
        ]


@dataclass(frozen=True, slots=True)
class _Packet:
    wire: bytes
    payload: bytes
    data_length: int | None


def _encode_varint(value: int) -> bytes:
    value &= 0xFFFFFFFF
    encoded = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            encoded.append(byte | 0x80)
        else:
            encoded.append(byte)
            return bytes(encoded)


def _decode_varint_bytes(value: bytes, cursor: int = 0) -> tuple[int, int]:
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


def _read_exact(connection: socket.socket, length: int) -> bytes:
    if length < 0 or length > _MAX_FRAME:
        raise ProtocolError(f"invalid Minecraft exact-read length: {length}")
    value = bytearray()
    while len(value) < length:
        chunk = connection.recv(length - len(value))
        if not chunk:
            raise ProtocolError("Minecraft connection closed during a packet")
        value.extend(chunk)
    return bytes(value)


def _read_varint(connection: socket.socket) -> tuple[int, bytes]:
    encoded = bytearray()
    result = 0
    for index in range(5):
        byte = _read_exact(connection, 1)[0]
        encoded.append(byte)
        result |= (byte & 0x7F) << (7 * index)
        if not byte & 0x80:
            return result, bytes(encoded)
    raise ProtocolError("Minecraft frame VarInt exceeded five bytes")


def _read_packet(connection: socket.socket, *, compression: bool) -> _Packet:
    length, encoded_length = _read_varint(connection)
    if length <= 0 or length > _MAX_FRAME:
        raise ProtocolError(f"invalid Minecraft frame length: {length}")
    frame_payload = _read_exact(connection, length)
    wire = encoded_length + frame_payload
    if not compression:
        return _Packet(wire=wire, payload=frame_payload, data_length=None)

    data_length, cursor = _decode_varint_bytes(frame_payload)
    encoded = frame_payload[cursor:]
    if data_length == 0:
        if not encoded:
            raise ProtocolError("compressed Minecraft envelope contained an empty packet")
        return _Packet(wire=wire, payload=encoded, data_length=0)
    if data_length > _MAX_FRAME:
        raise ProtocolError(f"Minecraft decompressed packet exceeded {_MAX_FRAME} bytes")
    inflater = zlib.decompressobj()
    payload = inflater.decompress(encoded, data_length + 1)
    payload += inflater.flush()
    if (
        len(payload) != data_length
        or not inflater.eof
        or inflater.unconsumed_tail
        or inflater.unused_data
    ):
        raise ProtocolError("Minecraft compressed packet did not match its declared length")
    return _Packet(wire=wire, payload=payload, data_length=data_length)


def _frame(payload: bytes) -> bytes:
    if not payload or len(payload) > _MAX_FRAME:
        raise ValueError("Minecraft test frame is outside the protocol budget")
    return _encode_varint(len(payload)) + payload


def _handshake(port: int, *, next_state: int = 2, protocol: int = 47) -> bytes:
    host = b"127.0.0.1"
    payload = b"".join(
        (
            b"\x00",
            _encode_varint(protocol),
            _encode_varint(len(host)),
            host,
            struct.pack(">H", port),
            _encode_varint(next_state),
        )
    )
    return _frame(payload)


def _login_start(username: bytes) -> bytes:
    return _frame(b"\x00" + _encode_varint(len(username)) + username)


def _send_fragmented(connection: socket.socket, value: bytes) -> None:
    cursor = 0
    sizes = (1, 2, 3, 5, 8)
    index = 0
    while cursor < len(value):
        size = sizes[index % len(sizes)]
        connection.sendall(value[cursor : cursor + size])
        cursor += size
        index += 1


def _read_string(value: bytes, cursor: int, *, max_units: int) -> tuple[str, int]:
    length, cursor = _decode_varint_bytes(value, cursor)
    end = cursor + length
    if length > max_units * 4 or end > len(value):
        raise ProtocolError("invalid Minecraft string length")
    try:
        decoded = value[cursor:end].decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProtocolError("outbound Minecraft string was not strict UTF-8") from error
    if len(decoded.encode("utf-16-le")) // 2 > max_units:
        raise ProtocolError("outbound Minecraft string exceeded its UTF-16 bound")
    return decoded, end


def _packet_id(packet: _Packet) -> tuple[int, int]:
    return _decode_varint_bytes(packet.payload)


def _offline_uuid(username: str) -> uuid.UUID:
    digest = hashlib.md5(f"OfflinePlayer:{username}".encode()).digest()  # noqa: S324
    return uuid.UUID(bytes=digest, version=3)


def _parse_login_success(packet: _Packet) -> dict[str, str]:
    packet_id, cursor = _packet_id(packet)
    if packet_id != 0x02:
        raise ProtocolError(f"unexpected Login Success packet id: {packet_id}")
    uuid_text, cursor = _read_string(packet.payload, cursor, max_units=36)
    username, cursor = _read_string(packet.payload, cursor, max_units=16)
    if cursor != len(packet.payload):
        raise ProtocolError("Login Success packet had trailing bytes")
    try:
        parsed_uuid = uuid.UUID(uuid_text)
    except ValueError as error:
        raise ProtocolError("Login Success UUID was invalid") from error
    return {"uuid": str(parsed_uuid), "username": username}


def _parse_join_game(packet: _Packet) -> tuple[dict[str, Any], bytes]:
    if packet.data_length != 0:
        raise ProtocolError("Join Game was not sent in a zero-length compression envelope")
    packet_id, cursor = _packet_id(packet)
    if packet_id != 0x01 or cursor + 8 > len(packet.payload):
        raise ProtocolError("invalid Join Game packet")
    entity_offset = cursor
    entity_id = struct.unpack_from(">i", packet.payload, cursor)[0]
    cursor += 4
    gamemode = packet.payload[cursor]
    dimension = struct.unpack_from(">b", packet.payload, cursor + 1)[0]
    difficulty = packet.payload[cursor + 2]
    max_players = packet.payload[cursor + 3]
    cursor += 4
    level_type, cursor = _read_string(packet.payload, cursor, max_units=16)
    if cursor + 1 != len(packet.payload):
        raise ProtocolError("Join Game packet had trailing or missing bytes")
    reduced_debug = packet.payload[cursor] != 0

    normalized_payload = bytearray(packet.payload)
    normalized_payload[entity_offset : entity_offset + 4] = b"\x00\x00\x00\x00"
    normalized_wire = _frame(b"\x00" + normalized_payload)
    return (
        {
            "entity_id_positive": entity_id > 0,
            "gamemode": gamemode,
            "dimension": dimension,
            "difficulty": difficulty,
            "max_players": max_players,
            "level_type": level_type,
            "reduced_debug": reduced_debug,
        },
        normalized_wire,
    )


def _parse_spawn_position(packet: _Packet) -> dict[str, int]:
    packet_id, cursor = _packet_id(packet)
    if packet_id != 0x05 or cursor + 8 != len(packet.payload):
        raise ProtocolError("invalid Spawn Position packet")
    packed = int.from_bytes(packet.payload[cursor:], "big")
    x = packed >> 38
    y = (packed >> 26) & 0xFFF
    z = packed & 0x3FFFFFF
    if x >= 1 << 25:
        x -= 1 << 26
    if y >= 1 << 11:
        y -= 1 << 12
    if z >= 1 << 25:
        z -= 1 << 26
    return {"x": x, "y": y, "z": z}


def _connect(port: int) -> socket.socket:
    connection = socket.create_connection(("127.0.0.1", port), timeout=_PACKET_READ_TIMEOUT_SECONDS)
    connection.settimeout(_PACKET_READ_TIMEOUT_SECONDS)
    return connection


def _begin_login(port: int, username: bytes) -> socket.socket:
    connection = _connect(port)
    try:
        _send_fragmented(connection, _handshake(port))
        _send_fragmented(connection, _login_start(username))
        return connection
    except BaseException:
        connection.close()
        raise


def _read_login_prefix(connection: socket.socket) -> tuple[_Packet, _Packet]:
    previous_timeout = connection.gettimeout()
    connection.settimeout(_LOGIN_READ_TIMEOUT_SECONDS)
    try:
        set_compression = _read_packet(connection, compression=False)
        packet_id, cursor = _packet_id(set_compression)
        threshold, cursor = _decode_varint_bytes(set_compression.payload, cursor)
        if packet_id != 0x03 or threshold != 256 or cursor != len(set_compression.payload):
            raise ProtocolError("unexpected Set Compression packet")
        login_success = _read_packet(connection, compression=True)
        if login_success.data_length != 0:
            raise ProtocolError("Login Success was not sent in the compression envelope")
        return set_compression, login_success
    finally:
        connection.settimeout(previous_timeout)


def test_login_prefix_restores_packet_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    class _TimeoutProbe:
        def __init__(self) -> None:
            self.timeout: float | None = _PACKET_READ_TIMEOUT_SECONDS
            self.history: list[float | None] = []

        def gettimeout(self) -> float | None:
            return self.timeout

        def settimeout(self, value: float | None) -> None:
            self.timeout = value
            self.history.append(value)

    set_compression = _Packet(
        wire=b"\x03\x03\x80\x02",
        payload=b"\x03\x80\x02",
        data_length=None,
    )
    login_success = _Packet(wire=b"\x01\x00", payload=b"\x02", data_length=0)
    packets = iter((set_compression, login_success))
    monkeypatch.setattr(
        sys.modules[__name__],
        "_read_packet",
        lambda _connection, *, compression: next(packets),
    )
    probe = _TimeoutProbe()

    if _read_login_prefix(cast(socket.socket, probe)) != (set_compression, login_success):
        pytest.fail("login prefix helper returned different packets")
    if probe.history != [_LOGIN_READ_TIMEOUT_SECONDS, _PACKET_READ_TIMEOUT_SECONDS]:
        pytest.fail(f"login prefix timeout history was not restored: {probe.history!r}")

    def fail_read(_connection: socket.socket, *, compression: bool) -> _Packet:
        raise TimeoutError("synthetic login timeout")

    monkeypatch.setattr(sys.modules[__name__], "_read_packet", fail_read)
    with pytest.raises(TimeoutError, match="synthetic login timeout"):
        _read_login_prefix(cast(socket.socket, probe))
    if probe.history[-2:] != [_LOGIN_READ_TIMEOUT_SECONDS, _PACKET_READ_TIMEOUT_SECONDS]:
        pytest.fail(f"failed login prefix timeout was not restored: {probe.history!r}")


def _capture_offline_bootstrap(target: RuntimeTarget) -> dict[str, Any]:
    if target.ports is None:
        raise RuntimeError("Minecraft capture target is not running")
    with _begin_login(target.ports.minecraft, _USERNAME.encode()) as connection:
        set_compression, login_success = _read_login_prefix(connection)
        login = _parse_login_success(login_success)
        expected_uuid = _offline_uuid(_USERNAME)
        if login != {"uuid": str(expected_uuid), "username": _USERNAME}:
            raise ProtocolError(f"unexpected offline Login Success: {login!r}")

        packet_ids = (0x01, 0x41, 0x05, 0x39, 0x03, 0x06, 0x09)
        play_packets = [_read_packet(connection, compression=True) for _ in packet_ids]
        actual_ids = tuple(_packet_id(packet)[0] for packet in play_packets)
        if actual_ids != packet_ids:
            raise ProtocolError(f"unexpected initial PLAY packet order: {actual_ids!r}")
        if any(packet.data_length != 0 for packet in play_packets):
            raise ProtocolError("small initial PLAY packet was unexpectedly zlib-compressed")
        join_game, normalized_join_wire = _parse_join_game(play_packets[0])
        spawn_position = _parse_spawn_position(play_packets[2])
        if spawn_position != {"x": -12, "y": 70, "z": 34}:
            raise ProtocolError(f"unexpected configured spawn: {spawn_position!r}")

    play_frames = [
        {
            "packet_id": packet_id,
            "frame": bytes_snapshot(
                normalized_join_wire if index == 0 else play_packets[index].wire
            ),
        }
        for index, packet_id in enumerate(packet_ids)
    ]
    return {
        "username": _USERNAME,
        "offline_uuid": str(expected_uuid),
        "compression_threshold": 256,
        "set_compression_frame": bytes_snapshot(set_compression.wire),
        "login_success_frame": bytes_snapshot(login_success.wire),
        "join_game": join_game,
        "spawn_position": spawn_position,
        "initial_play_frames": play_frames,
    }


cast(Any, _capture_offline_bootstrap).__lmyzmail_contract__ = {
    "protocol": "minecraft-1.8.9",
    "flow": (
        "fragmented handshake(LOGIN) -> Login Start -> Set Compression -> "
        "Login Success -> initial PLAY"
    ),
    "protocol_version": 47,
    "online_mode": False,
    "compression_threshold": 256,
    "configured_spawn": {"x": -12.75, "y": 70.9, "z": 34.5},
    "normalized_fields": ["join_game.entity_id"],
    "captured_play_packet_ids": [0x01, 0x41, 0x05, 0x39, 0x03, 0x06, 0x09],
}


def _expect_close_without_response(port: int, payload: bytes, *, shutdown_write: bool) -> None:
    with _connect(port) as connection:
        connection.sendall(payload)
        if shutdown_write:
            connection.shutdown(socket.SHUT_WR)
        try:
            received = connection.recv(1)
        except ConnectionResetError:
            received = b""
        if received:
            raise ProtocolError(f"Minecraft rejection returned bytes: {received!r}")


def _drain_until_close(connection: socket.socket) -> None:
    received = 0
    while True:
        try:
            chunk = connection.recv(65_536)
        except ConnectionResetError:
            return
        if not chunk:
            return
        received += len(chunk)
        if received > _MAX_REJECTION_DRAIN:
            raise ProtocolError("Minecraft rejection exceeded the bounded drain budget")


def _capture_login_boundaries(target: RuntimeTarget) -> dict[str, Any]:
    if target.ports is None:
        raise RuntimeError("Minecraft capture target is not running")
    port = target.ports.minecraft

    _expect_close_without_response(
        port,
        _handshake(port) + _login_start(b"x" * 17),
        shutdown_write=False,
    )

    truncated = _handshake(port) + _encode_varint(8) + b"\x00\x05xy"
    _expect_close_without_response(port, truncated, shutdown_write=True)

    with _connect(port) as connection:
        connection.sendall(_handshake(port))
        connection.sendall(_frame(b"\x7fignored"))
        connection.sendall(_login_start(_USERNAME.encode()))
        unknown_set_compression, unknown_login_success = _read_login_prefix(connection)
        unknown_login = _parse_login_success(unknown_login_success)

    with _begin_login(port, _REPLACEMENT_USERNAME_BYTES) as connection:
        replacement_set_compression, replacement_login_success = _read_login_prefix(connection)
        replacement_login = _parse_login_success(replacement_login_success)
    replacement_username = "\ufffd"
    expected_replacement = {
        "uuid": str(_offline_uuid(replacement_username)),
        "username": replacement_username,
    }
    if replacement_login != expected_replacement:
        raise ProtocolError(f"unexpected replacement-character login: {replacement_login!r}")

    with _begin_login(port, b"CompressionProbe") as connection:
        _read_login_prefix(connection)
        connection.sendall(_frame(_encode_varint(_MAX_FRAME + 1) + b"x"))
        _drain_until_close(connection)

    return {
        "overlong_username": {"closed": True, "response_bytes": 0},
        "truncated_login_start": {"closed": True, "response_bytes": 0},
        "unknown_login_packet_then_valid": {
            "login": unknown_login,
            "set_compression_frame": bytes_snapshot(unknown_set_compression.wire),
            "login_success_frame": bytes_snapshot(unknown_login_success.wire),
        },
        "invalid_utf8_replacement": {
            "login": replacement_login,
            "set_compression_frame": bytes_snapshot(replacement_set_compression.wire),
            "login_success_frame": bytes_snapshot(replacement_login_success.wire),
        },
        "oversized_decompressed_packet": {
            "declared_bytes": _MAX_FRAME + 1,
            "closed_within_receive_budget": True,
            "receive_budget_bytes": _MAX_REJECTION_DRAIN,
        },
    }


cast(Any, _capture_login_boundaries).__lmyzmail_contract__ = {
    "protocol": "minecraft-1.8.9",
    "flow": "login malformed/unknown/compression-boundary probes",
    "username_max_utf16_units": 16,
    "invalid_utf8": "Java UTF-8 replacement semantics",
    "max_decompressed_packet_bytes": _MAX_FRAME,
    "normalization_reason": "queued bootstrap bytes before decoder close are scheduler-dependent",
}


SCENARIOS = (
    Scenario(
        "minecraft/offline-login-bootstrap",
        _capture_offline_bootstrap,
        normalizers=("minecraft-join-game-entity-id-v1",),
    ),
    Scenario(
        "minecraft/login-boundaries",
        _capture_login_boundaries,
        normalizers=("minecraft-concurrent-bootstrap-drain-v1",),
    ),
)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(180)
def test_frozen_java_minecraft_offline_login_golden(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    golden = repository / "blackbox/golden/java" / _GOLDEN
    record = os.environ.get("LMYZMAIL_RECORD_JAVA_GOLDEN") == "1"
    runner = DifferentialRunner(
        repository,
        golden,
        _GOLDEN,
        record_java=record,
    )
    with _LoginJavaOracleRuntime(tmp_path / "java-minecraft-login") as oracle:
        target = _OracleTarget(oracle)
        if record:
            runner.record_from_java(SCENARIOS, target)
        else:
            runner.verify_java(SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_minecraft_offline_login_matches_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    runtime = CandidateRuntime(
        command_template=(
            str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
            "--config",
            "{config}",
            "--lmyzmail.minecraft.enabled=true",
            "--lmyzmail.minecraft.online-mode=false",
            "--lmyzmail.minecraft.spawn.x=-12.75",
            "--lmyzmail.minecraft.spawn.y=70.9",
            "--lmyzmail.minecraft.spawn.z=34.5",
            "--lmyzmail.minecraft.spawn.yaw=45.0",
            "--lmyzmail.minecraft.spawn.pitch=-15.0",
        )
    )
    with runtime as candidate:
        DifferentialRunner(
            repository,
            repository / "blackbox/golden/java" / _GOLDEN,
            _GOLDEN,
        ).verify_candidate(SCENARIOS, candidate)
