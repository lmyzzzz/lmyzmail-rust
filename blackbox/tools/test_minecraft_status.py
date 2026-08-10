from __future__ import annotations

import json
import os
import socket
import struct
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

_GOLDEN = "managed-minecraft-status-v8"
_CUSTOM_GOLDEN = "managed-minecraft-status-config-v5"
_MAX_FRAME = 2 * 1024 * 1024
_PING_PAYLOAD = 0x0123456789ABCDEF
_CUSTOM_MOTD = "Custom status"
_CUSTOM_FAVICON = "  cGl4ZWw=  "


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


class _ConfiguredJavaOracleRuntime(PersistentJavaOracleRuntime):
    def _application_arguments(self) -> list[str]:
        return [
            *super()._application_arguments(),
            "--botmail.minecraft.max-players=42",
            f"--botmail.minecraft.motd={_CUSTOM_MOTD}",
            f"--botmail.minecraft.favicon={_CUSTOM_FAVICON}",
        ]


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


def _read_frame(connection: socket.socket) -> tuple[bytes, bytes]:
    length, encoded_length = _read_varint(connection)
    if length <= 0 or length > _MAX_FRAME:
        raise ProtocolError(f"invalid Minecraft frame length: {length}")
    payload = _read_exact(connection, length)
    return encoded_length + payload, payload


def _frame(payload: bytes) -> bytes:
    return _encode_varint(len(payload)) + payload


def _handshake(port: int, *, next_state: int = 1, protocol: int = 47) -> bytes:
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


def _send_fragmented(connection: socket.socket, value: bytes) -> None:
    cursor = 0
    sizes = (1, 2, 3, 5, 8)
    index = 0
    while cursor < len(value):
        size = sizes[index % len(sizes)]
        connection.sendall(value[cursor : cursor + size])
        cursor += size
        index += 1


def _capture_status_ping(target: RuntimeTarget) -> dict[str, Any]:
    if target.ports is None:
        raise RuntimeError("Minecraft capture target is not running")
    with socket.create_connection(("127.0.0.1", target.ports.minecraft), timeout=5.0) as connection:
        connection.settimeout(5.0)
        _send_fragmented(connection, _handshake(target.ports.minecraft))
        connection.sendall(_frame(b"\x00"))
        status_wire, status_payload = _read_frame(connection)
        packet_id, cursor = _decode_varint_bytes(status_payload)
        if packet_id != 0:
            raise ProtocolError(f"unexpected Minecraft status packet id: {packet_id}")
        json_length, cursor = _decode_varint_bytes(status_payload, cursor)
        if cursor + json_length != len(status_payload):
            raise ProtocolError("invalid Minecraft status JSON length")
        status_json = json.loads(status_payload[cursor:].decode("utf-8"))

        ping = b"\x01" + struct.pack(">q", _PING_PAYLOAD)
        connection.sendall(_frame(ping))
        pong_wire, pong_payload = _read_frame(connection)
        if pong_payload != ping:
            raise ProtocolError("Minecraft pong did not preserve the ping payload")
        trailing = connection.recv(1)
        if trailing:
            raise ProtocolError("Minecraft server sent bytes after pong")

    return {
        "status_frame": bytes_snapshot(status_wire),
        "status_json": status_json,
        "pong_frame": bytes_snapshot(pong_wire),
        "closed_after_pong": True,
    }


cast(Any, _capture_status_ping).__lmyzmail_contract__ = {
    "protocol": "minecraft-1.8.9",
    "flow": "fragmented handshake -> status request -> response -> ping -> pong -> EOF",
    "protocol_version": 47,
    "ping_payload": _PING_PAYLOAD,
}


def _capture_custom_status_ping(target: RuntimeTarget) -> dict[str, Any]:
    return _capture_status_ping(target)


cast(Any, _capture_custom_status_ping).__lmyzmail_contract__ = {
    "protocol": "minecraft-1.8.9",
    "flow": "configured status request -> response -> ping -> pong -> EOF",
    "max_players": 42,
    "motd": _CUSTOM_MOTD,
    "favicon_input": _CUSTOM_FAVICON,
    "favicon_wire": "data:image/png;base64,cGl4ZWw=",
    "ping_payload": _PING_PAYLOAD,
}


def _expect_close(port: int, payload: bytes) -> dict[str, Any]:
    with socket.create_connection(("127.0.0.1", port), timeout=5.0) as connection:
        connection.settimeout(5.0)
        connection.sendall(payload)
        try:
            received = connection.recv(1024)
        except ConnectionResetError:
            received = b""
    return {"response": bytes_snapshot(received), "closed": True}


def _capture_rejections(target: RuntimeTarget) -> dict[str, Any]:
    if target.ports is None:
        raise RuntimeError("Minecraft capture target is not running")
    port = target.ports.minecraft
    return {
        "invalid_next_state": _expect_close(port, _handshake(port, next_state=3)),
        "negative_frame_length": _expect_close(port, b"\xff\xff\xff\xff\x0f"),
        "oversized_frame_length": _expect_close(port, _encode_varint(_MAX_FRAME + 1)),
        "overlong_frame_varint": _expect_close(port, b"\x80\x80\x80\x80\x80"),
    }


cast(Any, _capture_rejections).__lmyzmail_contract__ = {
    "protocol": "minecraft-1.8.9",
    "flow": "malformed or over-budget frame -> close without response",
    "max_frame_bytes": _MAX_FRAME,
}


SCENARIOS = (
    Scenario("minecraft/status-ping", _capture_status_ping),
    Scenario("minecraft/framing-rejections", _capture_rejections),
)
CUSTOM_SCENARIOS = (Scenario("minecraft/configured-status-ping", _capture_custom_status_ping),)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(180)
def test_frozen_java_minecraft_status_golden(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    golden = repository / "blackbox/golden/java" / _GOLDEN
    record = os.environ.get("LMYZMAIL_RECORD_JAVA_GOLDEN") == "1"
    runner = DifferentialRunner(
        repository,
        golden,
        _GOLDEN,
        record_java=record,
    )
    with PersistentJavaOracleRuntime(tmp_path / "java-minecraft-status") as oracle:
        target = _OracleTarget(oracle)
        if record:
            runner.record_from_java(SCENARIOS, target)
        else:
            runner.verify_java(SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(180)
def test_frozen_java_minecraft_configured_status_golden(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    record = os.environ.get("LMYZMAIL_RECORD_JAVA_GOLDEN") == "1"
    runner = DifferentialRunner(
        repository,
        repository / "blackbox/golden/java" / _CUSTOM_GOLDEN,
        _CUSTOM_GOLDEN,
        record_java=record,
    )
    with _ConfiguredJavaOracleRuntime(tmp_path / "java-minecraft-status-config") as oracle:
        target = _OracleTarget(oracle)
        if record:
            runner.record_from_java(CUSTOM_SCENARIOS, target)
        else:
            runner.verify_java(CUSTOM_SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_minecraft_status_matches_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    runtime = CandidateRuntime(
        command_template=(
            str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
            "--config",
            "{config}",
            "--lmyzmail.minecraft.enabled=true",
        )
    )
    with runtime as candidate:
        DifferentialRunner(
            repository,
            repository / "blackbox/golden/java" / _GOLDEN,
            _GOLDEN,
        ).verify_candidate(SCENARIOS, candidate)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_minecraft_configured_status_matches_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    runtime = CandidateRuntime(
        command_template=(
            str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
            "--config",
            "{config}",
            "--lmyzmail.minecraft.enabled=true",
            "--lmyzmail.minecraft.max-players=42",
            f"--lmyzmail.minecraft.motd={_CUSTOM_MOTD}",
            f"--lmyzmail.minecraft.favicon={_CUSTOM_FAVICON}",
        )
    )
    with runtime as candidate:
        DifferentialRunner(
            repository,
            repository / "blackbox/golden/java" / _CUSTOM_GOLDEN,
            _CUSTOM_GOLDEN,
        ).verify_candidate(CUSTOM_SCENARIOS, candidate)
