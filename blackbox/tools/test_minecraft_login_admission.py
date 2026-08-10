from __future__ import annotations

import json
import os
import socket
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

_GOLDEN = "managed-minecraft-login-admission-v5"
_MAX_FRAME = 2 * 1024 * 1024


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


class _AdmissionJavaOracleRuntime(PersistentJavaOracleRuntime):
    def _application_arguments(self) -> list[str]:
        return [
            *super()._application_arguments(),
            "--botmail.minecraft.blacklist.players=BlockedUser,\u00c4User",
            "--botmail.minecraft.whitelist.enabled=true",
            "--botmail.minecraft.whitelist.players=AllowedUser",
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


def _decode_varint(value: bytes, cursor: int = 0) -> tuple[int, int]:
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


def _read_frame(connection: socket.socket) -> tuple[bytes, bytes]:
    encoded_length = bytearray()
    length = 0
    for index in range(5):
        byte = _read_exact(connection, 1)[0]
        encoded_length.append(byte)
        length |= (byte & 0x7F) << (7 * index)
        if not byte & 0x80:
            break
    else:
        raise ProtocolError("Minecraft frame VarInt exceeded five bytes")
    if length <= 0 or length > _MAX_FRAME:
        raise ProtocolError(f"invalid Minecraft frame length: {length}")
    payload = _read_exact(connection, length)
    return bytes(encoded_length) + payload, payload


def _frame(payload: bytes) -> bytes:
    return _encode_varint(len(payload)) + payload


def _string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return _encode_varint(len(encoded)) + encoded


def _handshake(port: int) -> bytes:
    host = "127.0.0.1"
    payload = b"".join(
        (
            b"\x00",
            _encode_varint(47),
            _string(host),
            port.to_bytes(2, "big"),
            _encode_varint(2),
        )
    )
    return _frame(payload)


def _login_start(username: str) -> bytes:
    return _frame(b"\x00" + _string(username))


def _capture_rejection(port: int, username: str) -> dict[str, Any]:
    with socket.create_connection(("127.0.0.1", port), timeout=5.0) as connection:
        connection.settimeout(5.0)
        connection.sendall(_handshake(port) + _login_start(username))
        wire, payload = _read_frame(connection)
        packet_id, cursor = _decode_varint(payload)
        if packet_id != 0:
            raise ProtocolError(f"unexpected login rejection packet id: {packet_id}")
        reason_length, cursor = _decode_varint(payload, cursor)
        if cursor + reason_length != len(payload):
            raise ProtocolError("invalid login rejection JSON length")
        reason = json.loads(payload[cursor:].decode("utf-8"))
        trailing = connection.recv(1)
        if trailing:
            raise ProtocolError("Minecraft server sent bytes after login rejection")
    return {
        "response_frame": bytes_snapshot(wire),
        "reason": reason,
        "closed_after_rejection": True,
    }


def _capture_blacklist(target: RuntimeTarget) -> dict[str, Any]:
    if target.ports is None:
        raise RuntimeError("Minecraft capture target is not running")
    return _capture_rejection(target.ports.minecraft, "blockeduser")


cast(Any, _capture_blacklist).__lmyzmail_contract__ = {
    "protocol": "minecraft-1.8.9",
    "flow": "offline login start -> case-insensitive blacklist rejection -> EOF",
    "username": "blockeduser",
    "configured_blacklist": ["BlockedUser"],
}


def _capture_unicode_blacklist(target: RuntimeTarget) -> dict[str, Any]:
    if target.ports is None:
        raise RuntimeError("Minecraft capture target is not running")
    return _capture_rejection(target.ports.minecraft, "\u00e4user")


cast(Any, _capture_unicode_blacklist).__lmyzmail_contract__ = {
    "protocol": "minecraft-1.8.9",
    "flow": "offline login start -> Java Unicode case-insensitive blacklist -> EOF",
    "username": "\u00e4user",
    "configured_blacklist": ["\u00c4User"],
}


def _capture_whitelist(target: RuntimeTarget) -> dict[str, Any]:
    if target.ports is None:
        raise RuntimeError("Minecraft capture target is not running")
    return _capture_rejection(target.ports.minecraft, "OtherUser")


cast(Any, _capture_whitelist).__lmyzmail_contract__ = {
    "protocol": "minecraft-1.8.9",
    "flow": "offline login start -> whitelist rejection -> EOF",
    "username": "OtherUser",
    "configured_whitelist": ["AllowedUser"],
}


def _capture_overlong_username(target: RuntimeTarget) -> dict[str, Any]:
    if target.ports is None:
        raise RuntimeError("Minecraft capture target is not running")
    port = target.ports.minecraft
    with socket.create_connection(("127.0.0.1", port), timeout=5.0) as connection:
        connection.settimeout(5.0)
        connection.sendall(_handshake(port) + _login_start("A" * 17))
        try:
            response = connection.recv(1024)
        except ConnectionResetError:
            response = b""
    return {"response": bytes_snapshot(response), "closed": True}


cast(Any, _capture_overlong_username).__lmyzmail_contract__ = {
    "protocol": "minecraft-1.8.9",
    "flow": "17-character login username -> close without response",
    "max_username_utf16_units": 16,
}


SCENARIOS = (
    Scenario("minecraft/login/blacklist-rejection", _capture_blacklist),
    Scenario("minecraft/login/unicode-blacklist-rejection", _capture_unicode_blacklist),
    Scenario("minecraft/login/whitelist-rejection", _capture_whitelist),
    Scenario("minecraft/login/overlong-username", _capture_overlong_username),
)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(180)
def test_frozen_java_minecraft_login_admission_golden(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    record = os.environ.get("LMYZMAIL_RECORD_JAVA_GOLDEN") == "1"
    runner = DifferentialRunner(
        repository,
        repository / "blackbox/golden/java" / _GOLDEN,
        _GOLDEN,
        record_java=record,
    )
    with _AdmissionJavaOracleRuntime(
        tmp_path / "java-minecraft-login-admission", startup_timeout=30.0
    ) as oracle:
        target = _OracleTarget(oracle)
        if record:
            runner.record_from_java(SCENARIOS, target)
        else:
            runner.verify_java(SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_minecraft_login_admission_matches_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    runtime = CandidateRuntime(
        command_template=(
            str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
            "--config",
            "{config}",
            "--lmyzmail.minecraft.enabled=true",
            "--lmyzmail.minecraft.online-mode=false",
            "--lmyzmail.minecraft.blacklist.players=BlockedUser,\u00c4User",
            "--lmyzmail.minecraft.whitelist.enabled=true",
            "--lmyzmail.minecraft.whitelist.players=AllowedUser",
        )
    )
    with runtime as candidate:
        DifferentialRunner(
            repository,
            repository / "blackbox/golden/java" / _GOLDEN,
            _GOLDEN,
        ).verify_candidate(SCENARIOS, candidate)
