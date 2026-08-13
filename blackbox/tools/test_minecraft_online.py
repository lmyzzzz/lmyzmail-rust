from __future__ import annotations

import os
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from test_minecraft_login import (
    _connect,
    _encode_varint,
    _frame,
    _handshake,
    _login_start,
    _read_packet,
    _read_string,
)

from lmyzmail_blackbox.differential import DifferentialRunner, RuntimeTarget, Scenario
from lmyzmail_blackbox.errors import ProtocolError
from lmyzmail_blackbox.persistent_runtime import PersistentJavaOracleRuntime
from lmyzmail_blackbox.ports import PortSet
from lmyzmail_blackbox.runtime import CandidateRuntime

_GOLDEN = "managed-minecraft-online-v8"
_USERNAME = "OnlineUser"
_RSA_FIELD = 512


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


class _OnlineJavaOracleRuntime(PersistentJavaOracleRuntime):
    def _application_arguments(self) -> list[str]:
        arguments = super()._application_arguments()
        return [
            "--botmail.minecraft.online-mode=true"
            if argument == "--botmail.minecraft.online-mode=false"
            else argument
            for argument in arguments
        ]


def _read_encryption_request(connection: socket.socket) -> tuple[bytes, bytes, bytes]:
    packet = _read_packet(connection, compression=False)
    cursor = 0
    packet_id, cursor = _read_varint_bytes(packet.payload, cursor)
    if packet_id != 0x01:
        raise ProtocolError(f"unexpected online Login packet id: {packet_id}")
    server_id, cursor = _read_string(packet.payload, cursor, max_units=20)
    public_key, cursor = _read_byte_array(packet.payload, cursor)
    verify_token, cursor = _read_byte_array(packet.payload, cursor)
    if cursor != len(packet.payload):
        raise ProtocolError("Encryption Request had trailing bytes")
    if server_id:
        raise ProtocolError("frozen online-mode server id was not empty")
    if not 128 <= len(public_key) <= _RSA_FIELD or len(verify_token) != 4:
        raise ProtocolError("Encryption Request field bounds changed")
    return packet.wire, public_key, verify_token


def _read_varint_bytes(value: bytes, cursor: int = 0) -> tuple[int, int]:
    result = 0
    for index in range(5):
        if cursor >= len(value):
            raise ProtocolError("Minecraft packet ended during VarInt")
        byte = value[cursor]
        cursor += 1
        result |= (byte & 0x7F) << (index * 7)
        if not byte & 0x80:
            return result, cursor
    raise ProtocolError("Minecraft VarInt exceeded five bytes")


def _read_byte_array(value: bytes, cursor: int) -> tuple[bytes, int]:
    length, cursor = _read_varint_bytes(value, cursor)
    if length < 0 or length > _RSA_FIELD or cursor + length > len(value):
        raise ProtocolError("Minecraft encryption field exceeded its bound")
    end = cursor + length
    return value[cursor:end], end


def _encryption_response(public_key: bytes, secret: bytes, verify_token: bytes) -> bytes:
    key = serialization.load_der_public_key(public_key)
    if not isinstance(key, rsa.RSAPublicKey):
        raise ProtocolError("Minecraft Encryption Request key was not RSA")
    encrypted_secret = key.encrypt(secret, padding.PKCS1v15())
    encrypted_token = key.encrypt(verify_token, padding.PKCS1v15())
    return _frame(
        b"\x01"
        + _encode_varint(len(encrypted_secret))
        + encrypted_secret
        + _encode_varint(len(encrypted_token))
        + encrypted_token
    )


def _close_without_bytes(connection: socket.socket) -> None:
    connection.settimeout(5.0)
    try:
        if connection.recv(1):
            raise ProtocolError("online-mode rejection returned unexpected bytes")
    except (ConnectionResetError, ConnectionAbortedError):
        return


def _capture_online_boundaries(target: RuntimeTarget) -> dict[str, Any]:
    if target.ports is None:
        raise RuntimeError("Minecraft capture target is not running")
    port = target.ports.minecraft

    with _connect(port) as connection:
        connection.sendall(_handshake(port) + _login_start(_USERNAME.encode()))
        request_wire, public_key, verify_token = _read_encryption_request(connection)
    key = serialization.load_der_public_key(public_key)
    if not isinstance(key, rsa.RSAPublicKey):
        raise ProtocolError("Minecraft Encryption Request key was not RSA")
    request = {
        "server_id": "",
        "public_key_algorithm": "RSA",
        "public_key_bits": key.key_size,
        "public_key_der_length": len(public_key),
        "verify_token_length": len(verify_token),
        "request_frame_length": len(request_wire),
    }

    with _connect(port) as connection:
        connection.sendall(_handshake(port) + _login_start(_USERNAME.encode()))
        _, public_key, verify_token = _read_encryption_request(connection)
        wrong_token = bytes((verify_token[0] ^ 0x01, *verify_token[1:]))
        connection.sendall(_encryption_response(public_key, b"0123456789abcdef", wrong_token))
        _close_without_bytes(connection)

    with _connect(port) as connection:
        connection.sendall(_handshake(port) + _login_start(_USERNAME.encode()))
        _read_encryption_request(connection)
        connection.sendall(_frame(b"\x01\x01x\x01x"))
        _close_without_bytes(connection)

    with _connect(port) as connection:
        connection.sendall(_handshake(port) + _login_start(_USERNAME.encode()))
        _, public_key, verify_token = _read_encryption_request(connection)
        connection.sendall(_encryption_response(public_key, b"x", verify_token))
        _close_without_bytes(connection)

    return {
        "encryption_request": request,
        "wrong_verify_token": {"closed": True, "response_bytes": 0},
        "malformed_rsa_fields": {"closed": True, "response_bytes": 0},
        "invalid_secret_length": {"closed": True, "response_bytes": 0},
    }


cast(Any, _capture_online_boundaries).__lmyzmail_contract__ = {
    "protocol": "minecraft-1.8.9",
    "flow": "LOGIN -> Encryption Request -> malformed Encryption Response boundaries",
    "protocol_version": 47,
    "online_mode": True,
    "normalizations": [
        "random RSA public key bytes are omitted after DER and key-size validation",
        "random verify token bytes are omitted after length validation",
    ],
    "security_boundary": "No sessionserver request is made for malformed RSA or token inputs",
}


SCENARIOS = (Scenario("minecraft/online-login-boundaries", _capture_online_boundaries),)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(180)
def test_frozen_java_minecraft_online_boundaries(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    golden = repository / "blackbox/golden/java" / _GOLDEN
    record = os.environ.get("LMYZMAIL_RECORD_JAVA_GOLDEN") == "1"
    runner = DifferentialRunner(repository, golden, _GOLDEN, record_java=record)
    with _OnlineJavaOracleRuntime(tmp_path / "java-minecraft-online") as oracle:
        target = _OracleTarget(oracle)
        if record:
            runner.record_from_java(SCENARIOS, target)
        else:
            runner.verify_java(SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_minecraft_online_boundaries() -> None:
    repository = Path(__file__).resolve().parents[2]
    runtime = CandidateRuntime(
        command_template=(
            str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
            "--config",
            "{config}",
            "--lmyzmail.minecraft.enabled=true",
            "--lmyzmail.minecraft.online-mode=true",
        )
    )
    with runtime as candidate:
        DifferentialRunner(
            repository,
            repository / "blackbox/golden/java" / _GOLDEN,
            _GOLDEN,
        ).verify_candidate(SCENARIOS, candidate)
