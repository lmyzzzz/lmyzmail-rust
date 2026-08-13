from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import Any, cast

import pytest
from test_minecraft_login import (
    _begin_login,
    _LoginJavaOracleRuntime,
    _packet_id,
    _read_login_prefix,
    _read_packet,
)
from test_minecraft_post_static import _POST_STATIC_IDS, _read_expected_packets
from test_minecraft_static_play import (
    _INITIAL_PLAY_IDS,
    _STATIC_PLAY_IDS,
    _drain_to_player_position,
    _OracleTarget,
)

from lmyzmail_blackbox.differential import DifferentialRunner, RuntimeTarget, Scenario
from lmyzmail_blackbox.errors import ProtocolError
from lmyzmail_blackbox.runtime import CandidateRuntime
from lmyzmail_blackbox.snapshots import bytes_snapshot

_GOLDEN = "managed-minecraft-position-rebound-v6"
_USERNAME = b"PositionProbe"
_HOLOGRAM_IDS = (0x18,) * 7
_REBOUND_IDS = (0x08, 0x02)


def _frame(payload: bytes) -> bytes:
    value = len(payload)
    encoded = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            encoded.append(byte | 0x80)
        else:
            encoded.append(byte)
            return bytes(encoded) + payload


def _player_position_frame(x: float, y: float, z: float) -> bytes:
    packet = b"\x04" + struct.pack(">ddd", x, y, z) + b"\x00"
    return _frame(b"\x00" + packet)


def _capture_position_rebound(target: RuntimeTarget) -> dict[str, Any]:
    if target.ports is None:
        raise RuntimeError("Minecraft capture target is not running")
    with _begin_login(target.ports.minecraft, _USERNAME) as connection:
        connection.settimeout(60.0)
        _read_login_prefix(connection)
        _read_expected_packets(connection, _INITIAL_PLAY_IDS, "initial PLAY")
        world_packet_count, world_expanded_bytes = _drain_to_player_position(connection)
        _read_expected_packets(connection, _STATIC_PLAY_IDS, "static PLAY")
        _read_expected_packets(connection, _POST_STATIC_IDS, "post-static PLAY")

        connection.sendall(_player_position_frame(500.0, 500.0, 500.0))
        rebound = [_read_packet(connection, compression=True) for _ in _REBOUND_IDS]
        actual_rebound = tuple(_packet_id(packet)[0] for packet in rebound)
        if actual_rebound != _REBOUND_IDS:
            raise ProtocolError(f"unexpected position rebound packet order: {actual_rebound!r}")

        holograms = [_read_packet(connection, compression=True) for _ in _HOLOGRAM_IDS]
        actual_holograms = tuple(_packet_id(packet)[0] for packet in holograms)
        if actual_holograms != _HOLOGRAM_IDS:
            raise ProtocolError(f"unexpected hologram tick packet order: {actual_holograms!r}")

        packets = rebound + holograms
        if any(packet.data_length != 0 for packet in packets):
            raise ProtocolError("position rebound packet was unexpectedly zlib-compressed")

    return {
        "username": _USERNAME.decode(),
        "world_packet_count_through_position": world_packet_count,
        "world_expanded_bytes_through_position": world_expanded_bytes,
        "input": {"packet_id": 0x04, "position": [500.0, 500.0, 500.0]},
        "packets": [
            {
                "packet_id": packet_id,
                "frame": bytes_snapshot(packet.wire),
            }
            for packet_id, packet in zip((*_REBOUND_IDS, *_HOLOGRAM_IDS), packets, strict=True)
        ],
    }


cast(Any, _capture_position_rebound).__lmyzmail_contract__ = {
    "protocol": "minecraft-1.8.9",
    "flow": (
        "post-static PLAY -> far Player Position -> teleport-back position/chat -> "
        "seven hologram teleports"
    ),
    "protocol_version": 47,
    "compression_threshold": 256,
    "input_packet_id": 0x04,
    "captured_packet_ids": [*_REBOUND_IDS, *_HOLOGRAM_IDS],
    "normalization": "none",
}


SCENARIOS = (Scenario("minecraft/position-rebound", _capture_position_rebound),)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(600)
def test_frozen_java_minecraft_position_rebound_golden(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    golden = repository / "blackbox/golden/java" / _GOLDEN
    record = os.environ.get("LMYZMAIL_RECORD_JAVA_GOLDEN") == "1"
    runner = DifferentialRunner(
        repository,
        golden,
        _GOLDEN,
        record_java=record,
    )
    with _LoginJavaOracleRuntime(tmp_path / "java-minecraft-position-rebound") as oracle:
        target = _OracleTarget(oracle)
        if record:
            runner.record_from_java(SCENARIOS, target)
        else:
            runner.verify_java(SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(600)
def test_rust_candidate_minecraft_position_rebound_matches_golden() -> None:
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
            "--lmyzmail.minecraft.video.center-x=0",
            "--lmyzmail.minecraft.video.wall-z=-50",
        )
    )
    with runtime as candidate:
        DifferentialRunner(
            repository,
            repository / "blackbox/golden/java" / _GOLDEN,
            _GOLDEN,
        ).verify_candidate(SCENARIOS, candidate)
