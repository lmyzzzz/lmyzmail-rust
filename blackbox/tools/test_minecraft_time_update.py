from __future__ import annotations

import os
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

_GOLDEN = "managed-minecraft-time-update-v5"
_USERNAME = b"TimeUpdateProbe"
_TICKS = 7
_HOLOGRAM_TICK_IDS = (0x18,) * 7


def _capture_time_update(target: RuntimeTarget) -> dict[str, Any]:
    if target.ports is None:
        raise RuntimeError("Minecraft capture target is not running")
    with _begin_login(target.ports.minecraft, _USERNAME) as connection:
        connection.settimeout(60.0)
        _read_login_prefix(connection)
        _read_expected_packets(connection, _INITIAL_PLAY_IDS, "initial PLAY")
        world_packet_count, world_expanded_bytes = _drain_to_player_position(connection)
        _read_expected_packets(connection, _STATIC_PLAY_IDS, "static PLAY")
        _read_expected_packets(connection, _POST_STATIC_IDS, "post-static PLAY")
        for _ in range(_TICKS):
            packets = [_read_packet(connection, compression=True) for _ in _HOLOGRAM_TICK_IDS]
            actual = tuple(_packet_id(packet)[0] for packet in packets)
            if actual != _HOLOGRAM_TICK_IDS:
                raise ProtocolError(f"unexpected hologram tick packet order: {actual!r}")
            if any(packet.data_length != 0 for packet in packets):
                raise ProtocolError("hologram tick packet was unexpectedly zlib-compressed")
        time_update = _read_packet(connection, compression=True)
        packet_id, _ = _packet_id(time_update)
        if packet_id != 0x03 or time_update.data_length != 0:
            raise ProtocolError("expected uncompressed Time Update after seven ticks")

    return {
        "username": _USERNAME.decode(),
        "world_packet_count_through_position": world_packet_count,
        "world_expanded_bytes_through_position": world_expanded_bytes,
        "hologram_ticks": _TICKS,
        "time_update": {
            "packet_id": packet_id,
            "frame": bytes_snapshot(time_update.wire),
        },
    }


cast(Any, _capture_time_update).__lmyzmail_contract__ = {
    "protocol": "minecraft-1.8.9",
    "flow": "post-static PLAY -> seven 2-second hologram ticks -> 15-second Time Update",
    "protocol_version": 47,
    "compression_threshold": 256,
    "hologram_ticks": _TICKS,
    "captured_packet_ids": [0x03],
    "normalization": "none",
}


SCENARIOS = (Scenario("minecraft/time-update", _capture_time_update),)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(600)
def test_frozen_java_minecraft_time_update_golden(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    golden = repository / "blackbox/golden/java" / _GOLDEN
    record = os.environ.get("LMYZMAIL_RECORD_JAVA_GOLDEN") == "1"
    runner = DifferentialRunner(
        repository,
        golden,
        _GOLDEN,
        record_java=record,
    )
    with _LoginJavaOracleRuntime(tmp_path / "java-minecraft-time-update") as oracle:
        target = _OracleTarget(oracle)
        if record:
            runner.record_from_java(SCENARIOS, target)
        else:
            runner.verify_java(SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(600)
def test_rust_candidate_minecraft_time_update_matches_golden() -> None:
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
