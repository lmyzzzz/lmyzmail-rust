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

_GOLDEN = "managed-minecraft-scheduled-play-v7"
_USERNAME = b"ScheduledProbe"
_HOLOGRAM_IDS = (0x18,) * 7


def _capture_scheduled_play(target: RuntimeTarget) -> dict[str, Any]:
    if target.ports is None:
        raise RuntimeError("Minecraft capture target is not running")
    with _begin_login(target.ports.minecraft, _USERNAME) as connection:
        connection.settimeout(60.0)
        _read_login_prefix(connection)
        _read_expected_packets(connection, _INITIAL_PLAY_IDS, "initial PLAY")
        world_packet_count, world_expanded_bytes = _drain_to_player_position(connection)
        _read_expected_packets(connection, _STATIC_PLAY_IDS, "static PLAY")
        _read_expected_packets(connection, _POST_STATIC_IDS, "post-static PLAY")
        packets = [_read_packet(connection, compression=True) for _ in _HOLOGRAM_IDS]
        actual = tuple(_packet_id(packet)[0] for packet in packets)
        if actual != _HOLOGRAM_IDS:
            raise ProtocolError(f"unexpected first scheduled PLAY tick: {actual!r}")
        if any(packet.data_length != 0 for packet in packets):
            raise ProtocolError("scheduled PLAY packet was unexpectedly zlib-compressed")

    return {
        "username": _USERNAME.decode(),
        "world_packet_count_through_position": world_packet_count,
        "world_expanded_bytes_through_position": world_expanded_bytes,
        "tick": "first-hologram-teleport",
        "packets": [
            {
                "packet_id": packet_id,
                "frame": bytes_snapshot(packet.wire),
            }
            for packet_id, packet in zip(_HOLOGRAM_IDS, packets, strict=True)
        ],
    }


cast(Any, _capture_scheduled_play).__lmyzmail_contract__ = {
    "protocol": "minecraft-1.8.9",
    "flow": "post-static PLAY -> first 2-second hologram teleport tick",
    "protocol_version": 47,
    "compression_threshold": 256,
    "captured_packet_ids": list(_HOLOGRAM_IDS),
    "normalization": "none",
}


SCENARIOS = (Scenario("minecraft/scheduled-play", _capture_scheduled_play),)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(600)
def test_frozen_java_minecraft_scheduled_play_golden(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    golden = repository / "blackbox/golden/java" / _GOLDEN
    record = os.environ.get("LMYZMAIL_RECORD_JAVA_GOLDEN") == "1"
    runner = DifferentialRunner(
        repository,
        golden,
        _GOLDEN,
        record_java=record,
    )
    with _LoginJavaOracleRuntime(tmp_path / "java-minecraft-scheduled-play") as oracle:
        target = _OracleTarget(oracle)
        if record:
            runner.record_from_java(SCENARIOS, target)
        else:
            runner.verify_java(SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(600)
def test_rust_candidate_minecraft_scheduled_play_matches_golden() -> None:
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
