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

_GOLDEN = "managed-minecraft-post-static-v1"
_USERNAME = b"PostStaticProbe"
_POST_STATIC_IDS = (
    0x33,
    0x33,
    0x33,
    0x33,
    0x3B,
    0x3D,
    0x0F,
    0x1C,
    0x0F,
    0x1C,
    0x0F,
    0x1C,
    0x0F,
    0x1C,
    0x0F,
    0x1C,
    0x0F,
    0x1C,
    0x0F,
    0x1C,
)


def _read_expected_packets(connection: Any, expected: tuple[int, ...], phase: str) -> list[Any]:
    packets = [_read_packet(connection, compression=True) for _ in expected]
    actual = tuple(_packet_id(packet)[0] for packet in packets)
    if actual != expected:
        raise ProtocolError(f"unexpected {phase} packet order: {actual!r}")
    return packets


def _capture_post_static_bootstrap(target: RuntimeTarget) -> dict[str, Any]:
    if target.ports is None:
        raise RuntimeError("Minecraft capture target is not running")
    with _begin_login(target.ports.minecraft, _USERNAME) as connection:
        connection.settimeout(60.0)
        _read_login_prefix(connection)
        _read_expected_packets(connection, _INITIAL_PLAY_IDS, "initial PLAY")
        world_packet_count, world_expanded_bytes = _drain_to_player_position(connection)
        _read_expected_packets(connection, _STATIC_PLAY_IDS, "static PLAY")
        packets = _read_expected_packets(connection, _POST_STATIC_IDS, "post-static PLAY")
        if any(packet.data_length != 0 for packet in packets):
            raise ProtocolError("small post-static PLAY packet was unexpectedly zlib-compressed")

    return {
        "username": _USERNAME.decode(),
        "world_packet_count_through_position": world_packet_count,
        "world_expanded_bytes_through_position": world_expanded_bytes,
        "packets": [
            {
                "packet_id": packet_id,
                "frame": bytes_snapshot(packet.wire),
            }
            for packet_id, packet in zip(_POST_STATIC_IDS, packets, strict=True)
        ],
    }


cast(Any, _capture_post_static_bootstrap).__lmyzmail_contract__ = {
    "protocol": "minecraft-1.8.9",
    "flow": (
        "offline login -> world bootstrap -> static PLAY -> draft signs -> scoreboard -> "
        "hologram spawn"
    ),
    "protocol_version": 47,
    "compression_threshold": 256,
    "captured_packet_ids": list(_POST_STATIC_IDS),
    "hologram_entity_ids": [900_000, 900_006],
    "normalization": "none",
}


SCENARIOS = (
    Scenario("minecraft/post-static-bootstrap", _capture_post_static_bootstrap),
)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(600)
def test_frozen_java_minecraft_post_static_golden(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    golden = repository / "blackbox/golden/java" / _GOLDEN
    record = os.environ.get("LMYZMAIL_RECORD_JAVA_GOLDEN") == "1"
    runner = DifferentialRunner(
        repository,
        golden,
        "managed-minecraft-post-static",
        record_java=record,
    )
    with _LoginJavaOracleRuntime(tmp_path / "java-minecraft-post-static") as oracle:
        target = _OracleTarget(oracle)
        if record:
            runner.record_from_java(SCENARIOS, target)
        else:
            runner.verify_java(SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(600)
def test_rust_candidate_minecraft_post_static_matches_golden() -> None:
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
            "managed-minecraft-post-static",
        ).verify_candidate(SCENARIOS, candidate)
