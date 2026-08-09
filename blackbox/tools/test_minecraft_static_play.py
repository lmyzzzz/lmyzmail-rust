from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import pytest
from test_minecraft_login import (
    _begin_login,
    _LoginJavaOracleRuntime,
    _offline_uuid,
    _packet_id,
    _read_login_prefix,
    _read_packet,
)

from lmyzmail_blackbox.differential import DifferentialRunner, RuntimeTarget, Scenario
from lmyzmail_blackbox.errors import ProtocolError
from lmyzmail_blackbox.persistent_runtime import PersistentJavaOracleRuntime
from lmyzmail_blackbox.ports import PortSet
from lmyzmail_blackbox.runtime import CandidateRuntime
from lmyzmail_blackbox.snapshots import bytes_snapshot

_GOLDEN = "managed-minecraft-static-play-v2"
_USERNAME_TEXT = "StaticPlayProbe"
_USERNAME = _USERNAME_TEXT.encode()
_INITIAL_PLAY_IDS = (0x01, 0x41, 0x05, 0x39, 0x03, 0x06, 0x09)
_STATIC_PLAY_IDS = (0x38, 0x47, 0x45, 0x45, 0x45, 0x02, 0x02, 0x02, 0x02, 0x2F, 0x2F)
_WORLD_PACKET_IDS = {0x21, 0x35}
_MAX_WORLD_PACKETS = 4_096
_MAX_WORLD_DATA = 512 * 1024 * 1024


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


def _drain_to_player_position(connection: Any) -> tuple[int, int]:
    packet_count = 0
    expanded_bytes = 0
    for _ in range(_MAX_WORLD_PACKETS):
        packet = _read_packet(connection, compression=True)
        packet_id, _ = _packet_id(packet)
        packet_count += 1
        expanded_bytes += len(packet.payload)
        if expanded_bytes > _MAX_WORLD_DATA:
            raise ProtocolError("Minecraft world bootstrap exceeded aggregate byte budget")
        if packet_id == 0x08:
            return packet_count, expanded_bytes
        if packet_id not in _WORLD_PACKET_IDS:
            raise ProtocolError(
                f"unexpected packet 0x{packet_id:02x} before Player Position And Look"
            )
    raise ProtocolError("world bootstrap did not reach Player Position And Look")


def _capture_static_play_bootstrap(target: RuntimeTarget) -> dict[str, Any]:
    if target.ports is None:
        raise RuntimeError("Minecraft capture target is not running")
    with _begin_login(target.ports.minecraft, _USERNAME) as connection:
        connection.settimeout(60.0)
        _read_login_prefix(connection)
        initial = [_read_packet(connection, compression=True) for _ in _INITIAL_PLAY_IDS]
        actual_initial = tuple(_packet_id(packet)[0] for packet in initial)
        if actual_initial != _INITIAL_PLAY_IDS:
            raise ProtocolError(f"unexpected initial PLAY packet order: {actual_initial!r}")

        world_packet_count, world_expanded_bytes = _drain_to_player_position(connection)
        packets = [_read_packet(connection, compression=True) for _ in _STATIC_PLAY_IDS]
        actual_ids = tuple(_packet_id(packet)[0] for packet in packets)
        if actual_ids != _STATIC_PLAY_IDS:
            raise ProtocolError(f"unexpected static PLAY packet order: {actual_ids!r}")
        if any(packet.data_length != 0 for packet in packets):
            raise ProtocolError("small static PLAY packet was unexpectedly zlib-compressed")

    return {
        "username": _USERNAME_TEXT,
        "offline_uuid": str(_offline_uuid(_USERNAME_TEXT)),
        "world_packet_count_through_position": world_packet_count,
        "world_expanded_bytes_through_position": world_expanded_bytes,
        "packets": [
            {
                "packet_id": packet_id,
                "frame": bytes_snapshot(packet.wire),
            }
            for packet_id, packet in zip(_STATIC_PLAY_IDS, packets, strict=True)
        ],
    }


cast(Any, _capture_static_play_bootstrap).__lmyzmail_contract__ = {
    "protocol": "minecraft-1.8.9",
    "flow": (
        "offline login -> initial PLAY -> world bootstrap -> Player Position And Look -> "
        "static PLAY bootstrap"
    ),
    "protocol_version": 47,
    "compression_threshold": 256,
    "world_template": "worlds/mailroom",
    "captured_packet_ids": list(_STATIC_PLAY_IDS),
    "normalization": "none",
}


SCENARIOS = (
    Scenario("minecraft/static-play-bootstrap", _capture_static_play_bootstrap),
)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(600)
def test_frozen_java_minecraft_static_play_golden(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    golden = repository / "blackbox/golden/java" / _GOLDEN
    record = os.environ.get("LMYZMAIL_RECORD_JAVA_GOLDEN") == "1"
    runner = DifferentialRunner(
        repository,
        golden,
        _GOLDEN,
        record_java=record,
    )
    with _LoginJavaOracleRuntime(tmp_path / "java-minecraft-static-play") as oracle:
        target = _OracleTarget(oracle)
        if record:
            runner.record_from_java(SCENARIOS, target)
        else:
            runner.verify_java(SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(600)
def test_rust_candidate_minecraft_static_play_matches_golden() -> None:
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
