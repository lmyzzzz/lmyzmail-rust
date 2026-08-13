from __future__ import annotations

import os
from pathlib import Path
from typing import Any, cast

import pytest
from test_minecraft_email_prompt import _chat_frame
from test_minecraft_login import (
    _begin_login,
    _LoginJavaOracleRuntime,
    _packet_id,
    _read_login_prefix,
    _read_packet,
)
from test_minecraft_password_auth import _EMAIL, _GOOD_PASSWORD, _SUCCESS_IDS, _USERNAME
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

_GOLDEN = "managed-minecraft-authenticated-commands-v5"
_COMMANDS = (
    ("help", "  /HeLp  ", (0x02,) * 8),
    ("stuck", "/stuck", (0x08, 0x02)),
    ("skibidi", "/skibidi", (0x02,)),
    ("video-usage", "/video", (0x02, 0x02, 0x02)),
    ("unknown", "/definitely-unknown", (0x02,)),
)


def _read_packets(connection: Any, expected_ids: tuple[int, ...], label: str) -> list[Any]:
    packets = [_read_packet(connection, compression=True) for _ in expected_ids]
    actual_ids = tuple(_packet_id(packet)[0] for packet in packets)
    if actual_ids != expected_ids:
        raise ProtocolError(f"unexpected {label} packet order: {actual_ids!r}")
    if any(packet.data_length != 0 for packet in packets):
        raise ProtocolError(f"{label} packet was unexpectedly zlib-compressed")
    return packets


def _capture_authenticated_commands(target: RuntimeTarget) -> dict[str, Any]:
    if target.ports is None:
        raise RuntimeError("Minecraft capture target is not running")
    with _begin_login(target.ports.minecraft, _USERNAME) as connection:
        connection.settimeout(60.0)
        _read_login_prefix(connection)
        _read_expected_packets(connection, _INITIAL_PLAY_IDS, "initial PLAY")
        world_packet_count, world_expanded_bytes = _drain_to_player_position(connection)
        _read_expected_packets(connection, _STATIC_PLAY_IDS, "static PLAY")
        _read_expected_packets(connection, _POST_STATIC_IDS, "post-static PLAY")

        connection.sendall(_chat_frame(_EMAIL))
        _read_packets(connection, (0x02, 0x02, 0x02), "email prompt")
        connection.sendall(_chat_frame(_GOOD_PASSWORD))
        _read_packets(connection, _SUCCESS_IDS, "password success")

        observations = []
        for name, command, expected_ids in _COMMANDS:
            connection.sendall(_chat_frame(command))
            packets = _read_packets(connection, expected_ids, name)
            observations.append(
                {
                    "name": name,
                    "command": command,
                    "packets": [
                        {"packet_id": packet_id, "frame": bytes_snapshot(packet.wire)}
                        for packet_id, packet in zip(expected_ids, packets, strict=True)
                    ],
                }
            )
    return {
        "username": _USERNAME.decode(),
        "email": _EMAIL,
        "world_packet_count_through_position": world_packet_count,
        "world_expanded_bytes_through_position": world_expanded_bytes,
        "commands": observations,
    }


cast(Any, _capture_authenticated_commands).__lmyzmail_contract__ = {
    "protocol": "minecraft-1.8.9",
    "flow": "authenticated Chat commands with exact immediate server responses",
    "protocol_version": 47,
    "compression_threshold": 256,
    "input_packet_id": 0x01,
    "commands": [
        {"name": name, "input": command, "response_packet_ids": list(expected_ids)}
        for name, command, expected_ids in _COMMANDS
    ],
    "normalization": "none",
}


SCENARIOS = (Scenario("minecraft/authenticated-commands", _capture_authenticated_commands),)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(900)
def test_frozen_java_minecraft_authenticated_commands_golden(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    golden = repository / "blackbox/golden/java" / _GOLDEN
    record = os.environ.get("LMYZMAIL_RECORD_JAVA_GOLDEN") == "1"
    runner = DifferentialRunner(
        repository,
        golden,
        _GOLDEN,
        record_java=record,
    )
    with _LoginJavaOracleRuntime(tmp_path / "java-minecraft-authenticated-commands") as oracle:
        target = _OracleTarget(oracle)
        if record:
            runner.record_from_java(SCENARIOS, target)
        else:
            runner.verify_java(SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(900)
def test_rust_candidate_minecraft_authenticated_commands_matches_golden() -> None:
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
