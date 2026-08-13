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

_GOLDEN = "managed-minecraft-password-auth-v5"
_USERNAME = b"PassAuthProbe"
_EMAIL = "qa@example.test"
_BAD_PASSWORD = "DefinitelyWrong123!"  # noqa: S105
_GOOD_PASSWORD = "BlackboxPass123!"  # noqa: S105
_FAILURE_IDS = (0x02, 0x02)
_SUCCESS_IDS = (0x02,) * 11 + (0x33,) * 4 + (0x2F,) + (0x3B, 0x3B, 0x3D) + (0x3C,) * 10


def _bootstrap_and_auth(
    target: RuntimeTarget,
    password: str,
    expected_ids: tuple[int, ...],
) -> tuple[int, int, list[Any]]:
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
        for _ in range(3):
            prompt = _read_packet(connection, compression=True)
            if _packet_id(prompt)[0] != 0x02 or prompt.data_length != 0:
                raise ProtocolError("email prompt was not an uncompressed Chat packet")
        connection.sendall(_chat_frame(password))
        packets = [_read_packet(connection, compression=True) for _ in expected_ids]
        actual_ids = tuple(_packet_id(packet)[0] for packet in packets)
        if actual_ids != expected_ids:
            raise ProtocolError(f"unexpected password auth packet order: {actual_ids!r}")
        if any(packet.data_length != 0 for packet in packets):
            raise ProtocolError("password auth packet was unexpectedly zlib-compressed")
    return world_packet_count, world_expanded_bytes, packets


def _capture_password_auth(target: RuntimeTarget) -> dict[str, Any]:
    failure_count, failure_bytes, failures = _bootstrap_and_auth(
        target, _BAD_PASSWORD, _FAILURE_IDS
    )
    success_count, success_bytes, successes = _bootstrap_and_auth(
        target, _GOOD_PASSWORD, _SUCCESS_IDS
    )
    return {
        "username": _USERNAME.decode(),
        "email": _EMAIL,
        "failure": {
            "password": _BAD_PASSWORD,
            "world_packet_count_through_position": failure_count,
            "world_expanded_bytes_through_position": failure_bytes,
            "packets": [
                {"packet_id": packet_id, "frame": bytes_snapshot(packet.wire)}
                for packet_id, packet in zip(_FAILURE_IDS, failures, strict=True)
            ],
        },
        "success": {
            "world_packet_count_through_position": success_count,
            "world_expanded_bytes_through_position": success_bytes,
            "packets": [
                {"packet_id": packet_id, "frame": bytes_snapshot(packet.wire)}
                for packet_id, packet in zip(_SUCCESS_IDS, successes, strict=True)
            ],
        },
    }


cast(Any, _capture_password_auth).__lmyzmail_contract__ = {
    "protocol": "minecraft-1.8.9",
    "flow": (
        "AwaitingPassword -> wrong password failure/prompt -> fresh connection -> "
        "correct password -> authenticated instructions/signs/book/scoreboard"
    ),
    "protocol_version": 47,
    "compression_threshold": 256,
    "input_packet_id": 0x01,
    "minecraft_auth": {
        "max_attempts": 5,
        "lockout_seconds": 300,
        "window_seconds": 600,
    },
    "captured_failure_packet_ids": list(_FAILURE_IDS),
    "captured_success_packet_ids": list(_SUCCESS_IDS),
    "normalization": "none",
}


SCENARIOS = (Scenario("minecraft/password-auth", _capture_password_auth),)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(900)
def test_frozen_java_minecraft_password_auth_golden(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    golden = repository / "blackbox/golden/java" / _GOLDEN
    record = os.environ.get("LMYZMAIL_RECORD_JAVA_GOLDEN") == "1"
    runner = DifferentialRunner(
        repository,
        golden,
        _GOLDEN,
        record_java=record,
    )
    with _LoginJavaOracleRuntime(tmp_path / "java-minecraft-password-auth") as oracle:
        target = _OracleTarget(oracle)
        if record:
            runner.record_from_java(SCENARIOS, target)
        else:
            runner.verify_java(SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(900)
def test_rust_candidate_minecraft_password_auth_matches_golden() -> None:
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
