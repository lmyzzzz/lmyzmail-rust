from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import Any, cast

import pytest
from test_minecraft_authenticated_commands import _read_packets
from test_minecraft_email_prompt import _chat_frame
from test_minecraft_login import _begin_login, _LoginJavaOracleRuntime, _read_login_prefix
from test_minecraft_main_menu_lifecycle import (
    _play_frame,
    _read_lifecycle_packets,
    _read_main_menu,
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
from lmyzmail_blackbox.runtime import CandidateRuntime
from lmyzmail_blackbox.snapshots import bytes_snapshot

_GOLDEN = "managed-minecraft-main-menu-actions-v2"
_HELP_IDS = (0x32, 0x2F, 0x30, 0x2E, 0x2F, 0x2F) + (0x02,) * 6
_CLOSE_IDS = (0x32, 0x2F, 0x30, 0x2E, 0x2F, 0x2F)
_SWITCH_IDS = _CLOSE_IDS + (0x02,)
_EMAIL_IDS = (0x02, 0x02, 0x02)


def _click_frame(window_id: int, slot: int, action_number: int) -> bytes:
    payload = b"".join(
        (
            b"\x0e",
            bytes((window_id,)),
            struct.pack(">h", slot),
            b"\x00",
            struct.pack(">h", action_number),
            b"\x00",
            struct.pack(">h", -1),
        )
    )
    return _play_frame(payload)


def _snapshot_packets(
    packet_ids: tuple[int, ...], packets: list[Any]
) -> list[dict[str, Any]]:
    return [
        {
            "packet_id": packet_id,
            "data_length": packet.data_length,
            "frame": bytes_snapshot(packet.wire),
        }
        for packet_id, packet in zip(packet_ids, packets, strict=True)
    ]


def _open_menu(connection: Any) -> None:
    connection.sendall(_chat_frame("/menu"))
    _read_main_menu(connection)


def _capture_main_menu_actions(target: RuntimeTarget) -> dict[str, Any]:
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
        _read_packets(connection, _EMAIL_IDS, "email prompt")
        connection.sendall(_chat_frame(_GOOD_PASSWORD))
        _read_packets(connection, _SUCCESS_IDS, "password success")

        _open_menu(connection)
        connection.sendall(_click_frame(1, 30, 11))
        help_packets = _read_lifecycle_packets(connection, _HELP_IDS, "help click")

        _open_menu(connection)
        connection.sendall(_click_frame(2, 49, 12))
        close_packets = _read_lifecycle_packets(connection, _CLOSE_IDS, "close click")

        _open_menu(connection)
        connection.sendall(_click_frame(3, 32, 13))
        switch_packets = _read_lifecycle_packets(connection, _SWITCH_IDS, "switch click")
        connection.sendall(_chat_frame(_EMAIL))
        email_packets = _read_lifecycle_packets(
            connection, _EMAIL_IDS, "post-switch email prompt"
        )

    return {
        "username": _USERNAME.decode(),
        "email": _EMAIL,
        "world_packet_count_through_position": world_packet_count,
        "world_expanded_bytes_through_position": world_expanded_bytes,
        "help_packets": _snapshot_packets(_HELP_IDS, help_packets),
        "close_packets": _snapshot_packets(_CLOSE_IDS, close_packets),
        "switch_packets": _snapshot_packets(_SWITCH_IDS, switch_packets),
        "post_switch_email_packets": _snapshot_packets(_EMAIL_IDS, email_packets),
    }


cast(Any, _capture_main_menu_actions).__lmyzmail_contract__ = {
    "protocol": "minecraft-1.8.9",
    "flow": "authenticated main-menu help, close, and account-switch actions",
    "protocol_version": 47,
    "compression_threshold": 256,
    "actions": [
        {
            "name": "help",
            "window_id": 1,
            "slot": 30,
            "action_number": 11,
            "response_packet_ids": list(_HELP_IDS),
        },
        {
            "name": "close",
            "window_id": 2,
            "slot": 49,
            "action_number": 12,
            "response_packet_ids": list(_CLOSE_IDS),
        },
        {
            "name": "switch-account",
            "window_id": 3,
            "slot": 32,
            "action_number": 13,
            "response_packet_ids": list(_SWITCH_IDS),
            "followup_email_response_packet_ids": list(_EMAIL_IDS),
        },
    ],
    "normalization": "none",
}

SCENARIOS = (Scenario("minecraft/main-menu-actions", _capture_main_menu_actions),)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(900)
def test_frozen_java_minecraft_main_menu_actions_golden(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    golden = repository / "blackbox/golden/java" / _GOLDEN
    record = os.environ.get("LMYZMAIL_RECORD_JAVA_GOLDEN") == "1"
    runner = DifferentialRunner(
        repository,
        golden,
        _GOLDEN,
        record_java=record,
    )
    with _LoginJavaOracleRuntime(tmp_path / "java-minecraft-main-menu-actions") as oracle:
        target = _OracleTarget(oracle)
        if record:
            runner.record_from_java(SCENARIOS, target)
        else:
            runner.verify_java(SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(900)
def test_rust_candidate_minecraft_main_menu_actions_matches_golden() -> None:
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
