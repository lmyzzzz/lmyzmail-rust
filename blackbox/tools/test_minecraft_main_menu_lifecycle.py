from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import Any, cast

import pytest
from test_minecraft_authenticated_commands import _read_packets
from test_minecraft_email_prompt import _chat_frame, _frame
from test_minecraft_login import (
    _begin_login,
    _LoginJavaOracleRuntime,
    _packet_id,
    _read_login_prefix,
    _read_packet,
)
from test_minecraft_main_menu import _MENU_IDS
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

_GOLDEN = "managed-minecraft-main-menu-lifecycle-v2"
_CLICK_RESPONSE_IDS = (0x32, 0x2F, 0x30)
_CLOSE_RESPONSE_IDS = (0x2F, 0x2F)


def _play_frame(payload: bytes) -> bytes:
    return _frame(b"\x00" + payload)


def _filler_click_frame() -> bytes:
    payload = b"".join(
        (
            b"\x0e\x01",
            struct.pack(">h", 0),
            b"\x00",
            struct.pack(">h", 7),
            b"\x00",
            struct.pack(">h", -1),
        )
    )
    return _play_frame(payload)


def _close_window_frame() -> bytes:
    return _play_frame(b"\x0d\x01")


def _read_main_menu(connection: Any) -> None:
    packets = [_read_packet(connection, compression=True) for _ in _MENU_IDS]
    actual_ids = tuple(_packet_id(packet)[0] for packet in packets)
    if actual_ids != _MENU_IDS:
        raise ProtocolError(f"unexpected main-menu packet order: {actual_ids!r}")
    if packets[0].data_length != 0:
        raise ProtocolError("Open Window was unexpectedly zlib-compressed")
    if packets[1].data_length is None or packets[1].data_length <= 0:
        raise ProtocolError("Window Items did not use the configured compression threshold")


def _read_lifecycle_packets(
    connection: Any, expected_ids: tuple[int, ...], label: str
) -> list[Any]:
    packets = [_read_packet(connection, compression=True) for _ in expected_ids]
    actual_ids = tuple(_packet_id(packet)[0] for packet in packets)
    if actual_ids != expected_ids:
        raise ProtocolError(f"unexpected {label} packet order: {actual_ids!r}")
    return packets


def _capture_main_menu_lifecycle(target: RuntimeTarget) -> dict[str, Any]:
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
        connection.sendall(_chat_frame("/menu"))
        _read_main_menu(connection)

        connection.sendall(_filler_click_frame())
        click_packets = _read_lifecycle_packets(
            connection, _CLICK_RESPONSE_IDS, "filler click"
        )
        connection.sendall(_close_window_frame())
        close_packets = _read_lifecycle_packets(
            connection, _CLOSE_RESPONSE_IDS, "window close"
        )

    return {
        "username": _USERNAME.decode(),
        "email": _EMAIL,
        "world_packet_count_through_position": world_packet_count,
        "world_expanded_bytes_through_position": world_expanded_bytes,
        "click_packets": [
            {
                "packet_id": packet_id,
                "data_length": packet.data_length,
                "frame": bytes_snapshot(packet.wire),
            }
            for packet_id, packet in zip(_CLICK_RESPONSE_IDS, click_packets, strict=True)
        ],
        "close_packets": [
            {
                "packet_id": packet_id,
                "data_length": packet.data_length,
                "frame": bytes_snapshot(packet.wire),
            }
            for packet_id, packet in zip(_CLOSE_RESPONSE_IDS, close_packets, strict=True)
        ],
    }


cast(Any, _capture_main_menu_lifecycle).__lmyzmail_contract__ = {
    "protocol": "minecraft-1.8.9",
    "flow": "authenticated main-menu filler click and client close lifecycle",
    "protocol_version": 47,
    "compression_threshold": 256,
    "click": {
        "packet_id": 0x0E,
        "window_id": 1,
        "slot": 0,
        "button": 0,
        "action_number": 7,
        "mode": 0,
        "clicked_slot_item_id": -1,
        "response_packet_ids": list(_CLICK_RESPONSE_IDS),
    },
    "close": {
        "packet_id": 0x0D,
        "window_id": 1,
        "response_packet_ids": list(_CLOSE_RESPONSE_IDS),
    },
    "normalization": "none",
}

SCENARIOS = (Scenario("minecraft/main-menu-lifecycle", _capture_main_menu_lifecycle),)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(900)
def test_frozen_java_minecraft_main_menu_lifecycle_golden(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    golden = repository / "blackbox/golden/java" / _GOLDEN
    record = os.environ.get("LMYZMAIL_RECORD_JAVA_GOLDEN") == "1"
    runner = DifferentialRunner(
        repository,
        golden,
        _GOLDEN,
        record_java=record,
    )
    with _LoginJavaOracleRuntime(tmp_path / "java-minecraft-main-menu-lifecycle") as oracle:
        target = _OracleTarget(oracle)
        if record:
            runner.record_from_java(SCENARIOS, target)
        else:
            runner.verify_java(SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(900)
def test_rust_candidate_minecraft_main_menu_lifecycle_matches_golden() -> None:
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
