from __future__ import annotations

import json
import os
import socket
import struct
from pathlib import Path
from typing import Any, cast

import pytest
from test_minecraft_authenticated_commands import _read_packets
from test_minecraft_email_prompt import _chat_frame
from test_minecraft_login import (
    _begin_login,
    _encode_varint,
    _LoginJavaOracleRuntime,
    _packet_id,
    _read_login_prefix,
    _read_packet,
)
from test_minecraft_main_menu_actions import _click_frame, _snapshot_packets
from test_minecraft_main_menu_lifecycle import (
    _play_frame,
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

_GOLDEN = "managed-minecraft-render-settings-v6"
_MENU_IDS = (0x2D, 0x30)
_OPEN_EDITOR_IDS = (
    0x32,
    0x2F,
    0x30,
    0x2E,
    0x2F,
    0x2F,
    0x35,
    0x36,
    0x02,
    0x02,
    0x02,
    0x02,
)
_VALID_UPDATE_IDS = (0x02, 0x3B, 0x3B, 0x3D) + (0x3C,) * 10 + (0x33,) * 4
_REJECTED_UPDATE_IDS = (0x02,) + (0x33,) * 4
_INVALID_FONT_IDS = (
    0x02,
    0x02,
    0x3B,
    0x3B,
    0x3D,
) + (0x3C,) * 10 + (0x33,) * 4
_SCHEDULED_PLAY_IDS = frozenset((0x03, 0x18))
_MAX_SKIPPED_SCHEDULED_PACKETS = 64


def _update_sign_frame(lines: tuple[str, str, str, str]) -> bytes:
    payload = bytearray(b"\x12")
    payload.extend(struct.pack(">q", 0))
    for text in lines:
        component = json.dumps({"text": text}, ensure_ascii=False, separators=(",", ":"))
        encoded = component.encode()
        payload.extend(_encode_varint(len(encoded)))
        payload.extend(encoded)
    return _play_frame(bytes(payload))


def _read_response_packets(
    connection: Any,
    expected_ids: tuple[int, ...],
    label: str,
) -> list[Any]:
    packets: list[Any] = []
    skipped = 0
    while len(packets) < len(expected_ids):
        packet = _read_packet(connection, compression=True)
        packet_id = _packet_id(packet)[0]
        if packet_id == expected_ids[len(packets)]:
            packets.append(packet)
        elif packet_id in _SCHEDULED_PLAY_IDS:
            skipped += 1
            if skipped > _MAX_SKIPPED_SCHEDULED_PACKETS:
                raise ProtocolError(f"too many scheduled packets during {label}")
        else:
            actual = tuple(_packet_id(item)[0] for item in packets) + (packet_id,)
            raise ProtocolError(f"unexpected {label} packet order: {actual!r}")
    return packets


def _assert_closed_after_malformed_update(connection: Any) -> None:
    skipped = 0
    while connection.recv(1, socket.MSG_PEEK):
        packet = _read_packet(connection, compression=True)
        packet_id = _packet_id(packet)[0]
        if packet_id not in _SCHEDULED_PLAY_IDS:
            raise ProtocolError(
                f"malformed Update Sign emitted unexpected packet 0x{packet_id:02x}"
            )
        skipped += 1
        if skipped > _MAX_SKIPPED_SCHEDULED_PACKETS:
            raise ProtocolError("malformed Update Sign did not close within the packet budget")


def _open_menu_packets(connection: Any) -> list[Any]:
    connection.sendall(_chat_frame("/menu"))
    packets = _read_response_packets(connection, _MENU_IDS, "render-settings menu")
    return packets


def _open_editor(
    connection: Any,
    *,
    window_id: int,
    action_number: int,
) -> list[Any]:
    connection.sendall(_click_frame(window_id, 22, action_number))
    return _read_response_packets(connection, _OPEN_EDITOR_IDS, "render-settings editor")


def _capture_minecraft_render_settings(target: RuntimeTarget) -> dict[str, Any]:
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

        openings = []
        updates = []
        menus = []

        _open_menu_packets(connection)
        opening = _open_editor(connection, window_id=1, action_number=31)
        openings.append(_snapshot_packets(_OPEN_EDITOR_IDS, opening))

        update_cases = (
            ("valid-upper-bounds", ("24", "20", "48", "W H Font"), _VALID_UPDATE_IDS),
            ("invalid-width-low", ("1", "20", "48", ""), _REJECTED_UPDATE_IDS),
            ("invalid-height-high", ("24", "21", "48", ""), _REJECTED_UPDATE_IDS),
            (
                "invalid-font-retains-previous",
                ("12", "8", "49", ""),
                _INVALID_FONT_IDS,
            ),
            ("non-integer-width", ("twelve", "8", "48", ""), _REJECTED_UPDATE_IDS),
        )

        for index, (name, lines, expected_ids) in enumerate(update_cases, start=1):
            connection.sendall(_update_sign_frame(lines))
            packets = _read_response_packets(connection, expected_ids, name)
            updates.append(
                {
                    "name": name,
                    "lines": list(lines),
                    "packets": _snapshot_packets(expected_ids, packets),
                }
            )

            menu_packets = _open_menu_packets(connection)
            menus.append(
                {
                    "after": name,
                    "window_id": index + 1,
                    "packets": _snapshot_packets(_MENU_IDS, menu_packets),
                }
            )
            if index != len(update_cases):
                opening = _open_editor(
                    connection,
                    window_id=index + 1,
                    action_number=31 + index,
                )
                openings.append(_snapshot_packets(_OPEN_EDITOR_IDS, opening))

        opening = _open_editor(connection, window_id=6, action_number=36)
        openings.append(_snapshot_packets(_OPEN_EDITOR_IDS, opening))
        overlong_line = "a" * 385
        connection.sendall(_update_sign_frame((overlong_line, "", "", "")))
        _assert_closed_after_malformed_update(connection)

    return {
        "username": _USERNAME.decode(),
        "email": _EMAIL,
        "world_packet_count_through_position": world_packet_count,
        "world_expanded_bytes_through_position": world_expanded_bytes,
        "editor_openings": openings,
        "updates": updates,
        "menus_after_updates": menus,
        "overlong_update_connection_closed": True,
    }


cast(Any, _capture_minecraft_render_settings).__lmyzmail_contract__ = {
    "protocol": "minecraft-1.8.9",
    "flow": "authenticated render-settings sign editor and per-session state",
    "protocol_version": 47,
    "compression_threshold": 256,
    "menu_slot": 22,
    "sign_position": [0, 0, 0],
    "input_packet_id": 0x12,
    "input_string_max_utf16_units": 384,
    "malformed_boundary": {
        "first_line_text_utf16_units": 385,
        "result": "connection-closed-without-business-response",
    },
    "normalization": "exclude scheduled 0x03/0x18 PLAY ticks covered by scheduled-play",
    "cases": [
        {
            "name": "valid-upper-bounds",
            "lines": ["24", "20", "48", "W H Font"],
            "state_after": {"maps_x": 24, "maps_y": 20, "font_px": 48},
            "response_packet_ids": list(_VALID_UPDATE_IDS),
        },
        {
            "name": "invalid-width-low",
            "lines": ["1", "20", "48", ""],
            "state_after": {"maps_x": 24, "maps_y": 20, "font_px": 48},
            "response_packet_ids": list(_REJECTED_UPDATE_IDS),
        },
        {
            "name": "invalid-height-high",
            "lines": ["24", "21", "48", ""],
            "state_after": {"maps_x": 24, "maps_y": 20, "font_px": 48},
            "response_packet_ids": list(_REJECTED_UPDATE_IDS),
        },
        {
            "name": "invalid-font-retains-previous",
            "lines": ["12", "8", "49", ""],
            "state_after": {"maps_x": 12, "maps_y": 8, "font_px": 48},
            "response_packet_ids": list(_INVALID_FONT_IDS),
        },
        {
            "name": "non-integer-width",
            "lines": ["twelve", "8", "48", ""],
            "state_after": {"maps_x": 12, "maps_y": 8, "font_px": 48},
            "response_packet_ids": list(_REJECTED_UPDATE_IDS),
        },
    ],
}


SCENARIOS = (
    Scenario("minecraft/render-settings", _capture_minecraft_render_settings),
)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(900)
def test_frozen_java_minecraft_render_settings_golden(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    golden = repository / "blackbox/golden/java" / _GOLDEN
    record = os.environ.get("LMYZMAIL_RECORD_JAVA_GOLDEN") == "1"
    runner = DifferentialRunner(
        repository,
        golden,
        _GOLDEN,
        record_java=record,
    )
    with _LoginJavaOracleRuntime(tmp_path / "java-minecraft-render-settings") as oracle:
        target = _OracleTarget(oracle)
        if record:
            runner.record_from_java(SCENARIOS, target)
        else:
            runner.verify_java(SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(900)
def test_rust_candidate_minecraft_render_settings_matches_golden() -> None:
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
