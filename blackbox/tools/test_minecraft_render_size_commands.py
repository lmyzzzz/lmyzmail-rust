from __future__ import annotations

import os
from pathlib import Path
from typing import Any, cast

import pytest
from test_minecraft_authenticated_commands import _read_packets
from test_minecraft_email_prompt import _chat_frame
from test_minecraft_login import _begin_login, _LoginJavaOracleRuntime, _read_login_prefix
from test_minecraft_main_menu_actions import _snapshot_packets
from test_minecraft_password_auth import _EMAIL, _GOOD_PASSWORD, _SUCCESS_IDS, _USERNAME
from test_minecraft_post_static import _POST_STATIC_IDS, _read_expected_packets
from test_minecraft_render_settings import (
    _MENU_IDS,
    _VALID_UPDATE_IDS,
    _read_response_packets,
    _update_sign_frame,
)
from test_minecraft_static_play import (
    _INITIAL_PLAY_IDS,
    _STATIC_PLAY_IDS,
    _drain_to_player_position,
    _OracleTarget,
)

from lmyzmail_blackbox.differential import DifferentialRunner, RuntimeTarget, Scenario
from lmyzmail_blackbox.runtime import CandidateRuntime

_GOLDEN = "managed-minecraft-render-size-commands-v2"
_DIRECT_UPDATE_IDS = (0x3B, 0x3B, 0x3D) + (0x3C,) * 10 + (0x02,)
_ERROR_IDS = (0x02,)
_EDITOR_IDS = (0x35, 0x36) + (0x02,) * 4


def _capture_minecraft_render_size_commands(target: RuntimeTarget) -> dict[str, Any]:
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

        command_cases = (
            (
                "valid-upper-bounds",
                "/mail rendersize 24 20 48",
                _DIRECT_UPDATE_IDS,
            ),
            ("invalid-width-low", "/mail rs 1 20", _ERROR_IDS),
            ("invalid-height-high", "/mail rendersize 24 21", _ERROR_IDS),
            (
                "invalid-font-retains-previous",
                "/mail rendersize 12 8 49",
                _DIRECT_UPDATE_IDS,
            ),
            ("non-integer-width", "/mail rendersize twelve 8", _ERROR_IDS),
        )
        commands = []
        for name, command, expected_ids in command_cases:
            connection.sendall(_chat_frame(command))
            packets = _read_response_packets(connection, expected_ids, name)
            commands.append(
                {
                    "name": name,
                    "command": command,
                    "packets": _snapshot_packets(expected_ids, packets),
                }
            )

        connection.sendall(_chat_frame("/mail rs"))
        editor_packets = _read_response_packets(connection, _EDITOR_IDS, "rs sign editor")
        connection.sendall(_update_sign_frame(("2", "2", "8", "")))
        sign_update_packets = _read_response_packets(
            connection,
            _VALID_UPDATE_IDS,
            "rs sign update",
        )

        connection.sendall(_chat_frame("/menu"))
        menu_packets = _read_response_packets(connection, _MENU_IDS, "post-command menu")

    return {
        "username": _USERNAME.decode(),
        "email": _EMAIL,
        "world_packet_count_through_position": world_packet_count,
        "world_expanded_bytes_through_position": world_expanded_bytes,
        "commands": commands,
        "editor_packets": _snapshot_packets(_EDITOR_IDS, editor_packets),
        "sign_update_packets": _snapshot_packets(_VALID_UPDATE_IDS, sign_update_packets),
        "final_menu_packets": _snapshot_packets(_MENU_IDS, menu_packets),
    }


cast(Any, _capture_minecraft_render_size_commands).__lmyzmail_contract__ = {
    "protocol": "minecraft-1.8.9",
    "flow": "authenticated /mail rendersize and rs command paths",
    "protocol_version": 47,
    "compression_threshold": 256,
    "commands": [
        {
            "name": "valid-upper-bounds",
            "input": "/mail rendersize 24 20 48",
            "state_after": {"maps_x": 24, "maps_y": 20, "font_px": 48},
            "response_packet_ids": list(_DIRECT_UPDATE_IDS),
        },
        {
            "name": "invalid-width-low",
            "input": "/mail rs 1 20",
            "state_after": {"maps_x": 24, "maps_y": 20, "font_px": 48},
            "response_packet_ids": list(_ERROR_IDS),
        },
        {
            "name": "invalid-height-high",
            "input": "/mail rendersize 24 21",
            "state_after": {"maps_x": 24, "maps_y": 20, "font_px": 48},
            "response_packet_ids": list(_ERROR_IDS),
        },
        {
            "name": "invalid-font-retains-previous",
            "input": "/mail rendersize 12 8 49",
            "state_after": {"maps_x": 12, "maps_y": 8, "font_px": 48},
            "response_packet_ids": list(_DIRECT_UPDATE_IDS),
        },
        {
            "name": "non-integer-width",
            "input": "/mail rendersize twelve 8",
            "state_after": {"maps_x": 12, "maps_y": 8, "font_px": 48},
            "response_packet_ids": list(_ERROR_IDS),
        },
        {
            "name": "rs-sign-editor",
            "input": "/mail rs",
            "sign_lines": ["2", "2", "8", ""],
            "state_after": {"maps_x": 2, "maps_y": 2, "font_px": 8},
            "editor_packet_ids": list(_EDITOR_IDS),
            "update_response_packet_ids": list(_VALID_UPDATE_IDS),
        },
    ],
    "normalization": "exclude scheduled 0x03/0x18 PLAY ticks covered by scheduled-play",
}


SCENARIOS = (
    Scenario(
        "minecraft/render-size-commands",
        _capture_minecraft_render_size_commands,
    ),
)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(900)
def test_frozen_java_minecraft_render_size_commands_golden(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    golden = repository / "blackbox/golden/java" / _GOLDEN
    record = os.environ.get("LMYZMAIL_RECORD_JAVA_GOLDEN") == "1"
    runner = DifferentialRunner(
        repository,
        golden,
        _GOLDEN,
        record_java=record,
    )
    with _LoginJavaOracleRuntime(tmp_path / "java-minecraft-render-size-commands") as oracle:
        target = _OracleTarget(oracle)
        if record:
            runner.record_from_java(SCENARIOS, target)
        else:
            runner.verify_java(SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(900)
def test_rust_candidate_minecraft_render_size_commands_matches_golden() -> None:
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
