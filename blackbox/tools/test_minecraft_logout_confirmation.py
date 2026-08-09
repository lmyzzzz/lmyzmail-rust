from __future__ import annotations

import os
import socket
from pathlib import Path
from typing import Any, cast

import pytest
from test_minecraft_authenticated_commands import _read_packets
from test_minecraft_email_prompt import _chat_frame, _frame
from test_minecraft_login import (
    _begin_login,
    _encode_varint,
    _LoginJavaOracleRuntime,
    _packet_id,
    _read_login_prefix,
    _read_packet,
)
from test_minecraft_main_menu_actions import _click_frame, _open_menu, _snapshot_packets
from test_minecraft_main_menu_lifecycle import _read_lifecycle_packets
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

_GOLDEN = "managed-minecraft-logout-confirmation-v2"
_EMAIL_IDS = (0x02, 0x02, 0x02)
_OPEN_CONFIRM_IDS = (0x32, 0x2F, 0x30, 0x2F, 0x2F, 0x2D, 0x30)
_CANCEL_IDS = (0x32, 0x2F, 0x30, 0x2E, 0x2F, 0x2F, 0x2D, 0x30)
_CONFIRM_IDS = (0x32, 0x2F, 0x30, 0x2E, 0x2F, 0x2F, 0x40)


def _required_disconnect_wire() -> bytes:
    reason = '{"text":"§aLogged out. See you!","color":"red"}'.encode()
    packet = b"\x40" + _encode_varint(len(reason)) + reason
    return _frame(b"\x00" + packet)


def _capture_logout_confirmation(target: RuntimeTarget) -> dict[str, Any]:
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
        connection.sendall(_click_frame(1, 34, 21))
        first_open = _read_lifecycle_packets(
            connection, _OPEN_CONFIRM_IDS, "first logout confirmation"
        )

        connection.sendall(_click_frame(2, 15, 22))
        cancel = _read_lifecycle_packets(connection, _CANCEL_IDS, "logout cancellation")

        connection.sendall(_click_frame(3, 34, 23))
        second_open = _read_lifecycle_packets(
            connection, _OPEN_CONFIRM_IDS, "second logout confirmation"
        )

        connection.sendall(_click_frame(4, 11, 24))
        required_disconnect = _required_disconnect_wire()
        if target.target_kind == "java-oracle":
            confirm = []
            while connection.recv(1, socket.MSG_PEEK):
                confirm.append(_read_packet(connection, compression=True))
                if len(confirm) > len(_CONFIRM_IDS):
                    raise ProtocolError("Java logout emitted unexpected trailing packets")
            actual_ids = tuple(_packet_id(packet)[0] for packet in confirm)
            if actual_ids != _CONFIRM_IDS[: len(actual_ids)] or len(confirm) == len(
                _CONFIRM_IDS
            ):
                raise ProtocolError(
                    f"Java logout race was not a premature expected prefix: {actual_ids!r}"
                )
        else:
            confirm = _read_lifecycle_packets(connection, _CONFIRM_IDS, "logout confirmation")
            if confirm[-1].wire != required_disconnect:
                raise ProtocolError("candidate logout did not flush the required Disconnect Play")
            if connection.recv(1) != b"":
                raise ProtocolError("candidate logout did not close after Disconnect Play")

    return {
        "username": _USERNAME.decode(),
        "email": _EMAIL,
        "world_packet_count_through_position": world_packet_count,
        "world_expanded_bytes_through_position": world_expanded_bytes,
        "first_open_packets": _snapshot_packets(_OPEN_CONFIRM_IDS, first_open),
        "cancel_packets": _snapshot_packets(_CANCEL_IDS, cancel),
        "second_open_packets": _snapshot_packets(_OPEN_CONFIRM_IDS, second_open),
        "confirmed_connection_closed": True,
        "confirm_terminal_contract": {
            "expected_packet_ids": list(_CONFIRM_IDS),
            "java_behavior": "normalized-premature-prefix-then-eof",
            "candidate_requirement": "complete-sequence-then-eof",
        },
        "required_disconnect_frame": bytes_snapshot(required_disconnect),
        "terminal_policy": "approved-difference:minecraft-logout-flush-before-close",
    }


cast(Any, _capture_logout_confirmation).__lmyzmail_contract__ = {
    "protocol": "minecraft-1.8.9",
    "flow": "logout confirmation opens, cancels back, reopens, and disconnects",
    "protocol_version": 47,
    "compression_threshold": 256,
    "clicks": [
        {"window_id": 1, "slot": 34, "action_number": 21, "result": "open-confirm"},
        {"window_id": 2, "slot": 15, "action_number": 22, "result": "cancel"},
        {"window_id": 3, "slot": 34, "action_number": 23, "result": "open-confirm"},
        {"window_id": 4, "slot": 11, "action_number": 24, "result": "disconnect"},
    ],
    "response_packet_ids": {
        "open-confirm": list(_OPEN_CONFIRM_IDS),
        "cancel": list(_CANCEL_IDS),
        "confirm": list(_CONFIRM_IDS),
    },
    "behavior_difference": "minecraft-logout-flush-before-close",
    "normalization": "minecraft-logout-close-race-v1 only on the confirmed terminal prefix",
}

SCENARIOS = (
    Scenario(
        "minecraft/logout-confirmation",
        _capture_logout_confirmation,
        normalizers=("minecraft-logout-close-race-v1",),
    ),
)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(900)
def test_frozen_java_minecraft_logout_confirmation_golden(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    golden = repository / "blackbox/golden/java" / _GOLDEN
    record = os.environ.get("LMYZMAIL_RECORD_JAVA_GOLDEN") == "1"
    runner = DifferentialRunner(
        repository,
        golden,
        _GOLDEN,
        record_java=record,
    )
    with _LoginJavaOracleRuntime(tmp_path / "java-minecraft-logout-confirmation") as oracle:
        target = _OracleTarget(oracle)
        if record:
            runner.record_from_java(SCENARIOS, target)
        else:
            runner.verify_java(SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(900)
def test_rust_candidate_minecraft_logout_confirmation_matches_golden() -> None:
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
