from __future__ import annotations

import json
import os
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
    _read_login_prefix,
)
from test_minecraft_main_menu_lifecycle import _play_frame
from test_minecraft_password_auth import _EMAIL, _GOOD_PASSWORD, _SUCCESS_IDS, _USERNAME
from test_minecraft_post_static import _POST_STATIC_IDS, _read_expected_packets
from test_minecraft_render_settings import _read_response_packets
from test_minecraft_static_play import (
    _INITIAL_PLAY_IDS,
    _STATIC_PLAY_IDS,
    _drain_to_player_position,
    _OracleTarget,
)

from lmyzmail_blackbox.differential import DifferentialRunner, RuntimeTarget, Scenario
from lmyzmail_blackbox.runtime import CandidateRuntime
from lmyzmail_blackbox.snapshots import bytes_snapshot

_GOLDEN = "managed-minecraft-draft-editing-v2"
_SIGN_POSITIONS = {
    "to": (2, 161, 3),
    "cc": (4, 161, 3),
    "bcc": (6, 161, 3),
    "subject": (8, 161, 3),
}
_SIGN_VALUES = {
    "to": ("to@example.test", "", "", ""),
    "cc": ("cc@example.test", "", "", ""),
    "bcc": ("bcc@example.test", "", "", ""),
    "subject": ("Subject ", "two", " lines", ""),
}
_BODY_PAGES = ("First page", "Second page \u2603")
_SIGN_RESPONSE_IDS = (0x02, 0x33)
_BOOK_RESPONSE_IDS = (0x02,)
_DRAFT_RESPONSE_IDS = (0x02,) * 6
_RESTORED_SUCCESS_IDS = (0x02,) * 13 + (0x33,) * 4 + (0x2F,) + (0x3B, 0x3B, 0x3D) + (0x3C,) * 10
_CLEAR_RESPONSE_IDS = (0x02,) + (0x33,) * 4 + (0x2F,)


def _packed_position(x: int, y: int, z: int) -> int:
    return ((x & 0x3FFFFFF) << 38) | ((y & 0xFFF) << 26) | (z & 0x3FFFFFF)


def _update_sign_frame(position: tuple[int, int, int], lines: tuple[str, str, str, str]) -> bytes:
    payload = bytearray(b"\x12")
    payload.extend(struct.pack(">Q", _packed_position(*position)))
    for text in lines:
        component = json.dumps({"text": text}, ensure_ascii=False, separators=(",", ":"))
        encoded = component.encode()
        payload.extend(_encode_varint(len(encoded)))
        payload.extend(encoded)
    return _play_frame(bytes(payload))


def _nbt_string(value: str) -> bytes:
    encoded = value.encode()
    return struct.pack(">H", len(encoded)) + encoded


def _book_edit_frame(pages: tuple[str, ...]) -> bytes:
    nbt = bytearray(b"\x0a\x00\x00")
    nbt.extend(b"\x09")
    nbt.extend(_nbt_string("pages"))
    nbt.extend(b"\x08")
    nbt.extend(struct.pack(">i", len(pages)))
    for page in pages:
        nbt.extend(_nbt_string(page))
    nbt.extend(b"\x00")

    book = struct.pack(">hbh", 386, 1, 0) + bytes(nbt)
    channel = b"MC|BEdit"
    payload = b"\x17" + _encode_varint(len(channel)) + channel + book
    return _play_frame(payload)


def _snapshot(expected_ids: tuple[int, ...], packets: list[Any]) -> list[dict[str, Any]]:
    return [
        {"packet_id": packet_id, "frame": bytes_snapshot(packet.wire)}
        for packet_id, packet in zip(expected_ids, packets, strict=True)
    ]


def _bootstrap(connection: Any) -> tuple[int, int]:
    connection.settimeout(60.0)
    _read_login_prefix(connection)
    _read_expected_packets(connection, _INITIAL_PLAY_IDS, "initial PLAY")
    world_packet_count, world_expanded_bytes = _drain_to_player_position(connection)
    _read_expected_packets(connection, _STATIC_PLAY_IDS, "static PLAY")
    _read_expected_packets(connection, _POST_STATIC_IDS, "post-static PLAY")
    return world_packet_count, world_expanded_bytes


def _authenticate(connection: Any, success_ids: tuple[int, ...]) -> list[Any]:
    connection.sendall(_chat_frame(_EMAIL))
    _read_packets(connection, (0x02, 0x02, 0x02), "email prompt")
    connection.sendall(_chat_frame(_GOOD_PASSWORD))
    return _read_response_packets(connection, success_ids, "password success")


def _capture_minecraft_draft_editing(target: RuntimeTarget) -> dict[str, Any]:
    if target.ports is None:
        raise RuntimeError("Minecraft capture target is not running")

    edits: list[dict[str, Any]] = []
    with _begin_login(target.ports.minecraft, _USERNAME) as connection:
        first_world_count, first_world_bytes = _bootstrap(connection)
        _authenticate(connection, _SUCCESS_IDS)

        for field in ("to", "cc", "bcc", "subject"):
            connection.sendall(_update_sign_frame(_SIGN_POSITIONS[field], _SIGN_VALUES[field]))
            packets = _read_response_packets(connection, _SIGN_RESPONSE_IDS, f"{field} edit")
            edits.append(
                {
                    "field": field,
                    "position": list(_SIGN_POSITIONS[field]),
                    "lines": list(_SIGN_VALUES[field]),
                    "packets": _snapshot(_SIGN_RESPONSE_IDS, packets),
                }
            )

        connection.sendall(_book_edit_frame(_BODY_PAGES))
        book_packets = _read_response_packets(connection, _BOOK_RESPONSE_IDS, "book edit")
        connection.sendall(_chat_frame("/draft"))
        first_summary = _read_response_packets(
            connection, _DRAFT_RESPONSE_IDS, "edited draft summary"
        )

    with _begin_login(target.ports.minecraft, _USERNAME) as connection:
        second_world_count, second_world_bytes = _bootstrap(connection)
        restored = _authenticate(connection, _RESTORED_SUCCESS_IDS)
        connection.sendall(_chat_frame("/draft"))
        restored_summary = _read_response_packets(
            connection, _DRAFT_RESPONSE_IDS, "restored draft summary"
        )
        connection.sendall(_chat_frame("/clear"))
        cleared = _read_response_packets(connection, _CLEAR_RESPONSE_IDS, "clear restored draft")
        connection.sendall(_chat_frame("/draft"))
        empty_summary = _read_response_packets(
            connection, _DRAFT_RESPONSE_IDS, "cleared draft summary"
        )

    return {
        "username": _USERNAME.decode(),
        "email": _EMAIL,
        "first_connection": {
            "world_packet_count_through_position": first_world_count,
            "world_expanded_bytes_through_position": first_world_bytes,
            "sign_edits": edits,
            "book_edit": {
                "pages": list(_BODY_PAGES),
                "packets": _snapshot(_BOOK_RESPONSE_IDS, book_packets),
            },
            "draft_summary": _snapshot(_DRAFT_RESPONSE_IDS, first_summary),
        },
        "reconnected": {
            "world_packet_count_through_position": second_world_count,
            "world_expanded_bytes_through_position": second_world_bytes,
            "authentication_and_restore": _snapshot(_RESTORED_SUCCESS_IDS, restored),
            "draft_summary": _snapshot(_DRAFT_RESPONSE_IDS, restored_summary),
            "clear": _snapshot(_CLEAR_RESPONSE_IDS, cleared),
            "empty_summary": _snapshot(_DRAFT_RESPONSE_IDS, empty_summary),
        },
    }


cast(Any, _capture_minecraft_draft_editing).__lmyzmail_contract__ = {
    "protocol": "minecraft-1.8.9",
    "flow": "authenticated draft sign/book editing and same-process reconnect restore",
    "protocol_version": 47,
    "compression_threshold": 256,
    "inputs": {
        "sign_packet_id": 0x12,
        "book_packet_id": 0x17,
        "book_channel": "MC|BEdit",
        "book_item_id": 386,
    },
    "sign_positions": {key: list(value) for key, value in _SIGN_POSITIONS.items()},
    "body_pages": list(_BODY_PAGES),
    "reconnect_identity": "same offline-mode username and UUID in one process",
    "normalization": "exclude scheduled 0x03/0x18 PLAY ticks covered by scheduled-play",
}


SCENARIOS = (Scenario("minecraft/draft-editing", _capture_minecraft_draft_editing),)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(900)
def test_frozen_java_minecraft_draft_editing_golden(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    golden = repository / "blackbox/golden/java" / _GOLDEN
    record = os.environ.get("LMYZMAIL_RECORD_JAVA_GOLDEN") == "1"
    runner = DifferentialRunner(repository, golden, _GOLDEN, record_java=record)
    with _LoginJavaOracleRuntime(tmp_path / "java-minecraft-draft-editing") as oracle:
        target = _OracleTarget(oracle)
        if record:
            runner.record_from_java(SCENARIOS, target)
        else:
            runner.verify_java(SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(900)
def test_rust_candidate_minecraft_draft_editing_matches_golden() -> None:
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
