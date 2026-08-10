from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import psycopg
import pytest
from test_minecraft_authenticated_commands import _read_packets
from test_minecraft_email_prompt import _chat_frame
from test_minecraft_login import (
    _begin_login,
    _LoginJavaOracleRuntime,
    _packet_id,
    _read_login_prefix,
    _read_packet,
)
from test_minecraft_main_menu_actions import _click_frame, _snapshot_packets
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

_GOLDEN = "managed-minecraft-folder-gui-v3"
_MENU_IDS = (0x2D, 0x30)
_FOLDER_OPEN_IDS = (0x32, 0x2F, 0x30, 0x02, 0x2E, 0x2F, 0x2F, 0x2D, 0x30)
_PAGE_IDS = (0x32, 0x2F, 0x30, 0x30)
_BACK_IDS = (0x32, 0x2F, 0x30, 0x2F, 0x2F, 0x2D, 0x30)
_SCHEDULED_PLAY_IDS = frozenset((0x03, 0x18))
_MAX_SKIPPED_SCHEDULED_PACKETS = 64
_FOLDERS = (("inbox", 10), ("sent", 12), ("trash", 14), ("spam", 16))


def _seed_folder_fixture(target: RuntimeTarget) -> None:
    if target.ports is None:
        raise RuntimeError("Minecraft capture target is not running")
    rows: list[tuple[object, ...]] = []
    base = datetime(2024, 2, 1, tzinfo=UTC)
    for index in range(37):
        subject: str | None = f"Inbox message {index:02d}"
        sender: str | None = f"sender-{index:02d}@sender.example"
        if index == 34:
            subject = "Unicode subject " + ("x" * 15) + "\U0001f4e7tail"
        elif index == 35:
            subject = None
            sender = None
        elif index == 36:
            subject = "Attachment newest message"
        rows.append(
            (
                6000 + index,
                _EMAIL,
                "inbox",
                0,
                f"minecraft-inbox-{index:02d}.eml",
                f"<minecraft-inbox-{index:02d}@sender.example>",
                sender,
                _EMAIL,
                subject,
                base + timedelta(hours=index),
                base + timedelta(hours=index, seconds=1),
                512 + index,
                index == 36,
            )
        )
    for offset, folder in enumerate(("sent", "spam"), start=100):
        rows.append(
            (
                6000 + offset,
                _EMAIL,
                folder,
                0,
                f"minecraft-{folder}.eml",
                f"<minecraft-{folder}@sender.example>",
                f"{folder}-sender@sender.example",
                _EMAIL,
                f"{folder.title()} fixture message",
                base + timedelta(days=offset),
                base + timedelta(days=offset, seconds=1),
                700 + offset,
                folder == "spam",
            )
        )

    with psycopg.connect(
        host="127.0.0.1",
        port=target.ports.postgres,
        user="lmyzmail_test",
        dbname="lmyzmail",
        autocommit=True,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM email_label_assignment WHERE mailbox_address=%s",
                (_EMAIL,),
            )
            cursor.execute("DELETE FROM starred_email WHERE mailbox_address=%s", (_EMAIL,))
            cursor.execute("DELETE FROM email_index WHERE mailbox_address=%s", (_EMAIL,))
            cursor.executemany(
                """
                INSERT INTO email_index (
                    id, mailbox_address, folder, subdirectory, file_name, message_id,
                    from_address, to_addresses, subject, received_at, indexed_at,
                    size_bytes, has_attachments
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                """,
                rows,
            )


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


def _window_id(packet: Any, *, expected_packet_id: int) -> int:
    packet_id, cursor = _packet_id(packet)
    if packet_id != expected_packet_id or cursor >= len(packet.payload):
        raise ProtocolError("Minecraft GUI packet did not contain a window ID")
    return int(packet.payload[cursor])


def _open_menu(connection: Any) -> tuple[int, list[Any]]:
    connection.sendall(_chat_frame("/menu"))
    packets = _read_response_packets(connection, _MENU_IDS, "folder menu")
    return _window_id(packets[0], expected_packet_id=0x2D), packets


def _open_folder(
    connection: Any,
    *,
    menu_window_id: int,
    slot: int,
    action_number: int,
    folder: str,
) -> tuple[int, list[Any]]:
    connection.sendall(_click_frame(menu_window_id, slot, action_number))
    packets = _read_response_packets(connection, _FOLDER_OPEN_IDS, f"open {folder}")
    return _window_id(packets[-2], expected_packet_id=0x2D), packets


def _capture_minecraft_folder_gui(target: RuntimeTarget) -> dict[str, Any]:
    if target.ports is None:
        raise RuntimeError("Minecraft capture target is not running")
    _seed_folder_fixture(target)
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

        menu_window_id, initial_menu = _open_menu(connection)
        observations: list[dict[str, Any]] = []
        action_number = 41
        for folder, slot in _FOLDERS:
            folder_window_id, opening = _open_folder(
                connection,
                menu_window_id=menu_window_id,
                slot=slot,
                action_number=action_number,
                folder=folder,
            )
            action_number += 1
            observation: dict[str, Any] = {
                "folder": folder,
                "menu_window_id": menu_window_id,
                "folder_window_id": folder_window_id,
                "opening_packets": _snapshot_packets(_FOLDER_OPEN_IDS, opening),
            }

            if folder == "inbox":
                connection.sendall(_click_frame(folder_window_id, 52, action_number))
                action_number += 1
                next_page = _read_response_packets(connection, _PAGE_IDS, "inbox next page")
                connection.sendall(_click_frame(folder_window_id, 46, action_number))
                action_number += 1
                previous_page = _read_response_packets(
                    connection, _PAGE_IDS, "inbox previous page"
                )
                observation["next_page_packets"] = _snapshot_packets(_PAGE_IDS, next_page)
                observation["previous_page_packets"] = _snapshot_packets(
                    _PAGE_IDS, previous_page
                )
                observation["pagination_window_id"] = _window_id(
                    next_page[-1], expected_packet_id=0x30
                )

            connection.sendall(_click_frame(folder_window_id, 49, action_number))
            action_number += 1
            back = _read_response_packets(connection, _BACK_IDS, f"back from {folder}")
            menu_window_id = _window_id(back[-2], expected_packet_id=0x2D)
            observation["back_packets"] = _snapshot_packets(_BACK_IDS, back)
            observation["returned_menu_window_id"] = menu_window_id
            observations.append(observation)

    return {
        "username": _USERNAME.decode(),
        "email": _EMAIL,
        "world_packet_count_through_position": world_packet_count,
        "world_expanded_bytes_through_position": world_expanded_bytes,
        "initial_menu_packets": _snapshot_packets(_MENU_IDS, initial_menu),
        "folders": observations,
    }


cast(Any, _capture_minecraft_folder_gui).__lmyzmail_contract__ = {
    "protocol": "minecraft-1.8.9",
    "flow": "authenticated Inbox/Sent/Trash/Spam folder GUI and pagination",
    "protocol_version": 47,
    "compression_threshold": 256,
    "fixture": {
        "inbox_messages": 37,
        "inbox_page_size": 36,
        "sent_messages": 1,
        "trash_messages": 0,
        "spam_messages": 1,
        "covers": [
            "received-at-descending",
            "null-subject-and-from",
            "java-utf16-truncation",
            "attachment-enchantment-glow",
        ],
    },
    "menu_slots": {"inbox": 10, "sent": 12, "trash": 14, "spam": 16},
    "navigation_slots": {"previous": 46, "back": 49, "next": 52},
    "pagination": "same-window-id WindowItems refresh",
    "normalization": "exclude scheduled 0x03/0x18 PLAY ticks covered by scheduled-play",
}


SCENARIOS = (Scenario("minecraft/folder-gui", _capture_minecraft_folder_gui),)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(900)
def test_frozen_java_minecraft_folder_gui_golden(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    golden = repository / "blackbox/golden/java" / _GOLDEN
    record = os.environ.get("LMYZMAIL_RECORD_JAVA_GOLDEN") == "1"
    runner = DifferentialRunner(
        repository,
        golden,
        _GOLDEN,
        record_java=record,
    )
    with _LoginJavaOracleRuntime(tmp_path / "java-minecraft-folder-gui") as oracle:
        target = _OracleTarget(oracle)
        if record:
            runner.record_from_java(SCENARIOS, target)
        else:
            runner.verify_java(SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(900)
def test_rust_candidate_minecraft_folder_gui_matches_golden() -> None:
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
