from __future__ import annotations

import email
import hashlib
import json
import os
import re
import stat
import struct
import time
import zipfile
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass
from email import policy
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import psycopg
import pytest
from test_minecraft_authenticated_commands import _read_packets
from test_minecraft_email_prompt import _chat_frame
from test_minecraft_folder_gui import _open_folder, _open_menu
from test_minecraft_login import (
    _begin_login,
    _decode_varint_bytes,
    _encode_varint,
    _LoginJavaOracleRuntime,
    _packet_id,
    _read_login_prefix,
    _read_packet,
    _read_string,
)
from test_minecraft_main_menu_actions import _click_frame
from test_minecraft_password_auth import _EMAIL, _GOOD_PASSWORD, _SUCCESS_IDS, _USERNAME
from test_minecraft_post_static import _POST_STATIC_IDS, _read_expected_packets
from test_minecraft_render_settings import _read_response_packets
from test_minecraft_render_size_commands import _DIRECT_UPDATE_IDS
from test_minecraft_static_play import (
    _INITIAL_PLAY_IDS,
    _STATIC_PLAY_IDS,
    _drain_to_player_position,
    _OracleTarget,
)

from lmyzmail_blackbox.differential import DifferentialRunner, RuntimeTarget, Scenario
from lmyzmail_blackbox.errors import ProtocolError
from lmyzmail_blackbox.runtime import CandidateRuntime

_GOLDEN = "managed-minecraft-mail-view-v7"
_FILE_NAME = "minecraft-mail-view-v2.eml"
_FIXTURE_RELATIVE_PATH = Path("blackbox/fixtures/minecraft/mail-view-v2.eml")
_FIXTURE_SOURCE_SHA256 = "e4f436c626cefe7c9a5a317ed646c99b9e37c3817bac3e8b0b3fa0ff2f875ba0"
_FIXTURE_MESSAGE_SHA256 = "d7fb8eb206756a46e4ebd6f71a7bb08938af8655a95b91dc81c9145c6a362230"
_NATIVE_MEMBER = "BOOT-INF/classes/native/linux-x86_64/libasciiart.so"
_NATIVE_SIZE = 31_626_672
_NATIVE_SHA256 = "7eaff9429e056f867955236eadbb0474caa2c2492fa34a86ba479181fb53c505"
_FONT_FIXTURES = (
    (
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
        "ae7b7855e115a5966d8b1b3f80f254ccc117ec86f9965e202ee2940453837280",
    ),
    (
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"),
        "c805f9436dbc268644c1d9584f01a601a653e028e08fd74b9b949f6cf8304d88",
    ),
)
_SCHEDULED_PLAY_IDS = frozenset((0x03, 0x18))
_MAX_CAPTURE_PACKETS = 512
_MAX_SKIPPED_PACKETS = 128
_MAX_CAPTURE_WIRE_BYTES = 8 * 1024 * 1024
_MAX_CAPTURE_EXPANDED_BYTES = 16 * 1024 * 1024
_PHASE_TIMEOUT_SECONDS = 90.0
_LOGIN_READ_TIMEOUT_SECONDS = 60.0
_PACKET_READ_TIMEOUT_SECONDS = 5.0
_MAPS_X = 2
_MAPS_Y = 2
_MAP_TILE_SIZE = 128
_RENDER_COMPLETE_MARKER = "barrier item"
_CLOSE_COMPLETE_MARKER = "Mail view closed."
_INITIAL_PAGE_PATTERN = re.compile(r"(?:^|\s)Page 1/(\d+)(?:\s|$)")
_LEGACY_INDEX_ROWS = (
    (
        1301,
        0,
        "legacy-root.eml",
        "<legacy-root@sender.example>",
        "Legacy root mail",
        "2024-01-01 00:00:00+00",
        "2024-01-01 00:00:01+00",
        561,
        False,
    ),
    (
        1302,
        1,
        "legacy-shard-1.eml",
        "<legacy-shard-1@sender.example>",
        "Legacy shard one",
        "2024-01-02 00:00:00+00",
        "2024-01-02 00:00:01+00",
        567,
        False,
    ),
    (
        1303,
        2,
        "legacy-shard-2.eml",
        "<legacy-shard-2@sender.example>",
        "Legacy shard attachment",
        "2024-01-03 00:00:00+00",
        "2024-01-03 00:00:01+00",
        869,
        True,
    ),
)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _digest_snapshot(value: bytes) -> dict[str, Any]:
    return {"length": len(value), "sha256": _sha256(value)}


def _fixture_message(repository: Path) -> bytes:
    fixture = repository / _FIXTURE_RELATIVE_PATH
    source = fixture.read_bytes()
    if _sha256(source) != _FIXTURE_SOURCE_SHA256:
        raise ProtocolError("mail-view fixture source SHA-256 is not attested")
    if b"\r" in source or not source.endswith(b"\n"):
        raise ProtocolError("mail-view fixture source must use canonical LF with a final newline")
    message = source.replace(b"\n", b"\r\n")
    if _sha256(message) != _FIXTURE_MESSAGE_SHA256:
        raise ProtocolError("mail-view CRLF message SHA-256 is not attested")
    return message


def _verify_file(path: Path, expected_sha256: str, label: str) -> None:
    try:
        value = path.read_bytes()
    except OSError as error:
        raise ProtocolError(f"mail-view input unavailable ({label}): {error}") from error
    digest = _sha256(value)
    if digest != expected_sha256:
        raise ProtocolError(
            f"mail-view input drift ({label}): {digest}; expected {expected_sha256}"
        )


def _verify_render_inputs(repository: Path, target: RuntimeTarget) -> None:
    _fixture_message(repository)
    for path, expected in _FONT_FIXTURES:
        _verify_file(path, expected, f"font {path}")

    if target.target_kind != "java-oracle":
        return
    runtime = getattr(target, "runtime", None)
    paths = getattr(runtime, "paths", None)
    oracle_jar = getattr(paths, "oracle_jar", None)
    if not isinstance(oracle_jar, Path):
        raise ProtocolError("Java mail-view target does not expose its frozen oracle JAR")
    try:
        with zipfile.ZipFile(oracle_jar) as archive:
            native = archive.read(_NATIVE_MEMBER)
    except (OSError, KeyError, zipfile.BadZipFile) as error:
        raise ProtocolError(f"Java mail renderer native payload is unavailable: {error}") from error
    if len(native) != _NATIVE_SIZE or _sha256(native) != _NATIVE_SHA256:
        raise ProtocolError("Java mail renderer native payload is not the frozen binary")


def _write_atomic(path: Path, value: bytes) -> None:
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    resolved_parent = parent.resolve(strict=True)
    if path.parent != resolved_parent:
        raise ProtocolError("mail-view Maildir parent traversed a symbolic link")
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise ProtocolError("mail-view Maildir target is not a regular file")

    temporary = parent / f".{path.name}.{os.getpid()}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        stream = os.fdopen(descriptor, "wb", closefd=True)
        descriptor = -1
        with stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        directory = os.open(parent, directory_flags)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass

    status = path.lstat()
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
        raise ProtocolError("mail-view Maildir atomic target is not a regular file")
    if _sha256(path.read_bytes()) != _FIXTURE_MESSAGE_SHA256:
        raise ProtocolError("mail-view Maildir write failed its post-rename SHA-256 check")


def _seed_mail_view_fixture(target: RuntimeTarget) -> None:
    if target.workspace is None or target.ports is None:
        raise RuntimeError("Minecraft capture target is not running")

    repository = Path(__file__).resolve().parents[2]
    message = _fixture_message(repository)
    mail_path = target.workspace / "maildir" / _EMAIL / "inbox" / _FILE_NAME
    mail_root = (target.workspace / "maildir").resolve()
    expected_path = mail_root / _EMAIL / "inbox" / _FILE_NAME
    if mail_path != expected_path or not mail_path.is_relative_to(mail_root):
        raise ProtocolError("mail-view Maildir fixture escaped the isolated mail root")
    _write_atomic(mail_path, message)

    with psycopg.connect(
        host="127.0.0.1",
        port=target.ports.postgres,
        user="lmyzmail_test",
        dbname="lmyzmail",
        autocommit=False,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO email_index (
                    id, mailbox_address, folder, subdirectory, file_name, message_id,
                    from_address, to_addresses, subject, received_at, indexed_at,
                    size_bytes, has_attachments
                ) VALUES (
                    %s, %s, 'inbox', %s, %s, %s,
                    'sender@sender.example', %s, %s, %s, %s, %s, %s
                )
                ON CONFLICT (id) DO UPDATE SET
                    mailbox_address=EXCLUDED.mailbox_address,
                    folder=EXCLUDED.folder,
                    subdirectory=EXCLUDED.subdirectory,
                    file_name=EXCLUDED.file_name,
                    message_id=EXCLUDED.message_id,
                    from_address=EXCLUDED.from_address,
                    to_addresses=EXCLUDED.to_addresses,
                    subject=EXCLUDED.subject,
                    received_at=EXCLUDED.received_at,
                    indexed_at=EXCLUDED.indexed_at,
                    size_bytes=EXCLUDED.size_bytes,
                    has_attachments=EXCLUDED.has_attachments
                """,
                [
                    (
                        row_id,
                        _EMAIL,
                        subdirectory,
                        file_name,
                        message_id,
                        _EMAIL,
                        subject,
                        received_at,
                        indexed_at,
                        size_bytes,
                        has_attachments,
                    )
                    for (
                        row_id,
                        subdirectory,
                        file_name,
                        message_id,
                        subject,
                        received_at,
                        indexed_at,
                        size_bytes,
                        has_attachments,
                    ) in _LEGACY_INDEX_ROWS
                ],
            )
            cursor.execute(
                "DELETE FROM email_label_assignment "
                "WHERE mailbox_address=%s AND folder='inbox' AND email_file_name=%s",
                (_EMAIL, _FILE_NAME),
            )
            cursor.execute(
                "DELETE FROM starred_email "
                "WHERE mailbox_address=%s AND folder='inbox' AND email_file_name=%s",
                (_EMAIL, _FILE_NAME),
            )
            cursor.execute(
                "DELETE FROM email_index "
                "WHERE id=%s OR (mailbox_address=%s AND folder='inbox' AND file_name=%s)",
                (6900, _EMAIL, _FILE_NAME),
            )
            cursor.execute(
                """
                INSERT INTO email_index (
                    id, mailbox_address, folder, subdirectory, file_name, message_id,
                    from_address, to_addresses, subject, received_at, indexed_at,
                    size_bytes, has_attachments
                ) VALUES (
                    %s, %s, 'inbox', NULL, %s, %s,
                    %s, %s, %s, %s, %s, %s, true
                )
                """,
                (
                    6900,
                    _EMAIL,
                    _FILE_NAME,
                    "<minecraft-mail-view-v2@sender.example>",
                    "render-fixture@sender.example",
                    _EMAIL,
                    "Minecraft composite map wall fixture",
                    "2099-02-01 12:00:00+00",
                    "2099-02-01 12:00:01+00",
                    len(message),
                ),
            )
        connection.commit()


def _chat_payload(packet: Any) -> tuple[str, int] | None:
    packet_id, cursor = _packet_id(packet)
    if packet_id != 0x02:
        return None
    component, cursor = _read_string(packet.payload, cursor, max_units=32767)
    if cursor + 1 != len(packet.payload):
        raise ProtocolError("Minecraft chat packet had an invalid position field")
    try:
        parsed = json.loads(component)
    except json.JSONDecodeError as error:
        raise ProtocolError("Minecraft chat packet did not contain JSON") from error
    if not isinstance(parsed, dict) or not isinstance(parsed.get("text"), str):
        raise ProtocolError("Minecraft chat component did not contain text")
    return parsed["text"], int(packet.payload[cursor])


class _CaptureFailure(ProtocolError):
    def __init__(self, code: str, label: str, detail: str) -> None:
        self.code = code
        self.label = label
        super().__init__(f"mail-view {code} during {label}: {detail}")


@dataclass(frozen=True, slots=True)
class _PhaseCapture:
    packets: tuple[Any, ...]
    skipped_scheduled_packets: int
    wire_bytes: int
    expanded_bytes: int


@dataclass(frozen=True, slots=True)
class _MapUpdate:
    map_id: int
    scale: int
    icon_count: int
    columns: int
    rows: int
    x_offset: int
    z_offset: int
    pixels: bytes


_FAILURE_CHAT_MARKERS = (
    ("Mail rendering not available", "renderer-unavailable"),
    ("Server busy rendering", "renderer-busy"),
    ("Failed to read email:", "maildir-index-read-error"),
    ("Render error:", "native-render-error"),
)


def _read_until_chat(
    connection: Any,
    marker: str,
    *,
    label: str,
) -> _PhaseCapture:
    packets: list[Any] = []
    skipped = 0
    wire_bytes = 0
    expanded_bytes = 0
    deadline = time.monotonic() + _PHASE_TIMEOUT_SECONDS
    for _ in range(_MAX_CAPTURE_PACKETS):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _CaptureFailure("phase-timeout", label, f"marker {marker!r} was not reached")
        connection.settimeout(min(_PACKET_READ_TIMEOUT_SECONDS, remaining))
        try:
            packet = _read_packet(connection, compression=True)
        except TimeoutError as error:
            raise _CaptureFailure(
                "phase-timeout", label, f"timed out waiting for marker {marker!r}"
            ) from error
        except OSError as error:
            raise _CaptureFailure("disconnect", label, str(error)) from error
        except ProtocolError as error:
            raise _CaptureFailure("protocol-error", label, str(error)) from error

        wire_bytes += len(packet.wire)
        expanded_bytes += len(packet.payload)
        if wire_bytes > _MAX_CAPTURE_WIRE_BYTES:
            raise _CaptureFailure(
                "wire-byte-budget", label, f"exceeded {_MAX_CAPTURE_WIRE_BYTES} bytes"
            )
        if expanded_bytes > _MAX_CAPTURE_EXPANDED_BYTES:
            raise _CaptureFailure(
                "expanded-byte-budget",
                label,
                f"exceeded {_MAX_CAPTURE_EXPANDED_BYTES} bytes",
            )

        try:
            packet_id = _packet_id(packet)[0]
            chat = _chat_payload(packet)
        except ProtocolError as error:
            raise _CaptureFailure("protocol-error", label, str(error)) from error
        if packet_id in _SCHEDULED_PLAY_IDS:
            skipped += 1
            if skipped > _MAX_SKIPPED_PACKETS:
                raise _CaptureFailure(
                    "scheduled-packet-budget",
                    label,
                    f"exceeded {_MAX_SKIPPED_PACKETS} scheduled packets",
                )
            continue
        packets.append(packet)
        if chat is None:
            continue
        for failure_marker, code in _FAILURE_CHAT_MARKERS:
            if failure_marker in chat[0]:
                raise _CaptureFailure(code, label, chat[0])
        if chat[1] == 0 and marker in chat[0]:
            return _PhaseCapture(tuple(packets), skipped, wire_bytes, expanded_bytes)
    raise _CaptureFailure(
        "packet-budget",
        label,
        f"marker {marker!r} was not reached within {_MAX_CAPTURE_PACKETS} packets",
    )


def _map_data(packet: Any) -> _MapUpdate:
    packet_id, cursor = _packet_id(packet)
    if packet_id != 0x34:
        raise ProtocolError("map snapshot received a non-map packet")
    map_id, cursor = _decode_varint_bytes(packet.payload, cursor)
    if cursor >= len(packet.payload):
        raise ProtocolError("Map Data ended before scale")
    scale = packet.payload[cursor]
    cursor += 1
    if scale != 0:
        raise ProtocolError(f"Map Data scale was {scale}, expected zero")
    icon_count, cursor = _decode_varint_bytes(packet.payload, cursor)
    if icon_count != 0:
        raise ProtocolError(f"Map Data icon count was {icon_count}, expected zero")
    if cursor >= len(packet.payload):
        raise ProtocolError("Map Data ended before column count")
    columns = int(packet.payload[cursor])
    cursor += 1
    if columns != _MAP_TILE_SIZE or cursor + 3 > len(packet.payload):
        raise ProtocolError("Map Data was not a full-width 128x128 tile update")
    rows = int(packet.payload[cursor])
    x_offset = int(packet.payload[cursor + 1])
    z_offset = int(packet.payload[cursor + 2])
    cursor += 3
    if rows != _MAP_TILE_SIZE or x_offset != 0 or z_offset != 0:
        raise ProtocolError("Map Data was not a full 128x128 tile at offset 0,0")
    pixel_count, cursor = _decode_varint_bytes(packet.payload, cursor)
    if pixel_count != _MAP_TILE_SIZE * _MAP_TILE_SIZE:
        raise ProtocolError(f"Map Data had {pixel_count} pixels, expected 16384")
    end = cursor + pixel_count
    if end != len(packet.payload):
        raise ProtocolError("Map Data pixel length did not consume packet")
    return _MapUpdate(
        map_id,
        scale,
        icon_count,
        columns,
        rows,
        x_offset,
        z_offset,
        packet.payload[cursor:end],
    )


def _block_change(packet: Any) -> dict[str, int]:
    packet_id, cursor = _packet_id(packet)
    if packet_id != 0x23 or cursor + 8 > len(packet.payload):
        raise ProtocolError("Block Change packet was truncated")
    packed = int.from_bytes(packet.payload[cursor : cursor + 8], "big")
    cursor += 8
    block_state, cursor = _decode_varint_bytes(packet.payload, cursor)
    if cursor != len(packet.payload):
        raise ProtocolError("Block Change packet had trailing bytes")
    x = packed >> 38
    z = packed & 0x3FFFFFF
    if x & 0x2000000:
        x -= 0x4000000
    if z & 0x2000000:
        z -= 0x4000000
    return {"x": x, "y": (packed >> 26) & 0xFFF, "z": z, "state": block_state}


def _spawn_object(packet: Any) -> dict[str, int]:
    packet_id, cursor = _packet_id(packet)
    if packet_id != 0x0E:
        raise ProtocolError("Spawn Object parser received another packet")
    entity_id, cursor = _decode_varint_bytes(packet.payload, cursor)
    if cursor + 19 > len(packet.payload):
        raise ProtocolError("Spawn Object packet was truncated")
    object_type = int(packet.payload[cursor])
    x, y, z = struct.unpack_from(">iii", packet.payload, cursor + 1)
    pitch = int(packet.payload[cursor + 13])
    yaw = int(packet.payload[cursor + 14])
    object_data = struct.unpack_from(">i", packet.payload, cursor + 15)[0]
    cursor += 19
    if object_data > 0:
        if cursor + 6 > len(packet.payload):
            raise ProtocolError("Spawn Object velocity was truncated")
        cursor += 6
    if cursor != len(packet.payload):
        raise ProtocolError("Spawn Object packet had trailing bytes")
    return {
        "entity_id": entity_id,
        "type": object_type,
        "x_fixed": x,
        "y_fixed": y,
        "z_fixed": z,
        "pitch": pitch,
        "yaw": yaw,
        "object_data": object_data,
    }


def _entity_metadata_map(packet: Any) -> dict[str, int]:
    packet_id, cursor = _packet_id(packet)
    if packet_id != 0x1C:
        raise ProtocolError("Entity Metadata parser received another packet")
    entity_id, cursor = _decode_varint_bytes(packet.payload, cursor)
    expected_tail_size = 8
    if cursor + expected_tail_size != len(packet.payload):
        raise ProtocolError("item-frame Entity Metadata had an unexpected size")
    header = packet.payload[cursor]
    item_id = int.from_bytes(packet.payload[cursor + 1 : cursor + 3], "big")
    count = packet.payload[cursor + 3]
    map_id = int.from_bytes(packet.payload[cursor + 4 : cursor + 6], "big")
    nbt_end = packet.payload[cursor + 6]
    terminator = packet.payload[cursor + 7]
    if (header, item_id, count, nbt_end, terminator) != (0xA8, 358, 1, 0, 0x7F):
        raise ProtocolError("item-frame Entity Metadata did not contain the expected filled map")
    return {"entity_id": entity_id, "map_id": map_id}


def _destroy_entities(packet: Any) -> list[int]:
    packet_id, cursor = _packet_id(packet)
    if packet_id != 0x13:
        raise ProtocolError("Destroy Entities parser received another packet")
    count, cursor = _decode_varint_bytes(packet.payload, cursor)
    entities: list[int] = []
    for _ in range(count):
        entity_id, cursor = _decode_varint_bytes(packet.payload, cursor)
        entities.append(entity_id)
    if cursor != len(packet.payload):
        raise ProtocolError("Destroy Entities packet had trailing bytes")
    return entities


def _score_update(packet: Any) -> dict[str, Any]:
    packet_id, cursor = _packet_id(packet)
    if packet_id != 0x3C:
        raise ProtocolError("Update Score parser received another packet")
    name, cursor = _read_string(packet.payload, cursor, max_units=40)
    if cursor >= len(packet.payload):
        raise ProtocolError("Update Score packet ended before action")
    action = int(packet.payload[cursor])
    cursor += 1
    objective, cursor = _read_string(packet.payload, cursor, max_units=16)
    value: int | None = None
    if action != 1:
        value, cursor = _decode_varint_bytes(packet.payload, cursor)
    if cursor != len(packet.payload):
        raise ProtocolError("Update Score packet had trailing bytes")
    return {"name": name, "action": action, "objective": objective, "value": value}


def _wall_topology(
    capture: _PhaseCapture,
) -> tuple[dict[str, Any], tuple[int, ...], tuple[int, ...]]:
    blocks = [_block_change(packet) for packet in capture.packets if _packet_id(packet)[0] == 0x23]
    spawns = [_spawn_object(packet) for packet in capture.packets if _packet_id(packet)[0] == 0x0E]
    metadata = [
        _entity_metadata_map(packet) for packet in capture.packets if _packet_id(packet)[0] == 0x1C
    ]
    expected_tiles = _MAPS_X * _MAPS_Y
    if len(blocks) != expected_tiles * 2 or len(spawns) != expected_tiles:
        raise ProtocolError("map wall did not create exactly two blocks and one frame per tile")
    if len(metadata) != expected_tiles:
        raise ProtocolError("map wall did not assign exactly one map to every frame")
    entity_ids = tuple(spawn["entity_id"] for spawn in spawns)
    map_ids = tuple(item["map_id"] for item in metadata)
    if len(set(entity_ids)) != expected_tiles or len(set(map_ids)) != expected_tiles:
        raise ProtocolError("map wall allocated duplicate entity or map IDs")
    if entity_ids != tuple(range(entity_ids[0], entity_ids[0] + expected_tiles)):
        raise ProtocolError("map wall entity IDs were not contiguous row-major allocations")
    if map_ids != tuple(range(map_ids[0], map_ids[0] + expected_tiles)):
        raise ProtocolError("map wall map IDs were not contiguous row-major allocations")
    if tuple(item["entity_id"] for item in metadata) != entity_ids:
        raise ProtocolError("map wall metadata topology did not match spawned frame order")
    if any(item["type"] != 71 for item in spawns):
        raise ProtocolError("map wall spawned a non-item-frame object")
    states = Counter(item["state"] for item in blocks)
    if states != Counter({0: expected_tiles, 2480: expected_tiles}):
        raise ProtocolError("map wall block setup was not one quartz support plus air per tile")
    map_updates = [_map_data(packet) for packet in capture.packets if _packet_id(packet)[0] == 0x34]
    first_by_map: dict[int, _MapUpdate] = {}
    for update in map_updates:
        first_by_map.setdefault(update.map_id, update)
    if set(first_by_map) != set(map_ids) or any(
        set(update.pixels) != {34} for update in first_by_map.values()
    ):
        raise ProtocolError("map wall did not initialize every tile with palette color 34")
    entity_base = entity_ids[0]
    map_base = map_ids[0]
    return (
        {
            "blocks": blocks,
            "frames": [
                {**spawn, "entity_id": spawn["entity_id"] - entity_base} for spawn in spawns
            ],
            "map_assignments": [
                {
                    "entity_id": item["entity_id"] - entity_base,
                    "map_id": item["map_id"] - map_base,
                }
                for item in metadata
            ],
        },
        map_ids,
        entity_ids,
    )


def _page_snapshot(capture: _PhaseCapture, map_ids: tuple[int, ...]) -> dict[str, Any]:
    updates = [_map_data(packet) for packet in capture.packets if _packet_id(packet)[0] == 0x34]
    expected = set(map_ids)
    if any(update.map_id not in expected for update in updates):
        raise ProtocolError("map page updated an ID outside the active wall")
    last_by_id = {update.map_id: update for update in updates}
    if set(last_by_id) != expected:
        raise ProtocolError("map page did not update every tile in the active wall")
    update_counts = Counter(update.map_id for update in updates)
    counts_per_tile = set(update_counts.values())
    if len(counts_per_tile) != 1 or next(iter(counts_per_tile)) not in {1, 2}:
        raise ProtocolError("map page did not update every tile an equal bounded number of times")

    page_width = _MAPS_X * _MAP_TILE_SIZE
    page_height = _MAPS_Y * _MAP_TILE_SIZE
    page = bytearray(page_width * page_height)
    tiles: list[dict[str, Any]] = []
    map_base = map_ids[0]
    for index, map_id in enumerate(map_ids):
        update = last_by_id[map_id]
        row, column = divmod(index, _MAPS_X)
        for pixel_row in range(_MAP_TILE_SIZE):
            source = pixel_row * _MAP_TILE_SIZE
            destination = (row * _MAP_TILE_SIZE + pixel_row) * page_width + column * _MAP_TILE_SIZE
            page[destination : destination + _MAP_TILE_SIZE] = update.pixels[
                source : source + _MAP_TILE_SIZE
            ]
        tiles.append(
            {
                "row": row,
                "column": column,
                "relative_map_id": map_id - map_base,
                "pixels": _digest_snapshot(update.pixels),
            }
        )
    return {
        "map_update_count": len(updates),
        "width": page_width,
        "height": page_height,
        "pixels": _digest_snapshot(bytes(page)),
        "palette_counts": [[color, count] for color, count in sorted(Counter(page).items())],
        "tiles": tiles,
    }


def _snapshot_capture(
    capture: _PhaseCapture | list[Any],
    *,
    map_base: int | None = None,
    entity_base: int | None = None,
    unordered_blocks: bool = False,
) -> dict[str, Any]:
    if isinstance(capture, list):
        phase = _PhaseCapture(
            tuple(capture),
            0,
            sum(len(packet.wire) for packet in capture),
            sum(len(packet.payload) for packet in capture),
        )
    else:
        phase = capture
    snapshots: list[dict[str, Any]] = []
    unordered_block_snapshots: list[dict[str, Any]] = []
    packet_counts: Counter[int] = Counter()
    for packet in phase.packets:
        packet_id = _packet_id(packet)[0]
        packet_counts[packet_id] += 1
        snapshot: dict[str, Any] = {
            "packet_id": packet_id,
            "data_length": packet.data_length,
        }
        if packet_id == 0x34:
            update = _map_data(packet)
            if map_base is None:
                raise ProtocolError("Map Data snapshot is missing its relative ID base")
            snapshot["map"] = {
                "relative_map_id": update.map_id - map_base,
                "scale": update.scale,
                "icon_count": update.icon_count,
                "columns": update.columns,
                "rows": update.rows,
                "x_offset": update.x_offset,
                "z_offset": update.z_offset,
                "pixels": _digest_snapshot(update.pixels),
            }
        elif packet_id == 0x0E:
            spawn = _spawn_object(packet)
            if entity_base is None:
                raise ProtocolError("Spawn Object snapshot is missing its relative ID base")
            snapshot["spawn"] = {**spawn, "entity_id": spawn["entity_id"] - entity_base}
        elif packet_id == 0x1C:
            metadata = _entity_metadata_map(packet)
            if entity_base is None or map_base is None:
                raise ProtocolError("Entity Metadata snapshot is missing relative ID bases")
            snapshot["map_item"] = {
                "entity_id": metadata["entity_id"] - entity_base,
                "map_id": metadata["map_id"] - map_base,
            }
        elif packet_id == 0x13:
            if entity_base is None:
                raise ProtocolError("Destroy Entities snapshot is missing its relative ID base")
            snapshot["destroy_entities"] = [
                entity_id - entity_base for entity_id in _destroy_entities(packet)
            ]
        elif packet_id == 0x23:
            snapshot["block_change"] = _block_change(packet)
        elif packet_id == 0x3C:
            snapshot["score"] = _score_update(packet)
            snapshot["frame"] = _digest_snapshot(packet.wire)
        else:
            snapshot["frame"] = _digest_snapshot(packet.wire)
        chat = _chat_payload(packet)
        if chat is not None:
            snapshot["chat"] = {"text": chat[0], "position": chat[1]}
        if unordered_blocks and packet_id == 0x23:
            unordered_block_snapshots.append(snapshot)
        else:
            snapshots.append(snapshot)
    unordered_block_snapshots.sort(
        key=lambda item: tuple(item["block_change"][key] for key in ("x", "y", "z", "state"))
    )
    return {
        "packet_counts": [[packet_id, count] for packet_id, count in sorted(packet_counts.items())],
        "skipped_scheduled_packets": phase.skipped_scheduled_packets,
        "wire_bytes": phase.wire_bytes,
        "expanded_bytes": phase.expanded_bytes,
        "packets": snapshots,
        "unordered_block_changes": unordered_block_snapshots,
    }


def _plain_chat_texts(capture: _PhaseCapture) -> list[str]:
    return [text for text, _ in _plain_chats(capture)]


def _plain_chats(capture: _PhaseCapture) -> list[tuple[str, int]]:
    result: list[tuple[str, int]] = []
    for packet in capture.packets:
        chat = _chat_payload(packet)
        if chat is not None:
            result.append((re.sub(r"§.", "", chat[0]), chat[1]))
    return result


def _page_count(capture: _PhaseCapture) -> int:
    chat_texts = _plain_chat_texts(capture)
    totals = {
        int(match.group(1)) for text in chat_texts for match in _INITIAL_PAGE_PATTERN.finditer(text)
    }
    if len(totals) != 1:
        raise ProtocolError(
            "initial mail render did not report one consistent page count; "
            f"sanitized fixture chats={chat_texts!r}"
        )
    count = totals.pop()
    if count < 3 or count > 32:
        raise ProtocolError(f"mail-view fixture rendered {count} pages, expected 3..32")
    _assert_page_status(capture, 1, count, "initial mail render")
    return count


def _assert_page_status(
    capture: _PhaseCapture,
    page: int,
    total_pages: int,
    label: str,
) -> None:
    expected = f"Page {page}/{total_pages}"
    if not any(position == 2 and expected in text for text, position in _plain_chats(capture)):
        raise ProtocolError(f"{label} did not send exact action-bar state {expected!r}")
    score_names = [
        re.sub(r"§.", "", _score_update(packet)["name"])
        for packet in capture.packets
        if _packet_id(packet)[0] == 0x3C
    ]
    if not any(f"Page: {page}/{total_pages}" in name for name in score_names):
        raise ProtocolError(f"{label} did not send the exact scoreboard page state")


def _capture_page_command(
    connection: Any,
    command: str,
    *,
    page: int,
    total_pages: int,
    label: str,
) -> _PhaseCapture:
    connection.sendall(_chat_frame(command))
    capture = _read_until_chat(connection, "Page ", label=label)
    expected = f"Page {page}/{total_pages}"
    if (expected, 0) not in _plain_chats(capture):
        raise ProtocolError(f"{label} did not report the exact page state {expected!r}")
    _assert_page_status(capture, page, total_pages, label)
    return capture


def _assert_no_map_updates(capture: _PhaseCapture, label: str) -> None:
    if any(_packet_id(packet)[0] == 0x34 for packet in capture.packets):
        raise ProtocolError(f"{label} unexpectedly mutated map pixels")
    if tuple(_packet_id(packet)[0] for packet in capture.packets) != (0x02,):
        raise ProtocolError(f"{label} emitted packets other than its single boundary chat")


def _close_snapshot(
    capture: _PhaseCapture,
    *,
    entity_ids: tuple[int, ...],
    setup_blocks: list[dict[str, int]],
    map_base: int,
) -> dict[str, Any]:
    destroy_packets = [packet for packet in capture.packets if _packet_id(packet)[0] == 0x13]
    if len(destroy_packets) != 1 or tuple(_destroy_entities(destroy_packets[0])) != entity_ids:
        raise ProtocolError("mail close did not destroy exactly the active frame entity set")
    restored = [
        _block_change(packet) for packet in capture.packets if _packet_id(packet)[0] == 0x23
    ]
    if Counter((item["x"], item["y"], item["z"]) for item in restored) != Counter(
        (item["x"], item["y"], item["z"]) for item in setup_blocks
    ):
        raise ProtocolError("mail close did not restore every wall block position exactly once")
    packet_counts = Counter(_packet_id(packet)[0] for packet in capture.packets)
    if packet_counts[0x2F] != 9:
        raise ProtocolError("mail close did not restore the nine default hotbar slots")
    held_packets = [packet for packet in capture.packets if _packet_id(packet)[0] == 0x09]
    if len(held_packets) != 1:
        raise ProtocolError("mail close did not send exactly one held-slot restore")
    _, held_cursor = _packet_id(held_packets[0])
    if held_cursor + 1 != len(held_packets[0].payload) or held_packets[0].payload[held_cursor] != 0:
        raise ProtocolError("mail close did not select the default hotbar slot zero")
    score_names = [
        _score_update(packet)["name"] for packet in capture.packets if _packet_id(packet)[0] == 0x3C
    ]
    for required in ("Player:", "Email:", "Render:", "Font:", "/menu"):
        if not any(required in name for name in score_names):
            raise ProtocolError(
                f"mail close did not restore authenticated scoreboard line {required!r}"
            )
    return _snapshot_capture(
        capture,
        map_base=map_base,
        entity_base=entity_ids[0],
        unordered_blocks=True,
    )


def _capture_minecraft_mail_view(target: RuntimeTarget) -> dict[str, Any]:
    if target.ports is None:
        raise RuntimeError("Minecraft capture target is not running")
    repository = Path(__file__).resolve().parents[2]
    _verify_render_inputs(repository, target)
    _seed_mail_view_fixture(target)
    with _begin_login(target.ports.minecraft, _USERNAME) as connection:
        connection.settimeout(_LOGIN_READ_TIMEOUT_SECONDS)
        _read_login_prefix(connection)
        connection.settimeout(_PACKET_READ_TIMEOUT_SECONDS)
        _read_expected_packets(connection, _INITIAL_PLAY_IDS, "initial PLAY")
        world_packet_count, world_expanded_bytes = _drain_to_player_position(connection)
        _read_expected_packets(connection, _STATIC_PLAY_IDS, "static PLAY")
        _read_expected_packets(connection, _POST_STATIC_IDS, "post-static PLAY")

        connection.sendall(_chat_frame(_EMAIL))
        _read_packets(connection, (0x02, 0x02, 0x02), "email prompt")
        connection.sendall(_chat_frame(_GOOD_PASSWORD))
        _read_packets(connection, _SUCCESS_IDS, "password success")

        connection.sendall(_chat_frame("/mail rendersize 2 2 16"))
        render_size_packets = _read_response_packets(
            connection,
            _DIRECT_UPDATE_IDS,
            "mail-view render size",
        )

        menu_window_id, _ = _open_menu(connection)
        folder_window_id, _ = _open_folder(
            connection,
            menu_window_id=menu_window_id,
            slot=10,
            action_number=71,
            folder="inbox",
        )
        connection.sendall(_click_frame(folder_window_id, 0, 72))
        initial = _read_until_chat(
            connection,
            _RENDER_COMPLETE_MARKER,
            label="initial mail render",
        )
        total_pages = _page_count(initial)
        wall, map_ids, entity_ids = _wall_topology(initial)
        page_one = _page_snapshot(initial, map_ids)

        connection.sendall(_chat_frame("/mail prev"))
        first_boundary = _read_until_chat(
            connection,
            "Already on the first page",
            label="mail first-page boundary",
        )
        _assert_no_map_updates(first_boundary, "first-page boundary")

        page_two_first = _capture_page_command(
            connection,
            "/mail next",
            page=2,
            total_pages=total_pages,
            label="mail page-two transition",
        )
        page_two_first_pixels = _page_snapshot(page_two_first, map_ids)
        page_one_replay = _capture_page_command(
            connection,
            "/mail prev",
            page=1,
            total_pages=total_pages,
            label="mail page-one replay",
        )
        page_one_replay_pixels = _page_snapshot(page_one_replay, map_ids)
        if page_one_replay_pixels["pixels"] != page_one["pixels"]:
            raise ProtocolError("mail previous-page replay changed page-one pixels")

        pages: list[dict[str, Any]] = [page_one]
        page_transitions: list[dict[str, Any]] = []
        for page_number in range(2, total_pages + 1):
            transition = _capture_page_command(
                connection,
                "/mail next",
                page=page_number,
                total_pages=total_pages,
                label=f"mail canonical page {page_number}",
            )
            pixels = _page_snapshot(transition, map_ids)
            if page_number == 2 and pixels["pixels"] != page_two_first_pixels["pixels"]:
                raise ProtocolError("mail next-page replay changed page-two pixels")
            pages.append(pixels)
            page_transitions.append(
                {
                    "page": page_number,
                    "protocol": _snapshot_capture(
                        transition,
                        map_base=map_ids[0],
                        entity_base=entity_ids[0],
                    ),
                }
            )

        connection.sendall(_chat_frame("/mail next"))
        last_boundary = _read_until_chat(
            connection,
            "Already on the last page",
            label="mail last-page boundary",
        )
        _assert_no_map_updates(last_boundary, "last-page boundary")

        connection.sendall(_chat_frame("/mail close"))
        close = _read_until_chat(
            connection,
            _CLOSE_COMPLETE_MARKER,
            label="mail close",
        )
        close_snapshot = _close_snapshot(
            close,
            entity_ids=entity_ids,
            setup_blocks=wall["blocks"],
            map_base=map_ids[0],
        )
        restored_menu_window_id, restored_menu = _open_menu(connection)

    return {
        "username": _USERNAME.decode(),
        "email": _EMAIL,
        "fixture": {
            "file_name": _FILE_NAME,
            "source_sha256": _FIXTURE_SOURCE_SHA256,
            "message": _digest_snapshot(_fixture_message(repository)),
            "render_maps": [_MAPS_X, _MAPS_Y],
            "font_px": 16,
        },
        "world_packet_count_through_position": world_packet_count,
        "world_expanded_bytes_through_position": world_expanded_bytes,
        "render_size_packets": _snapshot_capture(render_size_packets),
        "total_pages": total_pages,
        "wall": wall,
        "initial_render": {
            "page": page_one,
            "protocol": _snapshot_capture(
                initial,
                map_base=map_ids[0],
                entity_base=entity_ids[0],
            ),
        },
        "first_page_boundary": _snapshot_capture(first_boundary),
        "page_two_first": {
            "page": page_two_first_pixels,
            "protocol": _snapshot_capture(
                page_two_first,
                map_base=map_ids[0],
                entity_base=entity_ids[0],
            ),
        },
        "page_one_replay": {
            "page": page_one_replay_pixels,
            "protocol": _snapshot_capture(
                page_one_replay,
                map_base=map_ids[0],
                entity_base=entity_ids[0],
            ),
        },
        "pages": pages,
        "page_transitions": page_transitions,
        "last_page_boundary": _snapshot_capture(last_boundary),
        "close": close_snapshot,
        "authenticated_menu_after_close": {
            "window_id": restored_menu_window_id,
            "protocol": _snapshot_capture(restored_menu),
        },
    }


cast(Any, _capture_minecraft_mail_view).__lmyzmail_contract__ = {
    "protocol": "minecraft-1.8.9",
    "flow": "authenticated Maildir email to paged map wall and close recovery",
    "protocol_version": 47,
    "compression_threshold": 256,
    "fixture": {
        "path": str(_FIXTURE_RELATIVE_PATH).replace("\\", "/"),
        "source_sha256": _FIXTURE_SOURCE_SHA256,
        "message_sha256": _FIXTURE_MESSAGE_SHA256,
        "content_type": "multipart/mixed",
        "parts": ["plain", "html", "cid-png", "attachment-with-html-sensitive-name"],
        "minimum_pages": 3,
        "maps_x": 2,
        "max_page_maps_y": 2,
        "font_px": 16,
        "font_fixture": {
            "sans": "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "sans_sha256": "ae7b7855e115a5966d8b1b3f80f254ccc117ec86f9965e202ee2940453837280",
            "monospace": "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
            "monospace_sha256": "c805f9436dbc268644c1d9584f01a601a653e028e08fd74b9b949f6cf8304d88",
        },
        "java_native": {
            "jar_member": _NATIVE_MEMBER,
            "size": _NATIVE_SIZE,
            "sha256": _NATIVE_SHA256,
        },
        "simd_mode": "SCALAR",
    },
    "budgets": {
        "login_read_timeout_seconds": _LOGIN_READ_TIMEOUT_SECONDS,
        "phase_timeout_seconds": _PHASE_TIMEOUT_SECONDS,
        "packets": _MAX_CAPTURE_PACKETS,
        "scheduled_packets": _MAX_SKIPPED_PACKETS,
        "wire_bytes": _MAX_CAPTURE_WIRE_BYTES,
        "expanded_bytes": _MAX_CAPTURE_EXPANDED_BYTES,
    },
    "capture": [
        "stable-frame-length-and-sha256-plus-exact-relative-dynamic-packet-semantics",
        "row-major-reassembled-page-pixel-length-and-sha256",
        "map-palette-histograms",
        "map-wall-setup",
        "all-pages",
        "first-and-last-page-boundaries",
        "page-one-and-page-two-replay",
        "teardown-and-authenticated-hotbar-scoreboard-restore",
        "authenticated-menu-after-close",
    ],
    "normalization": [
        "exclude scheduled 0x03/0x18 PLAY ticks with explicit bounded counts",
        "relative map/entity IDs",
        "sort only HashMap-backed teardown block restoration",
    ],
    "failure_classes": [
        "renderer-unavailable",
        "renderer-busy",
        "maildir-index-read-error",
        "native-render-error",
        "phase-timeout",
        "disconnect",
        "packet-budget",
        "scheduled-packet-budget",
        "wire-byte-budget",
        "expanded-byte-budget",
        "protocol-error",
        "golden-mismatch",
    ],
}


SCENARIOS = (Scenario("minecraft/mail-view", _capture_minecraft_mail_view),)


class _MailViewJavaOracleRuntime(_LoginJavaOracleRuntime):
    def _application_arguments(self) -> list[str]:
        return [
            *super()._application_arguments(),
            "--botmail.mailrender.simd-mode=SCALAR",
        ]


@contextmanager
def _renderer_capture_lock() -> Any:
    import fcntl

    path = Path("/tmp/lmyzmail-blackbox-mail-render.lock")  # noqa: S108
    flags = os.O_RDWR | os.O_CREAT
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            raise ProtocolError("mail renderer serialization lock is not a regular file")
        if status.st_uid != os.geteuid() or stat.S_IMODE(status.st_mode) & 0o077:
            raise ProtocolError("mail renderer serialization lock has unsafe ownership or mode")
        with os.fdopen(descriptor, "rb+", closefd=True) as stream:
            descriptor = -1
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            yield
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _require(condition: object, detail: str) -> None:
    if not condition:
        raise AssertionError(detail)


def _unit_packet(packet_id: int, body: bytes) -> Any:
    payload = _encode_varint(packet_id) + body
    return SimpleNamespace(wire=payload, payload=payload, data_length=0)


def _unit_map_packet(map_id: int, color: int, *, scale: int = 0) -> Any:
    pixels = bytes((color,)) * (_MAP_TILE_SIZE * _MAP_TILE_SIZE)
    return _unit_packet(
        0x34,
        b"".join(
            (
                _encode_varint(map_id),
                bytes((scale,)),
                _encode_varint(0),
                bytes((_MAP_TILE_SIZE, _MAP_TILE_SIZE, 0, 0)),
                _encode_varint(len(pixels)),
                pixels,
            )
        ),
    )


def _unit_block_packet(x: int, y: int, z: int, state: int) -> Any:
    packed = ((x & 0x3FFFFFF) << 38) | ((y & 0xFFF) << 26) | (z & 0x3FFFFFF)
    return _unit_packet(0x23, packed.to_bytes(8, "big") + _encode_varint(state))


def _unit_spawn_packet(entity_id: int, index: int) -> Any:
    return _unit_packet(
        0x0E,
        _encode_varint(entity_id)
        + bytes((71,))
        + struct.pack(">iiiBBi", 1000 + index, 2000, 3000, 0, 0, 0),
    )


def _unit_metadata_packet(entity_id: int, map_id: int) -> Any:
    return _unit_packet(
        0x1C,
        _encode_varint(entity_id)
        + b"\xa8"
        + (358).to_bytes(2, "big")
        + b"\x01"
        + map_id.to_bytes(2, "big")
        + b"\x00\x7f",
    )


def _unit_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return _encode_varint(len(encoded)) + encoded


def _unit_chat_packet(text: str, position: int) -> Any:
    component = json.dumps({"text": text}, ensure_ascii=False, separators=(",", ":"))
    return _unit_packet(0x02, _unit_string(component) + bytes((position,)))


def _unit_score_packet(name: str, value: int) -> Any:
    return _unit_packet(
        0x3C,
        _unit_string(name) + b"\x00" + _unit_string("lmyz") + _encode_varint(value),
    )


def test_mail_view_v2_fixture_contract(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    message = _fixture_message(repository)
    parsed = cast(Any, email.message_from_bytes(message, policy=policy.default))
    parts = list(parsed.walk())
    _require(parsed.get_content_type() == "multipart/mixed", "fixture root is not multipart/mixed")
    _require(
        sum(part.get_content_type() == "text/plain" for part in parts) == 1,
        "fixture does not contain exactly one plain alternative",
    )
    html = [part for part in parts if part.get_content_type() == "text/html"]
    _require(len(html) == 1 and "<table>" in html[0].get_content(), "fixture HTML is missing")
    cid = [part for part in parts if part.get("Content-ID") == "<fixture-image>"]
    _require(
        len(cid) == 1 and cid[0].get_payload(decode=True).startswith(b"\x89PNG\r\n\x1a\n"),
        "fixture CID PNG is missing or invalid",
    )
    attachments = [part for part in parts if part.get_content_disposition() == "attachment"]
    _require(
        len(attachments) == 1
        and attachments[0].get_filename() == "status<&>.txt"
        and attachments[0].get_payload(decode=True) == b"fixed-attachment-v2\n",
        "fixture attachment contract changed",
    )

    target = tmp_path / "maildir" / _FILE_NAME
    _write_atomic(target, message)
    _require(target.read_bytes() == message, "atomic fixture write changed bytes")
    _require(stat.S_IMODE(target.stat().st_mode) == 0o600, "atomic fixture mode is not 0600")
    symlink = tmp_path / "maildir" / "symlink.eml"
    symlink.symlink_to(target)
    with pytest.raises(ProtocolError, match="not a regular file"):
        _write_atomic(symlink, message)


def test_mail_view_v2_map_wall_and_page_contract() -> None:
    packets: list[Any] = []
    for index in range(_MAPS_X * _MAPS_Y):
        packets.extend(
            (
                _unit_block_packet(index, 70, 0, 2480),
                _unit_block_packet(index, 70, 1, 0),
                _unit_spawn_packet(100 + index, index),
                _unit_metadata_packet(100 + index, 10 + index),
                _unit_map_packet(10 + index, 34),
            )
        )
    packets.extend(_unit_map_packet(10 + index, index) for index in range(4))
    capture = _PhaseCapture(
        tuple(packets),
        0,
        sum(len(packet.wire) for packet in packets),
        sum(len(packet.payload) for packet in packets),
    )
    wall, map_ids, entity_ids = _wall_topology(capture)
    _require(map_ids == (10, 11, 12, 13), "map IDs are not row-major")
    _require(entity_ids == (100, 101, 102, 103), "entity IDs are not row-major")
    _require(
        [frame["entity_id"] for frame in wall["frames"]] == [0, 1, 2, 3],
        "entity IDs were not normalized relative to the allocation base",
    )

    page = _page_snapshot(capture, map_ids)
    expected = bytearray()
    for row in range(_MAPS_Y * _MAP_TILE_SIZE):
        colors = (0, 1) if row < _MAP_TILE_SIZE else (2, 3)
        expected.extend(bytes((colors[0],)) * _MAP_TILE_SIZE)
        expected.extend(bytes((colors[1],)) * _MAP_TILE_SIZE)
    _require(page["map_update_count"] == 8, "wall and page update count changed")
    _require(
        page["pixels"]["sha256"] == _sha256(bytes(expected)),
        "2x2 tiles were not reassembled in row-major order",
    )
    _require(
        page["palette_counts"] == [[0, 16384], [1, 16384], [2, 16384], [3, 16384]],
        "logical-page palette histogram changed",
    )
    with pytest.raises(ProtocolError, match="scale"):
        _map_data(_unit_map_packet(10, 0, scale=1))


def test_mail_view_v2_page_state_contract() -> None:
    packets = (
        _unit_chat_packet("§7📧 Page §f1§7/§f7 §8| §f◀ Prev §8| §f✖ Close", 2),
        _unit_score_packet("§2§r§fPage: §a1§7/§f7", 5),
        _unit_chat_packet("§7Page §f1§7/§f7 §7— Use hotbar arrows", 0),
    )
    capture = _PhaseCapture(
        packets,
        0,
        sum(len(packet.wire) for packet in packets),
        sum(len(packet.payload) for packet in packets),
    )
    _require(_page_count(capture) == 7, "initial page count was not derived consistently")

    inconsistent = _PhaseCapture(
        (*packets, _unit_chat_packet("§7Page §f1§7/§f8", 0)),
        0,
        0,
        0,
    )
    with pytest.raises(ProtocolError, match="one consistent page count"):
        _page_count(inconsistent)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(900)
def test_frozen_java_minecraft_mail_view_golden(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    golden = repository / "blackbox/golden/java" / _GOLDEN
    record = os.environ.get("LMYZMAIL_RECORD_JAVA_GOLDEN") == "1"
    runner = DifferentialRunner(
        repository,
        golden,
        _GOLDEN,
        record_java=record,
    )
    with _renderer_capture_lock():
        with _MailViewJavaOracleRuntime(tmp_path / "java-minecraft-mail-view-v2") as oracle:
            target = _OracleTarget(oracle)
            if record:
                runner.record_from_java(SCENARIOS, target)
            else:
                runner.verify_java(SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(900)
def test_rust_candidate_minecraft_mail_view_matches_golden() -> None:
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
            "--lmyzmail.mailrender.simd-mode=SCALAR",
        )
    )
    with _renderer_capture_lock():
        with runtime as candidate:
            DifferentialRunner(
                repository,
                repository / "blackbox/golden/java" / _GOLDEN,
                _GOLDEN,
            ).verify_candidate(SCENARIOS, candidate)
