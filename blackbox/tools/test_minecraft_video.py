from __future__ import annotations

import hashlib
import os
import time
import zipfile
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from typing import Any, cast

import pytest
from test_minecraft_authenticated_commands import _read_packets
from test_minecraft_email_prompt import _chat_frame
from test_minecraft_folder_gui import _open_menu, _window_id
from test_minecraft_login import (
    _begin_login,
    _decode_varint_bytes,
    _LoginJavaOracleRuntime,
    _packet_id,
    _read_login_prefix,
    _read_packet,
)
from test_minecraft_mail_view import (
    _CaptureFailure,
    _chat_payload,
    _destroy_entities,
    _digest_snapshot,
    _MapUpdate,
    _PhaseCapture,
    _plain_chat_texts,
    _snapshot_capture,
    _unit_chat_packet,
    _wall_topology,
)
from test_minecraft_mail_view import (
    _read_until_chat as _read_until_chat_raw,
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

_GOLDEN = "managed-minecraft-video-v7"
_VIDEO_MEMBER = "BOOT-INF/classes/skibidi_toilet_episode_1.mp4"
_VIDEO_SIZE = 15_048_248
_VIDEO_SHA256 = "0e76229bb77ebcf471aec692fa34709cfbbe3dc192127a852a518e34bdd0ecc7"
_CANDIDATE_VIDEO = Path("crates/lmyzmail/assets/skibidi_toilet_episode_1.mp4")
_SCHEDULED_PLAY_IDS = frozenset((0x03, 0x18))
_MAPS_X = 2
_MAPS_Y = 2
_MAP_PIXELS = 128 * 128
_MAX_PHASE_PACKETS = 1024
_MAX_PHASE_WIRE_BYTES = 32 * 1024 * 1024
_MAX_PHASE_EXPANDED_BYTES = 64 * 1024 * 1024
_VIDEO_FAILURE_MARKERS = (
    "video not available",
    "Could not load video file",
    "video error:",
)
_COMMANDS = (
    ("invalid-block-width", "/video play width=nope"),
    ("block-width-limit", "/video play width=65"),
    ("block-fps-limit", "/video play fps=21"),
    ("unknown-block-option", "/video play wat=1"),
    ("too-many-block-positionals", "/video play 4 1 1.2 extra"),
    ("map-width-limit", "/video play map width=11"),
    ("invalid-map-fps", "/video play map fps=nope"),
    ("no-video-stop", "/video stop"),
    ("no-video-pause", "/video pause"),
    ("video-usage", "/video nonsense"),
)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _video_resource(target: RuntimeTarget) -> bytes:
    repository = Path(__file__).resolve().parents[2]
    if target.target_kind == "java-oracle":
        runtime = getattr(target, "runtime", None)
        paths = getattr(runtime, "paths", None)
        oracle_jar = getattr(paths, "oracle_jar", None)
        if not isinstance(oracle_jar, Path):
            raise ProtocolError("Java video target does not expose its frozen oracle JAR")
        try:
            with zipfile.ZipFile(oracle_jar) as archive:
                value = archive.read(_VIDEO_MEMBER)
        except (OSError, KeyError, zipfile.BadZipFile) as error:
            raise ProtocolError(f"Java video resource is unavailable: {error}") from error
    else:
        path = repository / _CANDIDATE_VIDEO
        try:
            value = path.read_bytes()
        except OSError as error:
            raise ProtocolError(f"Rust video resource is unavailable: {error}") from error
    if len(value) != _VIDEO_SIZE or _sha256(value) != _VIDEO_SHA256:
        raise ProtocolError("Minecraft video resource does not match the frozen MP4")
    return value


@contextmanager
def _authenticated_connection(target: RuntimeTarget) -> Any:
    if target.ports is None:
        raise RuntimeError("Minecraft video target is not running")
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
        yield connection, world_packet_count, world_expanded_bytes


def _phase(packets: list[Any], skipped: int = 0) -> _PhaseCapture:
    return _PhaseCapture(
        tuple(packets),
        skipped,
        sum(len(packet.wire) for packet in packets),
        sum(len(packet.payload) for packet in packets),
    )


def _read_until_chat(connection: Any, marker: str, *, label: str) -> _PhaseCapture:
    """Keep scheduled PLAY ticks out of phase accounting as well as packet lists."""
    raw = _read_until_chat_raw(connection, marker, label=label)
    return _phase(list(raw.packets))


def _video_map_data(packet: Any) -> _MapUpdate:
    packet_id, cursor = _packet_id(packet)
    if packet_id != 0x34:
        raise ProtocolError("video map snapshot received a non-map packet")
    map_id, cursor = _decode_varint_bytes(packet.payload, cursor)
    if cursor >= len(packet.payload):
        raise ProtocolError("video Map Data ended before scale")
    scale = int(packet.payload[cursor])
    cursor += 1
    if scale != 0:
        raise ProtocolError(f"video Map Data scale was {scale}, expected zero")
    icon_count, cursor = _decode_varint_bytes(packet.payload, cursor)
    if icon_count != 0:
        raise ProtocolError(f"video Map Data icon count was {icon_count}, expected zero")
    if cursor + 4 > len(packet.payload):
        raise ProtocolError("video Map Data ended before its rectangle")
    columns = int(packet.payload[cursor])
    rows = int(packet.payload[cursor + 1])
    x_offset = int(packet.payload[cursor + 2])
    z_offset = int(packet.payload[cursor + 3])
    cursor += 4
    if columns < 1 or rows < 1:
        raise ProtocolError("video Map Data contained an empty rectangle")
    pixel_count, cursor = _decode_varint_bytes(packet.payload, cursor)
    if pixel_count != columns * rows:
        raise ProtocolError(
            f"video Map Data had {pixel_count} pixels for a {columns}x{rows} rectangle"
        )
    end = cursor + pixel_count
    if end != len(packet.payload):
        raise ProtocolError("video Map Data pixel length did not consume packet")
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


def _snapshot_video_map_capture(
    capture: _PhaseCapture | list[Any], *, map_base: int
) -> dict[str, Any]:
    phase = _phase(capture) if isinstance(capture, list) else capture
    packets: list[dict[str, Any]] = []
    counts: Counter[int] = Counter()
    for packet in phase.packets:
        packet_id = _packet_id(packet)[0]
        counts[packet_id] += 1
        if packet_id == 0x34:
            update = _video_map_data(packet)
            packets.append(
                {
                    "packet_id": packet_id,
                    "data_length": packet.data_length,
                    "map": {
                        "relative_map_id": update.map_id - map_base,
                        "scale": update.scale,
                        "icon_count": update.icon_count,
                        "columns": update.columns,
                        "rows": update.rows,
                        "x_offset": update.x_offset,
                        "z_offset": update.z_offset,
                        "pixels": _digest_snapshot(update.pixels),
                    },
                }
            )
        else:
            packets.append(_snapshot_capture([packet])["packets"][0])
    return {
        "packet_counts": [[packet_id, count] for packet_id, count in sorted(counts.items())],
        "skipped_scheduled_packets": phase.skipped_scheduled_packets,
        "wire_bytes": phase.wire_bytes,
        "expanded_bytes": phase.expanded_bytes,
        "packets": packets,
    }


def _ensure_no_video_failure(capture: _PhaseCapture, label: str) -> None:
    for text in _plain_chat_texts(capture):
        if any(marker.casefold() in text.casefold() for marker in _VIDEO_FAILURE_MARKERS):
            raise ProtocolError(f"{label} failed: {text}")


def _read_submenu(connection: Any) -> list[Any]:
    packets: list[Any] = []
    saw_open = False
    skipped = 0
    for _ in range(32):
        packet = _read_packet(connection, compression=True)
        packet_id = _packet_id(packet)[0]
        if packet_id in _SCHEDULED_PLAY_IDS:
            skipped += 1
            if skipped > 8:
                raise ProtocolError("video submenu exceeded its scheduled-packet budget")
            continue
        packets.append(packet)
        if packet_id == 0x2D:
            saw_open = True
        elif saw_open and packet_id == 0x30:
            return packets
    raise ProtocolError("video submenu did not finish within 32 packets")


def _read_quiet(connection: Any, seconds: float, *, label: str) -> list[Any]:
    packets: list[Any] = []
    wire_bytes = 0
    expanded_bytes = 0
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        connection.settimeout(min(0.1, max(0.001, remaining)))
        try:
            packet = _read_packet(connection, compression=True)
        except TimeoutError:
            continue
        packet_id = _packet_id(packet)[0]
        if packet_id in _SCHEDULED_PLAY_IDS:
            continue
        packets.append(packet)
        wire_bytes += len(packet.wire)
        expanded_bytes += len(packet.payload)
        if len(packets) > _MAX_PHASE_PACKETS:
            raise ProtocolError(f"{label} exceeded its packet budget")
        if wire_bytes > _MAX_PHASE_WIRE_BYTES or expanded_bytes > _MAX_PHASE_EXPANDED_BYTES:
            raise ProtocolError(f"{label} exceeded its byte budget")
    return packets


def _read_until_packet_batch(connection: Any, packet_id: int, *, label: str) -> _PhaseCapture:
    packets: list[Any] = []
    skipped = 0
    wire_bytes = 0
    expanded_bytes = 0
    deadline = time.monotonic() + 15.0
    saw_target = False
    quiet_deadline: float | None = None
    while time.monotonic() < deadline:
        now = time.monotonic()
        if quiet_deadline is not None and now >= quiet_deadline:
            break
        timeout = min(1.0, deadline - now)
        if quiet_deadline is not None:
            timeout = min(timeout, quiet_deadline - now)
        connection.settimeout(max(0.001, timeout))
        try:
            packet = _read_packet(connection, compression=True)
        except TimeoutError:
            if saw_target:
                break
            continue
        current_id = _packet_id(packet)[0]
        if current_id in _SCHEDULED_PLAY_IDS:
            skipped += 1
            continue
        packets.append(packet)
        wire_bytes += len(packet.wire)
        expanded_bytes += len(packet.payload)
        chat = _chat_payload(packet)
        if chat is not None and any(
            marker.casefold() in chat[0].casefold() for marker in _VIDEO_FAILURE_MARKERS
        ):
            raise ProtocolError(f"{label} failed: {chat[0]}")
        if current_id == packet_id:
            saw_target = True
            quiet_deadline = time.monotonic() + 0.2
        if len(packets) > _MAX_PHASE_PACKETS:
            raise ProtocolError(f"{label} exceeded its packet budget")
        if wire_bytes > _MAX_PHASE_WIRE_BYTES or expanded_bytes > _MAX_PHASE_EXPANDED_BYTES:
            raise ProtocolError(f"{label} exceeded its byte budget")
    if not saw_target:
        raise _CaptureFailure("phase-timeout", label, f"packet 0x{packet_id:02x} was not reached")
    return _PhaseCapture(tuple(packets), 0, wire_bytes, expanded_bytes)


def _tile_state(capture: _PhaseCapture, map_ids: tuple[int, ...]) -> dict[int, bytearray]:
    expected = set(map_ids)
    state = {map_id: bytearray(_MAP_PIXELS) for map_id in map_ids}
    seen: set[int] = set()
    for packet in capture.packets:
        if _packet_id(packet)[0] != 0x34:
            continue
        update = _video_map_data(packet)
        if update.map_id not in expected:
            raise ProtocolError("video frame updated a map outside its active wall")
        _apply_map_update(state[update.map_id], update)
        seen.add(update.map_id)
    if seen != expected:
        raise ProtocolError("video frame did not update every active map")
    return state


def _apply_map_update(tile: bytearray, update: _MapUpdate) -> None:
    if len(tile) != _MAP_PIXELS:
        raise ProtocolError("video map tile state has an invalid size")
    if (
        update.columns < 1
        or update.rows < 1
        or update.x_offset + update.columns > 128
        or update.z_offset + update.rows > 128
        or len(update.pixels) != update.columns * update.rows
    ):
        raise ProtocolError("video map delta is outside its 128x128 tile")
    for row in range(update.rows):
        source = row * update.columns
        destination = (update.z_offset + row) * 128 + update.x_offset
        tile[destination : destination + update.columns] = update.pixels[
            source : source + update.columns
        ]


def _apply_capture(
    state: dict[int, bytearray], capture: _PhaseCapture, map_ids: tuple[int, ...]
) -> None:
    expected = set(map_ids)
    updated: set[int] = set()
    for packet in capture.packets:
        if _packet_id(packet)[0] != 0x34:
            continue
        update = _video_map_data(packet)
        if update.map_id not in expected:
            raise ProtocolError("video delta updated a map outside its active wall")
        _apply_map_update(state[update.map_id], update)
        updated.add(update.map_id)
    if not updated:
        raise ProtocolError("resumed video did not send a map delta")


def _map_frame_snapshot(state: dict[int, bytearray], map_ids: tuple[int, ...]) -> dict[str, Any]:
    width = _MAPS_X * 128
    height = _MAPS_Y * 128
    pixels = bytearray(width * height)
    tiles: list[dict[str, Any]] = []
    for index, map_id in enumerate(map_ids):
        tile = state[map_id]
        tile_row, tile_column = divmod(index, _MAPS_X)
        for row in range(128):
            source = row * 128
            destination = (tile_row * 128 + row) * width + tile_column * 128
            pixels[destination : destination + 128] = tile[source : source + 128]
        tiles.append(
            {
                "row": tile_row,
                "column": tile_column,
                "relative_map_id": index,
                "pixels": _digest_snapshot(bytes(tile)),
            }
        )
    return {
        "width": width,
        "height": height,
        "pixels": _digest_snapshot(bytes(pixels)),
        "palette_counts": [[value, count] for value, count in sorted(Counter(pixels).items())],
        "tiles": tiles,
    }


def _capture_video_gui_and_commands(target: RuntimeTarget) -> dict[str, Any]:
    with _authenticated_connection(target) as (
        connection,
        world_packet_count,
        world_expanded_bytes,
    ):
        menu_window_id, menu_packets = _open_menu(connection)
        connection.sendall(_click_frame(menu_window_id, 28, 91))
        submenu_packets = _read_submenu(connection)
        open_packets = [packet for packet in submenu_packets if _packet_id(packet)[0] == 0x2D]
        contents_packets = [packet for packet in submenu_packets if _packet_id(packet)[0] == 0x30]
        if len(open_packets) != 1 or len(contents_packets) != 2:
            raise ProtocolError("video menu did not replace the main GUI exactly once")
        video_window_id = _window_id(open_packets[0], expected_packet_id=0x2D)
        if video_window_id == menu_window_id:
            raise ProtocolError("video submenu reused the main menu window ID")

    command_snapshots: list[dict[str, Any]] = []
    with _authenticated_connection(target) as (connection, _, _):
        for name, command in _COMMANDS:
            connection.sendall(_chat_frame(command))
            packets = _read_packets(connection, (0x02,), name)
            command_snapshots.append(
                {
                    "name": name,
                    "command": command,
                    "response": _snapshot_packets((0x02,), packets),
                }
            )

    return {
        "username": _USERNAME.decode(),
        "email": _EMAIL,
        "world_packet_count_through_position": world_packet_count,
        "world_expanded_bytes_through_position": world_expanded_bytes,
        "main_menu": _snapshot_packets((0x2D, 0x30), menu_packets),
        "video_submenu": {
            "main_window_id": menu_window_id,
            "video_window_id": video_window_id,
            "packets": _snapshot_capture(submenu_packets),
        },
        "commands": command_snapshots,
    }


def _capture_map_video(target: RuntimeTarget) -> dict[str, Any]:
    with _authenticated_connection(target) as (connection, _, _):
        command = "/video play map width=1 fps=0 dither=99 contrast=9"
        connection.sendall(_chat_frame(command))
        started = _read_until_chat(connection, "Playing!", label="map video setup")
        _ensure_no_video_failure(started, "map video setup")
        wall, map_ids, entity_ids = _wall_topology(started)
        if len(map_ids) != _MAPS_X * _MAPS_Y:
            raise ProtocolError("map video did not clamp to a 2x2 map wall")
        state = _tile_state(started, map_ids)
        first = _read_until_packet_batch(connection, 0x34, label="map video first frame")
        _apply_capture(state, first, map_ids)
        first_frame = _map_frame_snapshot(state, map_ids)

        connection.sendall(_chat_frame("/video pause"))
        paused = _read_until_chat(connection, "Paused", label="map video pause")
        _ensure_no_video_failure(paused, "map video pause")
        quiet = _read_quiet(connection, 1.25, label="paused map video")
        if any(_packet_id(packet)[0] == 0x34 for packet in quiet):
            raise ProtocolError("paused map video continued sending frames")

        connection.sendall(_chat_frame("/video pause"))
        resumed = _read_until_chat(connection, "Resumed", label="map video resume")
        delta = _read_until_packet_batch(connection, 0x34, label="resumed map video frame")
        _apply_capture(state, delta, map_ids)
        resumed_frame = _map_frame_snapshot(state, map_ids)
        if resumed_frame["pixels"] == first_frame["pixels"]:
            raise ProtocolError("resumed map video frame did not change pixels")

        connection.sendall(_chat_frame("/video stop"))
        stopped = _read_until_chat(
            connection,
            "Map video playback finished!",
            label="map video stop and teardown",
        )
        _ensure_no_video_failure(stopped, "map video stop and teardown")
        destroy = [packet for packet in stopped.packets if _packet_id(packet)[0] == 0x13]
        if len(destroy) != 1 or tuple(_destroy_entities(destroy[0])) != entity_ids:
            raise ProtocolError("map video teardown did not destroy its exact frame entity set")

    return {
        "command": command,
        "wall": wall,
        "first_frame": first_frame,
        "setup_protocol": _snapshot_capture(
            started,
            map_base=map_ids[0],
            entity_base=entity_ids[0],
        ),
        "first_frame_protocol": _snapshot_video_map_capture(first, map_base=map_ids[0]),
        "pause_protocol": _snapshot_video_map_capture(paused, map_base=map_ids[0]),
        "paused_non_scheduled_packets": _snapshot_video_map_capture(
            quiet, map_base=map_ids[0]
        ),
        "resume_protocol": _snapshot_video_map_capture(resumed, map_base=map_ids[0]),
        "delta_protocol": _snapshot_video_map_capture(delta, map_base=map_ids[0]),
        "resumed_frame": resumed_frame,
        "stop_protocol": _snapshot_capture(
            stopped,
            map_base=map_ids[0],
            entity_base=entity_ids[0],
            unordered_blocks=True,
        ),
    }


def _capture_block_video(target: RuntimeTarget) -> dict[str, Any]:
    with _authenticated_connection(target) as (connection, _, _):
        command = "/video play width=4 fps=1 contrast=1.2"
        connection.sendall(_chat_frame(command))
        started = _read_until_chat(connection, "Playing!", label="block video setup")
        _ensure_no_video_failure(started, "block video setup")
        first = _read_until_packet_batch(connection, 0x21, label="block video first frame")
        if not any(_packet_id(packet)[0] == 0x21 for packet in first.packets):
            raise ProtocolError("block video first frame did not send chunk data")

        connection.sendall(_chat_frame("/video pause"))
        paused = _read_until_chat(connection, "Paused", label="block video pause")
        quiet = _read_quiet(connection, 1.25, label="paused block video")
        if any(_packet_id(packet)[0] == 0x21 for packet in quiet):
            raise ProtocolError("paused block video continued sending chunk frames")

        connection.sendall(_chat_frame("/video pause"))
        resumed = _read_until_chat(connection, "Resumed", label="block video resume")
        delta = _read_until_packet_batch(connection, 0x21, label="resumed block video frame")

        connection.sendall(_chat_frame("/video stop"))
        stopped = _read_until_chat(
            connection,
            "Block video playback finished!",
            label="block video stop and restore",
        )
        _ensure_no_video_failure(stopped, "block video stop and restore")
        restored_chunks = [packet for packet in stopped.packets if _packet_id(packet)[0] == 0x21]
        if not restored_chunks:
            raise ProtocolError("block video teardown did not restore any touched chunk")
        if not any("Blocks restored." in text for text in _plain_chat_texts(stopped)):
            raise ProtocolError("block video teardown did not confirm block restoration")

    return {
        "command": command,
        "setup_protocol": _snapshot_capture(started),
        "first_frame_protocol": _snapshot_capture(first),
        "pause_protocol": _snapshot_capture(paused),
        "paused_non_scheduled_packets": _snapshot_capture(quiet),
        "resume_protocol": _snapshot_capture(resumed),
        "delta_protocol": _snapshot_capture(delta),
        "stop_protocol": _snapshot_capture(stopped),
    }


def _capture_minecraft_video(target: RuntimeTarget) -> dict[str, Any]:
    resource = _video_resource(target)
    return {
        "resource": {
            "jar_member": _VIDEO_MEMBER,
            "candidate_path": str(_CANDIDATE_VIDEO).replace("\\", "/"),
            "bytes": _digest_snapshot(resource),
            "container": {
                "format": "ISO Base Media",
                "video": "H.264 High, 1920x1080, yuv420p, 30 fps, 1987 frames",
                "audio": "AAC-LC, 44100 Hz, stereo",
                "duration_seconds": 66.292971,
            },
        },
        "gui_and_commands": _capture_video_gui_and_commands(target),
        "map_video": _capture_map_video(target),
        "block_video": _capture_block_video(target),
    }


cast(Any, _capture_minecraft_video).__lmyzmail_contract__ = {
    "protocol": "minecraft-1.8.9",
    "flow": "authenticated video GUI, commands, map playback, block playback, and recovery",
    "protocol_version": 47,
    "compression_threshold": 256,
    "resource": {
        "jar_member": _VIDEO_MEMBER,
        "candidate_path": str(_CANDIDATE_VIDEO).replace("\\", "/"),
        "size": _VIDEO_SIZE,
        "sha256": _VIDEO_SHA256,
    },
    "capture": [
        "three-row video mode GUI",
        "command parser errors and limits",
        "map wall setup and row-major IDs",
        "first full map frame and resumed dirty rectangles",
        "map pause silence, stop, teardown, hotbar, and scoreboard recovery",
        "block clear, first chunk-section frame, delta, pause silence, and chunk restore",
    ],
    "normalization": [
        "exclude bounded scheduled 0x03 and 0x18 packets and their phase accounting",
        "relative map and entity IDs",
        "sort only HashMap-backed map-wall teardown block restoration",
    ],
    "budgets": {
        "packets_per_phase": _MAX_PHASE_PACKETS,
        "wire_bytes_per_phase": _MAX_PHASE_WIRE_BYTES,
        "expanded_bytes_per_phase": _MAX_PHASE_EXPANDED_BYTES,
    },
    "known_java_difference": {
        "id": "minecraft-map-video-semaphore-release",
        "java_behavior": "releases the global video permit before submitting map decode work",
        "rust_policy": "hold one bounded permit for the complete map or block playback lifecycle",
    },
}


SCENARIOS = (Scenario("minecraft/video", _capture_minecraft_video),)


class _VideoJavaOracleRuntime(_LoginJavaOracleRuntime):
    def _application_arguments(self) -> list[str]:
        replaced = (
            "--botmail.minecraft.spawn.x=",
            "--botmail.minecraft.spawn.y=",
            "--botmail.minecraft.spawn.z=",
            "--botmail.minecraft.spawn.yaw=",
            "--botmail.minecraft.spawn.pitch=",
        )
        arguments = [
            argument
            for argument in super()._application_arguments()
            if not argument.startswith(replaced)
        ]
        return [
            *arguments,
            "--botmail.minecraft.spawn.x=0.5",
            "--botmail.minecraft.spawn.y=160.0",
            "--botmail.minecraft.spawn.z=0.5",
            "--botmail.minecraft.spawn.yaw=0.0",
            "--botmail.minecraft.spawn.pitch=0.0",
            "--botmail.minecraft.max-concurrent-videos=2",
            "--botmail.minecraft.read-timeout-seconds=120",
            "--botmail.minecraft.video.center-x=0",
            "--botmail.minecraft.video.center-y=161",
            "--botmail.minecraft.video.wall-z=-3",
            "--botmail.minecraft.video.clear-margin=2",
            "--botmail.minecraft.video.spawn-protect-radius=1",
            "--botmail.minecraft.map-video.center-x=0",
            "--botmail.minecraft.map-video.center-y=161",
            "--botmail.minecraft.map-video.center-z=-3",
            "--botmail.minecraft.map-video.facing=SOUTH",
        ]


def test_map_delta_application_contract() -> None:
    tile = bytearray(_MAP_PIXELS)
    update = _MapUpdate(10, 0, 0, 3, 2, 2, 4, b"abcdef")
    _apply_map_update(tile, update)
    if tile[4 * 128 + 2 : 4 * 128 + 5] != b"abc":
        raise AssertionError("first map-delta row was applied at the wrong offset")
    if tile[5 * 128 + 2 : 5 * 128 + 5] != b"def":
        raise AssertionError("second map-delta row was applied at the wrong offset")
    with pytest.raises(ProtocolError, match="outside"):
        _apply_map_update(tile, _MapUpdate(10, 0, 0, 127, 0, 2, 1, b"ab"))


def test_video_failure_matching_is_case_insensitive() -> None:
    packet = _unit_chat_packet("Map Video Error: decode failed", 0)
    with pytest.raises(ProtocolError, match="failed"):
        _ensure_no_video_failure(_phase([packet]), "unit video")


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(1200)
def test_frozen_java_minecraft_video_golden(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    golden = repository / "blackbox/golden/java" / _GOLDEN
    record = os.environ.get("LMYZMAIL_RECORD_JAVA_GOLDEN") == "1"
    runner = DifferentialRunner(
        repository,
        golden,
        _GOLDEN,
        record_java=record,
    )
    with _VideoJavaOracleRuntime(tmp_path / "java-minecraft-video-v1") as oracle:
        target = _OracleTarget(oracle)
        if record:
            runner.record_from_java(SCENARIOS, target)
        else:
            runner.verify_java(SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(1200)
def test_rust_candidate_minecraft_video_matches_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    runtime = CandidateRuntime(
        command_template=(
            str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
            "--config",
            "{config}",
            "--lmyzmail.minecraft.enabled=true",
            "--lmyzmail.minecraft.online-mode=false",
            "--lmyzmail.minecraft.spawn.x=0.5",
            "--lmyzmail.minecraft.spawn.y=160.0",
            "--lmyzmail.minecraft.spawn.z=0.5",
            "--lmyzmail.minecraft.spawn.yaw=0.0",
            "--lmyzmail.minecraft.spawn.pitch=0.0",
            "--lmyzmail.minecraft.max-concurrent-videos=2",
            "--lmyzmail.minecraft.read-timeout-seconds=120",
            "--lmyzmail.minecraft.video.center-x=0",
            "--lmyzmail.minecraft.video.center-y=161",
            "--lmyzmail.minecraft.video.wall-z=-3",
            "--lmyzmail.minecraft.video.clear-margin=2",
            "--lmyzmail.minecraft.video.spawn-protect-radius=1",
            "--lmyzmail.minecraft.map-video.center-x=0",
            "--lmyzmail.minecraft.map-video.center-y=161",
            "--lmyzmail.minecraft.map-video.center-z=-3",
            "--lmyzmail.minecraft.map-video.facing=SOUTH",
        )
    )
    with runtime as candidate:
        DifferentialRunner(
            repository,
            repository / "blackbox/golden/java" / _GOLDEN,
            _GOLDEN,
        ).verify_candidate(SCENARIOS, candidate)
