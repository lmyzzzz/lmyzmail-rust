from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import pytest
from test_minecraft_login import (
    _begin_login,
    _decode_varint_bytes,
    _LoginJavaOracleRuntime,
    _packet_id,
    _read_login_prefix,
    _read_packet,
)

from lmyzmail_blackbox.differential import DifferentialRunner, RuntimeTarget, Scenario
from lmyzmail_blackbox.errors import ProtocolError
from lmyzmail_blackbox.persistent_runtime import PersistentJavaOracleRuntime
from lmyzmail_blackbox.ports import PortSet
from lmyzmail_blackbox.runtime import CandidateRuntime

_GOLDEN = "managed-minecraft-world-v11"
_USERNAME = b"WorldProbe"
_INITIAL_PLAY_IDS = (0x01, 0x41, 0x05, 0x39, 0x03, 0x06, 0x09)
_MAX_BOOTSTRAP_PACKETS = 4_096
_MAX_BOOTSTRAP_DATA = 512 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class _OracleTarget:
    runtime: PersistentJavaOracleRuntime

    @property
    def target_kind(self) -> str:
        return "java-oracle"

    @property
    def workspace(self) -> Path | None:
        return self.runtime.workspace

    @property
    def ports(self) -> PortSet | None:
        return self.runtime.ports


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _decode_position(packed: int) -> tuple[int, int, int]:
    x = packed >> 38
    y = (packed >> 26) & 0xFFF
    z = packed & 0x3FFFFFF
    if x >= 1 << 25:
        x -= 1 << 26
    if y >= 1 << 11:
        y -= 1 << 12
    if z >= 1 << 25:
        z -= 1 << 26
    return x, y, z


def _parse_chunk(packet: Any) -> tuple[dict[str, Any], bytes]:
    packet_id, cursor = _packet_id(packet)
    if packet_id != 0x21 or cursor + 11 > len(packet.payload):
        raise ProtocolError("invalid Chunk Data packet")
    chunk_x, chunk_z = struct.unpack_from(">ii", packet.payload, cursor)
    cursor += 8
    ground_up = packet.payload[cursor]
    cursor += 1
    primary_mask = struct.unpack_from(">H", packet.payload, cursor)[0]
    cursor += 2
    length, cursor = _decode_varint_bytes(packet.payload, cursor)
    end = cursor + length
    if ground_up != 1 or end != len(packet.payload):
        raise ProtocolError("Chunk Data had invalid ground-up flag or byte-array length")
    if packet.data_length != len(packet.payload):
        raise ProtocolError("large Chunk Data packet was not compressed at the threshold")
    data = packet.payload[cursor:end]
    digest_input = struct.pack(">iiHI", chunk_x, chunk_z, primary_mask, length)
    digest_input += hashlib.sha256(data).digest()
    return (
        {
            "chunk_x": chunk_x,
            "chunk_z": chunk_z,
            "primary_mask": primary_mask,
            "data_length": length,
            "data_sha256": _sha256(data),
        },
        digest_input,
    )


def _parse_tile_entity(packet: Any) -> dict[str, Any]:
    packet_id, cursor = _packet_id(packet)
    if packet_id != 0x35 or cursor + 10 > len(packet.payload):
        raise ProtocolError("invalid Update Tile Entity packet")
    packed = int.from_bytes(packet.payload[cursor : cursor + 8], "big")
    cursor += 8
    action = packet.payload[cursor]
    cursor += 1
    nbt = packet.payload[cursor:]
    if not nbt or nbt[0] != 10 or action not in {6, 9}:
        raise ProtocolError("Update Tile Entity had invalid action or NBT root")
    x, y, z = _decode_position(packed)
    return {
        "x": x,
        "y": y,
        "z": z,
        "action": action,
        "nbt_length": len(nbt),
        "nbt_sha256": _sha256(nbt),
        "payload_sha256": _sha256(packet.payload),
    }


def _parse_player_position(packet: Any) -> dict[str, Any]:
    packet_id, cursor = _packet_id(packet)
    if packet_id != 0x08 or cursor + 33 != len(packet.payload):
        raise ProtocolError("invalid Player Position And Look packet")
    x, y, z, yaw, pitch, flags = struct.unpack_from(">dddffB", packet.payload, cursor)
    return {"x": x, "y": y, "z": z, "yaw": yaw, "pitch": pitch, "flags": flags}


def _capture_world_bootstrap(target: RuntimeTarget) -> dict[str, Any]:
    if target.ports is None:
        raise RuntimeError("Minecraft capture target is not running")
    chunks: list[dict[str, Any]] = []
    chunk_digest = hashlib.sha256()
    tile_entities: list[dict[str, Any]] = []
    expanded_bytes = 0

    with _begin_login(target.ports.minecraft, _USERNAME) as connection:
        connection.settimeout(60.0)
        _read_login_prefix(connection)
        initial = [_read_packet(connection, compression=True) for _ in _INITIAL_PLAY_IDS]
        actual_initial = tuple(_packet_id(packet)[0] for packet in initial)
        if actual_initial != _INITIAL_PLAY_IDS:
            raise ProtocolError(f"unexpected initial PLAY packet order: {actual_initial!r}")

        phase = "chunks"
        position: dict[str, Any] | None = None
        for _ in range(_MAX_BOOTSTRAP_PACKETS):
            packet = _read_packet(connection, compression=True)
            packet_id, _ = _packet_id(packet)
            expanded_bytes += len(packet.payload)
            if expanded_bytes > _MAX_BOOTSTRAP_DATA:
                raise ProtocolError("Minecraft world bootstrap exceeded aggregate byte budget")
            if packet_id == 0x21 and phase == "chunks":
                chunk, digest_input = _parse_chunk(packet)
                chunks.append(chunk)
                chunk_digest.update(digest_input)
            elif packet_id == 0x35:
                phase = "tiles"
                tile_entities.append(_parse_tile_entity(packet))
            elif packet_id == 0x08:
                position = _parse_player_position(packet)
                break
            else:
                raise ProtocolError(
                    f"unexpected packet 0x{packet_id:02x} during world bootstrap phase {phase}"
                )
        if position is None:
            raise ProtocolError("world bootstrap did not reach Player Position And Look")

    if not chunks:
        raise ProtocolError("world bootstrap sent no Chunk Data packets")
    return {
        "chunk_count": len(chunks),
        "chunk_order_sha256": chunk_digest.hexdigest(),
        "chunks": chunks,
        "tile_entity_count": len(tile_entities),
        "tile_entities": tile_entities,
        "player_position": position,
        "aggregate_uncompressed_packet_bytes": expanded_bytes,
    }


cast(Any, _capture_world_bootstrap).__lmyzmail_contract__ = {
    "protocol": "minecraft-1.8.9",
    "flow": "offline login -> initial PLAY -> world chunks -> tile entities -> player position",
    "protocol_version": 47,
    "compression_threshold": 256,
    "world_template": "worlds/mailroom",
    "view_distance": 32,
    "spawn": {"x": -12.75, "z": 34.5},
    "video_wall": {"center_x": 0, "wall_z": -50},
    "normalization": "none",
}


SCENARIOS = (Scenario("minecraft/world-bootstrap", _capture_world_bootstrap),)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(600)
def test_frozen_java_minecraft_world_golden(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    golden = repository / "blackbox/golden/java" / _GOLDEN
    record = os.environ.get("LMYZMAIL_RECORD_JAVA_GOLDEN") == "1"
    runner = DifferentialRunner(
        repository,
        golden,
        _GOLDEN,
        record_java=record,
    )
    with _LoginJavaOracleRuntime(tmp_path / "java-minecraft-world") as oracle:
        target = _OracleTarget(oracle)
        if record:
            runner.record_from_java(SCENARIOS, target)
        else:
            runner.verify_java(SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(600)
def test_rust_candidate_minecraft_world_matches_golden() -> None:
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
