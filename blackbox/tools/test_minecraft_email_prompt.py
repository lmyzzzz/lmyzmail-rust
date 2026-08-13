from __future__ import annotations

import os
from pathlib import Path
from typing import Any, cast

import pytest
from test_minecraft_login import (
    _begin_login,
    _encode_varint,
    _LoginJavaOracleRuntime,
    _packet_id,
    _read_login_prefix,
    _read_packet,
)
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

_GOLDEN = "managed-minecraft-email-prompt-v6"
_USERNAME = b"EmailPromptProbe"
_INVALID_EMAIL = "not-an-email"
_VALID_EMAIL_INPUT = "  qa@example.test  "
_RESPONSE_IDS = (0x02, 0x02, 0x02, 0x02)


def _frame(payload: bytes) -> bytes:
    return _encode_varint(len(payload)) + payload


def _chat_frame(message: str) -> bytes:
    encoded = message.encode()
    packet = b"\x01" + _encode_varint(len(encoded)) + encoded
    return _frame(b"\x00" + packet)


def _capture_email_prompt(target: RuntimeTarget) -> dict[str, Any]:
    if target.ports is None:
        raise RuntimeError("Minecraft capture target is not running")
    with _begin_login(target.ports.minecraft, _USERNAME) as connection:
        connection.settimeout(60.0)
        _read_login_prefix(connection)
        _read_expected_packets(connection, _INITIAL_PLAY_IDS, "initial PLAY")
        world_packet_count, world_expanded_bytes = _drain_to_player_position(connection)
        _read_expected_packets(connection, _STATIC_PLAY_IDS, "static PLAY")
        _read_expected_packets(connection, _POST_STATIC_IDS, "post-static PLAY")

        connection.sendall(_chat_frame(_INVALID_EMAIL))
        invalid_response = _read_packet(connection, compression=True)
        connection.sendall(_chat_frame(_VALID_EMAIL_INPUT))
        valid_responses = [_read_packet(connection, compression=True) for _ in range(3)]

        packets = [invalid_response, *valid_responses]
        actual = tuple(_packet_id(packet)[0] for packet in packets)
        if actual != _RESPONSE_IDS:
            raise ProtocolError(f"unexpected email prompt packet order: {actual!r}")
        if any(packet.data_length != 0 for packet in packets):
            raise ProtocolError("email prompt Chat packet was unexpectedly zlib-compressed")

    return {
        "username": _USERNAME.decode(),
        "world_packet_count_through_position": world_packet_count,
        "world_expanded_bytes_through_position": world_expanded_bytes,
        "inputs": {
            "invalid": _INVALID_EMAIL,
            "valid_with_ascii_padding": _VALID_EMAIL_INPUT,
        },
        "packets": [
            {
                "packet_id": packet_id,
                "frame": bytes_snapshot(packet.wire),
            }
            for packet_id, packet in zip(_RESPONSE_IDS, packets, strict=True)
        ],
    }


cast(Any, _capture_email_prompt).__lmyzmail_contract__ = {
    "protocol": "minecraft-1.8.9",
    "flow": (
        "AwaitingEmail -> invalid Chat response -> ASCII-padded valid email -> "
        "AwaitingPassword prompts"
    ),
    "protocol_version": 47,
    "compression_threshold": 256,
    "input_packet_id": 0x01,
    "chat_max_utf16_units": 100,
    "captured_packet_ids": list(_RESPONSE_IDS),
    "normalization": "none",
}


SCENARIOS = (Scenario("minecraft/email-prompt", _capture_email_prompt),)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(600)
def test_frozen_java_minecraft_email_prompt_golden(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    golden = repository / "blackbox/golden/java" / _GOLDEN
    record = os.environ.get("LMYZMAIL_RECORD_JAVA_GOLDEN") == "1"
    runner = DifferentialRunner(
        repository,
        golden,
        _GOLDEN,
        record_java=record,
    )
    with _LoginJavaOracleRuntime(tmp_path / "java-minecraft-email-prompt") as oracle:
        target = _OracleTarget(oracle)
        if record:
            runner.record_from_java(SCENARIOS, target)
        else:
            runner.verify_java(SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(600)
def test_rust_candidate_minecraft_email_prompt_matches_golden() -> None:
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
