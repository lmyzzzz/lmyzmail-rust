from __future__ import annotations

import email.policy
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from email.message import Message
from email.parser import BytesParser
from pathlib import Path
from typing import Any

import psycopg
import pytest
import redis
from test_minecraft_authenticated_commands import _read_packets
from test_minecraft_draft_editing import (
    _RESTORED_SUCCESS_IDS,
    _SIGN_RESPONSE_IDS,
    _authenticate,
    _book_edit_frame,
    _bootstrap,
    _packed_position,
    _update_sign_frame,
)
from test_minecraft_email_prompt import _chat_frame
from test_minecraft_login import (
    _begin_login,
    _packet_id,
    _read_packet,
)
from test_minecraft_mail_view import _chat_payload
from test_minecraft_main_menu_lifecycle import _play_frame
from test_minecraft_password_auth import _SUCCESS_IDS

from lmyzmail_blackbox.golden import GoldenAttestation, GoldenStore
from lmyzmail_blackbox.outbound_oracle_probe import (
    _FAKE_IP,
    OutboundCandidateRuntime,
    OutboundOracleRuntime,
    _candidate_dsn_dns_server,
    _outbound_worklist_lengths,
    _wait_until,
)
from lmyzmail_blackbox.runtime import QA_ADDRESS
from lmyzmail_blackbox.scripted_smtp import ScriptedSmtpServer, SmtpScenario
from lmyzmail_blackbox.snapshots import bytes_snapshot

_PROFILE = "managed-minecraft-outbound-v6"
_REDIS_PREFIX = "botmail:mail:queue:"
_USERNAME = b"MinecraftSender"
_BUTTON_SEND = (5, 161, 6)
_SIGN_POSITIONS = {
    "to": (2, 161, 3),
    "cc": (4, 161, 3),
    "bcc": (6, 161, 3),
    "subject": (8, 161, 3),
}
_SIGN_VALUES = {
    "to": "a@outbound.fixture.test, ; b@outbound.fixture.test",
    "cc": "c@outbound.fixture.test",
    "bcc": "d@outbound.fixture.test",
    "subject": "Minecraft outbound subject",
}
_PAGES = ("First outbound page", "Second outbound page")
_FOOTER = "--- Sent with lmyzmail from Minecraft 1.8.9 ---"
_SCHEDULED_IDS = frozenset((0x03, 0x18))
_MAX_PACKETS = 128
_MAX_WIRE_BYTES = 512 * 1024
_MAX_EXPANDED_BYTES = 2 * 1024 * 1024
_PHASE_TIMEOUT_SECONDS = 45.0
_QUEUE_ID_RE = re.compile(r"(Email queued \(ID: )\d+(\), waiting for delivery\.\.\.)")
_MESSAGE_ID_RE = re.compile(r"(Message ID: )<[^>]+>")


class _MinecraftOutboundOracleRuntime(OutboundOracleRuntime):
    def _application_arguments(self) -> list[str]:
        return [
            *super()._application_arguments(),
            "--botmail.minecraft.spawn.x=-12.75",
            "--botmail.minecraft.spawn.y=70.9",
            "--botmail.minecraft.spawn.z=34.5",
            "--botmail.minecraft.spawn.yaw=45.0",
            "--botmail.minecraft.spawn.pitch=-15.0",
        ]


class _MinecraftOutboundCandidateRuntime(OutboundCandidateRuntime):
    def _application_arguments(self) -> list[str]:
        return [
            *super()._application_arguments(),
            "--lmyzmail.minecraft.enabled=true",
            "--lmyzmail.minecraft.online-mode=false",
            "--lmyzmail.minecraft.spawn.x=-12.75",
            "--lmyzmail.minecraft.spawn.y=70.9",
            "--lmyzmail.minecraft.spawn.z=34.5",
            "--lmyzmail.minecraft.spawn.yaw=45.0",
            "--lmyzmail.minecraft.spawn.pitch=-15.0",
            "--lmyzmail.minecraft.video.center-x=0",
            "--lmyzmail.minecraft.video.wall-z=-50",
        ]


@dataclass(slots=True)
class _CaptureBudget:
    deadline: float
    packets: int = 0
    wire_bytes: int = 0
    expanded_bytes: int = 0

    @classmethod
    def start(cls) -> _CaptureBudget:
        return cls(time.monotonic() + _PHASE_TIMEOUT_SECONDS)

    def account(self, packet: Any) -> None:
        self.packets += 1
        self.wire_bytes += len(packet.wire)
        self.expanded_bytes += len(packet.payload)
        if self.packets > _MAX_PACKETS:
            raise AssertionError("Minecraft outbound capture exceeded its packet budget")
        if self.wire_bytes > _MAX_WIRE_BYTES:
            raise AssertionError("Minecraft outbound capture exceeded its wire-byte budget")
        if self.expanded_bytes > _MAX_EXPANDED_BYTES:
            raise AssertionError("Minecraft outbound capture exceeded its expanded-byte budget")


def _split_sign_lines(value: str) -> tuple[str, str, str, str]:
    if len(value) > 60:
        raise ValueError("Minecraft outbound sign fixture exceeded four 15-character lines")
    padded = [value[index : index + 15] for index in range(0, len(value), 15)]
    return tuple((padded + [""] * 4)[:4])  # type: ignore[return-value]


def _button_frame() -> bytes:
    payload = b"".join(
        (
            b"\x08",
            struct.pack(">Q", _packed_position(*_BUTTON_SEND)),
            b"\x01",
            struct.pack(">h", -1),
            b"\x08\x08\x08",
        )
    )
    return _play_frame(payload)


def _next_business_packet(connection: Any, budget: _CaptureBudget) -> Any:
    while True:
        remaining = budget.deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError("timed out waiting for Minecraft outbound response")
        connection.settimeout(min(5.0, remaining))
        packet = _read_packet(connection, compression=True)
        budget.account(packet)
        if _packet_id(packet)[0] not in _SCHEDULED_IDS:
            return packet


def _chat(packet: Any) -> str:
    parsed = _chat_payload(packet)
    if parsed is None or parsed[1] != 0:
        raise AssertionError("Minecraft outbound response was not a system Chat packet")
    return parsed[0]


def _normalized_chat(value: str) -> str:
    value = _QUEUE_ID_RE.sub(r"\1<QUEUE_ID>\2", value)
    return _MESSAGE_ID_RE.sub(r"\1<MESSAGE_ID>", value)


def _one_chat(connection: Any) -> str:
    return _normalized_chat(_chat(_next_business_packet(connection, _CaptureBudget.start())))


def _snapshot_packet(packet: Any) -> dict[str, Any]:
    packet_id = _packet_id(packet)[0]
    chat = _chat_payload(packet)
    if chat is not None:
        return {
            "packet_id": packet_id,
            "chat": _normalized_chat(chat[0]),
            "position": chat[1],
        }
    return {"packet_id": packet_id, "frame": bytes_snapshot(packet.wire)}


def _read_delivery(connection: Any, *, success: bool) -> list[dict[str, Any]]:
    budget = _CaptureBudget.start()
    packets: list[Any] = []
    terminal_seen = False
    trailing = 0
    while True:
        packet = _next_business_packet(connection, budget)
        packets.append(packet)
        chat = _chat_payload(packet)
        text = chat[0] if chat is not None else ""
        if success and "Email sent successfully!" in text:
            terminal_seen = True
            trailing = 6
        elif not success and "Your draft is preserved. Fix and retry." in text:
            terminal_seen = True
            trailing = 0
        elif terminal_seen:
            trailing -= 1
        if terminal_seen and trailing == 0:
            return [_snapshot_packet(value) for value in packets]


def _draft_summary(connection: Any) -> list[str]:
    connection.sendall(_chat_frame("/draft"))
    packets = _read_packets(connection, (0x02,) * 6, "Minecraft outbound draft summary")
    return [_normalized_chat(_chat(packet)) for packet in packets]


def _edit_sign(connection: Any, field: str, value: str) -> dict[str, Any]:
    lines = _split_sign_lines(value)
    connection.sendall(_update_sign_frame(_SIGN_POSITIONS[field], lines))
    packets = _read_packets(connection, _SIGN_RESPONSE_IDS, f"outbound {field} edit")
    return {
        "field": field,
        "value": value,
        "lines": list(lines),
        "response": [_snapshot_packet(packet) for packet in packets],
    }


def _message_snapshot(attempt: Any) -> dict[str, Any]:
    message: Message = BytesParser(policy=email.policy.default).parsebytes(attempt.data)
    plain = message.get_body(preferencelist=("plain",))
    if plain is None:
        raise AssertionError("Minecraft outbound SMTP message did not contain a plain body")
    return {
        "sender": attempt.sender.decode("ascii"),
        "envelope_recipients": [value.decode("ascii") for value in attempt.recipients],
        "accepted": attempt.accepted,
        "from": message.get("From"),
        "to": message.get("To"),
        "cc": message.get("Cc"),
        "bcc_absent": message.get("Bcc") is None,
        "subject": message.get("Subject"),
        "body": plain.get_content(),
        "footer_count": plain.get_content().count(_FOOTER),
    }


def _queue_record(runtime: Any) -> tuple[int, dict[str, Any]]:
    if runtime.ports is None:
        raise RuntimeError("Minecraft outbound runtime is not running")
    with psycopg.connect(
        host="127.0.0.1",
        port=runtime.ports.postgres,
        dbname="lmyzmail",
        user="lmyzmail_test",
        password="",
    ) as connection:
        row = connection.execute(
            """
            SELECT id, status, retry_count, max_retries, subject, body_text, last_error,
                   message_id IS NOT NULL, sent_file_name IS NOT NULL
            FROM outbound_mail_queue
            WHERE sender_address = %s AND subject = %s
            ORDER BY id DESC
            LIMIT 1
            """,
            (QA_ADDRESS, _SIGN_VALUES["subject"]),
        ).fetchone()
    if row is None:
        raise AssertionError("Minecraft outbound queue row was not persisted")
    return int(row[0]), {
        "status": row[1],
        "retry_count": int(row[2]),
        "max_retries": int(row[3]),
        "subject": row[4],
        "body_text": row[5],
        "last_error": row[6],
        "message_id_present": bool(row[7]),
        "sent_file_present": bool(row[8]),
    }


def _queue_row(runtime: Any) -> dict[str, Any]:
    return _queue_record(runtime)[1]


def _sent_count(runtime: Any) -> int:
    if runtime.workspace is None:
        raise RuntimeError("Minecraft outbound runtime workspace is unavailable")
    root = runtime.workspace / "maildir" / QA_ADDRESS / "sent"
    return sum(1 for path in root.rglob("*.eml") if path.is_file()) if root.exists() else 0


def _task_worklist_membership(runtime: Any, task_id: int) -> dict[str, bool]:
    if runtime.ports is None:
        raise RuntimeError("Minecraft outbound runtime is not running")
    task = str(task_id)
    client = redis.Redis(host="127.0.0.1", port=runtime.ports.redis, decode_responses=True)
    try:
        return {
            "pending": client.lpos(_REDIS_PREFIX + "pending", task) is not None,
            "processing": bool(client.sismember(_REDIS_PREFIX + "processing", task)),
            "retry": client.zscore(_REDIS_PREFIX + "retry", task) is not None,
            "task_detail": bool(client.exists(_REDIS_PREFIX + f"task:{task}")),
        }
    finally:
        client.close()


def _worklist_snapshot(
    runtime: Any,
    baseline: dict[str, int],
    task_id: int,
) -> dict[str, Any]:
    lengths = _outbound_worklist_lengths(runtime)
    return {
        "delta": {name: lengths[name] - baseline[name] for name in sorted(baseline)},
        "task_membership": _task_worklist_membership(runtime, task_id),
    }


def _terminal_worklists_settled(
    runtime: Any,
    baseline: dict[str, int],
    task_id: int,
) -> bool:
    return _outbound_worklist_lengths(runtime) == baseline and not any(
        _task_worklist_membership(runtime, task_id).values()
    )


def _worklist_diagnostics(runtime: Any, task_id: int) -> dict[str, Any]:
    if runtime.ports is None:
        raise RuntimeError("Minecraft outbound runtime is not running")
    client = redis.Redis(host="127.0.0.1", port=runtime.ports.redis, decode_responses=True)
    try:
        return {
            "pending": client.lrange(_REDIS_PREFIX + "pending", 0, -1),
            "processing": sorted(client.smembers(_REDIS_PREFIX + "processing")),
            "retry": client.zrange(_REDIS_PREFIX + "retry", 0, -1),
            "task_membership": _task_worklist_membership(runtime, task_id),
        }
    finally:
        client.close()


def _capture_case(runtime: Any, server: ScriptedSmtpServer, *, success: bool) -> dict[str, Any]:
    if runtime.ports is None:
        raise RuntimeError("Minecraft outbound runtime is not running")
    redis_client = redis.Redis(host="127.0.0.1", port=runtime.ports.redis, decode_responses=False)
    redis_client.set("dns:mx:outbound.fixture.test", b"outbound.fixture.test", ex=300)
    redis_client.close()
    worklist_baseline = _outbound_worklist_lengths(runtime)
    before_sent = _sent_count(runtime)
    edits: list[dict[str, Any]] = []
    with _begin_login(runtime.ports.minecraft, _USERNAME) as connection:
        _bootstrap(connection)
        _authenticate(connection, _SUCCESS_IDS)

        connection.sendall(_button_frame())
        empty_to = _one_chat(connection)
        edits.append(_edit_sign(connection, "to", _SIGN_VALUES["to"]))
        connection.sendall(_button_frame())
        empty_subject = _one_chat(connection)
        edits.append(_edit_sign(connection, "subject", _SIGN_VALUES["subject"]))
        connection.sendall(_button_frame())
        empty_body = _one_chat(connection)
        edits.append(_edit_sign(connection, "cc", _SIGN_VALUES["cc"]))
        edits.append(_edit_sign(connection, "bcc", _SIGN_VALUES["bcc"]))
        connection.sendall(_book_edit_frame(_PAGES))
        book_response = _read_packets(connection, (0x02,), "Minecraft outbound book edit")

        connection.sendall(_button_frame())
        delivery = _read_delivery(connection, success=success)
        same_connection_summary = _draft_summary(connection) if success else None

    reconnect_summary = None
    if not success:
        with _begin_login(runtime.ports.minecraft, _USERNAME) as connection:
            _bootstrap(connection)
            restored = _authenticate(connection, _RESTORED_SUCCESS_IDS)
            reconnect_summary = {
                "authentication_packet_ids": [_packet_id(packet)[0] for packet in restored],
                "draft": _draft_summary(connection),
            }

    _wait_until(
        lambda: len(server.messages()) == 1,
        timeout=10.0,
        description="Minecraft outbound SMTP attempt",
    )
    expected_status = "SENT" if success else "FAILED"
    _wait_until(
        lambda: _queue_row(runtime)["status"] == expected_status,
        timeout=15.0,
        description=f"Minecraft outbound {expected_status} persistence",
    )
    queue_id, queue_row = _queue_record(runtime)
    try:
        _wait_until(
            lambda: not any(_task_worklist_membership(runtime, queue_id).values()),
            timeout=10.0,
            description="Minecraft outbound queue task acknowledgement",
        )
        _wait_until(
            lambda: _terminal_worklists_settled(runtime, worklist_baseline, queue_id),
            timeout=35.0,
            description="Minecraft outbound terminal worklist settlement",
        )
    except AssertionError as error:
        diagnostics = _worklist_diagnostics(runtime, queue_id)
        raise AssertionError(
            "Minecraft outbound terminal worklists did not return to their baseline: "
            f"baseline={worklist_baseline!r}, current={diagnostics!r}"
        ) from error
    return {
        "case": "success" if success else "permanent-failure",
        "validation": {
            "empty_to": empty_to,
            "empty_subject": empty_subject,
            "empty_body": empty_body,
        },
        "edits": edits,
        "book_response": [_snapshot_packet(packet) for packet in book_response],
        "delivery": delivery,
        "same_connection_draft": same_connection_summary,
        "reconnect": reconnect_summary,
        "smtp": _message_snapshot(server.messages()[0]),
        "queue": queue_row,
        "worklists": _worklist_snapshot(runtime, worklist_baseline, queue_id),
        "sent_maildir_delta": _sent_count(runtime) - before_sent,
    }


def run_child() -> dict[str, Any]:
    target = os.environ.get("LMYZMAIL_OUTBOUND_TARGET", "java").casefold()
    case = os.environ.get("LMYZMAIL_MINECRAFT_OUTBOUND_CASE", "success").casefold()
    if target not in {"java", "candidate"}:
        raise AssertionError(f"unsupported Minecraft outbound target: {target}")
    if case not in {"success", "failure"}:
        raise AssertionError(f"unsupported Minecraft outbound case: {case}")
    success = case == "success"
    scenario = SmtpScenario(
        data_result_reply=(
            b"250 2.0.0 message accepted\r\n"
            if success
            else b"550 5.7.1 fixture policy rejection\r\n"
        ),
        max_connections=4,
        max_concurrent_connections=1,
        max_message_bytes=2 * 1024 * 1024,
    )
    server = ScriptedSmtpServer(scenario, bind_host=_FAKE_IP, bind_port=25)
    dns_server = _candidate_dsn_dns_server() if target == "candidate" else None
    repository = Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory(prefix=f"lmyzmail-minecraft-outbound-{case}-") as workspace:
        runtime = (
            _MinecraftOutboundOracleRuntime(Path(workspace))
            if target == "java"
            else _MinecraftOutboundCandidateRuntime(
                command_template=(
                    str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
                    "--config",
                    "{config}",
                )
            )
        )
        if dns_server is not None:
            dns_server.start()
        try:
            with server, runtime:
                return _capture_case(runtime, server, success=success)
        finally:
            if dns_server is not None:
                dns_server.stop()


def _run_probe(repository: Path, *, target: str, case: str) -> dict[str, Any]:
    result = subprocess.run(  # noqa: S603
        ["/bin/bash", str(repository / "blackbox/bin/run-minecraft-outbound-probe.sh")],
        cwd=repository,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "LMYZMAIL_BLACKBOX_PYTHON": sys.executable,
            "LMYZMAIL_OUTBOUND_TARGET": target,
            "LMYZMAIL_MINECRAFT_OUTBOUND_CASE": case,
        },
        timeout=240,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"Minecraft outbound {case} probe failed with {result.returncode}:\n"
            f"stdout={result.stdout}\nstderr={result.stderr}"
        )
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise AssertionError("Minecraft outbound probe returned a non-object")
    return value


def _assert_golden(repository: Path, observed: dict[str, Any], *, record: bool) -> None:
    attestation = GoldenAttestation.from_repository(
        repository,
        profile=_PROFILE,
        normalizers=(
            "minecraft-outbound:queue-id",
            "minecraft-outbound:message-id",
            "smtp:date-and-dkim-excluded-by-semantic-projection",
        ),
    )
    path = repository / f"blackbox/golden/java/{_PROFILE}.json"
    GoldenStore(path.parent, attestation, record=record).assert_observation(path.name, observed)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(520)
def test_frozen_java_minecraft_outbound_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    observed = {
        "success": _run_probe(repository, target="java", case="success"),
        "permanent_failure": _run_probe(repository, target="java", case="failure"),
    }
    _assert_golden(
        repository,
        observed,
        record=os.environ.get("LMYZMAIL_RECORD_JAVA_GOLDEN") == "1",
    )


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(520)
def test_rust_candidate_minecraft_outbound_matches_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    observed = {
        "success": _run_probe(repository, target="candidate", case="success"),
        "permanent_failure": _run_probe(repository, target="candidate", case="failure"),
    }
    _assert_golden(repository, observed, record=False)


def main() -> int:
    if sys.argv != [sys.argv[0], "--child"]:
        raise SystemExit("test_minecraft_outbound_delivery must use its namespace launcher")
    print(json.dumps(run_child(), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
