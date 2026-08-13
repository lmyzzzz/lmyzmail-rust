from __future__ import annotations

# ruff: noqa: S101
import json
import os
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

import psycopg
import pytest
import redis
from test_minecraft_draft_editing import _authenticate, _book_edit_frame, _bootstrap
from test_minecraft_login import _begin_login, _packet_id
from test_minecraft_mail_view import _chat_payload
from test_minecraft_outbound_delivery import (
    _FOOTER,
    _PAGES,
    _SIGN_VALUES,
    _SUCCESS_IDS,
    _button_frame,
    _CaptureBudget,
    _edit_sign,
    _message_snapshot,
    _MinecraftOutboundCandidateRuntime,
    _MinecraftOutboundOracleRuntime,
    _next_business_packet,
    _normalized_chat,
    _sent_count,
    _task_worklist_membership,
)

from lmyzmail_blackbox.golden import GoldenAttestation, GoldenStore
from lmyzmail_blackbox.outbound_oracle_probe import (
    _FAKE_IP,
    _candidate_dsn_dns_server,
    _outbound_worklist_lengths,
    _wait_until,
)
from lmyzmail_blackbox.runtime import QA_ADDRESS
from lmyzmail_blackbox.scripted_smtp import ScriptedSmtpServer, SmtpScenario

_PROFILE = "managed-minecraft-outbound-duplicate-oracle-evidence-v4"
_USERNAME = b"DuplicateSender"
_EXPECTED_ROWS = {"java": 2, "candidate": 1}


def _queue_records(runtime: Any) -> tuple[list[int], list[dict[str, Any]]]:
    if runtime.ports is None:
        raise RuntimeError("Minecraft duplicate-send runtime is not running")
    with psycopg.connect(
        host="127.0.0.1",
        port=runtime.ports.postgres,
        dbname="lmyzmail",
        user="lmyzmail_test",
        password="",
    ) as connection:
        rows = connection.execute(
            """
            SELECT id, status, retry_count, max_retries, subject, body_text, body_html,
                   attachments_json, last_error, message_id IS NOT NULL,
                   sent_file_name IS NOT NULL
            FROM outbound_mail_queue
            WHERE sender_address = %s AND subject = %s
            ORDER BY id
            """,
            (QA_ADDRESS, _SIGN_VALUES["subject"]),
        ).fetchall()
    return [int(row[0]) for row in rows], [
        {
            "status": row[1],
            "retry_count": int(row[2]),
            "max_retries": int(row[3]),
            "subject": row[4],
            "body_text_cleared": row[5] is None,
            "body_html_cleared": row[6] is None,
            "attachments_json_cleared": row[7] is None,
            "last_error": row[8],
            "message_id_present": bool(row[9]),
            "sent_file_present": bool(row[10]),
        }
        for row in rows
    ]


def _read_duplicate_delivery(connection: Any, expected_terminals: int) -> dict[str, Any]:
    budget = _CaptureBudget.start()
    chat_counts: Counter[str] = Counter()
    packet_counts: Counter[int] = Counter()
    terminal_count = 0
    message_id_count = 0
    sign_count = 0
    book_count = 0
    while True:
        packet = _next_business_packet(connection, budget)
        packet_id = _packet_id(packet)[0]
        packet_counts[packet_id] += 1
        if packet_id == 0x33:
            sign_count += 1
        elif packet_id == 0x2F:
            book_count += 1
        chat = _chat_payload(packet)
        if chat is not None:
            text = _normalized_chat(chat[0])
            chat_counts[text] += 1
            terminal_count += int("Email sent successfully!" in text)
            message_id_count += int(text.startswith("§7Message ID: "))
        if (
            terminal_count == expected_terminals
            and message_id_count == expected_terminals
            and sign_count == 4 * expected_terminals
            and book_count == expected_terminals
        ):
            return {
                "chat_counts": dict(sorted(chat_counts.items())),
                "packet_id_counts": {
                    str(key): value for key, value in sorted(packet_counts.items())
                },
                "terminal_count": terminal_count,
            }


def _terminal_state_ready(runtime: Any, expected_rows: int) -> bool:
    _, rows = _queue_records(runtime)
    return len(rows) == expected_rows and all(row["status"] == "SENT" for row in rows)


def _all_tasks_absent(runtime: Any, task_ids: list[int]) -> bool:
    return all(
        not any(_task_worklist_membership(runtime, task_id).values()) for task_id in task_ids
    )


def _capture_duplicate(runtime: Any, server: ScriptedSmtpServer, target: str) -> dict[str, Any]:
    if runtime.ports is None:
        raise RuntimeError("Minecraft duplicate-send runtime is not running")
    expected_rows = _EXPECTED_ROWS[target]
    redis_client = redis.Redis(host="127.0.0.1", port=runtime.ports.redis, decode_responses=False)
    redis_client.set("dns:mx:outbound.fixture.test", b"outbound.fixture.test", ex=300)
    redis_client.close()
    worklist_baseline = _outbound_worklist_lengths(runtime)
    before_sent = _sent_count(runtime)

    with _begin_login(runtime.ports.minecraft, _USERNAME) as connection:
        _bootstrap(connection)
        _authenticate(connection, _SUCCESS_IDS)
        for field in ("to", "subject", "cc", "bcc"):
            _edit_sign(connection, field, _SIGN_VALUES[field])
        connection.sendall(_book_edit_frame(_PAGES))
        book_response = _next_business_packet(connection, _CaptureBudget.start())
        assert _packet_id(book_response)[0] == 0x02

        # Both C08 packets share one raw socket write so TCP packetization cannot
        # hide or serialize the repeated-click behavior under test.
        connection.sendall(_button_frame() + _button_frame())
        response = _read_duplicate_delivery(connection, expected_rows)

    _wait_until(
        lambda: len(server.messages()) == expected_rows,
        timeout=20.0,
        description="Minecraft duplicate-send SMTP attempt count",
    )
    _wait_until(
        lambda: _terminal_state_ready(runtime, expected_rows),
        timeout=20.0,
        description="Minecraft duplicate-send terminal queue rows",
    )
    task_ids, rows = _queue_records(runtime)
    _wait_until(
        lambda: _all_tasks_absent(runtime, task_ids),
        timeout=10.0,
        description="Minecraft duplicate-send task acknowledgements",
    )
    _wait_until(
        lambda: _outbound_worklist_lengths(runtime) == worklist_baseline,
        timeout=35.0,
        description="Minecraft duplicate-send terminal worklist settlement",
    )
    task_membership = [_task_worklist_membership(runtime, task_id) for task_id in task_ids]
    current_worklists = _outbound_worklist_lengths(runtime)
    return {
        "coalesced_clicks": 2,
        "response": response,
        "smtp": {
            "attempt_count": len(server.messages()),
            "messages": [_message_snapshot(message) for message in server.messages()],
            "all_have_one_footer": all(
                _message_snapshot(message)["footer_count"] == 1 for message in server.messages()
            ),
            "frozen_footer": _FOOTER,
        },
        "queue": {"row_count": len(rows), "rows": rows},
        "worklists": {
            "delta": {
                name: current_worklists[name] - worklist_baseline[name]
                for name in sorted(worklist_baseline)
            },
            "task_membership": task_membership,
        },
        "sent_maildir_delta": _sent_count(runtime) - before_sent,
    }


def run_child() -> dict[str, Any]:
    target = os.environ.get("LMYZMAIL_MINECRAFT_OUTBOUND_DUPLICATE_TARGET", "java").casefold()
    if target not in _EXPECTED_ROWS:
        raise AssertionError(f"unsupported Minecraft duplicate-send target: {target}")
    scenario = SmtpScenario(
        max_connections=8,
        max_concurrent_connections=2,
        max_message_bytes=2 * 1024 * 1024,
    )
    server = ScriptedSmtpServer(scenario, bind_host=_FAKE_IP, bind_port=25)
    dns_server = _candidate_dsn_dns_server() if target == "candidate" else None
    repository = Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory(prefix="lmyzmail-minecraft-duplicate-") as workspace:
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
                return _capture_duplicate(runtime, server, target)
        finally:
            if dns_server is not None:
                dns_server.stop()


def _run_probe(repository: Path, target: str) -> dict[str, Any]:
    result = subprocess.run(  # noqa: S603
        [
            "/bin/bash",
            str(repository / "blackbox/bin/run-minecraft-outbound-duplicate-probe.sh"),
        ],
        cwd=repository,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "LMYZMAIL_BLACKBOX_PYTHON": sys.executable,
            "LMYZMAIL_MINECRAFT_OUTBOUND_DUPLICATE_TARGET": target,
        },
        timeout=240,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"Minecraft duplicate-send {target} probe failed with {result.returncode}:\n"
            f"stdout={result.stdout}\nstderr={result.stderr}"
        )
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise AssertionError("Minecraft duplicate-send probe returned a non-object")
    return value


def _assert_golden(repository: Path, observed: dict[str, Any], record: bool) -> None:
    attestation = GoldenAttestation.from_repository(
        repository,
        profile=_PROFILE,
        normalizers=(
            "minecraft-outbound:queue-id",
            "minecraft-outbound:message-id",
            "minecraft-outbound:concurrent-completion-projected-as-counts",
            "smtp:date-and-dkim-excluded-by-semantic-projection",
        ),
    )
    path = repository / f"blackbox/golden/java/{_PROFILE}.json"
    GoldenStore(path.parent, attestation, record=record).assert_observation(path.name, observed)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(260)
def test_frozen_java_minecraft_duplicate_send_oracle_evidence() -> None:
    repository = Path(__file__).resolve().parents[2]
    observed = _run_probe(repository, "java")
    _assert_golden(
        repository,
        observed,
        record=os.environ.get("LMYZMAIL_RECORD_JAVA_GOLDEN") == "1",
    )


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(260)
def test_rust_candidate_rejects_overlapping_minecraft_send() -> None:
    repository = Path(__file__).resolve().parents[2]
    observed = _run_probe(repository, "candidate")
    expected_chats = {
        "§6Sending email...": 1,
        "§7Email queued (ID: <QUEUE_ID>), waiting for delivery...": 1,
        "§7Message ID: <MESSAGE_ID>": 1,
        "§a§l✓ Email sent successfully!": 1,
        "§cEmail send already in progress.": 1,
    }
    assert observed["coalesced_clicks"] == 2
    assert observed["response"] == {
        "chat_counts": dict(sorted(expected_chats.items())),
        "packet_id_counts": {"2": 5, "47": 1, "51": 4},
        "terminal_count": 1,
    }
    assert observed["smtp"]["attempt_count"] == 1
    assert observed["smtp"]["all_have_one_footer"] is True
    assert observed["queue"]["row_count"] == 1
    assert observed["queue"]["rows"] == [
        {
            "status": "SENT",
            "retry_count": 0,
            "max_retries": 5,
            "subject": _SIGN_VALUES["subject"],
            "body_text_cleared": True,
            "body_html_cleared": True,
            "attachments_json_cleared": True,
            "last_error": None,
            "message_id_present": True,
            "sent_file_present": True,
        }
    ]
    assert observed["worklists"]["delta"] == {
        "archive": 0,
        "pending": 0,
        "processing": 0,
        "retry": 0,
        "status_updates": 0,
    }
    assert observed["worklists"]["task_membership"] == [
        {"pending": False, "processing": False, "retry": False, "task_detail": False}
    ]
    assert observed["sent_maildir_delta"] == 1


def main() -> int:
    if sys.argv != [sys.argv[0], "--child"]:
        raise SystemExit("test_minecraft_outbound_duplicate must use its namespace launcher")
    print(json.dumps(run_child(), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
