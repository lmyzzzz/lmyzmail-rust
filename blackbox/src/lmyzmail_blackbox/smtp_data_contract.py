from __future__ import annotations

import hashlib
import select
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .differential import RuntimeTarget, Scenario
from .protocols import BoundedSocket, _encode_smtp_data, read_smtp_reply
from .smtp_contract import (
    _COUNT_KEY,
    _check,
    _connect_postgres,
    _index_count,
    _maildir_files,
    _redis_state,
    _set_statement_timeout,
    _storage_snapshot,
    capture_delivery,
    open_smtp_client,
    smtp_ehlo,
    smtp_greeting_snapshot,
    smtp_reply_snapshot,
)
from .snapshots import bytes_snapshot

_MAX_MESSAGE_SIZE = 15_728_640
_NORMALIZERS = (
    "smtp:greeting-skibidi-grammar",
    "smtp:server-hostname",
    "smtp:session-id",
    "maildir:generated-filename",
    "maildir:server-hostname",
    "maildir:received-id",
    "maildir:received-at",
    "postgres:identity-timestamps-and-hostname-derived-size",
)


def _simple_message(subject: str, message_id: str, body: bytes) -> bytes:
    return (
        f"Subject: {subject}\r\nMessage-ID: {message_id}\r\n"
        "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=us-ascii\r\n"
        "\r\n"
    ).encode("ascii") + body


_DATA_MESSAGE_ID = "<bb-fragmented-data-001@example.test>"
_DATA_SUBJECT = "bb-fragmented-data-001"
_DATA_MESSAGE = _simple_message(
    _DATA_SUBJECT,
    _DATA_MESSAGE_ID,
    b"fragmented DATA body\r\n.dot-leading-line\r\n..two-dots\r\n",
)
_BDAT_MESSAGE_ID = "<bb-fragmented-bdat-001@example.test>"
_BDAT_SUBJECT = "bb-fragmented-bdat-001"
_BDAT_MESSAGE = _simple_message(
    _BDAT_SUBJECT,
    _BDAT_MESSAGE_ID,
    b"binary=\x00\xff\x80\r\nBDAT body\r\n",
)
_COALESCED_CHUNKS_MESSAGE_ID = "<bb-coalesced-bdat-chunks-001@example.test>"
_COALESCED_CHUNKS_SUBJECT = "bb-coalesced-bdat-chunks-001"
_COALESCED_CHUNKS_MESSAGE = _simple_message(
    _COALESCED_CHUNKS_SUBJECT,
    _COALESCED_CHUNKS_MESSAGE_ID,
    b"two BDAT chunks share one socket write after prerequisites are confirmed.\r\n",
)
_RECOVERY_DATA_ID = "<bb-data-recovery-001@example.test>"
_RECOVERY_DATA_SUBJECT = "bb-data-recovery-001"
_RECOVERY_DATA_MESSAGE = _simple_message(
    _RECOVERY_DATA_SUBJECT,
    _RECOVERY_DATA_ID,
    b"recovered DATA\r\n",
)
_RECOVERY_BDAT_ID = "<bb-bdat-recovery-001@example.test>"
_RECOVERY_BDAT_SUBJECT = "bb-bdat-recovery-001"
_RECOVERY_BDAT_MESSAGE = _simple_message(
    _RECOVERY_BDAT_SUBJECT,
    _RECOVERY_BDAT_ID,
    b"recovered BDAT\r\n",
)
_ZERO_LAST_MESSAGE_ID = "<bb-bdat-zero-last-after-data-001@example.test>"
_ZERO_LAST_SUBJECT = "bb-bdat-zero-last-after-data-001"
_ZERO_LAST_MESSAGE = _simple_message(
    _ZERO_LAST_SUBJECT,
    _ZERO_LAST_MESSAGE_ID,
    b"This complete non-LAST chunk is discarded by the frozen oracle.\r\n",
)
_COALESCED_BDAT_MESSAGE_ID = "<bb-coalesced-bdat-stall-001@example.test>"
_COALESCED_BDAT_MESSAGE = _simple_message(
    "bb-coalesced-bdat-stall-001",
    _COALESCED_BDAT_MESSAGE_ID,
    b"binary=\x00\xff\x80\r\nNOOP\r\nRCPT TO:<tail@example.test>\r\nBDAT 0 LAST\r\n",
)


def _send_fragments(stream: BoundedSocket, payload: bytes, sizes: tuple[int, ...]) -> None:
    _check(sum(sizes) == len(payload), (sum(sizes), len(payload)))
    offset = 0
    for size in sizes:
        _check(size > 0, sizes)
        stream.sendall(payload[offset : offset + size])
        offset += size


def _fragment_sizes(total: int, first: tuple[int, ...]) -> tuple[int, ...]:
    used = sum(first)
    _check(total > used, (total, first))
    return first + (total - used,)


def _assert_no_socket_data(stream: BoundedSocket, *, timeout: float = 0.15) -> None:
    _check(not stream.buffer, "unexpected buffered SMTP reply")
    ready, _, _ = select.select([stream.sock], [], [], timeout)
    _check(not ready, "unexpected SMTP reply before the declared data was complete")


def _capture_fragmented_data(target: RuntimeTarget) -> dict[str, Any]:
    workspace = target.workspace
    if workspace is None:
        raise AssertionError("SMTP target is not started")
    maildir_before = _maildir_files(workspace, deadline=time.monotonic() + 5.0)
    _check(_index_count(target, _DATA_MESSAGE_ID) == 0, _DATA_MESSAGE_ID)
    redis_before = _redis_state(target, _COUNT_KEY, deadline=time.monotonic() + 5.0)[0]
    started_at = datetime.now(UTC)

    client, hostname = open_smtp_client(target)
    with client:
        ehlo = smtp_ehlo(client, hostname)
        mail_from = client.command(b"MAIL FROM:<>")
        rcpt_to = client.command(b"RCPT TO:<qa@example.test>")
        data_ready = client.command(b"DATA")
        _check(data_ready[0].startswith(b"354 "), data_ready)
        encoded = _encode_smtp_data(_DATA_MESSAGE)
        sizes = _fragment_sizes(len(encoded), (len(encoded) - 3, 1, 1))
        _send_fragments(client.stream, encoded, sizes)
        accepted = read_smtp_reply(client.stream)
        quit_reply = client.quit()

    return {
        "mode": "DATA",
        "wire": {
            "greeting": smtp_greeting_snapshot(),
            "ehlo": smtp_reply_snapshot(ehlo, hostname),
            "mail_from": smtp_reply_snapshot(mail_from, hostname),
            "rcpt_to": smtp_reply_snapshot(rcpt_to, hostname),
            "data_ready": smtp_reply_snapshot(data_ready, hostname),
            "accepted": smtp_reply_snapshot(accepted, hostname, accepted=True),
            "fragment_sizes": list(sizes),
            "quit": smtp_reply_snapshot(quit_reply, hostname),
        },
        "storage": _storage_snapshot(
            target,
            message_id=_DATA_MESSAGE_ID,
            subject=_DATA_SUBJECT,
            message=_DATA_MESSAGE,
            hostname=hostname,
            received_protocol=b"ESMTP",
            maildir_before=maildir_before,
            redis_before=redis_before,
            started_at=started_at,
        ),
    }


def _capture_fragmented_bdat(target: RuntimeTarget) -> dict[str, Any]:
    workspace = target.workspace
    if workspace is None:
        raise AssertionError("SMTP target is not started")
    maildir_before = _maildir_files(workspace, deadline=time.monotonic() + 5.0)
    _check(_index_count(target, _BDAT_MESSAGE_ID) == 0, _BDAT_MESSAGE_ID)
    redis_before = _redis_state(target, _COUNT_KEY, deadline=time.monotonic() + 5.0)[0]
    started_at = datetime.now(UTC)

    client, hostname = open_smtp_client(target)
    with client:
        ehlo = smtp_ehlo(client, hostname)
        mail_from = client.command(b"MAIL FROM:<>")
        rcpt_to = client.command(b"RCPT TO:<qa@example.test>")
        command = b"BDAT " + str(len(_BDAT_MESSAGE)).encode("ascii") + b" LAST\r\n"
        payload = command + _BDAT_MESSAGE
        sizes = _fragment_sizes(len(payload), (len(command) - 1, 1, 17, 29))
        client.stream.sendall(payload[: sizes[0]])
        _assert_no_socket_data(client.stream)
        _send_fragments(client.stream, payload[sizes[0] :], sizes[1:])
        accepted = read_smtp_reply(client.stream)
        quit_reply = client.quit()

    return {
        "mode": "BDAT",
        "wire": {
            "greeting": smtp_greeting_snapshot(),
            "ehlo": smtp_reply_snapshot(ehlo, hostname),
            "mail_from": smtp_reply_snapshot(mail_from, hostname),
            "rcpt_to": smtp_reply_snapshot(rcpt_to, hostname),
            "command": command.decode("ascii"),
            "accepted": smtp_reply_snapshot(accepted, hostname, accepted=True),
            "fragment_sizes": list(sizes),
            "quit": smtp_reply_snapshot(quit_reply, hostname),
        },
        "storage": _storage_snapshot(
            target,
            message_id=_BDAT_MESSAGE_ID,
            subject=_BDAT_SUBJECT,
            message=_BDAT_MESSAGE,
            hostname=hostname,
            received_protocol=b"ESMTP",
            maildir_before=maildir_before,
            redis_before=redis_before,
            started_at=started_at,
        ),
    }


def _capture_coalesced_bdat_chunks(target: RuntimeTarget) -> dict[str, Any]:
    workspace = target.workspace
    if workspace is None:
        raise AssertionError("SMTP target is not started")
    maildir_before = _maildir_files(workspace, deadline=time.monotonic() + 5.0)
    _check(_index_count(target, _COALESCED_CHUNKS_MESSAGE_ID) == 0, _COALESCED_CHUNKS_MESSAGE_ID)
    redis_before = _redis_state(target, _COUNT_KEY, deadline=time.monotonic() + 5.0)[0]
    started_at = datetime.now(UTC)
    split_at = len(_COALESCED_CHUNKS_MESSAGE) // 2
    first = _COALESCED_CHUNKS_MESSAGE[:split_at]
    second = _COALESCED_CHUNKS_MESSAGE[split_at:]
    coalesced = (
        b"BDAT "
        + str(len(first)).encode("ascii")
        + b"\r\n"
        + first
        + b"BDAT "
        + str(len(second)).encode("ascii")
        + b" LAST\r\n"
        + second
    )

    client, hostname = open_smtp_client(target)
    with client:
        ehlo = smtp_ehlo(client, hostname)
        mail_from = client.command(b"MAIL FROM:<>")
        rcpt_to = client.command(b"RCPT TO:<qa@example.test>")
        client.stream.sendall(coalesced)
        first_reply = read_smtp_reply(client.stream)
        accepted = read_smtp_reply(client.stream)
        quit_reply = client.quit()

    return {
        "mode": "BDAT",
        "wire": {
            "greeting": smtp_greeting_snapshot(),
            "ehlo": smtp_reply_snapshot(ehlo, hostname),
            "mail_from": smtp_reply_snapshot(mail_from, hostname),
            "rcpt_to": smtp_reply_snapshot(rcpt_to, hostname),
            "coalesced_chunks": bytes_snapshot(coalesced),
            "chunk_sizes": [len(first), len(second)],
            "first_reply": smtp_reply_snapshot(first_reply, hostname),
            "accepted": smtp_reply_snapshot(accepted, hostname, accepted=True),
            "quit": smtp_reply_snapshot(quit_reply, hostname),
        },
        "storage": _storage_snapshot(
            target,
            message_id=_COALESCED_CHUNKS_MESSAGE_ID,
            subject=_COALESCED_CHUNKS_SUBJECT,
            message=_COALESCED_CHUNKS_MESSAGE,
            hostname=hostname,
            received_protocol=b"ESMTP",
            maildir_before=maildir_before,
            redis_before=redis_before,
            started_at=started_at,
        ),
    }


def _capture_bdat_size_and_zero_state(target: RuntimeTarget) -> dict[str, Any]:
    client, hostname = open_smtp_client(target)
    with client:
        ehlo = smtp_ehlo(client, hostname)
        mail_from = client.command(b"MAIL FROM:<>")
        rcpt_to = client.command(b"RCPT TO:<qa@example.test>")
        zero = client.command(b"BDAT 0")
        oversize = client.command(b"BDAT 15728641 LAST")
        noop = client.command(b"NOOP")
        mail_after_reset = client.command(b"MAIL FROM:<>")
        rset = client.command(b"RSET")
        quit_reply = client.quit()

    _check(zero == (b"250 2.0.0 0 bytes received\r\n",), zero)
    _check(
        oversize == (b"552 5.3.4 Message size exceeds limit of 15728640 bytes\r\n",),
        oversize,
    )
    _check(noop == (b"250 OK\r\n",), noop)
    _check(mail_after_reset == (b"250 2.1.0 Sender OK\r\n",), mail_after_reset)
    _check(rset == (b"250 2.0.0 Reset OK\r\n",), rset)
    return {
        "greeting": smtp_greeting_snapshot(),
        "ehlo": smtp_reply_snapshot(ehlo, hostname),
        "mail_from": smtp_reply_snapshot(mail_from, hostname),
        "rcpt_to": smtp_reply_snapshot(rcpt_to, hostname),
        "zero_non_last": smtp_reply_snapshot(zero, hostname),
        "oversize_without_payload": smtp_reply_snapshot(oversize, hostname),
        "session_after_oversize": {
            "noop": smtp_reply_snapshot(noop, hostname),
            "mail_from": smtp_reply_snapshot(mail_after_reset, hostname),
            "rset": smtp_reply_snapshot(rset, hostname),
        },
        "quit": smtp_reply_snapshot(quit_reply, hostname),
    }


def _temporary_files(workspace: Path) -> tuple[str, ...]:
    roots = (workspace / "java-tmp", workspace / "tmp", workspace / "maildir" / "temp")
    found: list[str] = []
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.is_file() and (
                path.name.startswith("smtp-") or path.name.startswith("incoming_")
            ):
                found.append(path.relative_to(workspace).as_posix())
    return tuple(sorted(found))


def _wait_for_no_delivery(
    target: RuntimeTarget,
    *,
    message_id: str,
    maildir_before: dict[str, tuple[int, str]],
    redis_before: int | None,
    workspace: Path,
) -> dict[str, Any]:
    deadline = time.monotonic() + 3.0
    stable_since: float | None = None
    last = {}
    while time.monotonic() < deadline:
        maildir_after = _maildir_files(workspace, deadline=deadline)
        redis_after = _redis_state(target, _COUNT_KEY, deadline=deadline)[0]
        index_count = _index_count(target, message_id, deadline=deadline)
        temp_files = _temporary_files(workspace)
        added = sorted(set(maildir_after).difference(maildir_before))
        removed = sorted(set(maildir_before).difference(maildir_after))
        clean = (
            not added
            and not removed
            and index_count == 0
            and redis_after == redis_before
            and not temp_files
        )
        if clean:
            now = time.monotonic()
            if stable_since is None:
                stable_since = now
            elif now - stable_since >= 0.5:
                return {
                    "maildir_unchanged": True,
                    "index_rows": 0,
                    "redis_before": redis_before,
                    "redis_after": redis_after,
                    "temporary_files": [],
                }
        else:
            stable_since = None
        last = {
            "added": added,
            "removed": removed,
            "index_rows": index_count,
            "redis_after": redis_after,
            "temporary_files": list(temp_files),
        }
        time.sleep(0.05)
    raise AssertionError(f"SMTP disconnect left delivery state: {last!r}")


def _index_total(target: RuntimeTarget, *, deadline: float) -> int:
    with _connect_postgres(target, deadline=deadline) as connection:
        _set_statement_timeout(connection, deadline=deadline)
        row = connection.execute("SELECT count(*) FROM email_index").fetchone()
    if row is None or len(row) != 1 or not isinstance(row[0], int):
        raise AssertionError(f"SMTP contract violation: invalid index count row {row!r}")
    return row[0]


def _wait_for_unchanged_storage(
    target: RuntimeTarget,
    *,
    maildir_before: dict[str, tuple[int, str]],
    redis_before: int | None,
    index_before: int,
    workspace: Path,
) -> dict[str, Any]:
    deadline = time.monotonic() + 3.0
    stable_since: float | None = None
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        maildir_after = _maildir_files(workspace, deadline=deadline)
        redis_after = _redis_state(target, _COUNT_KEY, deadline=deadline)[0]
        index_after = _index_total(target, deadline=deadline)
        temp_files = _temporary_files(workspace)
        clean = (
            maildir_after == maildir_before
            and redis_after == redis_before
            and index_after == index_before
            and not temp_files
        )
        if clean:
            now = time.monotonic()
            if stable_since is None:
                stable_since = now
            elif now - stable_since >= 0.5:
                return {
                    "maildir_unchanged": True,
                    "index_before": index_before,
                    "index_after": index_after,
                    "redis_before": redis_before,
                    "redis_after": redis_after,
                    "temporary_files": [],
                }
        else:
            stable_since = None
        last = {
            "maildir_changed": maildir_after != maildir_before,
            "redis_after": redis_after,
            "index_after": index_after,
            "temporary_files": list(temp_files),
        }
        time.sleep(0.05)
    raise AssertionError(f"SMTP transaction changed storage state: {last!r}")


def _capture_data_disconnect(target: RuntimeTarget) -> dict[str, Any]:
    workspace = target.workspace
    if workspace is None:
        raise AssertionError("SMTP target is not started")
    message_id = "<bb-data-partial-001@example.test>"
    partial = _simple_message("bb-data-partial-001", message_id, b"partial body")
    before = _maildir_files(workspace, deadline=time.monotonic() + 5.0)
    redis_before = _redis_state(target, _COUNT_KEY, deadline=time.monotonic() + 5.0)[0]
    client, hostname = open_smtp_client(target)
    try:
        smtp_ehlo(client, hostname)
        mail_from = client.command(b"MAIL FROM:<>")
        rcpt_to = client.command(b"RCPT TO:<qa@example.test>")
        data_ready = client.command(b"DATA")
        _check(mail_from[0].startswith(b"250 "), mail_from)
        _check(rcpt_to[0].startswith(b"250 "), rcpt_to)
        _check(data_ready[0].startswith(b"354 "), data_ready)
        client.stream.sendall(partial)
    finally:
        client.close()
    no_delivery = _wait_for_no_delivery(
        target,
        message_id=message_id,
        maildir_before=before,
        redis_before=redis_before,
        workspace=workspace,
    )
    recovery = capture_delivery(
        target,
        mode="data",
        subject=_RECOVERY_DATA_SUBJECT,
        message_id=_RECOVERY_DATA_ID,
        message=_RECOVERY_DATA_MESSAGE,
    )
    return {
        "mode": "DATA",
        "partial": {"message_id": message_id, "bytes_sent": len(partial), **no_delivery},
        "recovery": recovery,
    }


def _capture_bdat_disconnect(target: RuntimeTarget) -> dict[str, Any]:
    workspace = target.workspace
    if workspace is None:
        raise AssertionError("SMTP target is not started")
    message_id = "<bb-bdat-partial-001@example.test>"
    partial = _simple_message("bb-bdat-partial-001", message_id, b"partial body")
    declared = len(partial) + 40
    before = _maildir_files(workspace, deadline=time.monotonic() + 5.0)
    redis_before = _redis_state(target, _COUNT_KEY, deadline=time.monotonic() + 5.0)[0]
    client, hostname = open_smtp_client(target)
    try:
        smtp_ehlo(client, hostname)
        mail_from = client.command(b"MAIL FROM:<>")
        rcpt_to = client.command(b"RCPT TO:<qa@example.test>")
        _check(mail_from[0].startswith(b"250 "), mail_from)
        _check(rcpt_to[0].startswith(b"250 "), rcpt_to)
        command = b"BDAT " + str(declared).encode("ascii") + b" LAST\r\n"
        client.stream.sendall(command + partial)
    finally:
        client.close()
    no_delivery = _wait_for_no_delivery(
        target,
        message_id=message_id,
        maildir_before=before,
        redis_before=redis_before,
        workspace=workspace,
    )
    recovery = capture_delivery(
        target,
        mode="bdat",
        subject=_RECOVERY_BDAT_SUBJECT,
        message_id=_RECOVERY_BDAT_ID,
        message=_RECOVERY_BDAT_MESSAGE,
    )
    return {
        "mode": "BDAT",
        "partial": {
            "message_id": message_id,
            "declared_bytes": declared,
            "bytes_sent": len(partial),
            **no_delivery,
        },
        "recovery": recovery,
    }


def _capture_data_tail_command_evidence(target: RuntimeTarget) -> dict[str, Any]:
    workspace = target.workspace
    if workspace is None:
        raise AssertionError("SMTP target is not started")
    message_id = "<bb-data-tail-command-001@example.test>"
    subject = "bb-data-tail-command-001"
    message = _simple_message(subject, message_id, b"tail command body\r\n")
    maildir_before = _maildir_files(workspace, deadline=time.monotonic() + 5.0)
    _check(_index_count(target, message_id) == 0, message_id)
    redis_before = _redis_state(target, _COUNT_KEY, deadline=time.monotonic() + 5.0)[0]
    started_at = datetime.now(UTC)
    client, hostname = open_smtp_client(target)
    with client:
        ehlo = smtp_ehlo(client, hostname)
        mail_from = client.command(b"MAIL FROM:<>")
        rcpt_to = client.command(b"RCPT TO:<qa@example.test>")
        ready = client.command(b"DATA")
        encoded = _encode_smtp_data(message) + b"NOOP\r\n"
        client.stream.sendall(encoded)
        accepted = read_smtp_reply(client.stream)
        _assert_no_socket_data(client.stream, timeout=0.15)
        follow_up = client.command(b"NOOP")
        quit_reply = client.quit()
    return {
        "difference_id": "smtp-data-terminator-command-loss",
        "message": bytes_snapshot(message),
        "wire": {
            "greeting": smtp_greeting_snapshot(),
            "ehlo": smtp_reply_snapshot(ehlo, hostname),
            "mail_from": smtp_reply_snapshot(mail_from, hostname),
            "rcpt_to": smtp_reply_snapshot(rcpt_to, hostname),
            "data_ready": smtp_reply_snapshot(ready, hostname),
            "coalesced_payload": bytes_snapshot(encoded),
            "accepted": smtp_reply_snapshot(accepted, hostname, accepted=True),
            "no_unsolicited_tail_reply": True,
            "follow_up_noop": smtp_reply_snapshot(follow_up, hostname),
            "quit": smtp_reply_snapshot(quit_reply, hostname),
        },
        "storage": _storage_snapshot(
            target,
            message_id=message_id,
            subject=subject,
            message=message,
            hostname=hostname,
            received_protocol=b"ESMTP",
            maildir_before=maildir_before,
            redis_before=redis_before,
            started_at=started_at,
        ),
    }


def _capture_bdat_zero_last_no_delivery(target: RuntimeTarget) -> dict[str, Any]:
    workspace = target.workspace
    if workspace is None:
        raise AssertionError("SMTP target is not started")
    before = _maildir_files(workspace, deadline=time.monotonic() + 5.0)
    redis_before = _redis_state(target, _COUNT_KEY, deadline=time.monotonic() + 5.0)[0]
    index_before = _index_total(target, deadline=time.monotonic() + 5.0)
    client, hostname = open_smtp_client(target)
    with client:
        ehlo = smtp_ehlo(client, hostname)
        empty_mail_from = client.command(b"MAIL FROM:<>")
        empty_rcpt_to = client.command(b"RCPT TO:<qa@example.test>")
        empty_zero_last = client.command(b"BDAT 0 LAST")
        empty_noop = client.command(b"NOOP")
        data_mail_from = client.command(b"MAIL FROM:<>")
        data_rcpt_to = client.command(b"RCPT TO:<qa@example.test>")
        data_chunk = client.bdat(_ZERO_LAST_MESSAGE)
        data_zero_last = client.command(b"BDAT 0 LAST")
        data_noop = client.command(b"NOOP")
        quit_reply = client.quit()
    _check(empty_zero_last == (b"250 2.0.0 0 bytes received\r\n",), empty_zero_last)
    _check(
        data_chunk == (f"250 2.0.0 {len(_ZERO_LAST_MESSAGE)} bytes received\r\n".encode(),),
        data_chunk,
    )
    _check(data_zero_last == (b"250 2.0.0 0 bytes received\r\n",), data_zero_last)
    return {
        "message": bytes_snapshot(_ZERO_LAST_MESSAGE),
        "wire": {
            "greeting": smtp_greeting_snapshot(),
            "ehlo": smtp_reply_snapshot(ehlo, hostname),
            "empty_transaction": {
                "mail_from": smtp_reply_snapshot(empty_mail_from, hostname),
                "rcpt_to": smtp_reply_snapshot(empty_rcpt_to, hostname),
                "zero_last": smtp_reply_snapshot(empty_zero_last, hostname),
                "noop": smtp_reply_snapshot(empty_noop, hostname),
            },
            "complete_non_last_then_zero_last": {
                "mail_from": smtp_reply_snapshot(data_mail_from, hostname),
                "rcpt_to": smtp_reply_snapshot(data_rcpt_to, hostname),
                "data_chunk": smtp_reply_snapshot(data_chunk, hostname),
                "zero_last": smtp_reply_snapshot(data_zero_last, hostname),
                "noop": smtp_reply_snapshot(data_noop, hostname),
            },
            "quit": smtp_reply_snapshot(quit_reply, hostname),
        },
        "storage": _wait_for_unchanged_storage(
            target,
            maildir_before=before,
            redis_before=redis_before,
            index_before=index_before,
            workspace=workspace,
        ),
    }


def _capture_coalesced_bdat_stall_evidence(target: RuntimeTarget) -> dict[str, Any]:
    workspace = target.workspace
    if workspace is None:
        raise AssertionError("SMTP target is not started")
    before = _maildir_files(workspace, deadline=time.monotonic() + 5.0)
    redis_before = _redis_state(target, _COUNT_KEY, deadline=time.monotonic() + 5.0)[0]
    index_before = _index_total(target, deadline=time.monotonic() + 5.0)
    client, hostname = open_smtp_client(target)
    try:
        ehlo = smtp_ehlo(client, hostname)
        command = (
            b"MAIL FROM:<>\r\n"
            b"RCPT TO:<qa@example.test>\r\n"
            + b"BDAT "
            + str(len(_COALESCED_BDAT_MESSAGE)).encode("ascii")
            + b" LAST\r\n"
            + _COALESCED_BDAT_MESSAGE
        )
        client.stream.sendall(command)
        mail_from = read_smtp_reply(client.stream)
        rcpt_to = read_smtp_reply(client.stream)
        _assert_no_socket_data(client.stream, timeout=0.25)
        client.stream.sendall(b"NOOP\r\n")
        _assert_no_socket_data(client.stream, timeout=0.25)
    finally:
        client.close()
    return {
        "difference_id": "smtp-bdat-coalesced-prerequisite-state-stall",
        "message": bytes_snapshot(_COALESCED_BDAT_MESSAGE),
        "wire": {
            "greeting": smtp_greeting_snapshot(),
            "ehlo": smtp_reply_snapshot(ehlo, hostname),
            "coalesced_write": bytes_snapshot(command),
            "mail_from": smtp_reply_snapshot(mail_from, hostname),
            "rcpt_to": smtp_reply_snapshot(rcpt_to, hostname),
            "bdat_reply_within_250_ms": False,
            "follow_up_noop_reply_within_250_ms": False,
            "connection_closed_by_client": True,
        },
        "storage": _wait_for_unchanged_storage(
            target,
            maildir_before=before,
            redis_before=redis_before,
            index_before=index_before,
            workspace=workspace,
        ),
    }


def _contract(mode: str, message: bytes, message_id: str) -> dict[str, Any]:
    return {
        "protocol": "smtp",
        "operation": "inbound-data-framing",
        "mode": mode,
        "message_id": message_id,
        "message_sha256": hashlib.sha256(message).hexdigest(),
        "max_message_size_bytes": _MAX_MESSAGE_SIZE,
        "requirements": [
            "incremental-framing",
            "bounded-buffering",
            "exact-bdat-octet-count",
            "partial-disconnect-cleans-state",
            "fresh-session-recovery",
        ],
        "side_effects": ["maildir", "postgres:email_index", "redis:mail-count"],
    }


SMTP_DATA_SCENARIOS = (
    Scenario(
        "smtp/data/fragmented-terminator-storage",
        _capture_fragmented_data,
        _NORMALIZERS + ("smtp:data-dot-unstuff",),
        _contract("DATA", _DATA_MESSAGE, _DATA_MESSAGE_ID),
    ),
    Scenario(
        "smtp/bdat/fragmented-binary-storage",
        _capture_fragmented_bdat,
        _NORMALIZERS + ("smtp:bdat-exact-octet-count",),
        _contract("BDAT", _BDAT_MESSAGE, _BDAT_MESSAGE_ID),
    ),
    Scenario(
        "smtp/bdat/coalesced-multi-chunk-storage",
        _capture_coalesced_bdat_chunks,
        _NORMALIZERS + ("smtp:bdat-coalesced-multi-chunk",),
        {
            **_contract(
                "BDAT",
                _COALESCED_CHUNKS_MESSAGE,
                _COALESCED_CHUNKS_MESSAGE_ID,
            ),
            "coalesced_after_confirmed_prerequisites": True,
            "chunk_count": 2,
            "reply_per_chunk": True,
        },
    ),
    Scenario(
        "smtp/bdat/zero-and-oversize-state",
        _capture_bdat_size_and_zero_state,
        _NORMALIZERS,
        {
            "protocol": "smtp",
            "operation": "bdat-size-and-zero-state",
            "zero_non_last_reply": "250 2.0.0 0 bytes received",
            "oversize_declared_bytes": _MAX_MESSAGE_SIZE + 1,
            "oversize_rejected_before_payload": True,
            "oversize_resets_transaction": True,
            "connection_remains_usable": True,
        },
    ),
    Scenario(
        "smtp/bdat/zero-last-transaction-state",
        _capture_bdat_zero_last_no_delivery,
        _NORMALIZERS + ("smtp:bdat-zero-last-state",),
        {
            "protocol": "smtp",
            "operation": "bdat-zero-last-transaction-state",
            "empty_zero_last": "250 2.0.0 0 bytes received",
            "non_last_chunk_is_acknowledged": True,
            "non_last_chunk_then_zero_last": "discarded-without-delivery",
            "transaction_resets": True,
            "connection_remains_usable": True,
        },
    ),
    Scenario(
        "smtp/data/partial-disconnect-recovery",
        _capture_data_disconnect,
        _NORMALIZERS + ("smtp:disconnect-no-delivery",),
        {
            "protocol": "smtp",
            "operation": "partial-disconnect-recovery",
            "mode": "DATA",
            "partial_delivery": "no-maildir-no-index-no-temp",
            "fresh_session": "normal-delivery-after-disconnect",
        },
    ),
    Scenario(
        "smtp/bdat/partial-disconnect-recovery",
        _capture_bdat_disconnect,
        _NORMALIZERS + ("smtp:disconnect-no-delivery",),
        {
            "protocol": "smtp",
            "operation": "partial-disconnect-recovery",
            "mode": "BDAT",
            "partial_delivery": "no-maildir-no-index-no-temp",
            "fresh_session": "normal-delivery-after-disconnect",
        },
    ),
)

SMTP_DATA_ORACLE_EVIDENCE_SCENARIOS = (
    Scenario(
        "smtp/data/oracle-terminator-tail-command-loss",
        _capture_data_tail_command_evidence,
        _NORMALIZERS + ("smtp:oracle-tail-command-loss",),
        {
            "protocol": "smtp",
            "operation": "oracle-security-evidence",
            "difference_id": "smtp-data-terminator-command-loss",
        },
    ),
    Scenario(
        "smtp/bdat/oracle-coalesced-prerequisite-state-stall",
        _capture_coalesced_bdat_stall_evidence,
        _NORMALIZERS + ("smtp:oracle-coalesced-prerequisite-state-stall",),
        {
            "protocol": "smtp",
            "operation": "oracle-security-evidence",
            "difference_id": "smtp-bdat-coalesced-prerequisite-state-stall",
            "candidate_deadline_ms": 5_000,
        },
    ),
)
