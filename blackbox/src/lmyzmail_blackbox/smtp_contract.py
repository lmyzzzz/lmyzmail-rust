from __future__ import annotations

import hashlib
import math
import os
import re
import stat
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any, cast

import psycopg
import redis

from .differential import RuntimeTarget, Scenario
from .protocols import RawSmtpClient
from .snapshots import bytes_snapshot

_QA_ADDRESS = "qa@example.test"
_FOLDER = "spam"
_COUNT_KEY = f"mail:count:{_QA_ADDRESS}:{_FOLDER}"
_GREETING = re.compile(
    rb"220 (?P<hostname>[^\s]+) ESMTP lmyzmail SMTP Server 2\.8\.0 - "
    rb"(?:Brrrrr )?Skibidi (?:[dD][oO][pPmM] ){1,5}"
    rb"(?:(?:[yY][eE][sS] [yY][eE][sS])|(?:[nN][oO] [nN][oO]))!\r\n"
)
_ACCEPTED = re.compile(
    rb"250 2\.0\.0 Message accepted for delivery, id="
    rb"(?P<session>[0-9a-f]{8})\r\n"
)
_FILE_NAME = re.compile(rb"(?P<timestamp>\d{14}\.\d{3})-(?P<monotonic>\d+)-(?P<counter>\d+)\.eml")
_RECEIVED_ID = re.compile(rb"( with (?P<protocol>ESMTPS?) id )[0-9A-F]{14}(\r\n)")
_RECEIVED_AT = re.compile(rb"(;\r\n\t)(?P<value>[^\r\n]+)(\r\nAuthentication-Results:)")
_JAVA_RFC_1123 = re.compile(
    rb"(?P<weekday>Mon|Tue|Wed|Thu|Fri|Sat|Sun), "
    rb"(?P<day>[1-9]|[12][0-9]|3[01]) "
    rb"(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) "
    rb"(?P<year>[0-9]{4}) "
    rb"(?P<hour>[01][0-9]|2[0-3]):(?P<minute>[0-5][0-9]):(?P<second>[0-5][0-9]) GMT"
)
_MONTHS = {
    month: index
    for index, month in enumerate(
        (
            b"Jan",
            b"Feb",
            b"Mar",
            b"Apr",
            b"May",
            b"Jun",
            b"Jul",
            b"Aug",
            b"Sep",
            b"Oct",
            b"Nov",
            b"Dec",
        ),
        start=1,
    )
}
_WEEKDAYS = (b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat", b"Sun")
_MAILDIR_ENTRY_LIMIT = 10_000
_DELIVERY_SETTLE_SECONDS = 0.1
_STORAGE_TIMEOUT_SECONDS = 15.0
_MAILDIR_HASH_CHUNK_BYTES = 1024 * 1024
_MAX_CAPTURED_MESSAGE_BYTES = 16 * 1024 * 1024

type _MaildirSnapshot = dict[str, tuple[int, str]]
type SmtpSessionSetup = Callable[[RuntimeTarget, RawSmtpClient, bytes], dict[str, Any]]


def _check(condition: bool, details: object) -> None:
    if not condition:
        raise AssertionError(f"SMTP contract violation: {details!r}")


def _remaining(deadline: float, operation: str) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise AssertionError(
            f"SMTP contract violation: storage deadline expired during {operation}"
        )
    return remaining


def _endpoint(target: RuntimeTarget) -> tuple[str, int]:
    ports = target.ports
    if ports is None:
        raise AssertionError("SMTP target is not started")
    return "127.0.0.1", ports.smtp


def open_smtp_client(
    target: RuntimeTarget,
    *,
    source: str | None = None,
) -> tuple[RawSmtpClient, bytes]:
    host, port = _endpoint(target)
    client = RawSmtpClient.connect(host, port, timeout=10.0, source=source)
    try:
        _check(len(client.greeting) == 1, client.greeting)
        match = _GREETING.fullmatch(client.greeting[0])
        if match is None:
            raise AssertionError(f"invalid SMTP greeting: {client.greeting!r}")
        return client, match.group("hostname")
    except BaseException:
        client.close()
        raise


def smtp_reply_snapshot(
    reply: tuple[bytes, ...],
    hostname: bytes,
    *,
    accepted: bool = False,
) -> list[str]:
    if accepted:
        _check(len(reply) == 1, reply)
        _check(_ACCEPTED.fullmatch(reply[0]) is not None, reply)
        reply = (b"250 2.0.0 Message accepted for delivery, id=<session-id>\r\n",)
    normalized = tuple(line.replace(hostname, b"<hostname>") for line in reply)
    return [line.decode("ascii", errors="strict") for line in normalized]


def smtp_greeting_snapshot() -> list[str]:
    return ["220 <hostname> ESMTP lmyzmail SMTP Server 2.8.0 - <skibidi-expression>\r\n"]


def smtp_ehlo(
    client: RawSmtpClient,
    hostname: bytes,
    *,
    advertise_starttls: bool = False,
) -> tuple[bytes, ...]:
    reply = client.command(b"EHLO blackbox.example")
    extensions = [
        b"250-" + hostname + b" Hello blackbox.example\r\n",
        b"250-PIPELINING\r\n",
        b"250-SIZE 15728640\r\n",
        b"250-8BITMIME\r\n",
        b"250-CHUNKING\r\n",
    ]
    if advertise_starttls:
        extensions.append(b"250-STARTTLS\r\n")
    extensions.extend(
        (
            b"250-ENHANCEDSTATUSCODES\r\n",
            b"250-SMTPUTF8\r\n",
            b"250 SKIBIDITOILET\r\n",
        )
    )
    _check(
        reply == tuple(extensions),
        reply,
    )
    return reply


def _redis_state(
    target: RuntimeTarget,
    key: str,
    *,
    deadline: float,
) -> tuple[int | None, bytes, int]:
    ports = target.ports
    if ports is None:
        raise AssertionError("SMTP target is not started")
    timeout = _remaining(deadline, "Redis connect")
    client = redis.Redis(
        host="127.0.0.1",
        port=ports.redis,
        socket_connect_timeout=timeout,
        socket_timeout=timeout,
    )
    try:
        with client.pipeline(transaction=False) as pipeline:
            values = cast(
                list[Any],
                pipeline.get(key).type(key).pttl(key).execute(),
            )
    except redis.RedisError as error:
        if time.monotonic() >= deadline:
            raise AssertionError(
                "SMTP contract violation: storage deadline expired during Redis query"
            ) from error
        raise
    finally:
        client.close()
    _remaining(deadline, "Redis query")
    _check(len(values) == 3, values)
    raw_value, raw_type, raw_pttl = values
    _check(raw_value is None or isinstance(raw_value, bytes), raw_value)
    _check(isinstance(raw_type, bytes), raw_type)
    _check(isinstance(raw_pttl, int), raw_pttl)
    value = None if raw_value is None else int(raw_value)
    return value, raw_type, raw_pttl


def _parse_java_rfc1123(value: bytes) -> datetime:
    match = _JAVA_RFC_1123.fullmatch(value)
    if match is None:
        raise AssertionError(f"SMTP contract violation: invalid Java RFC 1123 date {value!r}")
    try:
        parsed = datetime(
            int(match.group("year")),
            _MONTHS[match.group("month")],
            int(match.group("day")),
            int(match.group("hour")),
            int(match.group("minute")),
            int(match.group("second")),
            tzinfo=UTC,
        )
    except (KeyError, ValueError) as error:
        raise AssertionError(
            f"SMTP contract violation: invalid Java RFC 1123 date {value!r}"
        ) from error
    _check(_WEEKDAYS[parsed.weekday()] == match.group("weekday"), value)
    return parsed


def _parse_maildir_filename_time(file_name: str) -> datetime:
    try:
        encoded = file_name.encode("ascii")
    except UnicodeEncodeError as error:
        raise AssertionError(
            f"SMTP contract violation: non-ASCII Maildir filename {file_name!r}"
        ) from error
    match = _FILE_NAME.fullmatch(encoded)
    if match is None:
        raise AssertionError(f"SMTP contract violation: invalid Maildir filename {file_name!r}")
    try:
        return datetime.strptime(
            match.group("timestamp").decode("ascii"), "%Y%m%d%H%M%S.%f"
        ).replace(tzinfo=UTC)
    except ValueError as error:
        raise AssertionError(
            f"SMTP contract violation: invalid Maildir UTC timestamp {file_name!r}"
        ) from error


def _file_identity(path: Path, *, deadline: float | None) -> tuple[int, str]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    digest = hashlib.sha256()
    total = 0
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        _check(stat.S_ISREG(metadata.st_mode), path)
        while True:
            if deadline is not None:
                _remaining(deadline, "Maildir hash")
            chunk = stream.read(_MAILDIR_HASH_CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            digest.update(chunk)
    if deadline is not None:
        _remaining(deadline, "Maildir hash")
    _check(total == metadata.st_size, (path, total, metadata.st_size))
    return total, digest.hexdigest()


def _maildir_files(
    workspace: Path,
    *,
    deadline: float | None = None,
) -> _MaildirSnapshot:
    root = workspace / "maildir"
    _check(not root.is_symlink(), root)
    if not root.exists():
        return {}
    _check(root.is_dir(), root)

    files: _MaildirSnapshot = {}
    pending = [root]
    entry_count = 0
    while pending:
        if deadline is not None:
            _remaining(deadline, "Maildir traversal")
        directory = pending.pop()
        _check(not directory.is_symlink() and directory.is_dir(), directory)
        with os.scandir(directory) as entries:
            for entry in entries:
                if deadline is not None:
                    _remaining(deadline, "Maildir traversal")
                entry_count += 1
                _check(entry_count <= _MAILDIR_ENTRY_LIMIT, "Maildir entry limit exceeded")
                entry_path = Path(entry.path)
                _check(not entry.is_symlink(), entry_path)
                if entry.is_dir(follow_symlinks=False):
                    pending.append(entry_path)
                elif entry.is_file(follow_symlinks=False):
                    relative = entry_path.relative_to(root).as_posix()
                    files[relative] = _file_identity(entry_path, deadline=deadline)
                else:
                    raise AssertionError(
                        f"SMTP contract violation: unsupported Maildir entry {entry_path!r}"
                    )
    return files


def _check_maildir_delta(
    before: Mapping[str, tuple[int, str]],
    after: Mapping[str, tuple[int, str]],
    expected: str,
) -> None:
    removed = sorted(set(before).difference(after))
    _check(not removed, (removed, "pre-existing Maildir files disappeared"))
    modified = sorted(path for path, identity in before.items() if after.get(path) != identity)
    _check(not modified, (modified, "pre-existing Maildir files changed"))
    residual_temp = _maildir_temp_files(after)
    _check(not residual_temp, ("residual Maildir temp files", residual_temp))
    added = set(after).difference(before)
    _check(added == {expected}, (added, expected))


def _maildir_temp_files(files: Mapping[str, tuple[int, str]]) -> tuple[str, ...]:
    return tuple(
        sorted(
            path
            for path in files
            if "temp" in PurePosixPath(path).parts or PurePosixPath(path).name.endswith(".tmp")
        )
    )


def _assert_path_chain_without_symlinks(workspace: Path, path: Path) -> None:
    _check(not workspace.is_symlink(), workspace)
    try:
        relative = path.relative_to(workspace)
    except ValueError as error:
        raise AssertionError(
            f"SMTP contract violation: path escaped workspace: {path!r}"
        ) from error
    current = workspace
    for component in relative.parts:
        current /= component
        _check(not current.is_symlink(), current)


def _connect_postgres(
    target: RuntimeTarget,
    *,
    deadline: float,
) -> psycopg.Connection[tuple[Any, ...]]:
    ports = target.ports
    if ports is None:
        raise AssertionError("SMTP target is not started")
    remaining = _remaining(deadline, "PostgreSQL connect")
    connection = psycopg.connect(
        host="127.0.0.1",
        port=ports.postgres,
        user="lmyzmail_test",
        dbname="lmyzmail",
        connect_timeout=min(5, max(1, math.ceil(remaining))),
        autocommit=True,
    )
    _remaining(deadline, "PostgreSQL connect")
    return connection


def _set_statement_timeout(
    connection: psycopg.Connection[tuple[Any, ...]],
    *,
    deadline: float,
) -> None:
    milliseconds = max(1, math.floor(_remaining(deadline, "PostgreSQL query") * 1000))
    connection.execute(
        "SELECT set_config('statement_timeout', %s, false)",
        (f"{milliseconds}ms",),
    ).fetchone()


def _index_count(
    target: RuntimeTarget,
    message_id: str,
    *,
    deadline: float | None = None,
) -> int:
    effective_deadline = time.monotonic() + 5.0 if deadline is None else deadline
    try:
        with _connect_postgres(target, deadline=effective_deadline) as connection:
            _set_statement_timeout(connection, deadline=effective_deadline)
            row = connection.execute(
                "SELECT count(*) FROM email_index WHERE mailbox_address = %s AND message_id = %s",
                (_QA_ADDRESS, message_id),
            ).fetchone()
            _remaining(effective_deadline, "PostgreSQL count query")
    except psycopg.errors.QueryCanceled as error:
        raise AssertionError(
            "SMTP contract violation: storage deadline expired during PostgreSQL query"
        ) from error
    if row is None:
        raise AssertionError("email_index count query returned no row")
    return cast(int, row[0])


def _index_rows(
    connection: psycopg.Connection[tuple[Any, ...]],
    message_id: str,
    *,
    folder: str = _FOLDER,
    deadline: float,
) -> list[tuple[Any, ...]]:
    _set_statement_timeout(connection, deadline=deadline)
    try:
        rows = connection.execute(
            "SELECT id, mailbox_address, folder, subdirectory, file_name, "
            "subject, from_address, to_addresses, received_at, has_attachments, "
            "size_bytes, message_id, indexed_at FROM email_index "
            "WHERE mailbox_address = %s AND folder = %s AND message_id = %s "
            "ORDER BY indexed_at ASC, id ASC",
            (_QA_ADDRESS, folder, message_id),
        ).fetchall()
    except psycopg.errors.QueryCanceled as error:
        raise AssertionError(
            "SMTP contract violation: storage deadline expired during PostgreSQL query"
        ) from error
    _remaining(deadline, "PostgreSQL index query")
    return list(rows)


def _wait_for_delivery_state(
    target: RuntimeTarget,
    connection: psycopg.Connection[tuple[Any, ...]],
    message_id: str,
    *,
    folder: str = _FOLDER,
    maildir_before: Mapping[str, tuple[int, str]],
    redis_before: int | None,
    deadline: float,
) -> tuple[tuple[Any, ...], _MaildirSnapshot, tuple[int | None, bytes, int]]:
    workspace = target.workspace
    if workspace is None:
        raise AssertionError("SMTP target is not started")
    expected_redis = (redis_before or 0) + 1
    stable_since: float | None = None
    last_details: object = "delivery state was not observed"

    while True:
        rows = _index_rows(connection, message_id, folder=folder, deadline=deadline)
        maildir_after = _maildir_files(workspace, deadline=deadline)
        count_key = f"mail:count:{_QA_ADDRESS}:{folder}"
        redis_state = _redis_state(target, count_key, deadline=deadline)
        expected_path: str | None = None
        if len(rows) == 1:
            subdirectory = rows[0][3]
            file_name = rows[0][4]
            if isinstance(subdirectory, int) and isinstance(file_name, str):
                expected_path = f"{_QA_ADDRESS}/{folder}/{subdirectory}/{file_name}"
        added = set(maildir_after).difference(maildir_before)
        removed = set(maildir_before).difference(maildir_after)
        modified = {
            path for path, identity in maildir_before.items() if maildir_after.get(path) != identity
        }
        ready = (
            len(rows) == 1
            and not removed
            and not modified
            and expected_path is not None
            and added == {expected_path}
            and not _maildir_temp_files(maildir_after)
            and redis_state == (expected_redis, b"string", -1)
        )
        now = time.monotonic()
        if ready:
            if stable_since is None:
                stable_since = now
            elif now - stable_since >= _DELIVERY_SETTLE_SECONDS:
                _check_maildir_delta(
                    maildir_before,
                    maildir_after,
                    cast(str, expected_path),
                )
                return rows[0], maildir_after, redis_state
        else:
            stable_since = None
        last_details = {
            "database_rows": len(rows),
            "maildir_added": sorted(added),
            "maildir_removed": sorted(removed),
            "maildir_modified": sorted(modified),
            "maildir_temp": _maildir_temp_files(maildir_after),
            "expected_path": expected_path,
            "redis": redis_state,
        }
        remaining = _remaining(deadline, "delivery convergence")
        if remaining <= _DELIVERY_SETTLE_SECONDS and ready:
            raise AssertionError(
                "SMTP contract violation: delivery did not remain stable before "
                f"the deadline: {last_details!r}"
            )
        time.sleep(min(0.05, remaining))


def _replace_once(value: bytes, old: bytes, new: bytes) -> bytes:
    _check(value.count(old) == 1, (old, value[:1000]))
    return value.replace(old, new, 1)


def _normalized_mail_snapshot(
    raw: bytes,
    *,
    hostname: bytes,
    message: bytes,
    received_protocol: bytes,
    started_at: datetime,
    observed_at: datetime,
) -> dict[str, Any]:
    _check(raw.endswith(message), "stored message does not preserve submitted suffix")
    prefix = raw[: -len(message)]
    prefix = _replace_once(
        prefix,
        b"\r\n\tby " + hostname + b" with ",
        b"\r\n\tby <hostname> with ",
    )
    prefix = _replace_once(
        prefix,
        b"Authentication-Results: " + hostname + b";",
        b"Authentication-Results: <hostname>;",
    )
    received_id_matches = tuple(_RECEIVED_ID.finditer(prefix))
    _check(len(received_id_matches) == 1, prefix[:1000])
    _check(received_id_matches[0].group("protocol") == received_protocol, prefix[:1000])
    prefix = _RECEIVED_ID.sub(rb"\1<received-id>\3", prefix, count=1)

    received_at_match = _RECEIVED_AT.search(prefix)
    if received_at_match is None:
        raise AssertionError(f"Received timestamp is missing: {prefix[:1000]!r}")
    received_at = _parse_java_rfc1123(received_at_match.group("value"))
    _check(
        started_at - timedelta(seconds=5) <= received_at.astimezone(UTC),
        received_at,
    )
    _check(
        received_at.astimezone(UTC) <= observed_at + timedelta(seconds=5),
        received_at,
    )
    prefix, received_at_count = _RECEIVED_AT.subn(
        rb"\1<received-at>\3",
        prefix,
        count=1,
    )
    _check(received_at_count == 1, prefix[:1000])
    return cast(dict[str, Any], bytes_snapshot(prefix + message))


def _storage_snapshot(
    target: RuntimeTarget,
    *,
    message_id: str,
    subject: str,
    message: bytes,
    hostname: bytes,
    received_protocol: bytes,
    maildir_before: Mapping[str, tuple[int, str]],
    redis_before: int | None,
    started_at: datetime,
    expected_folder: str = _FOLDER,
    expected_from_address: str | None = None,
    expected_to_addresses: str = "[]",
    expected_has_attachments: bool = False,
) -> dict[str, Any]:
    deadline = time.monotonic() + _STORAGE_TIMEOUT_SECONDS
    with _connect_postgres(target, deadline=deadline) as connection:
        row, maildir_after, redis_state = _wait_for_delivery_state(
            target,
            connection,
            message_id,
            folder=expected_folder,
            maildir_before=maildir_before,
            redis_before=redis_before,
            deadline=deadline,
        )
    observed_at = datetime.now(UTC)
    (
        identity,
        mailbox_address,
        folder,
        subdirectory,
        file_name,
        actual_subject,
        from_address,
        to_addresses,
        received_at,
        has_attachments,
        size_bytes,
        actual_message_id,
        indexed_at,
    ) = row

    _check(isinstance(identity, int) and identity > 0, identity)
    _check(mailbox_address == _QA_ADDRESS, mailbox_address)
    _check(folder == expected_folder, folder)
    _check(isinstance(subdirectory, int) and subdirectory > 0, subdirectory)
    _check(isinstance(file_name, str), file_name)
    file_timestamp = _parse_maildir_filename_time(file_name)
    _check(
        started_at - timedelta(seconds=5) <= file_timestamp <= observed_at + timedelta(seconds=5),
        file_timestamp,
    )
    _check(actual_subject == subject, actual_subject)
    _check(from_address == expected_from_address, from_address)
    _check(to_addresses == expected_to_addresses, to_addresses)
    _check(isinstance(received_at, datetime) and received_at.tzinfo is not None, received_at)
    _check(isinstance(indexed_at, datetime) and indexed_at.tzinfo is not None, indexed_at)
    _check(
        started_at - timedelta(seconds=5) <= received_at.astimezone(UTC) <= observed_at,
        received_at,
    )
    _check(
        started_at - timedelta(seconds=5) <= indexed_at.astimezone(UTC) <= observed_at,
        indexed_at,
    )
    _check(has_attachments is expected_has_attachments, has_attachments)
    _check(isinstance(size_bytes, int) and size_bytes > len(message), size_bytes)
    _check(actual_message_id == message_id, actual_message_id)

    workspace = target.workspace
    if workspace is None:
        raise AssertionError("SMTP target is not started")
    maildir_root = workspace / "maildir"
    folder_root = maildir_root / _QA_ADDRESS / expected_folder
    file_path = folder_root / str(subdirectory) / file_name
    _assert_path_chain_without_symlinks(workspace, file_path)
    _check(folder_root.is_dir(), folder_root)
    _check(file_path.is_file(), file_path)
    resolved_root = maildir_root.resolve(strict=True)
    resolved_file = file_path.resolve(strict=True)
    _check(resolved_root in resolved_file.parents, resolved_file)
    expected_relative = resolved_file.relative_to(resolved_root).as_posix()
    _check_maildir_delta(maildir_before, maildir_after, expected_relative)
    _remaining(deadline, "Maildir message read")
    _check(size_bytes <= _MAX_CAPTURED_MESSAGE_BYTES, size_bytes)
    with resolved_file.open("rb") as stream:
        raw = stream.read(_MAX_CAPTURED_MESSAGE_BYTES + 1)
    _remaining(deadline, "Maildir message read")
    _check(len(raw) == size_bytes, (len(raw), size_bytes))

    count_key = f"mail:count:{_QA_ADDRESS}:{expected_folder}"
    redis_final = _redis_state(target, count_key, deadline=deadline)
    _check(redis_final == redis_state, (redis_state, redis_final))
    _check(_index_count(target, message_id, deadline=deadline) == 1, message_id)
    maildir_final = _maildir_files(workspace, deadline=deadline)
    _check_maildir_delta(maildir_before, maildir_final, expected_relative)
    _check(maildir_final == maildir_after, "Maildir changed during final verification")

    redis_after, redis_type, redis_pttl = redis_state

    raw_snapshot = _normalized_mail_snapshot(
        raw,
        hostname=hostname,
        message=message,
        received_protocol=received_protocol,
        started_at=started_at,
        observed_at=observed_at,
    )
    _remaining(deadline, "storage snapshot normalization")
    return {
        "maildir": {
            "path": f"{_QA_ADDRESS}/{expected_folder}/{subdirectory}/<generated>.eml",
            "raw": raw_snapshot,
            "new_regular_files": 1,
            "orphan_files": 0,
            "residual_temp_files": 0,
            "symlinks": 0,
            "preexisting_files_unchanged": True,
        },
        "postgres": {
            "matching_rows": 1,
            "id": "<identity>",
            "mailbox_address": mailbox_address,
            "folder": folder,
            "subdirectory": subdirectory,
            "file_name": "<generated>.eml",
            "subject": actual_subject,
            "from_address": from_address,
            "to_addresses": to_addresses,
            "received_at": "<timestamp>",
            "has_attachments": has_attachments,
            "size_bytes": "<maildir-byte-length>",
            "message_id": actual_message_id,
            "indexed_at": "<timestamp>",
        },
        "size_contract": "postgres-size_bytes-equals-maildir-byte-length",
        "redis": {
            "key": count_key,
            "before": redis_before,
            "after": redis_after,
            "delta": 1,
            "type": redis_type.decode("ascii", errors="strict"),
            "pttl": redis_pttl,
        },
    }


def _message(subject: str, message_id: str, body: bytes) -> bytes:
    return (
        f"Subject: {subject}\r\nMessage-ID: {message_id}\r\n"
        "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=us-ascii\r\n"
        "\r\n"
    ).encode("ascii") + body


_DATA_MESSAGE_ID = "<bb-data-001@example.test>"
_DATA_SUBJECT = "bb-data-001"
_DATA_MESSAGE = _message(
    _DATA_SUBJECT,
    _DATA_MESSAGE_ID,
    b"DATA body\r\n.dot-leading-line\r\n",
)
_PIPELINE_MESSAGE_ID = "<bb-pipeline-001@example.test>"
_PIPELINE_SUBJECT = "bb-pipeline-001"
_PIPELINE_MESSAGE = _message(
    _PIPELINE_SUBJECT,
    _PIPELINE_MESSAGE_ID,
    b"PIPELINING body\r\n",
)
_BDAT_MESSAGE_ID = "<bb-bdat-001@example.test>"
_BDAT_SUBJECT = "bb-bdat-001"
_BDAT_MESSAGE = _message(
    _BDAT_SUBJECT,
    _BDAT_MESSAGE_ID,
    b"BDAT body preserves chunk boundaries only on the wire.\r\n",
)


def capture_delivery(
    target: RuntimeTarget,
    *,
    mode: str,
    subject: str,
    message_id: str,
    message: bytes,
    session_setup: SmtpSessionSetup | None = None,
    received_protocol: bytes = b"ESMTP",
    expected_from_address: str | None = None,
    expected_to_addresses: str = "[]",
    expected_has_attachments: bool = False,
    expected_folder: str = _FOLDER,
    envelope_sender: str = "",
    source: str | None = None,
) -> dict[str, Any]:
    workspace = target.workspace
    if workspace is None:
        raise AssertionError("SMTP target is not started")
    _check(received_protocol in {b"ESMTP", b"ESMTPS"}, received_protocol)
    preflight_deadline = time.monotonic() + 5.0
    maildir_before = _maildir_files(workspace, deadline=preflight_deadline)
    _check(
        _index_count(target, message_id, deadline=preflight_deadline) == 0,
        message_id,
    )
    count_key = f"mail:count:{_QA_ADDRESS}:{expected_folder}"
    redis_before = _redis_state(target, count_key, deadline=preflight_deadline)[0]

    started_at = datetime.now(UTC)
    mail_from_command = f"MAIL FROM:<{envelope_sender}>".encode()
    client, hostname = open_smtp_client(target, source=source)
    with client:
        wire: dict[str, Any] = {"greeting": smtp_greeting_snapshot()}
        if session_setup is None:
            wire["ehlo"] = smtp_reply_snapshot(smtp_ehlo(client, hostname), hostname)
        else:
            wire.update(session_setup(target, client, hostname))
        if mode == "data":
            mail_from = client.command(mail_from_command)
            rcpt_to = client.command(b"RCPT TO:<qa@example.test>")
            data_ready, accepted = client.data(message)
            wire.update(
                {
                    "mail_from": smtp_reply_snapshot(mail_from, hostname),
                    "rcpt_to": smtp_reply_snapshot(rcpt_to, hostname),
                    "data_ready": smtp_reply_snapshot(data_ready, hostname),
                    "accepted": smtp_reply_snapshot(accepted, hostname, accepted=True),
                }
            )
        elif mode == "pipeline":
            replies = client.pipeline(
                (
                    mail_from_command,
                    b"RCPT TO:<qa@example.test>",
                    b"DATA",
                )
            )
            _check(
                len(replies) == 3 and replies[2][0].startswith(b"354 "),
                replies,
            )
            accepted = client.data_body(message)
            wire["pipeline"] = [smtp_reply_snapshot(reply, hostname) for reply in replies]
            wire["accepted"] = smtp_reply_snapshot(accepted, hostname, accepted=True)
        elif mode == "bdat":
            replies = client.pipeline(
                (
                    mail_from_command,
                    b"RCPT TO:<qa@example.test>",
                )
            )
            split_at = len(message) // 2
            first = client.bdat(message[:split_at])
            accepted = client.bdat(message[split_at:], last=True)
            wire["pipeline"] = [smtp_reply_snapshot(reply, hostname) for reply in replies]
            wire["bdat_chunk"] = smtp_reply_snapshot(first, hostname)
            wire["accepted"] = smtp_reply_snapshot(accepted, hostname, accepted=True)
        else:
            raise AssertionError(f"unsupported SMTP capture mode: {mode}")
        wire["quit"] = smtp_reply_snapshot(client.quit(), hostname)

    return {
        "mode": mode,
        "wire": wire,
        "storage": _storage_snapshot(
            target,
            message_id=message_id,
            subject=subject,
            message=message,
            hostname=hostname,
            received_protocol=received_protocol,
            maildir_before=maildir_before,
            redis_before=redis_before,
            started_at=started_at,
            expected_folder=expected_folder,
            expected_from_address=expected_from_address,
            expected_to_addresses=expected_to_addresses,
            expected_has_attachments=expected_has_attachments,
        ),
    }


def capture_accepted_without_delivery(
    target: RuntimeTarget,
    *,
    subject: str,
    message_id: str,
    message: bytes,
    envelope_sender: str = "",
    source: str | None = None,
    observation_seconds: float = 5.0,
) -> dict[str, Any]:
    workspace = target.workspace
    if workspace is None:
        raise AssertionError("SMTP target is not started")
    _check(0.1 <= observation_seconds <= 30.0, observation_seconds)
    preflight_deadline = time.monotonic() + 5.0
    maildir_before = _maildir_files(workspace, deadline=preflight_deadline)
    _check(
        _index_count(target, message_id, deadline=preflight_deadline) == 0,
        message_id,
    )
    count_keys = tuple(
        f"mail:count:{_QA_ADDRESS}:{folder}" for folder in ("inbox", "spam")
    )
    redis_before = {
        key: _redis_state(target, key, deadline=preflight_deadline) for key in count_keys
    }

    client, hostname = open_smtp_client(target, source=source)
    with client:
        greeting = smtp_greeting_snapshot()
        ehlo = smtp_reply_snapshot(smtp_ehlo(client, hostname), hostname)
        mail_from = client.command(f"MAIL FROM:<{envelope_sender}>".encode())
        rcpt_to = client.command(b"RCPT TO:<qa@example.test>")
        data_ready, accepted = client.data(message)
        quit_reply = client.quit()

    observation_deadline = time.monotonic() + observation_seconds
    while True:
        check_deadline = time.monotonic() + 2.0
        maildir_after = _maildir_files(workspace, deadline=check_deadline)
        _check(maildir_after == maildir_before, (maildir_before, maildir_after))
        _check(
            _index_count(target, message_id, deadline=check_deadline) == 0,
            message_id,
        )
        redis_after = {
            key: _redis_state(target, key, deadline=check_deadline) for key in count_keys
        }
        _check(redis_after == redis_before, (redis_before, redis_after))
        remaining = observation_deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(0.05, remaining))

    return {
        "mode": "data",
        "wire": {
            "greeting": greeting,
            "ehlo": ehlo,
            "mail_from": smtp_reply_snapshot(mail_from, hostname),
            "rcpt_to": smtp_reply_snapshot(rcpt_to, hostname),
            "data_ready": smtp_reply_snapshot(data_ready, hostname),
            "accepted": smtp_reply_snapshot(accepted, hostname, accepted=True),
            "quit": smtp_reply_snapshot(quit_reply, hostname),
        },
        "storage": {
            "observation_seconds": observation_seconds,
            "maildir_unchanged": True,
            "postgres_matching_rows": 0,
            "redis_unchanged": True,
            "subject": subject,
            "message_id": message_id,
        },
    }


def _capture_data(target: RuntimeTarget) -> dict[str, Any]:
    return capture_delivery(
        target,
        mode="data",
        subject=_DATA_SUBJECT,
        message_id=_DATA_MESSAGE_ID,
        message=_DATA_MESSAGE,
    )


def _capture_pipeline(target: RuntimeTarget) -> dict[str, Any]:
    return capture_delivery(
        target,
        mode="pipeline",
        subject=_PIPELINE_SUBJECT,
        message_id=_PIPELINE_MESSAGE_ID,
        message=_PIPELINE_MESSAGE,
    )


def _capture_bdat(target: RuntimeTarget) -> dict[str, Any]:
    return capture_delivery(
        target,
        mode="bdat",
        subject=_BDAT_SUBJECT,
        message_id=_BDAT_MESSAGE_ID,
        message=_BDAT_MESSAGE,
    )


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


def _contract(mode: str, message: bytes, message_id: str) -> dict[str, Any]:
    return {
        "protocol": "smtp",
        "operation": "inbound-delivery",
        "mode": mode,
        "envelope_from": "<>",
        "recipient": _QA_ADDRESS,
        "message_id": message_id,
        "message_sha256": hashlib.sha256(message).hexdigest(),
        "side_effects": ["maildir", "postgres:email_index", "redis:mail-count"],
        "delivery_cardinality": "exactly-once",
        "storage_visibility": "joint-15-second-absolute-deadline",
        "maildir_residue": "no-orphans-no-temp-no-symlinks-no-prior-file-mutation",
    }


SMTP_SCENARIOS = (
    Scenario(
        "smtp/inbound/data-storage",
        _capture_data,
        _NORMALIZERS + ("smtp:data-dot-unstuff",),
        _contract("DATA", _DATA_MESSAGE, _DATA_MESSAGE_ID),
    ),
    Scenario(
        "smtp/inbound/pipelining-storage",
        _capture_pipeline,
        _NORMALIZERS + ("smtp:pipelining-data-waits-for-354",),
        _contract("PIPELINING", _PIPELINE_MESSAGE, _PIPELINE_MESSAGE_ID),
    ),
    Scenario(
        "smtp/inbound/bdat-storage",
        _capture_bdat,
        _NORMALIZERS + ("smtp:bdat-chunk-framing",),
        _contract("BDAT", _BDAT_MESSAGE, _BDAT_MESSAGE_ID),
    ),
)
