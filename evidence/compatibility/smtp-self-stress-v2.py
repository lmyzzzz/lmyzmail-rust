from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.util
import json
import math
import os
import queue
import re
import socket
import stat as stat_module
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email import policy
from email.parser import BytesHeaderParser, BytesParser
from email.utils import getaddresses, parseaddr
from pathlib import Path
from typing import Any, BinaryIO


REPOSITORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY / "blackbox/src"))

from lmyzmail_blackbox.golden import GoldenAttestation  # noqa: E402


BASE_SOURCE = Path(__file__).with_name("smtp-self-stress-v1.py")
RUNNER = Path(__file__).resolve()
BASE_SPEC = importlib.util.spec_from_file_location("smtp_self_stress_v1", BASE_SOURCE)
if BASE_SPEC is None or BASE_SPEC.loader is None:
    raise RuntimeError(f"cannot load SMTP stress base runner: {BASE_SOURCE}")
base = importlib.util.module_from_spec(BASE_SPEC)
sys.modules[BASE_SPEC.name] = base
BASE_SPEC.loader.exec_module(base)


CAPTURE_ROOT_NAME = "smtp-wire-capture"
SMTP_CAPTURE_ADDRESS = "1.1.1.1"
SMTP_CAPTURE_PORT = 25
CAPTURE_HEADER_LIMIT = 256 * 1024
VERIFY_CONCURRENCY = 8
MAX_CAPTURE_CONNECTIONS = 2048
MAX_WIRE_MESSAGE_BYTES = 12 * 1024 * 1024
MAILBOX_PATH_CHUNK_BYTES = 120
STATE_STABLE_POLLS = 3
RESOURCE_SAMPLE_SECONDS = 5.0
RESOURCE_POLICY = {
    "max_rss_kib": 2 * 1024 * 1024,
    "max_fd_count": 1024,
    "max_task_count": 1024,
    "max_steady_rss_growth_kib": 256 * 1024,
    "max_steady_fd_growth": 16,
    "max_steady_task_growth": 16,
    "minimum_filesystem_free_bytes": 2 * 1024**3,
    "max_queue_pending": 2000,
}
SUBJECT_PATTERN = re.compile(
    r"^Stress Test R(?P<round>[0-9]+) #(?P<index>[0-9]+) - (?P<millis>[0-9]+)$"
)
BODY_PATTERN = re.compile(
    rb"\A=== Stress Test Email ===\n"
    rb"Round: (?P<round>[0-9]+)\n"
    rb"Mode: (?P<mode>[A-Z-]+)\n"
    rb"Index: (?P<index>[0-9]+)\n"
    rb"Timestamp: (?P<millis>[0-9]+)\n"
    rb"Target Size: (?P<size_kib>[0-9]+) KB\n"
    rb"Generation: (?P<generation>[A-Z-]+)\n"
    rb"=========================\n\n"
)
FILLER = b"The quick brown fox jumps over the lazy dog. Lorem ipsum dolor sit amet. "
EMPTY_RECEIPT_VALUE_STREAM_SHA256 = (
    "7cfe27cd7a354def8edb89c5613efe9e01b344cdfada3306c8b9ac29ed595ced"
)
REDIS_SNAPSHOT_PIPELINE_KEY_LIMIT = 512
REDIS_SNAPSHOT_VALUE_PAGE_LIMIT = 512
REDIS_SNAPSHOT_STRING_CHUNK_BYTES = 64 * 1024
# Unordered Redis collections require a canonical sort for the digest. Refuse
# pathological cardinalities before the client materializes an unbounded value
# set; a snapshot failure is safer than silently producing an incomplete one.
REDIS_SNAPSHOT_UNORDERED_CARDINALITY_LIMIT = 131_072


def _v2_mailbox_relative_path(address: str) -> Path:
    normalized = address.strip().lower().encode("utf-8")
    path = Path("v2")
    for offset in range(0, len(normalized), MAILBOX_PATH_CHUNK_BYTES):
        path /= f"c-{normalized[offset : offset + MAILBOX_PATH_CHUNK_BYTES].hex().upper()}"
    return path / f"z-{len(normalized):08X}"


def _sha256_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _git_head() -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPOSITORY,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _checkpoint_digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(_json_bytes(value)).hexdigest()


def _atomic_create_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.path.lexists(path):
        raise FileExistsError(f"evidence already exists: {path}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(
                json.dumps(value, sort_keys=True, indent=2).encode("utf-8") + b"\n"
            )
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _load_json_file(path: Path) -> dict[str, Any]:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if not stat_module.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"evidence path is not a regular file: {path}")
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            descriptor = -1
            value = json.load(stream)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not isinstance(value, dict):
        raise RuntimeError(f"evidence JSON is not an object: {path}")
    return value


class JsonlCheckpoint:
    def __init__(
        self,
        path: Path,
        *,
        resume: bool,
        existing_records: list[dict[str, Any]] | None = None,
    ):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_APPEND
        if resume:
            flags |= os.O_NOFOLLOW
        else:
            flags |= os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        self.descriptor = os.open(path, flags, 0o600)
        if resume:
            if not existing_records:
                os.close(self.descriptor)
                self.descriptor = -1
                raise RuntimeError("resume checkpoint records are required")
            last = existing_records[-1]
            self.sequence = int(last["_sequence"]) + 1
            self.previous_record_sha256 = str(last["_record_sha256"])
        else:
            self.sequence = 0
            self.previous_record_sha256: str | None = None
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)

    def append(self, value: dict[str, Any]) -> None:
        reserved = {
            "_sequence",
            "_previous_record_sha256",
            "_record_sha256",
        }
        if reserved.intersection(value):
            raise RuntimeError("checkpoint record used a reserved integrity field")
        record = dict(value)
        record["_sequence"] = self.sequence
        record["_previous_record_sha256"] = self.previous_record_sha256
        record["_record_sha256"] = _checkpoint_digest(record)
        payload = _json_bytes(record)
        view = memoryview(payload)
        while view:
            written = os.write(self.descriptor, view)
            view = view[written:]
        os.fsync(self.descriptor)
        self.sequence += 1
        self.previous_record_sha256 = str(record["_record_sha256"])

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


class StressCandidateRuntimeV2(base.StressCandidateRuntime):
    def _start_application(self) -> None:
        base.CandidateRuntime._start_application(self)

    def _candidate_configuration(self) -> Path:
        path = base.StressCandidateRuntime._candidate_configuration(self)
        value = json.loads(path.read_text(encoding="utf-8"))
        value["listen"]["host"] = "127.0.0.1"
        path.write_text(
            json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
        return path


def _expected_body(
    *, round_number: int, index: int, millis: int, size: int
) -> bytes:
    generation = "IN-MEMORY" if size <= 20 * 1024 else "STREAMING"
    header = (
        "=== Stress Test Email ===\r\n"
        f"Round: {round_number}\r\n"
        "Mode: PRODUCTION\r\n"
        f"Index: {index}\r\n"
        f"Timestamp: {millis}\r\n"
        f"Target Size: {size // 1024} KB\r\n"
        f"Generation: {generation}\r\n"
        "=========================\r\n\r\n"
    ).encode("ascii")
    output = bytearray(header)
    remaining = max(0, size - len(output))
    line_length = 0
    while remaining:
        count = min(len(FILLER), remaining)
        output.extend(FILLER[:count])
        remaining -= count
        line_length += count
        if line_length >= 70 and remaining > 2:
            output.extend(b"\r\n")
            remaining -= 2
            line_length = 0
    return bytes(output)


def _file_suffix_sha256(path: Path, size: int) -> tuple[str, int]:
    file_size = path.stat().st_size
    if file_size < size:
        raise RuntimeError(f"stored message is shorter than SMTP payload: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        stream.seek(file_size - size)
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest(), file_size


@dataclass
class BatchCapture:
    expected: int
    message_bytes: int
    started_monotonic: float
    seen_indexes: bytearray = field(init=False)
    message_ids: set[str] = field(default_factory=set)
    rounds: set[int] = field(default_factory=set)
    latencies_ms: list[float] = field(default_factory=list)
    digest: Any = field(default_factory=hashlib.sha256)
    verified: int = 0
    wire_bytes: int = 0
    stored_bytes: int = 0
    failures: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.seen_indexes = bytearray(self.expected)

    def add(self, record: dict[str, Any]) -> None:
        index = int(record["index"])
        if index < 0 or index >= self.expected:
            raise RuntimeError(f"SMTP capture index is outside batch: {index}")
        if self.seen_indexes[index]:
            raise RuntimeError(f"SMTP capture duplicated batch index: {index}")
        message_id = str(record["message_id"])
        if message_id in self.message_ids:
            raise RuntimeError(f"SMTP capture duplicated Message-ID: {message_id}")
        self.seen_indexes[index] = 1
        self.message_ids.add(message_id)
        self.rounds.add(int(record["round"]))
        self.verified += 1
        self.wire_bytes += int(record["wire_bytes"])
        self.stored_bytes += int(record["stored_bytes"])
        self.latencies_ms.append(float(record["latency_ms"]))
        self.digest.update(_json_bytes(record))

    def summary(self) -> dict[str, Any]:
        missing = [index for index, value in enumerate(self.seen_indexes) if not value]
        return {
            "expected": self.expected,
            "verified": self.verified,
            "missing_indexes": missing[:20],
            "missing_count": len(missing),
            "unique_message_ids": len(self.message_ids),
            "rounds": sorted(self.rounds),
            "wire_bytes": self.wire_bytes,
            "stored_bytes": self.stored_bytes,
            "record_stream_sha256": self.digest.hexdigest(),
            "latency_ms": base._distribution(self.latencies_ms),
            "failures": list(self.failures),
        }


class CaptureFile:
    def __init__(self, root: Path):
        descriptor, name = tempfile.mkstemp(prefix="smtp-", suffix=".eml", dir=root)
        self.path = Path(name)
        self.stream: BinaryIO = os.fdopen(descriptor, "wb")
        self.digest = hashlib.sha256()
        self.size = 0

    def write(self, value: bytes) -> None:
        if self.size + len(value) > MAX_WIRE_MESSAGE_BYTES:
            raise RuntimeError("SMTP wire message exceeded capture ceiling")
        self.stream.write(value)
        self.digest.update(value)
        self.size += len(value)

    def finish(self) -> tuple[str, int]:
        self.stream.flush()
        os.fsync(self.stream.fileno())
        self.stream.close()
        return self.digest.hexdigest(), self.size

    def close(self) -> None:
        if not self.stream.closed:
            self.stream.close()
        self.path.unlink(missing_ok=True)


class SmtpCaptureProxy:
    def __init__(self, runtime: StressCandidateRuntimeV2):
        assert runtime.ports is not None and runtime.workspace is not None
        self.runtime = runtime
        self.backend_port = runtime.ports.smtp
        self.root = runtime.workspace / CAPTURE_ROOT_NAME
        self.root.mkdir(mode=0o700)
        self.ready = threading.Event()
        self.stop_requested = threading.Event()
        self.condition = threading.Condition()
        self.batch: BatchCapture | None = None
        self.error: BaseException | None = None
        self.active_connections = 0
        self.connection_lock = threading.Lock()
        self.verification_semaphore: asyncio.Semaphore | None = None
        self.database_pool: queue.LifoQueue[Any] = queue.LifoQueue()
        try:
            for _ in range(VERIFY_CONCURRENCY):
                connection = base.psycopg.connect(
                    host="127.0.0.1",
                    port=runtime.ports.postgres,
                    dbname="lmyzmail",
                    user="lmyzmail_test",
                    connect_timeout=5,
                    autocommit=True,
                )
                connection.execute("SET statement_timeout = '5s'")
                self.database_pool.put(connection)
        except BaseException:
            self._close_database_pool()
            self.root.rmdir()
            raise
        self.thread = threading.Thread(target=self._run, name="smtp-capture-proxy")
        self.thread.start()
        try:
            if not self.ready.wait(10.0):
                raise TimeoutError("SMTP capture proxy did not bind before deadline")
            if self.error is not None:
                raise RuntimeError("SMTP capture proxy failed to start") from self.error
        except BaseException:
            self.stop_requested.set()
            self.thread.join(timeout=30.0)
            self._close_database_pool()
            if self.root.exists():
                self.root.rmdir()
            raise

    def _close_database_pool(self) -> None:
        while not self.database_pool.empty():
            self.database_pool.get_nowait().close()

    def begin_batch(self, expected: int, message_bytes: int) -> None:
        with self.condition:
            if self.batch is not None:
                raise RuntimeError("SMTP capture batch was not finalized")
            self.batch = BatchCapture(expected, message_bytes, time.monotonic())

    def finish_batch(self, timeout: float = 120.0) -> tuple[dict[str, Any], list[float]]:
        deadline = time.monotonic() + timeout
        with self.condition:
            while True:
                if self.error is not None:
                    raise RuntimeError("SMTP capture proxy failed") from self.error
                if self.batch is not None and self.batch.verified == self.batch.expected:
                    batch = self.batch
                    self.batch = None
                    summary = batch.summary()
                    if summary["missing_count"] or summary["failures"]:
                        raise RuntimeError(f"SMTP payload verification failed: {summary!r}")
                    return summary, batch.latencies_ms
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    observed = self.batch.verified if self.batch is not None else 0
                    raise TimeoutError(
                        f"SMTP capture verified {observed} messages before deadline"
                    )
                self.condition.wait(min(remaining, 1.0))

    def diagnostics(self) -> dict[str, Any]:
        with self.condition:
            error = self.error
            batch = None if self.batch is None else self.batch.summary()
        with self.connection_lock:
            active_connections = self.active_connections
        return {
            "error": None
            if error is None
            else {"type": type(error).__name__, "message": str(error)},
            "active_connections": active_connections,
            "batch": batch,
        }

    def _run(self) -> None:
        try:
            asyncio.run(self._serve())
        except BaseException as error:
            self.error = error
            self.ready.set()
            with self.condition:
                self.condition.notify_all()

    async def _serve(self) -> None:
        self.verification_semaphore = asyncio.Semaphore(VERIFY_CONCURRENCY)
        server = await asyncio.start_server(
            self._handle,
            SMTP_CAPTURE_ADDRESS,
            SMTP_CAPTURE_PORT,
            limit=512 * 1024,
            backlog=2048,
        )
        self.ready.set()
        try:
            await asyncio.to_thread(self.stop_requested.wait)
        finally:
            server.close()
            await server.wait_closed()

    @staticmethod
    async def _read_reply(reader: asyncio.StreamReader) -> bytes:
        first = await asyncio.wait_for(reader.readline(), timeout=30.0)
        if len(first) < 4 or not first[:3].isdigit():
            raise RuntimeError(f"SMTP backend returned invalid reply: {first!r}")
        output = bytearray(first)
        if first[3:4] == b"-":
            terminal = first[:3] + b" "
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=30.0)
                if not line:
                    raise RuntimeError("SMTP backend closed during multiline reply")
                output.extend(line)
                if line.startswith(terminal):
                    break
                if len(output) > 512 * 1024:
                    raise RuntimeError("SMTP backend multiline reply exceeded limit")
        return bytes(output)

    async def _relay_data(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        capture: CaptureFile,
    ) -> None:
        marker = b"\r\n.\r\n"
        pending = bytearray()
        while True:
            chunk = await asyncio.wait_for(reader.read(64 * 1024), timeout=120.0)
            if not chunk:
                raise RuntimeError("SMTP client disconnected during DATA")
            pending.extend(chunk)
            position = pending.find(marker)
            if position >= 0:
                payload_end = position + 2
                capture.write(bytes(pending[:payload_end]))
                writer.write(bytes(pending[: position + len(marker)]))
                await writer.drain()
                if pending[position + len(marker) :]:
                    raise RuntimeError("SMTP client pipelined bytes after DATA terminator")
                return
            safe = len(pending) - (len(marker) - 1)
            if safe > 0:
                value = bytes(pending[:safe])
                del pending[:safe]
                if b"\r\n.." in value:
                    raise RuntimeError("stress payload unexpectedly required dot unstuffing")
                capture.write(value)
                writer.write(value)
                await writer.drain()

    async def _handle(
        self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter
    ) -> None:
        backend_writer: asyncio.StreamWriter | None = None
        capture: CaptureFile | None = None
        try:
            with self.connection_lock:
                self.active_connections += 1
                if self.active_connections > MAX_CAPTURE_CONNECTIONS:
                    raise RuntimeError("SMTP capture connection ceiling exceeded")
            backend_reader, backend_writer = await asyncio.open_connection(
                "127.0.0.1", self.backend_port, limit=512 * 1024
            )
            greeting = await self._read_reply(backend_reader)
            client_writer.write(greeting)
            await client_writer.drain()
            while True:
                line = await asyncio.wait_for(client_reader.readline(), timeout=120.0)
                if not line:
                    return
                command = line.split(None, 1)[0].upper()
                backend_writer.write(line)
                await backend_writer.drain()
                if command == b"DATA":
                    reply = await self._read_reply(backend_reader)
                    client_writer.write(reply)
                    await client_writer.drain()
                    if not reply.startswith(b"354"):
                        continue
                    capture = CaptureFile(self.root)
                    await self._relay_data(client_reader, backend_writer, capture)
                    final_reply = await self._read_reply(backend_reader)
                    if final_reply.startswith(b"250"):
                        await self._verify_and_record(capture)
                        capture = None
                    client_writer.write(final_reply)
                    await client_writer.drain()
                    continue
                if command == b"BDAT":
                    fields = line.rstrip(b"\r\n").split()
                    if len(fields) not in (2, 3) or not fields[1].isdigit():
                        raise RuntimeError(f"SMTP client sent invalid BDAT: {line!r}")
                    size = int(fields[1])
                    if size < 0 or size > MAX_WIRE_MESSAGE_BYTES:
                        raise RuntimeError("SMTP BDAT chunk exceeded capture ceiling")
                    last = len(fields) == 3 and fields[2].upper() == b"LAST"
                    if capture is None:
                        capture = CaptureFile(self.root)
                    remaining = size
                    while remaining:
                        chunk = await asyncio.wait_for(
                            client_reader.read(min(64 * 1024, remaining)), timeout=120.0
                        )
                        if not chunk:
                            raise RuntimeError("SMTP client disconnected during BDAT")
                        remaining -= len(chunk)
                        capture.write(chunk)
                        backend_writer.write(chunk)
                        await backend_writer.drain()
                    reply = await self._read_reply(backend_reader)
                    if last and reply.startswith(b"250"):
                        await self._verify_and_record(capture)
                        capture = None
                    client_writer.write(reply)
                    await client_writer.drain()
                    continue
                reply = await self._read_reply(backend_reader)
                client_writer.write(reply)
                await client_writer.drain()
        except BaseException as error:
            self.error = error
            with self.condition:
                if self.batch is not None and len(self.batch.failures) < 20:
                    self.batch.failures.append(f"{type(error).__name__}: {error}")
                self.condition.notify_all()
        finally:
            if capture is not None:
                capture.close()
            client_writer.close()
            if backend_writer is not None:
                backend_writer.close()
            with self.connection_lock:
                self.active_connections -= 1

    async def _verify_and_record(self, capture: CaptureFile) -> None:
        wire_sha256, wire_bytes = capture.finish()
        try:
            if self.verification_semaphore is None:
                raise RuntimeError("SMTP verifier semaphore was not initialized")
            async with self.verification_semaphore:
                record = await asyncio.wait_for(
                    asyncio.to_thread(
                        self._verify_capture, capture.path, wire_sha256, wire_bytes
                    ),
                    timeout=120.0,
                )
        finally:
            capture.path.unlink(missing_ok=True)
        with self.condition:
            if self.batch is None:
                raise RuntimeError("SMTP payload arrived outside an active batch")
            self.batch.add(record)
            self.condition.notify_all()

    def _verify_capture(
        self, path: Path, wire_sha256: str, wire_bytes: int
    ) -> dict[str, Any]:
        with path.open("rb") as stream:
            header_bytes = stream.read(CAPTURE_HEADER_LIMIT)
        split = header_bytes.find(b"\r\n\r\n")
        if split < 0:
            raise RuntimeError("SMTP payload headers exceeded capture limit")
        headers = BytesHeaderParser(policy=policy.default).parsebytes(
            header_bytes[: split + 4]
        )
        subject = str(headers.get("Subject", ""))
        matched = SUBJECT_PATTERN.fullmatch(subject)
        if matched is None:
            raise RuntimeError(f"SMTP payload subject contract changed: {subject!r}")
        round_number = int(matched.group("round"))
        index = int(matched.group("index"))
        message_id = str(headers.get("Message-ID", ""))
        if not message_id:
            raise RuntimeError("SMTP payload omitted Message-ID")
        with path.open("rb") as stream:
            message = BytesParser(policy=policy.default).parse(stream)
        _, from_address = parseaddr(str(message.get("From", "")))
        to_addresses = {
            address.lower()
            for _, address in getaddresses(message.get_all("To", []))
            if address
        }
        if from_address.lower() != base.ENDPOINT_SENDER:
            raise RuntimeError("SMTP payload From header changed")
        if base.RECEIVER not in to_addresses:
            raise RuntimeError("SMTP payload To header changed")
        if any(True for _ in message.iter_attachments()):
            raise RuntimeError("stress SMTP payload unexpectedly contained attachments")
        body_part = message.get_body(preferencelist=("plain",))
        if body_part is None:
            body_part = message
        if (
            body_part.get_content_type() != "text/plain"
            or str(body_part.get("Content-Transfer-Encoding", "")).lower()
            != "quoted-printable"
        ):
            raise RuntimeError("stress SMTP body MIME contract changed")
        body = body_part.get_payload(decode=True)
        if not isinstance(body, bytes):
            raise RuntimeError("SMTP payload text body was not decodable")
        body_match = BODY_PATTERN.match(body)
        if body_match is None:
            raise RuntimeError(
                "SMTP payload body header contract changed: "
                f"content_type={body_part.get_content_type()!r} "
                f"transfer_encoding={body_part.get('Content-Transfer-Encoding')!r} "
                f"bytes={len(body)} sha256={hashlib.sha256(body).hexdigest()} "
                f"prefix={body[:512]!r}"
            )
        body_round = int(body_match.group("round"))
        body_index = int(body_match.group("index"))
        body_millis = int(body_match.group("millis"))
        subject_millis = int(matched.group("millis"))
        if body_round != round_number or body_index != index:
            raise RuntimeError("SMTP subject/body sequence mismatch")
        if not subject_millis <= body_millis <= subject_millis + 60_000:
            raise RuntimeError("SMTP subject/body generation clocks diverged")
        with self.condition:
            if self.batch is None:
                raise RuntimeError("SMTP verification lost its active batch")
            expected_size = self.batch.message_bytes
            started = self.batch.started_monotonic
        expected_source = _expected_body(
            round_number=round_number,
            index=index,
            millis=body_millis,
            size=expected_size,
        )
        expected = expected_source.replace(b"\r\n", b"\n") + b"\n"
        if body != expected:
            raise RuntimeError(
                "SMTP generated body mismatch: "
                f"actual={hashlib.sha256(body).hexdigest()} "
                f"expected={hashlib.sha256(expected).hexdigest()}"
            )
        connection = self.database_pool.get(timeout=30.0)
        try:
            row, stored_path = _wait_for_indexed_message(
                self.runtime, subject, connection=connection
            )
        finally:
            self.database_pool.put(connection)
        stored_sha256, stored_bytes = _file_suffix_sha256(stored_path, wire_bytes)
        if stored_sha256 != wire_sha256:
            raise RuntimeError("Maildir payload suffix differs from SMTP wire payload")
        if int(row["size_bytes"]) != stored_bytes:
            raise RuntimeError("email_index size differs from stored Maildir file")
        if row["subject"] != subject or row["message_id"] != message_id:
            raise RuntimeError("email_index metadata differs from SMTP payload")
        with stored_path.open("rb") as stream:
            stored_header_bytes = stream.read(CAPTURE_HEADER_LIMIT)
        stored_split = stored_header_bytes.find(b"\r\n\r\n")
        if stored_split < 0:
            raise RuntimeError("stored Maildir headers exceeded verification limit")
        stored_headers = BytesHeaderParser(policy=policy.default).parsebytes(
            stored_header_bytes[: stored_split + 4]
        )
        if not stored_headers.get("Received"):
            raise RuntimeError("stored Maildir message omitted Received header")
        if not stored_headers.get("Authentication-Results"):
            raise RuntimeError("stored Maildir message omitted Authentication-Results")
        if str(stored_headers.get("X-Spam-Status", "")) not in ("Yes", "No"):
            raise RuntimeError("stored Maildir message omitted X-Spam-Status")
        return {
            "round": round_number,
            "index": index,
            "message_id": message_id,
            "wire_sha256": wire_sha256,
            "wire_bytes": wire_bytes,
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "body_bytes": len(body),
            "stored_suffix_sha256": stored_sha256,
            "stored_bytes": stored_bytes,
            "latency_ms": round((time.monotonic() - started) * 1000.0, 3),
        }

    def close(self) -> None:
        try:
            deadline = time.monotonic() + 30.0
            while time.monotonic() < deadline:
                with self.connection_lock:
                    if self.active_connections == 0:
                        break
                time.sleep(0.05)
            else:
                raise TimeoutError("SMTP capture connections did not drain")
            self.stop_requested.set()
            self.thread.join(timeout=30.0)
            if self.thread.is_alive():
                raise TimeoutError("SMTP capture proxy did not stop before deadline")
            if self.error is not None:
                raise RuntimeError("SMTP capture proxy stopped after an error") from self.error
            if self.root.exists():
                self.root.rmdir()
        finally:
            self.stop_requested.set()
            self._close_database_pool()


def _wait_for_indexed_message(
    runtime: StressCandidateRuntimeV2,
    subject: str,
    *,
    connection: Any,
    timeout: float = 30.0,
) -> tuple[dict[str, Any], Path]:
    assert runtime.ports is not None and runtime.workspace is not None
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        row = connection.execute(
            "SELECT file_name,subdirectory,subject,message_id,size_bytes "
            "FROM email_index WHERE mailbox_address=%s AND folder='inbox' "
            "AND subject=%s ORDER BY id DESC LIMIT 1",
            (base.RECEIVER, subject),
        ).fetchone()
        if row is not None:
            maildir = runtime.workspace / "maildir"
            folder = maildir / _v2_mailbox_relative_path(base.RECEIVER) / "inbox"
            subdirectory = int(row[1]) if row[1] is not None else 0
            candidate_path = (
                folder / str(subdirectory) / str(row[0])
                if subdirectory > 0
                else folder / str(row[0])
            )
            try:
                if maildir.is_symlink() or folder.is_symlink():
                    raise RuntimeError("Maildir fixture root contains a symlink")
                maildir_root = maildir.resolve(strict=True)
                folder_root = folder.resolve(strict=True)
                if not folder_root.is_relative_to(maildir_root):
                    raise RuntimeError("indexed folder escaped the Maildir fixture root")
                relative = candidate_path.relative_to(maildir)
                if any(part in ("", ".", "..") for part in relative.parts):
                    raise RuntimeError("indexed Maildir path contains traversal")
                cursor = maildir
                for part in relative.parts:
                    cursor /= part
                    if stat_module.S_ISLNK(cursor.lstat().st_mode):
                        raise RuntimeError(
                            f"indexed Maildir path contains a symlink: {cursor}"
                        )
                path = candidate_path.resolve(strict=True)
                metadata = path.lstat()
            except FileNotFoundError:
                time.sleep(0.01)
                continue
            if (
                path.is_relative_to(folder_root)
                and path.is_relative_to(maildir_root)
                and stat_module.S_ISREG(metadata.st_mode)
            ):
                return (
                    {
                        "subject": str(row[2]),
                        "message_id": str(row[3]),
                        "size_bytes": int(row[4]),
                    },
                    path,
                )
        time.sleep(0.01)
    raise TimeoutError(f"Maildir message was not indexable before deadline: {subject}")


def _hash_redis_values(values: list[bytes]) -> str:
    digest = hashlib.sha256()
    for value in values:
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
    return digest.hexdigest()


def _scan_redis_keys(client: Any) -> tuple[bytes, ...]:
    cursor = 0
    keys: set[bytes] = set()
    while True:
        cursor, batch = client.scan(cursor=cursor, match="*", count=1000)
        keys.update(batch)
        if cursor == 0:
            return tuple(sorted(keys))


def _redis_snapshot_value_summary(
    client: Any, key: bytes, kind: str
) -> tuple[int, str, int]:
    digest = hashlib.sha256()
    cardinality = 0
    value_bytes = 0

    def observe(value: bytes) -> None:
        nonlocal cardinality, value_bytes
        if not isinstance(value, bytes):
            raise RuntimeError("Redis snapshot value was not binary")
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
        cardinality += 1
        value_bytes += len(value)

    if kind == "none":
        pass
    elif kind == "string":
        length = int(client.strlen(key))
        if length < 0:
            raise RuntimeError("Redis string length was negative")
        digest.update(length.to_bytes(8, "big"))
        cardinality = 1
        value_bytes = length
        for offset in range(0, length, REDIS_SNAPSHOT_STRING_CHUNK_BYTES):
            expected_chunk_bytes = min(
                REDIS_SNAPSHOT_STRING_CHUNK_BYTES, length - offset
            )
            value = client.getrange(
                key, offset, offset + expected_chunk_bytes - 1
            )
            if not isinstance(value, bytes) or len(value) != expected_chunk_bytes:
                raise RuntimeError("Redis string changed during bounded snapshot")
            digest.update(value)
    elif kind == "list":
        expected = int(client.llen(key))
        for offset in range(0, expected, REDIS_SNAPSHOT_VALUE_PAGE_LIMIT):
            values = client.lrange(
                key,
                offset,
                min(expected - 1, offset + REDIS_SNAPSHOT_VALUE_PAGE_LIMIT - 1),
            )
            for value in values:
                observe(value)
        if cardinality != expected:
            raise RuntimeError("Redis list changed during bounded snapshot")
    elif kind == "set":
        expected = int(client.scard(key))
        if expected > REDIS_SNAPSHOT_UNORDERED_CARDINALITY_LIMIT:
            raise RuntimeError("Redis set exceeds bounded snapshot cardinality")
        values = sorted(client.smembers(key))
        for value in values:
            observe(value)
        if cardinality != expected:
            raise RuntimeError("Redis set changed during bounded snapshot")
    elif kind == "zset":
        expected = int(client.zcard(key))
        for offset in range(0, expected, REDIS_SNAPSHOT_VALUE_PAGE_LIMIT):
            values = client.zrange(
                key,
                offset,
                min(expected - 1, offset + REDIS_SNAPSHOT_VALUE_PAGE_LIMIT - 1),
                withscores=True,
            )
            for member, score in values:
                observe(member + b"\x00" + repr(float(score)).encode("ascii"))
        if cardinality != expected:
            raise RuntimeError("Redis sorted set changed during bounded snapshot")
    elif kind == "hash":
        expected = int(client.hlen(key))
        if expected > REDIS_SNAPSHOT_UNORDERED_CARDINALITY_LIMIT:
            raise RuntimeError("Redis hash exceeds bounded snapshot cardinality")
        names = sorted(client.hkeys(key))
        if len(names) != expected:
            raise RuntimeError("Redis hash changed during bounded snapshot")
        for offset in range(0, expected, REDIS_SNAPSHOT_VALUE_PAGE_LIMIT):
            batch_names = names[offset : offset + REDIS_SNAPSHOT_VALUE_PAGE_LIMIT]
            values = client.hmget(key, batch_names)
            if len(values) != len(batch_names) or any(
                value is None for value in values
            ):
                raise RuntimeError("Redis hash changed during bounded snapshot")
            for name, value in zip(batch_names, values, strict=True):
                observe(name + b"\x00" + value)
    elif kind == "stream":
        expected = int(client.xlen(key))
        if expected > REDIS_SNAPSHOT_UNORDERED_CARDINALITY_LIMIT:
            raise RuntimeError("Redis stream exceeds bounded snapshot cardinality")
        values = client.xrange(key)
        for item in values:
            observe(repr(item).encode("utf-8"))
        if cardinality != expected:
            raise RuntimeError("Redis stream changed during bounded snapshot")
    else:
        raise RuntimeError(f"unsupported Redis type in stress snapshot: {kind}")
    return cardinality, digest.hexdigest(), value_bytes


def _redis_snapshot_records(client: Any, keys: tuple[bytes, ...]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for offset in range(0, len(keys), REDIS_SNAPSHOT_PIPELINE_KEY_LIMIT):
        batch = keys[offset : offset + REDIS_SNAPSHOT_PIPELINE_KEY_LIMIT]
        metadata = client.pipeline(transaction=False)
        for key in batch:
            metadata.type(key)
            metadata.pttl(key)
        metadata_results = metadata.execute()
        if len(metadata_results) != 2 * len(batch):
            raise RuntimeError("Redis snapshot metadata pipeline changed cardinality")

        kinds_and_ttls: list[tuple[str, int]] = []
        for index, key in enumerate(batch):
            kind_raw = metadata_results[index * 2]
            kind = (
                kind_raw.decode("ascii")
                if isinstance(kind_raw, bytes)
                else str(kind_raw)
            )
            pttl = int(metadata_results[index * 2 + 1])
            kinds_and_ttls.append((kind, pttl))
        for key, (kind, pttl) in zip(batch, kinds_and_ttls, strict=True):
            cardinality, value_stream_sha256, value_bytes = (
                _redis_snapshot_value_summary(client, key, kind)
            )
            records.append(
                {
                    "key": key.decode("utf-8", errors="backslashreplace"),
                    "type": kind,
                    "pttl_ms": pttl,
                    "cardinality": cardinality,
                    "value_stream_sha256": value_stream_sha256,
                    "value_bytes": value_bytes,
                }
            )
    return records


def _redis_snapshot(runtime: StressCandidateRuntimeV2) -> dict[str, Any]:
    assert runtime.ports is not None
    client = base.redis.Redis(
        host="127.0.0.1",
        port=runtime.ports.redis,
        db=0,
        socket_timeout=5.0,
        socket_connect_timeout=5.0,
    )
    records: list[dict[str, Any]] = []
    dbsize_before = 0
    dbsize_after = 0
    try:
        dbsize_before = int(client.dbsize())
        keys_before = _scan_redis_keys(client)
        records = _redis_snapshot_records(client, keys_before)
        keys_after = _scan_redis_keys(client)
        dbsize_after = int(client.dbsize())
    finally:
        client.close()
    scan_complete_and_stable = (
        keys_before == keys_after
        and dbsize_before == len(keys_before)
        and len(records) == len(keys_before)
        and dbsize_after == len(keys_after)
    )
    return {
        "key_count": len(records),
        "database": 0,
        "dbsize_before": dbsize_before,
        "dbsize_after": dbsize_after,
        "scan_complete_and_stable": scan_complete_and_stable,
        "scan_keyset_sha256": _hash_redis_values(list(keys_before)),
        "ttl_contract_passed": all(
            record["pttl_ms"] == -1 or record["pttl_ms"] >= 0 for record in records
        ),
        "keys": records,
        "snapshot_sha256": hashlib.sha256(_json_bytes(records)).hexdigest(),
    }


def _db_snapshot(runtime: StressCandidateRuntimeV2) -> dict[str, int]:
    assert runtime.ports is not None
    with base.psycopg.connect(
        host="127.0.0.1",
        port=runtime.ports.postgres,
        dbname="lmyzmail",
        user="lmyzmail_test",
        connect_timeout=5,
    ) as connection:
        connection.execute("SET statement_timeout = '5s'")
        row = connection.execute(
            "SELECT "
            "(SELECT count(*) FROM email_index WHERE mailbox_address IN (%s,%s)),"
            "(SELECT count(*) FROM outbound_mail_queue WHERE sender_address=%s),"
            "(SELECT count(*) FROM lmyzmail_outbound_delivery_recipient recipient "
            " JOIN outbound_mail_queue queue ON queue.id=recipient.task_id "
            " WHERE queue.sender_address=%s AND recipient.state='DELIVERED'),"
            "(SELECT count(*) FROM lmyzmail_outbound_delivery_recipient recipient "
            " JOIN outbound_mail_queue queue ON queue.id=recipient.task_id "
            " WHERE queue.sender_address=%s AND recipient.state IN "
            " ('PENDING','RETRYABLE','COMMIT_ARMED')) ,"
            "(SELECT count(*) FROM lmyzmail_outbound_delivery_recipient recipient "
            " JOIN outbound_mail_queue queue ON queue.id=recipient.task_id "
            " WHERE queue.sender_address=%s AND recipient.state IN "
            " ('PERMANENT','AMBIGUOUS')) ,"
            "(SELECT count(*) FROM lmyzmail_outbound_spool spool "
            " JOIN outbound_mail_queue queue ON queue.id=spool.task_id "
            " WHERE queue.sender_address=%s),"
            "(SELECT count(*) FROM lmyzmail_outbound_delivery_attempt attempt "
            " JOIN outbound_mail_queue queue ON queue.id=attempt.task_id "
            " WHERE queue.sender_address=%s),"
            "(SELECT count(*) FROM lmyzmail_outbound_dsn dsn "
            " JOIN outbound_mail_queue queue ON queue.id=dsn.original_task_id "
            " WHERE queue.sender_address=%s)",
            (
                base.ENDPOINT_SENDER,
                base.RECEIVER,
                base.ENDPOINT_SENDER,
                base.ENDPOINT_SENDER,
                base.ENDPOINT_SENDER,
                base.ENDPOINT_SENDER,
                base.ENDPOINT_SENDER,
                base.ENDPOINT_SENDER,
                base.ENDPOINT_SENDER,
            ),
        ).fetchone()
    if row is None:
        raise RuntimeError("stress database snapshot returned no row")
    names = (
        "email_index",
        "outbound_queue",
        "delivered",
        "active",
        "failed",
        "spool_rows",
        "attempt_rows",
        "dsn_rows",
    )
    return {name: int(value) for name, value in zip(names, row, strict=True)}


def _tree_snapshot(path: Path) -> dict[str, int | bool]:
    try:
        root_metadata = path.lstat()
    except FileNotFoundError:
        return {"exists": False, "files": 0, "directories": 0, "allocated_bytes": 0}
    if stat_module.S_ISLNK(root_metadata.st_mode) or not stat_module.S_ISDIR(
        root_metadata.st_mode
    ):
        raise RuntimeError(f"stress state root is not a real directory: {path}")
    files = 0
    directories = 0
    allocated = 0
    for child in path.rglob("*"):
        try:
            metadata = child.lstat()
        except FileNotFoundError:
            continue
        if stat_module.S_ISLNK(metadata.st_mode):
            raise RuntimeError(f"stress state contains unexpected symlink: {child}")
        if stat_module.S_ISREG(metadata.st_mode):
            files += 1
            allocated += metadata.st_blocks * 512
        elif stat_module.S_ISDIR(metadata.st_mode):
            directories += 1
    return {
        "exists": True,
        "files": files,
        "directories": directories,
        "allocated_bytes": allocated,
    }


_STAGING_LEASE_RELATIVE_PATH = Path(".lmyzmail-quarantine/.lmyzmail-staging.lease")


def _outbound_spool_snapshot(path: Path) -> dict[str, Any]:
    snapshot = _tree_snapshot(path)
    lease = path / _STAGING_LEASE_RELATIVE_PATH
    try:
        metadata = lease.lstat()
    except FileNotFoundError:
        return {
            **snapshot,
            "control_files": 0,
            "staging_lease": {"present": False, "validated": True},
        }

    try:
        root_metadata = path.lstat()
    except FileNotFoundError as error:
        raise RuntimeError("outbound staging lease exists without its spool root") from error
    mode = stat_module.S_IMODE(metadata.st_mode)
    if (
        stat_module.S_ISLNK(metadata.st_mode)
        or not stat_module.S_ISREG(metadata.st_mode)
        or stat_module.S_ISLNK(root_metadata.st_mode)
        or not stat_module.S_ISDIR(root_metadata.st_mode)
        or metadata.st_uid != root_metadata.st_uid
        or mode != 0o600
        or metadata.st_size != 0
        or metadata.st_nlink != 1
    ):
        raise RuntimeError("outbound staging lease failed its bounded control-file contract")
    allocated_bytes = metadata.st_blocks * 512
    if (
        int(snapshot["files"]) < 1
        or int(snapshot["allocated_bytes"]) < allocated_bytes
    ):
        raise RuntimeError("outbound staging lease was absent from its tree snapshot")
    return {
        **snapshot,
        "files": int(snapshot["files"]) - 1,
        "allocated_bytes": int(snapshot["allocated_bytes"]) - allocated_bytes,
        "control_files": 1,
        "staging_lease": {
            "present": True,
            "validated": True,
            "relative_path": _STAGING_LEASE_RELATIVE_PATH.as_posix(),
            "mode": f"{mode:04o}",
            "size_bytes": metadata.st_size,
            "hard_links": metadata.st_nlink,
        },
    }


def _maildir_snapshot(runtime: StressCandidateRuntimeV2) -> dict[str, Any]:
    assert runtime.workspace is not None
    maildir = runtime.workspace / "maildir"
    return {
        "sender": _tree_snapshot(maildir / base.ENDPOINT_SENDER),
        "receiver": _tree_snapshot(maildir / base.RECEIVER),
        "outbound_spool": _outbound_spool_snapshot(maildir / ".lmyzmail-outbound"),
        "stress_temp": _tree_snapshot(maildir / ".lmyzmail-stress"),
        "wire_capture": _tree_snapshot(runtime.workspace / CAPTURE_ROOT_NAME),
    }


def _state_snapshot(runtime: StressCandidateRuntimeV2, phase: str) -> dict[str, Any]:
    snapshot = {
        "phase": phase,
        "captured_at": _utc_now(),
        "database": _db_snapshot(runtime),
        "redis": _redis_snapshot(runtime),
        "maildir": _maildir_snapshot(runtime),
    }
    snapshot["state_sha256"] = hashlib.sha256(_json_bytes(snapshot)).hexdigest()
    return snapshot


def _state_semantic(snapshot: dict[str, Any]) -> dict[str, Any]:
    redis = snapshot["redis"]
    return {
        "database": snapshot["database"],
        "redis": {
            "key_count": redis["key_count"],
            "dbsize_before": redis["dbsize_before"],
            "dbsize_after": redis["dbsize_after"],
            "scan_complete_and_stable": redis["scan_complete_and_stable"],
            "ttl_contract_passed": redis["ttl_contract_passed"],
            "keys": [
                {
                    "key": record["key"],
                    "type": record["type"],
                    "cardinality": record["cardinality"],
                    "value_stream_sha256": record["value_stream_sha256"],
                    "value_bytes": record["value_bytes"],
                    "ttl_kind": "persistent"
                    if record["pttl_ms"] == -1
                    else "expiring",
                }
                for record in redis["keys"]
            ],
        },
        "maildir": snapshot["maildir"],
    }


def _redis_stress_contract(snapshot: dict[str, Any]) -> bool:
    allowed_queue_prefixes = ("botmail:mail:queue:", "lmyzmail:mail:queue:")
    allowed_mail_counts = (
        f"mail:count:{base.ENDPOINT_SENDER}:",
        f"mail:count:{base.RECEIVER}:",
    )
    for record in snapshot["redis"]["keys"]:
        key = record["key"]
        if key == "dns:mx:lmyz.net":
            pttl = int(record["pttl_ms"])
            if (
                record["type"] != "string"
                or int(record["cardinality"]) != 1
                or not 0 <= pttl <= 30 * 60 * 1000
            ):
                return False
            continue
        if not key.startswith((*allowed_queue_prefixes, *allowed_mail_counts)):
            return False
        pttl = int(record["pttl_ms"])
        if pttl > 7 * 24 * 60 * 60 * 1000:
            return False
        if key.endswith(":pending") and int(record["cardinality"]) != 0:
            return False
    return _migration_receipt_contract(snapshot)


def _migration_receipt_contract(snapshot: dict[str, Any]) -> bool:
    records = {
        record["key"]: record
        for record in snapshot["redis"]["keys"]
        if record["key"].startswith("lmyzmail:mail:queue:migration:")
    }
    if not records:
        return True
    for namespace in ("archive", "status-updates"):
        prefix = f"lmyzmail:mail:queue:migration:{namespace}"
        index = records.pop(f"{prefix}:done-index", None)
        receipt_names = [
            key for key in records if key.startswith(f"{prefix}:done:migrate:")
        ]
        if index is None or not 1 <= len(receipt_names) <= 4_096:
            return False
        cardinality = int(index["cardinality"])
        if (
            index["type"] != "zset"
            or int(index["pttl_ms"]) != -1
            or cardinality != len(receipt_names)
            or not cardinality * 41
            <= int(index["value_bytes"])
            <= cardinality * 64
        ):
            return False
        for receipt_name in receipt_names:
            if re.fullmatch(
                re.escape(f"{prefix}:done:migrate:") + r"[0-9a-f]{32}",
                receipt_name,
            ) is None:
                return False
            receipt = records.pop(receipt_name)
            pttl = int(receipt["pttl_ms"])
            if (
                receipt["type"] != "string"
                or not 0 <= pttl <= 5 * 60 * 1000
                or int(receipt["cardinality"]) != 1
                or int(receipt["value_bytes"]) != 5
                or receipt["value_stream_sha256"]
                != EMPTY_RECEIPT_VALUE_STREAM_SHA256
            ):
                return False
    return not records


def _startup_redis_contract(snapshot: dict[str, Any]) -> bool:
    redis_snapshot = snapshot["redis"]
    if (
        not redis_snapshot["scan_complete_and_stable"]
        or not redis_snapshot["ttl_contract_passed"]
        or redis_snapshot["key_count"] != 4
    ):
        return False
    records = {record["key"]: record for record in redis_snapshot["keys"]}
    for namespace in ("archive", "status-updates"):
        prefix = f"lmyzmail:mail:queue:migration:{namespace}"
        index = records.pop(f"{prefix}:done-index", None)
        if index is None or (
            index["type"] != "zset"
            or int(index["pttl_ms"]) != -1
            or int(index["cardinality"]) != 1
            or int(index["value_bytes"]) != 53
        ):
            return False
        receipt_names = [
            key for key in records if key.startswith(f"{prefix}:done:migrate:")
        ]
        if len(receipt_names) != 1:
            return False
        receipt_name = receipt_names[0]
        if re.fullmatch(
            re.escape(f"{prefix}:done:migrate:") + r"[0-9a-f]{32}",
            receipt_name,
        ) is None:
            return False
        receipt = records.pop(receipt_name)
        pttl = int(receipt["pttl_ms"])
        if (
            receipt["type"] != "string"
            or not 0 <= pttl <= 5 * 60 * 1000
            or int(receipt["cardinality"]) != 1
            or int(receipt["value_bytes"]) != 5
            or receipt["value_stream_sha256"]
            != EMPTY_RECEIPT_VALUE_STREAM_SHA256
        ):
            return False
    return not records


def _initial_state_ready(snapshot: dict[str, Any]) -> bool:
    return (
        all(value == 0 for value in snapshot["database"].values())
        and all(
            tree["files"] == 0 for tree in snapshot["maildir"].values()
        )
        and _startup_redis_contract(snapshot)
    )


def _cleanup_state_semantic(snapshot: dict[str, Any]) -> dict[str, Any]:
    semantic = _state_semantic(snapshot)
    keys = [
        record
        for record in semantic["redis"]["keys"]
        if not record["key"].startswith(
            "lmyzmail:mail:queue:migration:"
        )
    ]
    semantic["redis"]["keys"] = keys
    semantic["redis"]["key_count"] = len(keys)
    semantic["redis"]["dbsize_before"] = len(keys)
    semantic["redis"]["dbsize_after"] = len(keys)
    return semantic


def _natural_state_ready(snapshot: dict[str, Any], expected: int) -> bool:
    database = snapshot["database"]
    maildir = snapshot["maildir"]
    return (
        database["email_index"] == 0
        and database["outbound_queue"] == expected
        and database["delivered"] == expected
        and database["active"] == 0
        and database["failed"] == 0
        and maildir["sender"]["files"] == 0
        and maildir["receiver"]["files"] == 0
        and maildir["stress_temp"]["files"] == 0
        and snapshot["redis"]["scan_complete_and_stable"]
        and snapshot["redis"]["ttl_contract_passed"]
        and _redis_stress_contract(snapshot)
    )


def _wait_natural_drain(
    runtime: StressCandidateRuntimeV2, expected: int, timeout: float = 120.0
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    stable = 0
    last_semantic: str | None = None
    while time.monotonic() < deadline:
        snapshot = _state_snapshot(runtime, "after_natural_drain")
        semantic = hashlib.sha256(
            _json_bytes(_cleanup_state_semantic(snapshot))
        ).hexdigest()
        if _natural_state_ready(snapshot, expected) and semantic == last_semantic:
            stable += 1
        elif _natural_state_ready(snapshot, expected):
            stable = 1
        else:
            stable = 0
        last_semantic = semantic
        if stable >= STATE_STABLE_POLLS:
            snapshot["stable_polls"] = stable
            snapshot["maximum_wait_seconds"] = timeout
            return snapshot
        time.sleep(0.25)
    raise TimeoutError("stress workload did not reach a stable natural drain state")


def _purged_state_ready(snapshot: dict[str, Any]) -> bool:
    database = snapshot["database"]
    maildir = snapshot["maildir"]
    return (
        all(value == 0 for value in database.values())
        and snapshot["redis"]["key_count"] == 0
        and maildir["sender"]["files"] == 0
        and maildir["receiver"]["files"] == 0
        and maildir["outbound_spool"]["files"] == 0
        and maildir["stress_temp"]["files"] == 0
        and maildir["wire_capture"]["files"] == 0
        and snapshot["redis"]["scan_complete_and_stable"]
        and snapshot["redis"]["ttl_contract_passed"]
        and _redis_stress_contract(snapshot)
    )


def _final_pre_stop_state_ready(snapshot: dict[str, Any]) -> bool:
    redis = snapshot["redis"]
    redis_keys = redis["keys"]
    return (
        all(value == 0 for value in snapshot["database"].values())
        and all(tree["files"] == 0 for tree in snapshot["maildir"].values())
        and redis["scan_complete_and_stable"]
        and redis["ttl_contract_passed"]
        and all(
            record["key"].startswith(
                "lmyzmail:mail:queue:migration:"
            )
            for record in redis_keys
        )
        and _migration_receipt_contract(snapshot)
    )


class ResourceMonitor:
    def __init__(
        self, runtime: StressCandidateRuntimeV2, hard_disk_budget_bytes: int
    ) -> None:
        assert runtime.workspace is not None
        self.runtime = runtime
        self.hard_disk_budget_bytes = hard_disk_budget_bytes
        self.workspace_baseline = base._allocated_bytes(runtime.workspace)
        self.filesystem_baseline = base._filesystem_used(runtime.workspace)
        self.samples: list[dict[str, int]] = []
        self.error: BaseException | None = None
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, name="stress-resource-monitor")
        self.thread.start()

    def _run(self) -> None:
        started = time.monotonic()
        try:
            while not self.stop_event.is_set():
                sample = base._sample(
                    self.runtime,
                    self.workspace_baseline,
                    self.filesystem_baseline,
                )
                sample["elapsed_millis"] = int((time.monotonic() - started) * 1000)
                self.samples.append(sample)
                self._enforce_sample(sample)
                self.stop_event.wait(RESOURCE_SAMPLE_SECONDS)
        except BaseException as error:
            self.error = error

    def _enforce_sample(self, sample: dict[str, int]) -> None:
        if sample["rss_kib"] > RESOURCE_POLICY["max_rss_kib"]:
            raise RuntimeError("stress candidate exceeded RSS ceiling")
        if sample["fd_count"] > RESOURCE_POLICY["max_fd_count"]:
            raise RuntimeError("stress candidate exceeded FD ceiling")
        if sample["task_count"] > RESOURCE_POLICY["max_task_count"]:
            raise RuntimeError("stress candidate exceeded task ceiling")
        if sample["queue_pending"] > RESOURCE_POLICY["max_queue_pending"]:
            raise RuntimeError("stress Redis pending queue exceeded ceiling")
        if sample["workspace_delta_bytes"] > self.hard_disk_budget_bytes:
            raise RuntimeError("stress workspace exceeded hard disk budget")
        if sample["filesystem_delta_bytes"] > self.hard_disk_budget_bytes:
            raise RuntimeError("stress filesystem delta exceeded hard disk budget")
        if (
            sample["filesystem_free_bytes"]
            < RESOURCE_POLICY["minimum_filesystem_free_bytes"]
        ):
            raise RuntimeError("stress filesystem free space fell below reserve")

    def check(self) -> None:
        if self.error is not None:
            raise RuntimeError("stress resource monitor failed") from self.error

    def stop(self) -> dict[str, Any]:
        self.stop_event.set()
        self.thread.join(timeout=30.0)
        if self.thread.is_alive():
            raise TimeoutError("stress resource monitor did not stop")
        self.check()
        if not self.samples:
            raise RuntimeError("stress resource monitor captured no samples")
        samples = self.samples
        steady = [sample for sample in samples if sample["elapsed_millis"] >= 60_000]
        steady_first = steady[0] if steady else samples[-1]
        final = samples[-1]
        steady_growth = {
            "rss_kib": max(sample["rss_kib"] for sample in steady or [final])
            - steady_first["rss_kib"],
            "fd_count": max(sample["fd_count"] for sample in steady or [final])
            - steady_first["fd_count"],
            "task_count": max(sample["task_count"] for sample in steady or [final])
            - steady_first["task_count"],
        }
        checks = {
            "rss": steady_growth["rss_kib"]
            <= RESOURCE_POLICY["max_steady_rss_growth_kib"],
            "fd": steady_growth["fd_count"]
            <= RESOURCE_POLICY["max_steady_fd_growth"],
            "task": steady_growth["task_count"]
            <= RESOURCE_POLICY["max_steady_task_growth"],
        }
        if steady and not all(checks.values()):
            raise RuntimeError(f"stress steady resource growth exceeded policy: {checks}")
        return {
            "sample_interval_seconds": RESOURCE_SAMPLE_SECONDS,
            "samples": len(samples),
            "rss_first_kib": samples[0]["rss_kib"],
            "rss_final_kib": final["rss_kib"],
            "rss_peak_kib": max(sample["rss_kib"] for sample in samples),
            "fd_first": samples[0]["fd_count"],
            "fd_final": final["fd_count"],
            "fd_peak": max(sample["fd_count"] for sample in samples),
            "task_first": samples[0]["task_count"],
            "task_final": final["task_count"],
            "task_peak": max(sample["task_count"] for sample in samples),
            "queue_peak": max(sample["queue_pending"] for sample in samples),
            "workspace_delta_peak_bytes": max(
                sample["workspace_delta_bytes"] for sample in samples
            ),
            "workspace_delta_final_bytes": final["workspace_delta_bytes"],
            "filesystem_delta_peak_bytes": max(
                sample["filesystem_delta_bytes"] for sample in samples
            ),
            "filesystem_delta_final_bytes": final["filesystem_delta_bytes"],
            "filesystem_free_min_bytes": min(
                sample["filesystem_free_bytes"] for sample in samples
            ),
            "steady_growth": steady_growth,
            "steady_growth_checks": checks,
            "samples_all": samples,
        }


def _call_start(
    runtime: StressCandidateRuntimeV2, *, expected_count: int, expected_size_kib: int
) -> dict[str, Any]:
    assert runtime.ports is not None
    requested_at = _utc_now()
    started = time.monotonic()
    response = base.http_exchange(
        "127.0.0.1",
        runtime.ports.http,
        "POST",
        "/api/stress/start",
        headers=(("X-API-Key", base.API_KEY),),
    )
    try:
        response_json = json.loads(response.body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("stress start returned invalid JSON") from error
    record = {
        "method": "POST",
        "path": "/api/stress/start",
        "requested_at": requested_at,
        "completed_at": _utc_now(),
        "duration_ms": round((time.monotonic() - started) * 1000.0, 3),
        "status_code": response.status_code,
        "body_sha256": hashlib.sha256(response.body).hexdigest(),
        "body": response_json,
    }
    if response.status_code != 200:
        raise RuntimeError(f"stress start request failed: {record!r}")
    expected = {
        "mode": "PRODUCTION",
        "emailCount": expected_count,
        "emailSizeKB": expected_size_kib,
    }
    if not isinstance(response_json, dict) or any(
        response_json.get(name) != value for name, value in expected.items()
    ):
        raise RuntimeError(f"stress start response contract changed: {response_json!r}")
    if not isinstance(response_json.get("round"), int) or response_json["round"] <= 0:
        raise RuntimeError("stress start response omitted a positive round")
    return record


def _call_cleanup(
    runtime: StressCandidateRuntimeV2, *, invocation: int, timeout: float = 120.0
) -> dict[str, Any]:
    assert runtime.ports is not None
    started = time.monotonic()
    requested_at = _utc_now()
    attempts: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        response = base.http_exchange(
            "127.0.0.1",
            runtime.ports.http,
            "POST",
            "/api/stress/cleanup",
            headers=(("X-API-Key", base.API_KEY),),
        )
        try:
            response_json = json.loads(response.body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RuntimeError("stress cleanup returned invalid JSON") from error
        attempts.append(
            {
                "status_code": response.status_code,
                "body_sha256": hashlib.sha256(response.body).hexdigest(),
                "body": response_json,
            }
        )
        if response.status_code == 200:
            expected_body = {
                "message": (
                    f"Cleanup completed for {base.ENDPOINT_SENDER} and "
                    f"{base.RECEIVER}"
                )
            }
            if response_json != expected_body:
                raise RuntimeError("stress cleanup success body changed")
            return {
                "invocation": invocation,
                "method": "POST",
                "path": "/api/stress/cleanup",
                "requested_at": requested_at,
                "completed_at": _utc_now(),
                "duration_ms": round((time.monotonic() - started) * 1000.0, 3),
                "attempts": attempts,
                "status_code": 200,
            }
        if response.status_code != 503:
            raise RuntimeError(
                f"stress cleanup returned unexpected status: {response.status_code}"
            )
        time.sleep(0.05)
    raise TimeoutError("stress cleanup remained busy before deadline")


def _port_released(host: str, port: int) -> bool:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    probe = socket.socket(family, socket.SOCK_STREAM)
    try:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def _process_tree_identities(roots: dict[str, int]) -> dict[str, dict[str, int]]:
    processes: dict[int, tuple[int, int]] = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            status = (entry / "status").read_text(encoding="ascii")
            parent = int(
                next(line.split()[1] for line in status.splitlines() if line.startswith("PPid:"))
            )
            stat_fields = (entry / "stat").read_text(encoding="ascii").rsplit(") ", 1)[1].split()
            start_ticks = int(stat_fields[19])
        except (
            FileNotFoundError,
            ProcessLookupError,
            PermissionError,
            StopIteration,
            ValueError,
            IndexError,
        ):
            continue
        processes[int(entry.name)] = (parent, start_ticks)
    output: dict[str, dict[str, int]] = {}
    for name, root in roots.items():
        pending = [root]
        seen: set[int] = set()
        while pending:
            pid = pending.pop()
            if pid in seen:
                continue
            seen.add(pid)
            identity = processes.get(pid)
            if identity is not None:
                output[f"{name}:{pid}"] = {"pid": pid, "start_ticks": identity[1]}
            pending.extend(
                child for child, (parent, _) in processes.items() if parent == pid
            )
    return output


def _identity_still_exists(identity: dict[str, int]) -> bool:
    pid = identity["pid"]
    try:
        fields = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").rsplit(") ", 1)[1].split()
        return int(fields[19]) == identity["start_ticks"]
    except (
        FileNotFoundError,
        ProcessLookupError,
        PermissionError,
        ValueError,
        IndexError,
    ):
        return False


def _process_group_identities(groups: dict[str, int]) -> dict[str, dict[str, int]]:
    output: dict[str, dict[str, int]] = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / "stat").read_text(encoding="ascii").rsplit(") ", 1)[1].split()
            process_group = int(fields[2])
            start_ticks = int(fields[19])
        except (
            FileNotFoundError,
            ProcessLookupError,
            PermissionError,
            ValueError,
            IndexError,
        ):
            continue
        for name, expected_group in groups.items():
            if process_group == expected_group:
                pid = int(entry.name)
                output[f"{name}:{pid}"] = {
                    "pid": pid,
                    "process_group": process_group,
                    "start_ticks": start_ticks,
                }
    return output


def run_plan(
    plan: Any,
    hard_disk_budget_bytes: int,
    checkpoint: Any | None = None,
) -> dict[str, Any]:
    if plan.total_messages <= 0 or plan.batch_size <= 0:
        raise ValueError("stress counts must be positive")
    if plan.total_messages % plan.batch_size:
        raise ValueError("stress total must be an exact multiple of batch size")
    if plan.message_bytes <= 0 or plan.message_bytes % 1024:
        raise ValueError("stress message size must be a positive whole KiB")
    candidate = REPOSITORY / "target/x86_64-unknown-linux-gnu/release/lmyzmail"
    spf_dns = base.StressDnsServer()
    runtime = StressCandidateRuntimeV2(
        command_template=(str(candidate), "--config", "{config}")
    )
    runtime.production_count = plan.batch_size
    runtime.email_size_kb = plan.message_bytes // 1024
    runtime.spf_dns_port = spf_dns.port
    runtime.shutdown_timeout = 35.0
    proxy: SmtpCaptureProxy | None = None
    monitor: ResourceMonitor | None = None
    monitor_summary: dict[str, Any] | None = None
    workspace_path: Path | None = None
    managed_pids: dict[str, int] = {}
    managed_process_tree: dict[str, dict[str, int]] = {}
    managed_process_groups: dict[str, int] = {}
    managed_process_group_members: dict[str, dict[str, int]] = {}
    ports: dict[str, int] = {}
    latencies: list[float] = []
    batch_latencies: list[float] = []
    batch_evidence: list[dict[str, Any]] = []
    failures = 0
    retries = 0
    sent = 0
    started = time.monotonic()
    result: dict[str, Any] | None = None
    primary_error: BaseException | None = None
    cleanup_errors: list[str] = []
    recovery_actions: list[dict[str, Any]] = []
    try:
        runtime.start()
        assert runtime.ports is not None and runtime.workspace is not None
        workspace_path = runtime.workspace
        ports = {
            "http": runtime.ports.http,
            "smtp_backend": runtime.ports.smtp,
            "postgres": runtime.ports.postgres,
            "redis": runtime.ports.redis,
            "smtp_capture": SMTP_CAPTURE_PORT,
        }
        processes = {
            "candidate": runtime._application,
            "postgres": runtime._postgres,
            "redis": runtime._redis,
        }
        managed_pids = {
            name: process.pid
            for name, process in processes.items()
            if process is not None
        }
        managed_process_tree = _process_tree_identities(managed_pids)
        managed_process_groups = {
            name: os.getpgid(pid) for name, pid in managed_pids.items()
        }
        managed_process_group_members = _process_group_identities(
            managed_process_groups
        )
        proxy = SmtpCaptureProxy(runtime)
        monitor = ResourceMonitor(runtime, hard_disk_budget_bytes)
        initial_state = _state_snapshot(runtime, "before_plan")
        if not _initial_state_ready(initial_state):
            raise RuntimeError(
                "isolated fixture startup migration contract changed"
            )
        expected_clean_state = _state_semantic(initial_state)
        for batch_start in range(0, plan.total_messages, plan.batch_size):
            monitor.check()
            batch_started = time.monotonic()
            before = _state_snapshot(runtime, "before")
            if _state_semantic(before) != expected_clean_state:
                raise RuntimeError("previous stress batch did not finish cleanly")
            proxy.begin_batch(plan.batch_size, plan.message_bytes)
            start_request = _call_start(
                runtime,
                expected_count=plan.batch_size,
                expected_size_kib=plan.message_bytes // 1024,
            )
            wait_samples: list[dict[str, int]] = []
            rows, ledger = base._wait_for_deliveries(
                runtime,
                plan.batch_size,
                monitor.workspace_baseline,
                monitor.filesystem_baseline,
                hard_disk_budget_bytes,
                wait_samples,
            )
            capture, batch_message_latencies = proxy.finish_batch()
            if len(rows) != plan.batch_size or capture["verified"] != plan.batch_size:
                raise RuntimeError("stress batch did not verify every requested message")
            if capture["rounds"] != [start_request["body"]["round"]]:
                raise RuntimeError("SMTP payload round differed from start response")
            latencies.extend(batch_message_latencies)
            sent += capture["verified"]
            failures += ledger["failed"]
            retries += ledger["retries"]
            natural = _wait_natural_drain(runtime, plan.batch_size)
            cleanup_requests: list[dict[str, Any]] = []
            cleanup_requests.append(_call_cleanup(runtime, invocation=1))
            after_api_cleanup = _state_snapshot(runtime, "after_api_cleanup")
            cleanup_requests.append(_call_cleanup(runtime, invocation=2))
            after_api_cleanup_idempotent = _state_snapshot(
                runtime, "after_api_cleanup_idempotent"
            )
            before_purge = _state_snapshot(runtime, "before_harness_purge")
            if not _natural_state_ready(after_api_cleanup, plan.batch_size):
                raise RuntimeError("first API cleanup changed the natural drain contract")
            if not _natural_state_ready(
                after_api_cleanup_idempotent, plan.batch_size
            ):
                raise RuntimeError("idempotent API cleanup changed the drain contract")
            if not _natural_state_ready(before_purge, plan.batch_size):
                raise RuntimeError("stress state changed before harness purge")
            natural_semantic = _cleanup_state_semantic(natural)
            if _cleanup_state_semantic(after_api_cleanup) != natural_semantic:
                raise RuntimeError("first API cleanup mutated already-clean stress state")
            if (
                _cleanup_state_semantic(after_api_cleanup_idempotent)
                != natural_semantic
            ):
                raise RuntimeError("second API cleanup was not idempotent")
            if _cleanup_state_semantic(before_purge) != natural_semantic:
                raise RuntimeError("stress state changed before harness purge")
            base._purge_isolated_queue(runtime)
            after_purge = _state_snapshot(runtime, "after_harness_purge")
            if not _purged_state_ready(after_purge):
                raise RuntimeError(
                    f"harness purge did not clean isolated state: {after_purge!r}"
                )
            expected_clean_state = _state_semantic(after_purge)
            monitor.check()
            batch_latency = (time.monotonic() - batch_started) * 1000.0
            batch_latencies.append(batch_latency)
            batch_record = {
                "batch_ordinal": len(batch_evidence),
                "message_ordinal_start": batch_start,
                "message_count": plan.batch_size,
                "duration_ms": round(batch_latency, 3),
                "start_request": start_request,
                "smtp_capture": capture,
                "delivery_ledger": ledger,
                "states": {
                    "before": before,
                    "after_natural_drain": natural,
                    "after_api_cleanup": after_api_cleanup,
                    "after_api_cleanup_idempotent": after_api_cleanup_idempotent,
                    "before_harness_purge": before_purge,
                    "after_harness_purge": after_purge,
                },
                "cleanup_requests": cleanup_requests,
                "natural_drain_preceded_api_cleanup": True,
                "natural_drain_source": (
                    "Rust stress run_stress final cleanup completed before any "
                    "/api/stress/cleanup request"
                ),
                "harness_purge_excluded_from_natural_and_api_pass": True,
            }
            batch_evidence.append(batch_record)
            if checkpoint is not None:
                checkpoint(
                    {
                        "batch_ordinal": batch_record["batch_ordinal"],
                        "batches_total": plan.total_messages // plan.batch_size,
                        "sent": sent,
                        "requested": plan.total_messages,
                        "failures": failures,
                        "retries": retries,
                        "smtp_capture_sha256": capture["record_stream_sha256"],
                        "after_purge_sha256": after_purge["state_sha256"],
                    }
                )
        final_state = _state_snapshot(runtime, "final_teardown_before_stop")
        if not _final_pre_stop_state_ready(final_state):
            raise RuntimeError("stress final pre-stop state was not clean")
        if monitor is None:
            raise RuntimeError("stress resource monitor was not started")
        monitor_summary = monitor.stop()
        monitor = None
        if proxy is None:
            raise RuntimeError("SMTP capture proxy was not started")
        proxy.close()
        proxy = None
        duration = time.monotonic() - started
        result = {
            "label": plan.label,
            "message_bytes": plan.message_bytes,
            "requested": plan.total_messages,
            "sent": sent,
            "batch_size": plan.batch_size,
            "batches": len(batch_evidence),
            "failures": failures,
            "retries": retries,
            "duration_seconds": round(duration, 3),
            "throughput_messages_per_second": round(sent / max(duration, 0.001), 3),
            "throughput_body_bytes_per_second": round(
                sent * plan.message_bytes / max(duration, 0.001), 3
            ),
            "independent_delivery_latency_ms": base._distribution(latencies),
            "batch_completion_ms": base._distribution(batch_latencies),
            "resource": monitor_summary,
            "initial_state": initial_state,
            "final_state": final_state,
            "batch_evidence": batch_evidence,
        }
    except BaseException as error:
        primary_error = error
        if proxy is not None and proxy.error is not None:
            error.add_note(
                "SMTP proxy error: "
                f"{type(proxy.error).__name__}: {proxy.error}"
            )
        if runtime.ports is not None and checkpoint is not None:
            try:
                checkpoint(
                    {
                        "_event": "failure_snapshot",
                        "error": {
                            "type": type(error).__name__,
                            "message": str(error),
                        },
                        "smtp_proxy": None
                        if proxy is None
                        else proxy.diagnostics(),
                        "state": _state_snapshot(runtime, "failure_before_recovery"),
                    }
                )
            except BaseException as snapshot_error:
                error.add_note(
                    "failure snapshot failed: "
                    f"{type(snapshot_error).__name__}: {snapshot_error}"
                )
    finally:
        if monitor is not None:
            try:
                monitor_summary = monitor.stop()
            except BaseException as error:
                cleanup_errors.append(f"resource monitor: {type(error).__name__}: {error}")
        if primary_error is not None and runtime.ports is not None:
            try:
                cleanup_record = _call_cleanup(runtime, invocation=99, timeout=30.0)
                recovery_actions.append(
                    {"action": "api_cleanup", "status": "completed", "record": cleanup_record}
                )
            except BaseException as error:
                cleanup_errors.append(f"API cleanup: {type(error).__name__}: {error}")
                recovery_actions.append(
                    {
                        "action": "api_cleanup",
                        "status": "failed",
                        "error": {"type": type(error).__name__, "message": str(error)},
                    }
                )
            try:
                base._purge_isolated_queue(runtime)
                recovery_actions.append(
                    {"action": "harness_purge", "status": "completed"}
                )
            except BaseException as error:
                cleanup_errors.append(f"harness purge: {type(error).__name__}: {error}")
                recovery_actions.append(
                    {
                        "action": "harness_purge",
                        "status": "failed",
                        "error": {"type": type(error).__name__, "message": str(error)},
                    }
                )
            if checkpoint is not None:
                try:
                    checkpoint(
                        {
                            "_event": "failure_recovery",
                            "actions": recovery_actions,
                            "state": _state_snapshot(
                                runtime, "failure_after_recovery"
                            ),
                        }
                    )
                except BaseException as error:
                    cleanup_errors.append(
                        "failure recovery snapshot: "
                        f"{type(error).__name__}: {error}"
                    )
        if managed_pids:
            managed_process_tree.update(_process_tree_identities(managed_pids))
        if managed_process_groups:
            managed_process_group_members.update(
                _process_group_identities(managed_process_groups)
            )
        runtime.stop()
        if proxy is not None:
            try:
                proxy.close()
            except BaseException as error:
                cleanup_errors.append(f"SMTP proxy: {type(error).__name__}: {error}")
        spf_dns.close()
    residual_process_tree = {
        name: identity
        for name, identity in managed_process_tree.items()
        if _identity_still_exists(identity)
    }
    residual_process_group_members = _process_group_identities(
        managed_process_groups
    )
    ports_released = {
        name: _port_released(
            SMTP_CAPTURE_ADDRESS if name == "smtp_capture" else "127.0.0.1", port
        )
        for name, port in ports.items()
        if name in ("http", "smtp_backend", "smtp_capture", "postgres", "redis")
    }
    cleanup = {
        "managed_pids": managed_pids,
        "managed_process_groups": managed_process_groups,
        "managed_process_group_members": managed_process_group_members,
        "managed_process_tree": managed_process_tree,
        "residual_process_tree": residual_process_tree,
        "residual_process_group_members": residual_process_group_members,
        "ports_released": ports_released,
        "workspace_removed": workspace_path is not None and not workspace_path.exists(),
        "cleanup_errors": cleanup_errors,
    }
    if primary_error is not None:
        if cleanup_errors:
            primary_error.add_note(f"cleanup errors: {cleanup_errors!r}")
        raise primary_error
    if result is None:
        raise RuntimeError("stress plan completed without a result")
    result["cleanup"] = cleanup
    result["status"] = (
        "passed"
        if sent == plan.total_messages
        and failures == 0
        and retries == 0
        and not residual_process_tree
        and not residual_process_group_members
        and all(ports_released.values())
        and cleanup["workspace_removed"]
        and not cleanup_errors
        else "failed"
    )
    if result["status"] != "passed":
        raise RuntimeError(f"stress plan cleanup acceptance failed: {cleanup!r}")
    return result


def _load_checkpoint(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    previous_record_sha256: str | None = None
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if not stat_module.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"checkpoint is not a regular file: {path}")
        stream = os.fdopen(descriptor, "r", encoding="utf-8")
        descriptor = -1
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    with stream:
        for number, line in enumerate(stream, start=1):
            try:
                value = json.loads(line)
            except json.JSONDecodeError as error:
                raise RuntimeError(f"invalid checkpoint JSON at line {number}") from error
            if not isinstance(value, dict):
                raise RuntimeError(f"invalid checkpoint record at line {number}")
            sequence = value.get("_sequence")
            previous = value.get("_previous_record_sha256")
            record_sha256 = value.get("_record_sha256")
            if sequence != number - 1 or previous != previous_record_sha256:
                raise RuntimeError(
                    f"checkpoint sequence/hash chain changed at line {number}"
                )
            if not isinstance(record_sha256, str):
                raise RuntimeError(f"checkpoint digest is missing at line {number}")
            unsigned = dict(value)
            del unsigned["_record_sha256"]
            if _checkpoint_digest(unsigned) != record_sha256:
                raise RuntimeError(f"checkpoint digest changed at line {number}")
            previous_record_sha256 = record_sha256
            records.append(value)
    if not records:
        raise RuntimeError("stress checkpoint is empty")
    return records


def _plan_dict(plan: Any) -> dict[str, Any]:
    return {
        "label": plan.label,
        "message_bytes": plan.message_bytes,
        "total_messages": plan.total_messages,
        "batch_size": plan.batch_size,
    }


def _validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if args.output is None:
        parser.error("--output is required for auditable SMTP stress evidence")
    if not math.isfinite(args.disk_budget_gib) or args.disk_budget_gib <= 0:
        parser.error("--disk-budget-gib must be finite and positive")
    if args.disk_budget_gib < 1.0:
        parser.error("--disk-budget-gib must reserve at least 1 GiB")
    if os.path.lexists(args.output) and not args.resume:
        parser.error(f"final evidence already exists: {args.output}")


def _enter_isolated_namespace() -> None:
    if os.environ.get(base.NAMESPACE_ENV) == "1":
        return
    environment = dict(os.environ)
    environment[base.NAMESPACE_ENV] = "1"
    arguments = [
        base._required_command("unshare"),
        "--user",
        f"--map-user={os.getuid()}",
        f"--map-group={os.getgid()}",
        "--keep-caps",
        "--net",
        "--mount",
        "--propagation",
        "private",
        str(Path(sys.executable).absolute()),
        str(RUNNER),
        *sys.argv[1:],
    ]
    os.execve(arguments[0], arguments, environment)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--disk-budget-gib", type=float, default=20.0)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    _validate_args(args, parser)
    assert args.output is not None
    output = args.output.resolve()
    running = output.with_name(f"{output.name}.running.jsonl")
    complete_checkpoint = output.with_name(f"{output.name}.complete.jsonl")
    if args.resume and os.path.lexists(output) and not complete_checkpoint.exists():
        parser.error("existing final evidence requires a complete checkpoint")
    if not args.resume and (os.path.lexists(running) or os.path.lexists(complete_checkpoint)):
        parser.error("checkpoint already exists; use --resume after auditing it")
    _enter_isolated_namespace()
    budget = int(args.disk_budget_gib * 1024**3)
    large_target = max(1, budget // (10 * 1024 * 1024) // 2)
    large_batch = min(50, large_target)
    large_count = max(large_batch, (large_target // large_batch) * large_batch)
    plans = (
        (
            base.StressPlan("1KB-smoke", 1024, 4, 2),
            base.StressPlan("10KB-smoke", 10 * 1024, 4, 2),
            base.StressPlan("10MB-smoke", 10 * 1024 * 1024, 2, 2),
        )
        if args.smoke
        else (
            base.StressPlan("1KB", 1024, 500_000, 1_000),
            base.StressPlan("10KB", 10 * 1024, 500_000, 1_000),
            base.StressPlan("10MB-budgeted", 10 * 1024 * 1024, large_count, large_batch),
        )
    )
    plan_contract = [_plan_dict(plan) for plan in plans]
    runner_sha256 = _sha256_file(RUNNER)
    base_sha256 = _sha256_file(BASE_SOURCE)
    candidate = REPOSITORY / "target/x86_64-unknown-linux-gnu/release/lmyzmail"
    release_sha256 = _sha256_file(candidate)
    definition = GoldenAttestation.from_repository(
        REPOSITORY,
        profile="candidate-smtp-self-receive-disk-stress-v2",
        normalizers=(),
    ).harness_definition_sha256
    git_head = _git_head()
    completed_plans: list[dict[str, Any]] = []
    if args.resume and complete_checkpoint.exists():
        records = _load_checkpoint(complete_checkpoint)
        final_ready = records[-1]
        if final_ready.get("event") != "final_ready":
            raise RuntimeError("complete checkpoint has no final_ready record")
        result = final_ready["result"]
        immutable = result.get("immutable_inputs", {})
        current = {
            "runner_sha256_after": runner_sha256,
            "base_runner_sha256_after": base_sha256,
            "definition_tree_sha256_after": definition,
            "candidate_release_sha256_after": release_sha256,
            "git_head_after": git_head,
        }
        contract_matches = (
            result.get("profile")
            == "candidate-smtp-self-receive-disk-stress-v2"
            and result.get("smoke") is args.smoke
            and result.get("qualified_formal_stress") is (not args.smoke)
            and result.get("hard_disk_budget_bytes") == budget
            and result.get("plans_contract") == plan_contract
            and result.get("resource_policy") == RESOURCE_POLICY
        )
        if (
            result.get("status") != "passed"
            or result.get("complete") is not True
            or not contract_matches
            or any(immutable.get(name) != value for name, value in current.items())
        ):
            raise RuntimeError("complete checkpoint no longer matches immutable inputs")
        if os.path.lexists(output):
            if _load_json_file(output) != result:
                raise RuntimeError(
                    "existing final evidence differs from complete checkpoint"
                )
        else:
            _atomic_create_json(output, result)
        if running.exists():
            if _load_checkpoint(running) != records:
                raise RuntimeError(
                    "running and complete checkpoints differ during recovery"
                )
            running.unlink()
            directory = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        print(json.dumps({"status": result["status"], "output": str(output)}, indent=2))
        return 0 if result["status"] == "passed" else 1
    if args.resume:
        if not running.exists():
            parser.error("--resume requires an existing running checkpoint")
        records = _load_checkpoint(running)
        header = records[0]
        expected = {
            "runner_sha256": runner_sha256,
            "base_runner_sha256": base_sha256,
            "definition_tree_sha256": definition,
            "candidate_release_sha256": release_sha256,
            "git_head": git_head,
            "plans": plan_contract,
            "smoke": args.smoke,
            "qualified_formal_stress": not args.smoke,
            "hard_disk_budget_bytes": budget,
            "resource_policy": RESOURCE_POLICY,
        }
        for name, value in expected.items():
            if header.get(name) != value:
                raise RuntimeError(f"checkpoint resume contract changed: {name}")
        plan_records = [
            record for record in records if record.get("event") == "plan_complete"
        ]
        completed_plans = [record["result"] for record in plan_records]
        if len(completed_plans) > len(plans):
            raise RuntimeError("checkpoint contains more plans than the active contract")
        for index, (record, plan_result) in enumerate(
            zip(plan_records, completed_plans, strict=True)
        ):
            if (
                record.get("plan_index") != index
                or
                plan_result.get("label") != plans[index].label
                or plan_result.get("status") != "passed"
            ):
                raise RuntimeError(f"checkpoint plan sequence is invalid at index {index}")
        run_id = str(header["run_id"])
        checkpoint = JsonlCheckpoint(
            running, resume=True, existing_records=records
        )
        checkpoint.append(
            {
                "event": "resumed",
                "at": _utc_now(),
                "argv": [str(RUNNER.relative_to(REPOSITORY)), *sys.argv[1:]],
                "completed_plans": len(completed_plans),
            }
        )
    else:
        run_id = str(uuid.uuid4())
        checkpoint = JsonlCheckpoint(running, resume=False)
        checkpoint.append(
            {
                "event": "started",
                "schema_version": 2,
                "run_id": run_id,
                "at": _utc_now(),
                "complete": False,
                "runner_sha256": runner_sha256,
                "base_runner_sha256": base_sha256,
                "definition_tree_sha256": definition,
                "candidate_release_sha256": release_sha256,
                "git_head": git_head,
                "plans": plan_contract,
                "smoke": args.smoke,
                "qualified_formal_stress": not args.smoke,
                "hard_disk_budget_bytes": budget,
                "resource_policy": RESOURCE_POLICY,
                "argv": [str(RUNNER.relative_to(REPOSITORY)), *sys.argv[1:]],
                "cwd": str(Path.cwd().resolve()),
                "resume_granularity": "completed plan",
            }
        )
    started_at = _utc_now()
    checkpoint_closed = False
    try:
        with tempfile.TemporaryDirectory(
            prefix="lmyzmail-smtp-stress-v2-namespace-"
        ) as temporary:
            base._configure_isolated_namespace(Path(temporary))
            for index, plan in enumerate(plans[len(completed_plans) :], start=len(completed_plans)):

                def progress(current: dict[str, Any], plan_index: int = index) -> None:
                    event = str(current.pop("_event", "batch_complete"))
                    checkpoint.append(
                        {
                            "event": event,
                            "at": _utc_now(),
                            "plan_index": plan_index,
                            "current": current,
                        }
                    )

                plan_result = run_plan(plan, budget, progress)
                completed_plans.append(plan_result)
                checkpoint.append(
                    {
                        "event": "plan_complete",
                        "at": _utc_now(),
                        "plan_index": index,
                        "result": plan_result,
                    }
                )
        release_after = _sha256_file(candidate)
        definition_after = GoldenAttestation.from_repository(
            REPOSITORY,
            profile="candidate-smtp-self-receive-disk-stress-v2",
            normalizers=(),
        ).harness_definition_sha256
        immutable_inputs = {
            "runner_sha256_before": runner_sha256,
            "runner_sha256_after": _sha256_file(RUNNER),
            "base_runner_sha256_before": base_sha256,
            "base_runner_sha256_after": _sha256_file(BASE_SOURCE),
            "definition_tree_sha256_before": definition,
            "definition_tree_sha256_after": definition_after,
            "candidate_release_sha256_before": release_sha256,
            "candidate_release_sha256_after": release_after,
            "git_head_before": git_head,
            "git_head_after": _git_head(),
        }
        immutable_inputs["unchanged"] = all(
            immutable_inputs[f"{name}_before"] == immutable_inputs[f"{name}_after"]
            for name in (
                "runner_sha256",
                "base_runner_sha256",
                "definition_tree_sha256",
                "candidate_release_sha256",
                "git_head",
            )
        )
        result = {
            "schema_version": 4,
            "profile": "candidate-smtp-self-receive-disk-stress-v2",
            "run_id": run_id,
            "started_at": started_at,
            "finished_at": _utc_now(),
            "complete": True,
            "smoke": args.smoke,
            "qualified_formal_stress": not args.smoke,
            "hard_disk_budget_bytes": budget,
            "plans_contract": plan_contract,
            "plans": completed_plans,
            "resource_policy": RESOURCE_POLICY,
            "immutable_inputs": immutable_inputs,
            "network_isolation": {
                "user_namespace": True,
                "network_namespace": True,
                "mount_namespace": True,
                "mapped_uid": os.getuid(),
                "smtp_capture_address": SMTP_CAPTURE_ADDRESS,
                "smtp_capture_port": SMTP_CAPTURE_PORT,
                "plaintext_capture_reason": (
                    "The base candidate fixture has TLS disabled; the isolated proxy "
                    "captures and forwards the exact SMTP DATA/BDAT stream."
                ),
            },
            "cleanup_semantics": {
                "natural_drain_precedes_api_cleanup": True,
                "api_cleanup_called_twice_for_idempotency": True,
                "harness_purge_recorded_separately": True,
                "harness_purge_excluded_from_natural_and_api_pass": True,
                "final_teardown_state_captured_before_runtime_stop": True,
                "final_evidence_created_before_running_checkpoint_removed": True,
                "redis_migration_receipts_raw_snapshotted": True,
                "redis_migration_receipt_tokens_normalized_only_for_stability": True,
                "redis_migration_receipt_limit_per_namespace": 4_096,
            },
            "checkpoint_integrity": "sha256-chain-v1",
        }
        result["status"] = (
            "passed"
            if len(completed_plans) == len(plans)
            and all(plan["status"] == "passed" for plan in completed_plans)
            and immutable_inputs["unchanged"]
            else "failed"
        )
        checkpoint.append({"event": "final_ready", "at": _utc_now(), "result": result})
        checkpoint.close()
        checkpoint_closed = True
        os.link(running, complete_checkpoint)
        directory = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        _atomic_create_json(output, result)
        running.unlink()
        directory = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        print(
            json.dumps(
                {
                    "status": result["status"],
                    "output": str(output),
                    "qualified_formal_stress": result["qualified_formal_stress"],
                    "plans": [
                        {
                            "label": plan["label"],
                            "sent": plan["sent"],
                            "duration_seconds": plan["duration_seconds"],
                            "status": plan["status"],
                        }
                        for plan in completed_plans
                    ],
                },
                sort_keys=True,
                indent=2,
            )
        )
        return 0 if result["status"] == "passed" else 1
    except BaseException as error:
        if not checkpoint_closed:
            checkpoint.append(
                {
                    "event": "failed",
                    "at": _utc_now(),
                    "complete": False,
                    "error": {"type": type(error).__name__, "message": str(error)},
                }
            )
            checkpoint.close()
        raise


if __name__ == "__main__":
    raise SystemExit(main())
