from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import ctypes
import hashlib
import importlib.util
import json
import math
import os
import platform
import re
import select
import socket
import stat
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from array import array
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field as dataclass_field
from datetime import UTC, datetime
from email import policy
from email.parser import BytesHeaderParser
from email.utils import getaddresses, parseaddr
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

REPOSITORY = Path(__file__).resolve().parents[2]
CANDIDATE_RELEASE = REPOSITORY / "target/x86_64-unknown-linux-gnu/release/lmyzmail"
CANDIDATE_PROFILING_RELEASE = (
    REPOSITORY / "target/profiling/x86_64-unknown-linux-gnu/release-with-debug/lmyzmail"
)
sys.path.insert(0, str(REPOSITORY / "blackbox/src"))

V2_SOURCE = REPOSITORY / "evidence/compatibility/smtp-self-stress-v2.py"
V2_SPEC = importlib.util.spec_from_file_location(
    "smtp_endpoint_throughput_v1_base", V2_SOURCE
)
if V2_SPEC is None or V2_SPEC.loader is None:
    raise RuntimeError(f"cannot load SMTP stress support: {V2_SOURCE}")
v2 = importlib.util.module_from_spec(V2_SPEC)
sys.modules[V2_SPEC.name] = v2
V2_SPEC.loader.exec_module(v2)
base = v2.base

from lmyzmail_blackbox.ports import PortSet  # noqa: E402
from lmyzmail_blackbox.processes import ManagedProcess  # noqa: E402
from lmyzmail_blackbox.errors import HarnessError, ProcessStartError  # noqa: E402
from lmyzmail_blackbox import protocols as blackbox_protocols  # noqa: E402
from lmyzmail_blackbox.runtime import JavaOracleRuntime  # noqa: E402

ENDPOINT_SENDER = "stress-sender@lmyz.net"
ENDPOINT_RECEIVER = "stress-receiver@lmyz.net"
MAILBOX_PATH_CHUNK_BYTES = 120
SMTP_CAPTURE_ADDRESS = "1.1.1.1"
SMTP_CAPTURE_PORT = 25
MAX_CAPTURE_CONNECTIONS = 2_048
BENCHMARK_SELF_SMTP_MAX_CONNECTIONS_PER_IP = MAX_CAPTURE_CONNECTIONS
BENCHMARK_SELF_SMTP_MAX_NEW_CONNECTIONS_PER_MINUTE = 1_000_000
BENCHMARK_SELF_SMTP_MAX_INBOUND_BYTES_PER_WINDOW = 8 * 1024**3
MAX_WIRE_MESSAGE_BYTES = 12 * 1024 * 1024
HEADER_CAPTURE_BYTES = 64 * 1024
SAMPLE_MESSAGES = 8
MEASUREMENT_TIMEOUT_SECONDS = 45 * 60
CLEANUP_TIMEOUT_SECONDS = 30 * 60
RESOURCE_SAMPLE_SECONDS = 1.0
STATE_STABLE_POLLS = 3
MINIMUM_FILESYSTEM_FREE_BYTES = 2 * 1024**3
IO_CALIBRATION_BYTES = 16 * 1024**2
IO_ACCOUNTING_MINIMUM_RATIO = 0.95
FORMAL_DISK_BUDGET_BYTES = 20 * 1024**3
FORMAL_HOST_RESERVE_BYTES = 10 * 1024**3
FORMAL_IO_BYTES_PER_SECOND = 500_000_000
FORMAL_MAX_MEMORY_BYTES = 8 * 1024**3
FORMAL_MAX_PIDS = 8_192
FORMAL_NOFILE_LIMIT = 8_192
RUST_BENCHMARK_POSTGRES_POOL = 96
RUST_BENCHMARK_REDIS_POOL = 32
RUST_BENCHMARK_OUTBOUND_MAX_CONCURRENT_SENDS = 64
RUST_BENCHMARK_OUTBOUND_MAX_CONNECTIONS_PER_HOST = 100
RUST_BENCHMARK_OUTBOUND_MAX_MESSAGES_PER_CONNECTION = 1_500
RUST_BENCHMARK_OUTBOUND_MAX_IDLE_TIME_MS = 30_000
RUST_BENCHMARK_OUTBOUND_CONNECTION_LIFE_TIME_MS = 300_000
RUST_BENCHMARK_OUTBOUND_POOL_CLEANUP_INTERVAL_MS = 1_000
PR_GET_DUMPABLE = 3
PR_SET_DUMPABLE = 4
PR_CAPBSET_DROP = 24
CAP_SYS_PTRACE = 19
MINIMUM_CLEAR_IMPROVEMENT = 1.20
MINIMUM_PROXY_HEADROOM_RATIO = 2.0
MAXIMUM_ABBA_ARM_RELATIVE_RANGE = 0.20
MAXIMUM_WITHIN_ARM_RELATIVE_RANGE = 0.30
MAXIMUM_COORDINATOR_DIAGNOSTIC_STAGES = 8
MAXIMUM_COORDINATOR_SELECTED_DIAGNOSTIC_STAGES = 16
COORDINATOR_DIAGNOSTIC_STAGES_ENV = "LMYZMAIL_COORDINATOR_DIAGNOSTIC_STAGES"
COORDINATOR_SELECTED_DIAGNOSTIC_STAGES = (
    "smtp_commit",
    "smtp_final_reply",
    "prepared_checkpoint",
    "result_checkpoint",
    "result_checkpoint_snapshot",
    "result_checkpoint_mutation",
    "legacy_projection",
    "queue_acknowledge",
    "result_checkpoint_legacy_lock",
    "result_checkpoint_attempt_lock",
    "result_checkpoint_attempt_row_lock",
    "result_checkpoint_roster_verify",
    "result_checkpoint_barrier_verify",
    "result_checkpoint_recipient_update",
    "result_checkpoint_attempt_update",
    "result_checkpoint_commit",
)


def _coordinator_selected_diagnostic_stages() -> tuple[str, ...]:
    """Return the default stage contract or an explicit bounded diagnostic override."""
    raw = os.environ.get(COORDINATOR_DIAGNOSTIC_STAGES_ENV)
    if raw is None or not raw.strip():
        return COORDINATOR_SELECTED_DIAGNOSTIC_STAGES
    selected = tuple(part.strip() for part in raw.split(","))
    if (
        not selected
        or len(selected) > MAXIMUM_COORDINATOR_SELECTED_DIAGNOSTIC_STAGES
        or len(set(selected)) != len(selected)
        or any(not name for name in selected)
    ):
        raise RuntimeError(
            f"{COORDINATOR_DIAGNOSTIC_STAGES_ENV} is invalid or exceeds the bounded stage limit"
        )
    return selected


MAXIMUM_PROXY_PROGRESS_SAMPLES = 20_000
MAXIMUM_RESOURCE_SAMPLES = 10_000
MAXIMUM_POST_FINAL_PERSISTENCE_LAG_SECONDS = 30.0
PERSISTENCE_GATE_TIMEOUT_SECONDS = 30.0
PERSISTENCE_VISIBILITY_POLL_SECONDS = 0.05
MAXIMUM_PERSISTENCE_GATE_HOLD_NS = 250_000_000
MAXIMUM_PERSISTENCE_GATE_DURATION_FRACTION = 0.005
REAL_GATE_CALIBRATION_SEQUENCE = (
    "off",
    "on",
    "on",
    "off",
    "on",
    "off",
    "off",
    "on",
)
REAL_GATE_CALIBRATION_SHAPES = {
    "1KB": (12_000, 1_024, 1_500),
    "10KB": (8_000, 10 * 1_024, 1_000),
    "10MB": (100, 10 * 1_024 * 1_024, 80),
}
MINIMUM_REAL_GATE_CALIBRATION_DURATION_SECONDS = 5.0
MAXIMUM_REAL_GATE_CALIBRATION_SPREAD = 0.01
MINIMUM_REAL_GATE_CALIBRATION_MEDIAN_RATIO = 0.995
MINIMUM_REAL_GATE_CALIBRATION_PAIRED_RATIO = 0.99
PROXY_PROGRESS_COMMAND_TIMEOUT_SECONDS = 2.0
PROXY_MONITOR_JOIN_TIMEOUT_SECONDS = 10.0
PROXY_PROCESS_EXIT_TIMEOUT_SECONDS = 10.0
MAXIMUM_RECORDED_TEMPERATURE_MILLICELSIUS = 95_000
EXTERNAL_PREREQUISITE_PROFILE = "lmyzmail-smtp-throughput-external-prerequisites-v1"
BENCHMARK_PROFILE = "mixed-single-invocation-smtp-endpoint-throughput-v2"
JAVA_SMALL_BASELINE_PROFILE = "java-small-single-invocation-smtp-endpoint-baseline-v1"
JAVA_FROZEN_CONFIG_RELATIVE = Path(
    "evidence/freeze/java-oracle/application.properties.redacted"
)
JAVA_FROZEN_CONFIG = REPOSITORY / JAVA_FROZEN_CONFIG_RELATIVE
BENCHMARK_DKIM_SELECTOR = "mail"
BENCHMARK_DKIM_KEY_BITS = 2_048
BENCHMARK_DKIM_DIRECTORY = "benchmark-fixtures"
BENCHMARK_DKIM_FILENAME = "dkim-private.pem"
BENCHMARK_DMARC_RECORD = b"v=DMARC1; p=none; adkim=s; aspf=s"
MISSING_DKIM_LOG_PREFIX = "No DKIM configuration for domain:"
ASYNC_DROP_LOG_PREFIX = "Async drop: email rejected after verification:"
COORDINATOR_OBSERVER_PREFIX = "LMYZMAIL_COORDINATOR_OBSERVER "
JAVA_FROZEN_STRESS_CONFIGURATION = (
    ("botmail.queue.persist.save-body-to-db", "false"),
    ("botmail.queue.persist.flush-size", "1000"),
    ("botmail.outbound-persist-threads", "8"),
    ("botmail.inbound-index-threads", "8"),
    ("botmail.outbound.heloHostname", "smtp-in.lmyz.net"),
    ("botmail.outbound.retryCount", "3"),
    ("botmail.outbound.connectionTimeoutMs", "20000"),
    ("botmail.outbound.pool-enabled", "true"),
    ("botmail.outbound.max-connections-per-host", "100"),
    ("botmail.outbound.max-messages-per-connection", "1500"),
    ("botmail.outbound.max-idle-time-ms", "30000"),
    ("botmail.outbound.connection-life-time-ms", "300000"),
    ("botmail.outbound.pool-cleanup-interval-ms", "1000"),
    ("botmail.queue.batch-size", "1200"),
    ("botmail.queue.max-concurrent-sends", "400"),
    ("botmail.queue.poll-interval-ms", "100"),
    ("botmail.queue.processing-timeout-minutes", "10"),
    ("botmail.queue.sent-retention-days", "7"),
    ("botmail.queue.failed-retention-days", "30"),
)
JAVA_STRESS_READINESS_MARKERS = (
    "Loaded DKIM key for domain: lmyz.net",
    "Started 8 outbound persist worker threads",
    "Application ready, enabling mail queue scheduler",
    "Redis connection is healthy",
)
BENCHMARK_PROXY_BINARY = (
    REPOSITORY / "target/x86_64-unknown-linux-gnu/release/lmyzmail-benchmark-proxy"
)
BENCHMARK_PROXY_SOURCE = REPOSITORY / "crates/lmyzmail-benchmark-proxy"
NAMESPACE_ENV = "LMYZMAIL_SMTP_ENDPOINT_BENCHMARK_NAMESPACE"
SUBJECT_PATTERN = re.compile(
    r"^Stress Test R(?P<round>[0-9]+) #(?P<index>[0-9]+) - (?P<millis>[0-9]+)$"
)
JAVA_QUEUE_RESULT_PATTERN = re.compile(
    r"Actually Queued: (?P<queued>[0-9]+) \(success=(?P<success>[0-9]+), "
    r"failed=(?P<failed>[0-9]+), exceptions=(?P<exceptions>[0-9]+), "
    r"oom=(?P<oom>[0-9]+), rateLimited=(?P<rate_limited>[0-9]+)\)"
)
JAVA_RECEIVED_RESULT_PATTERN = re.compile(
    r"\[RESULT\] Received: (?P<received>[0-9]+)\s*$"
)


def _v2_mailbox_relative_path(address: str) -> Path:
    normalized = address.strip().lower().encode("utf-8")
    path = Path("v2")
    for offset in range(0, len(normalized), MAILBOX_PATH_CHUNK_BYTES):
        path /= (
            f"c-{normalized[offset : offset + MAILBOX_PATH_CHUNK_BYTES].hex().upper()}"
        )
    return path / f"z-{len(normalized):08X}"


@dataclass(frozen=True, slots=True)
class BenchmarkPlan:
    label: str
    message_bytes: int
    total_messages: int


@dataclass(frozen=True, slots=True)
class LogCursor:
    path: Path
    offset: int
    device: int | None
    inode: int | None


class DurablePostgresRuntimeMixin:
    def _start_postgres(self) -> None:
        workspace, ports = self._require_state()
        if self._port_allocator is None:
            raise RuntimeError("port allocator is not available")
        root = self.paths.runtime / "postgres-root"
        bin_dir = root / "usr/lib/postgresql/16/bin"
        data = workspace / "postgres-data"
        log = workspace / "postgres.log"
        env = self._postgres_env()
        self._run_checked(
            [
                str(bin_dir / "initdb"),
                "--pgdata",
                str(data),
                "--username=lmyzmail_test",
                "--auth=trust",
                "--encoding=UTF8",
                "--no-locale",
            ],
            env=env,
            log_path=log,
        )
        self._port_allocator.release_port(ports.postgres)
        self._postgres = ManagedProcess(
            "postgres",
            [
                str(bin_dir / "postgres"),
                "-D",
                str(data),
                "-h",
                "127.0.0.1",
                "-p",
                str(ports.postgres),
                "-k",
                "",
                "-c",
                "fsync=on",
                "-c",
                "synchronous_commit=on",
                "-c",
                "full_page_writes=on",
                "-c",
                "max_connections=128",
            ],
            log,
            env=env,
            inherit_env=False,
        )
        self._postgres.start()
        self._postgres.wait_for_tcp("127.0.0.1", ports.postgres, timeout=20.0)
        self._wait_for_postgres_ready(
            bin_dir,
            ports.postgres,
            env=env,
            log_path=log,
        )
        self._run_checked(
            [
                str(bin_dir / "createdb"),
                "--host=127.0.0.1",
                f"--port={ports.postgres}",
                "--username=lmyzmail_test",
                "lmyzmail",
            ],
            env=env,
            log_path=log,
        )
        fixture_root = self.paths.repository / "blackbox/fixtures/legacy"
        schema = fixture_root / "postgres-schema.sql"
        metadata = json.loads(
            (fixture_root / "postgres-schema.json").read_text(encoding="utf-8")
        )
        expected_schema_sha256 = metadata.get("schema_sha256")
        if (
            not isinstance(expected_schema_sha256, str)
            or _sha256_file(schema) != expected_schema_sha256
        ):
            raise HarnessError("benchmark PostgreSQL schema fixture is not attested")
        self._run_checked(
            [
                str(bin_dir / "psql"),
                "--host=127.0.0.1",
                f"--port={ports.postgres}",
                "--username=lmyzmail_test",
                "--dbname=lmyzmail",
                "--single-transaction",
                "--set=ON_ERROR_STOP=1",
                '--command=DROP SCHEMA "public";',
                f"--file={schema}",
            ],
            env=env,
            log_path=log,
        )


def _replace_cli_arguments(
    arguments: Sequence[str], replacements: Sequence[str]
) -> list[str]:
    replacement_names: set[str] = set()
    for replacement in replacements:
        name, separator, _ = replacement.partition("=")
        if not separator or not name.startswith("--") or name in replacement_names:
            raise ValueError(f"invalid duplicate CLI replacement: {replacement!r}")
        replacement_names.add(name)
    retained = [
        argument
        for argument in arguments
        if argument.partition("=")[0] not in replacement_names
    ]
    return [*retained, *replacements]


def _proxy_control_path(workspace: Path, control_root: Path | None = None) -> Path:
    root = workspace if control_root is None else control_root
    if not root.is_absolute() or not root.is_dir():
        raise RuntimeError("Rust SMTP proxy control root is invalid")
    path = root / "p.sock"
    if len(os.fsencode(path)) > 100:
        raise RuntimeError("Rust SMTP proxy control path exceeds AF_UNIX limit")
    if os.path.lexists(path):
        raise FileExistsError(f"Rust SMTP proxy control path already exists: {path}")
    return path


def _bounded_file_tail(path: Path, maximum_bytes: int = 32 * 1024) -> str:
    try:
        with path.open("rb") as stream:
            stream.seek(0, os.SEEK_END)
            size = stream.tell()
            stream.seek(max(0, size - maximum_bytes))
            return stream.read(maximum_bytes).decode("utf-8", errors="replace")
    except OSError as error:
        return f"<log tail unavailable: {error}>"


def _java_frozen_stress_profile() -> dict[str, Any]:
    return {
        "profile": "java-oracle-frozen-production-stress-path-v1",
        "source_path": JAVA_FROZEN_CONFIG_RELATIVE.as_posix(),
        "source_sha256": _sha256_file(JAVA_FROZEN_CONFIG),
        "properties": dict(JAVA_FROZEN_STRESS_CONFIGURATION),
        "readiness_log_markers": list(JAVA_STRESS_READINESS_MARKERS),
        "dkim_signing_fixture": {
            "provisioning": "fresh-per-isolated-arm",
            "algorithm": "rsa-sha256",
            "key_bits": BENCHMARK_DKIM_KEY_BITS,
            "private_key_format": "pkcs8-pem",
            "selector": BENCHMARK_DKIM_SELECTOR,
            "relative_path": f"{BENCHMARK_DKIM_DIRECTORY}/{BENCHMARK_DKIM_FILENAME}",
            "directory_mode": "0700",
            "file_mode": "0600",
            "production_secret_used": False,
        },
        "isolated_self_smtp_transport": {
            "untrusted_ingress": False,
            "connection_limits_enabled": True,
            "max_connections_per_ip": BENCHMARK_SELF_SMTP_MAX_CONNECTIONS_PER_IP,
            "max_new_connections_per_minute_per_ip": (
                BENCHMARK_SELF_SMTP_MAX_NEW_CONNECTIONS_PER_MINUTE
            ),
            "inbound_byte_limit_enabled": True,
            "max_inbound_bytes_per_window": (
                BENCHMARK_SELF_SMTP_MAX_INBOUND_BYTES_PER_WINDOW
            ),
            "inbound_rate_window_hours": 1,
        },
        "forbidden_measurement_log_prefixes": [
            MISSING_DKIM_LOG_PREFIX,
            ASYNC_DROP_LOG_PREFIX,
        ],
    }


@dataclass(frozen=True, slots=True)
class BenchmarkDkimMaterial:
    private_key_bytes: bytes = dataclass_field(repr=False)
    private_key_sha256: str
    public_key_spki_sha256: str
    public_dns_record: bytes

    def attestation(self) -> dict[str, Any]:
        return {
            "profile": "lmyzmail-shared-ephemeral-dkim-material-v1",
            "selector": BENCHMARK_DKIM_SELECTOR,
            "domain": "lmyz.net",
            "dns_name": f"{BENCHMARK_DKIM_SELECTOR}._domainkey.lmyz.net",
            "algorithm": "rsa-sha256",
            "key_bits": BENCHMARK_DKIM_KEY_BITS,
            "private_key_format": "pkcs8-pem",
            "private_key_sha256": self.private_key_sha256,
            "public_key_spki_sha256": self.public_key_spki_sha256,
            "public_dns_record_sha256": hashlib.sha256(
                self.public_dns_record
            ).hexdigest(),
            "production_secret_used": False,
            "passed": True,
        }


def _generate_benchmark_dkim_material() -> BenchmarkDkimMaterial:
    private_key = rsa.generate_private_key(
        public_exponent=65_537,
        key_size=BENCHMARK_DKIM_KEY_BITS,
    )
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_dns_record = b"v=DKIM1; k=rsa; p=" + base64.b64encode(public_key_der)
    return BenchmarkDkimMaterial(
        private_key_bytes=private_key_bytes,
        private_key_sha256=hashlib.sha256(private_key_bytes).hexdigest(),
        public_key_spki_sha256=hashlib.sha256(public_key_der).hexdigest(),
        public_dns_record=public_dns_record,
    )


class BenchmarkDnsServer(base.StressDnsServer):
    def __init__(self, material: BenchmarkDkimMaterial):
        self._dkim_material = material
        self._query_lock = threading.Lock()
        self._query_counts = {
            "dkim_txt": 0,
            "dmarc_txt": 0,
            "spf_txt": 0,
            "mx": 0,
            "a": 0,
        }
        super().__init__()

    @staticmethod
    def _txt_response(query: bytes, question: bytes, value: bytes) -> bytes:
        chunks = tuple(
            value[offset : offset + 255] for offset in range(0, len(value), 255)
        )
        rdata = b"".join(bytes([len(chunk)]) + chunk for chunk in chunks)
        return (
            query[:2]
            + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
            + question
            + b"\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x3c"
            + len(rdata).to_bytes(2, "big")
            + rdata
        )

    def _answer(self, query: bytes) -> bytes | None:
        decoded = self._decode_question(query)
        if decoded is None:
            return None
        qname, qtype, question = decoded
        dkim_name = f"{BENCHMARK_DKIM_SELECTOR}._domainkey.lmyz.net"
        if qname == dkim_name and qtype == 16:
            with self._query_lock:
                self._query_counts["dkim_txt"] += 1
            return self._txt_response(
                query,
                question,
                self._dkim_material.public_dns_record,
            )
        if qname == "_dmarc.lmyz.net" and qtype == 16:
            with self._query_lock:
                self._query_counts["dmarc_txt"] += 1
            return self._txt_response(query, question, BENCHMARK_DMARC_RECORD)
        counter = None
        if qname == "lmyz.net" and qtype == 16:
            counter = "spf_txt"
        elif qname == "lmyz.net" and qtype == 15:
            counter = "mx"
        elif qname == base.PUBLIC_MX_HOST and qtype == 1:
            counter = "a"
        if counter is not None:
            with self._query_lock:
                self._query_counts[counter] += 1
        return super()._answer(query)

    def attestation(self) -> dict[str, Any]:
        with self._query_lock:
            query_counts = dict(self._query_counts)
        return {
            "profile": "lmyzmail-smtp-benchmark-dns-v1",
            "spf_record": "v=spf1 +all",
            "dmarc_record": BENCHMARK_DMARC_RECORD.decode("ascii"),
            "dkim": self._dkim_material.attestation(),
            "query_counts": query_counts,
            "dkim_txt_query_count": query_counts["dkim_txt"],
            "dmarc_txt_query_count": query_counts["dmarc_txt"],
            "passed": True,
        }


class BenchmarkDkimFixtureMixin:
    workspace: Path | None
    benchmark_dkim_key_path: Path | None
    benchmark_dkim_private_key_bytes: bytes | None

    def _ensure_benchmark_dkim_fixture(self) -> Path:
        workspace = self.workspace
        if workspace is None:
            raise HarnessError("DKIM fixture requires an allocated runtime workspace")
        workspace = workspace.resolve(strict=True)
        if workspace.is_symlink() or not workspace.is_dir():
            raise HarnessError("DKIM fixture workspace must be a real directory")
        if self.benchmark_dkim_key_path is not None:
            self._benchmark_dkim_fixture_attestation()
            return self.benchmark_dkim_key_path

        directory = workspace / BENCHMARK_DKIM_DIRECTORY
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError as error:
            raise HarnessError(
                f"DKIM fixture directory already exists: {directory}"
            ) from error
        directory.chmod(0o700)
        key_path = directory / BENCHMARK_DKIM_FILENAME
        descriptor = -1
        try:
            if self.benchmark_dkim_private_key_bytes is None:
                self.benchmark_dkim_private_key_bytes = (
                    _generate_benchmark_dkim_material().private_key_bytes
                )
            key_bytes = self.benchmark_dkim_private_key_bytes
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(key_path, flags, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = -1
                stream.write(key_bytes)
                stream.flush()
                os.fsync(stream.fileno())
            key_path.chmod(0o600)
            self.benchmark_dkim_key_path = key_path
            self._benchmark_dkim_fixture_attestation()
            return key_path
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            key_path.unlink(missing_ok=True)
            with contextlib.suppress(OSError):
                directory.rmdir()
            self.benchmark_dkim_key_path = None
            raise

    def _benchmark_dkim_fixture_attestation(self) -> dict[str, Any]:
        workspace = self.workspace
        path = self.benchmark_dkim_key_path
        if workspace is None or path is None:
            raise HarnessError("DKIM fixture has not been provisioned")
        workspace = workspace.resolve(strict=True)
        directory = path.parent.resolve(strict=True)
        resolved_path = path.resolve(strict=True)
        if directory.parent != workspace or resolved_path.parent != directory:
            raise HarnessError("DKIM fixture escaped the isolated runtime workspace")
        directory_metadata = os.lstat(directory)
        if (
            not stat.S_ISDIR(directory_metadata.st_mode)
            or stat.S_IMODE(directory_metadata.st_mode) != 0o700
            or directory_metadata.st_uid != os.geteuid()
        ):
            raise HarnessError("DKIM fixture directory identity or permissions changed")

        flags = os.O_RDONLY | os.O_CLOEXEC
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_nlink != 1
                or metadata.st_uid != os.geteuid()
                or metadata.st_size <= 0
                or metadata.st_size > 32 * 1024
            ):
                raise HarnessError("DKIM private key identity or permissions changed")
            with os.fdopen(descriptor, "rb") as stream:
                descriptor = -1
                private_key_bytes = stream.read(32 * 1024 + 1)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if len(private_key_bytes) != metadata.st_size:
            raise HarnessError("DKIM private key changed while it was attested")
        private_key = serialization.load_pem_private_key(
            private_key_bytes,
            password=None,
        )
        if (
            not isinstance(private_key, rsa.RSAPrivateKey)
            or private_key.key_size != BENCHMARK_DKIM_KEY_BITS
        ):
            raise HarnessError("DKIM fixture is not the required RSA private key")
        public_key_der = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return {
            "profile": "lmyzmail-ephemeral-dkim-signing-fixture-v1",
            "relative_path": str(path.relative_to(workspace)),
            "selector": BENCHMARK_DKIM_SELECTOR,
            "algorithm": "rsa-sha256",
            "key_bits": private_key.key_size,
            "private_key_format": "pkcs8-pem",
            "private_key_bytes": len(private_key_bytes),
            "private_key_sha256": hashlib.sha256(private_key_bytes).hexdigest(),
            "public_key_spki_sha256": hashlib.sha256(public_key_der).hexdigest(),
            "directory_mode": f"{stat.S_IMODE(directory_metadata.st_mode):04o}",
            "file_mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
            "owner_uid": metadata.st_uid,
            "owner_gid": metadata.st_gid,
            "hard_link_count": metadata.st_nlink,
            "inside_quota_workspace": True,
            "production_secret_used": False,
            "passed": True,
        }


@dataclass(slots=True)
class JavaStressRuntime(
    BenchmarkDkimFixtureMixin, DurablePostgresRuntimeMixin, JavaOracleRuntime
):
    benchmark_maildir_address_layout = "java-raw"
    production_count: int = 1
    warmup_count: int = 0
    warmup_rounds: int = 0
    email_size_kb: int = 10
    benchmark_cpu: int | None = None
    benchmark_dkim_key_path: Path | None = dataclass_field(
        default=None, init=False, repr=False
    )
    benchmark_dkim_private_key_bytes: bytes | None = dataclass_field(
        default=None, repr=False
    )

    @property
    def requires_qa_account(self) -> bool:
        return False

    @property
    def requires_htcpcp_readiness(self) -> bool:
        return False

    def _application_service_ports(self) -> tuple[int, ...]:
        _, ports = self._require_state()
        return (ports.http, ports.smtp)

    def _application_environment(self) -> dict[str, str]:
        environment = JavaOracleRuntime._application_environment(self)
        if self.benchmark_cpu is not None:
            environment["JAVA_TOOL_OPTIONS"] = "-XX:ActiveProcessorCount=1"
        return environment

    def _start_application(self) -> None:
        started = time.monotonic()
        if self.ports is None or self._port_allocator is None:
            raise RuntimeError("stress runtime ports were not allocated")
        if self.ports.smtp != SMTP_CAPTURE_PORT:
            old = self.ports
            self._port_allocator.release_port(old.smtp)
            self._port_allocator.reserve_port(SMTP_CAPTURE_PORT)
            self.ports = PortSet(
                old.postgres,
                old.redis,
                old.http,
                SMTP_CAPTURE_PORT,
                old.htcpcp,
                old.minecraft,
                old.honeypots,
            )
        JavaOracleRuntime._start_application(self)
        remaining = self.startup_timeout - (time.monotonic() - started)
        self._wait_for_stress_services(remaining)

    def _wait_for_stress_services(self, timeout: float) -> None:
        if not math.isfinite(timeout) or timeout <= 0:
            raise ProcessStartError(
                "Java stress services missed the shared startup deadline"
            )
        application = self._application
        if application is None or application._process is None:
            raise ProcessStartError("Java stress application process is unavailable")
        deadline = time.monotonic() + timeout
        missing = list(JAVA_STRESS_READINESS_MARKERS)
        while True:
            exit_code = application._process.poll()
            if exit_code is not None:
                raise ProcessStartError(
                    f"Java stress application exited with {exit_code}; "
                    f"tail:\n{application.log_tail()}"
                )
            log_tail = application.log_tail(max_bytes=256 * 1024)
            missing = [
                marker
                for marker in JAVA_STRESS_READINESS_MARKERS
                if marker not in log_tail
            ]
            if not missing:
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(0.02, remaining))
        raise ProcessStartError(
            f"Java stress services did not become ready; missing={missing}; "
            f"tail:\n{application.log_tail()}"
        )

    def _application_arguments(self) -> list[str]:
        arguments = JavaOracleRuntime._application_arguments(self)
        dkim_key_path = self._ensure_benchmark_dkim_fixture()
        arguments = _replace_cli_arguments(
            arguments,
            (
                "--botmail.domains.main.domain=lmyz.net",
                "--botmail.domains.main.receiveEnabled=true",
                "--botmail.domains.main.sendEnabled=true",
                "--botmail.domains.main.requireExistingMailbox=true",
                f"--botmail.domains.main.dkimSelector={BENCHMARK_DKIM_SELECTOR}",
                f"--botmail.domains.main.dkimPrivateKeyPath={dkim_key_path}",
                "--botmail.smtp.bind-address=127.0.0.1",
                "--botmail.smtp-security.connection-limits-enabled=true",
                "--botmail.smtp-security.max-connections-per-ip="
                f"{BENCHMARK_SELF_SMTP_MAX_CONNECTIONS_PER_IP}",
                "--botmail.smtp-security.max-new-connections-per-minute-per-ip="
                f"{BENCHMARK_SELF_SMTP_MAX_NEW_CONNECTIONS_PER_MINUTE}",
                "--botmail.rate-limit.inbound-enabled=true",
                "--botmail.rate-limit.max-inbound-bytes-per-window="
                f"{BENCHMARK_SELF_SMTP_MAX_INBOUND_BYTES_PER_WINDOW}",
                "--botmail.rate-limit.inbound-rate-window-hours=1",
                "--botmail.htcpcp.enabled=false",
                "--botmail.minecraft.enabled=false",
                "--botmail.honeypot.enabled=false",
                "--botmail.reporting.enabled=false",
                "--botmail.cringe.batch.enabled=false",
                "--spring.jpa.hibernate.ddl-auto=validate",
            ),
        )
        arguments = _replace_cli_arguments(
            arguments,
            (
                "--botmail.stress-test-enabled=true",
                "--botmail.stress-test-sender-prefix=stress-sender",
                "--botmail.stress-test-receiver-prefix=stress-receiver",
                "--botmail.stress-test-password=StressBlackboxPass123!",
                f"--botmail.stress-test-count={self.production_count}",
                f"--botmail.stress-test-warmup-count={self.warmup_count}",
                f"--botmail.stress-test-warmup-rounds={self.warmup_rounds}",
                f"--botmail.stress-test-email-size-kb={self.email_size_kb}",
                *(
                    f"--{name}={value}"
                    for name, value in JAVA_FROZEN_STRESS_CONFIGURATION
                ),
                "--botmail.contentfilter.enabled=false",
            ),
        )
        if self.production_count <= 8:
            arguments = _replace_cli_arguments(
                arguments,
                (
                    "--logging.level.net.lmyz.lmyzmail.outbound.DkimSigner=DEBUG",
                    "--logging.level.net.lmyz.lmyzmail.inbound.SpamVerifierService=DEBUG",
                    "--logging.level.org.xbill.DNS=DEBUG",
                ),
            )
        return arguments


@dataclass(slots=True)
class RustStressRuntime(
    BenchmarkDkimFixtureMixin,
    DurablePostgresRuntimeMixin,
    v2.StressCandidateRuntimeV2,
):
    benchmark_maildir_address_layout = "lmyzmail-v2"
    benchmark_warmup_rounds: int = 0
    coordinator_observer: bool = False
    filesystem_fsync_mode: str = "on"
    benchmark_cpu: int | None = None
    benchmark_dkim_key_path: Path | None = dataclass_field(
        default=None, init=False, repr=False
    )
    benchmark_dkim_private_key_bytes: bytes | None = dataclass_field(
        default=None, repr=False
    )

    def _application_environment(self) -> dict[str, str]:
        environment = v2.StressCandidateRuntimeV2._application_environment(self)
        if self.benchmark_cpu is not None:
            environment["TOKIO_WORKER_THREADS"] = "1"
        if self.coordinator_observer:
            environment["LMYZMAIL_COORDINATOR_OBSERVER"] = "1"
            environment["LMYZMAIL_STRESS_ENQUEUE_OBSERVER"] = "1"
            environment["LMYZMAIL_QUEUE_OBSERVER"] = "1"
        return environment

    def _candidate_configuration(self) -> Path:
        if self.filesystem_fsync_mode not in ("on", "off"):
            raise HarnessError(
                f"invalid Rust filesystem fsync mode: {self.filesystem_fsync_mode!r}"
            )
        dkim_key_path = self._ensure_benchmark_dkim_fixture()
        path = v2.StressCandidateRuntimeV2._candidate_configuration(self)
        value = json.loads(path.read_text(encoding="utf-8"))
        storage = value.setdefault("storage", {})
        if not isinstance(storage, dict):
            raise HarnessError("candidate storage configuration is not an object")
        storage["fsync_enabled"] = self.filesystem_fsync_mode == "on"
        value["stress"]["warmup_rounds"] = self.benchmark_warmup_rounds
        # The functional harness uses a 16-connection PostgreSQL pool. That is
        # intentionally small for differential tests, but it cannot service
        # the benchmark's concurrent outbound and self-SMTP inbound durable
        # transactions before their fixed eight-second deadlines. Keep 32 of
        # the isolated PostgreSQL server's 128 slots available for the harness,
        # observers, and maintenance work.
        value["limits"]["postgres_pool"] = RUST_BENCHMARK_POSTGRES_POOL
        value["limits"]["redis_pool"] = RUST_BENCHMARK_REDIS_POOL
        # Keep the candidate cadence aligned with the frozen Java scheduler
        # profile so queue throughput is measured without an artificial idle
        # interval between claim passes.
        value["limits"]["outbound_poll_interval_ms"] = 100
        # Match the frozen Java stress scheduler knobs. The Rust production
        # defaults remain conservative; this benchmark compares the queue
        # implementation at the oracle's configured concurrency and cadence.
        # Bound self-SMTP transactions below the shared database pool instead
        # of admitting 256 deliveries into a 16-connection functional-test
        # pool. Java's frozen 400-task setting remains recorded independently.
        value["limits"]["outbound_max_concurrent_sends"] = (
            RUST_BENCHMARK_OUTBOUND_MAX_CONCURRENT_SENDS
        )
        value["limits"]["outbound_batch_size"] = 1200
        value["limits"]["outbound_migration_batch_size"] = 1000
        value["limits"]["outbound_pool_enabled"] = True
        value["limits"]["outbound_max_connections_per_host"] = (
            RUST_BENCHMARK_OUTBOUND_MAX_CONNECTIONS_PER_HOST
        )
        value["limits"]["outbound_max_messages_per_connection"] = (
            RUST_BENCHMARK_OUTBOUND_MAX_MESSAGES_PER_CONNECTION
        )
        value["limits"]["outbound_max_idle_time_ms"] = (
            RUST_BENCHMARK_OUTBOUND_MAX_IDLE_TIME_MS
        )
        value["limits"]["outbound_connection_life_time_ms"] = (
            RUST_BENCHMARK_OUTBOUND_CONNECTION_LIFE_TIME_MS
        )
        value["limits"]["outbound_pool_cleanup_interval_ms"] = (
            RUST_BENCHMARK_OUTBOUND_POOL_CLEANUP_INTERVAL_MS
        )
        value["domains"][0]["dkim_selector"] = BENCHMARK_DKIM_SELECTOR
        value["domains"][0]["dkim_private_key_path"] = str(dkim_key_path)
        path.write_text(
            json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
        return path


def _parse_cpu_list(value: str) -> tuple[int, ...]:
    cpus: set[int] = set()
    for part in value.split(","):
        bounds = part.split("-", 1)
        if not bounds[0].isdigit() or not bounds[-1].isdigit():
            raise RuntimeError(f"invalid cgroup CPU list: {value!r}")
        start, stop = int(bounds[0]), int(bounds[-1])
        if stop < start:
            raise RuntimeError(f"invalid cgroup CPU range: {part!r}")
        cpus.update(range(start, stop + 1))
    if not cpus:
        raise RuntimeError("cgroup CPU list is empty")
    return tuple(sorted(cpus))


def _parse_io_max(path: Path) -> dict[str, dict[str, str]]:
    devices: dict[str, dict[str, str]] = {}
    for line in path.read_text(encoding="ascii").splitlines():
        fields = line.split()
        if len(fields) < 2 or not re.fullmatch(r"[0-9]+:[0-9]+", fields[0]):
            raise RuntimeError(f"invalid cgroup io.max line: {line!r}")
        device = fields[0]
        if device in devices:
            raise RuntimeError(f"duplicate cgroup io.max device: {device}")
        limits: dict[str, str] = {}
        for field in fields[1:]:
            name, separator, raw = field.partition("=")
            if not separator or name in limits or not raw:
                raise RuntimeError(f"invalid cgroup io.max field: {field!r}")
            if raw != "max" and not raw.isdigit():
                raise RuntimeError(f"invalid cgroup io.max value: {field!r}")
            limits[name] = raw
        devices[device] = limits
    return devices


@dataclass(frozen=True, slots=True)
class CgroupLayout:
    parent: Path
    harness: Path
    workload: Path
    services: Path
    cpu: int
    housekeeping_cpus: tuple[int, ...]
    device: str
    backing_device: str
    io_bytes_per_second: int
    max_pids: int
    max_memory_bytes: int
    nofile_limit: int
    host_reserve_bytes: int
    supervisor_socket: Path

    @classmethod
    def from_environment(cls) -> CgroupLayout:
        required = {
            "parent": "LMYZMAIL_BENCHMARK_CGROUP_PARENT",
            "harness": "LMYZMAIL_BENCHMARK_HARNESS_CGROUP",
            "workload": "LMYZMAIL_BENCHMARK_WORKLOAD_CGROUP",
            "services": "LMYZMAIL_BENCHMARK_SERVICES_CGROUP",
            "cpu": "LMYZMAIL_BENCHMARK_CPU",
            "housekeeping": "LMYZMAIL_BENCHMARK_HOUSEKEEPING_CPUS",
            "device": "LMYZMAIL_BENCHMARK_DEVICE",
            "backing_device": "LMYZMAIL_BENCHMARK_BACKING_DEVICE",
            "io": "LMYZMAIL_BENCHMARK_IO_BPS",
            "pids": "LMYZMAIL_BENCHMARK_MAX_PIDS",
            "memory": "LMYZMAIL_BENCHMARK_MAX_MEMORY_BYTES",
            "nofile": "LMYZMAIL_BENCHMARK_NOFILE_LIMIT",
            "reserve": "LMYZMAIL_BENCHMARK_HOST_RESERVE_BYTES",
            "supervisor": "LMYZMAIL_BENCHMARK_CGROUP_SUPERVISOR_SOCKET",
        }
        missing = [name for name in required.values() if not os.environ.get(name)]
        if missing:
            raise RuntimeError(
                "benchmark must be launched through run-smtp-endpoint-throughput-v1.sh; "
                f"missing environment: {missing}"
            )
        value = cls(
            parent=Path(os.environ[required["parent"]]),
            harness=Path(os.environ[required["harness"]]),
            workload=Path(os.environ[required["workload"]]),
            services=Path(os.environ[required["services"]]),
            cpu=int(os.environ[required["cpu"]]),
            housekeeping_cpus=_parse_cpu_list(os.environ[required["housekeeping"]]),
            device=os.environ[required["device"]],
            backing_device=os.environ[required["backing_device"]],
            io_bytes_per_second=int(os.environ[required["io"]]),
            max_pids=int(os.environ[required["pids"]]),
            max_memory_bytes=int(os.environ[required["memory"]]),
            nofile_limit=int(os.environ[required["nofile"]]),
            host_reserve_bytes=int(os.environ[required["reserve"]]),
            supervisor_socket=Path(os.environ[required["supervisor"]]),
        )
        value.verify()
        return value

    def verify(self) -> None:
        for path in (self.parent, self.harness, self.workload, self.services):
            if not path.is_dir() or path.parent != self.parent and path != self.parent:
                raise RuntimeError(f"invalid benchmark cgroup layout: {path}")
        if self.device == self.backing_device:
            raise RuntimeError("loop and backing devices must be distinct")
        if self.cpu in self.housekeeping_cpus or not self.housekeeping_cpus:
            raise RuntimeError("housekeeping cpuset must exclude the benchmark CPU")
        io_limits = _parse_io_max(self.parent / "io.max")
        if set(io_limits) != {self.device, self.backing_device}:
            raise RuntimeError(
                "run cgroup I/O limit device set does not match the contract"
            )
        for device in (self.device, self.backing_device):
            limits = io_limits[device]
            if (
                limits.get("rbps") != str(self.io_bytes_per_second)
                or limits.get("wbps") != str(self.io_bytes_per_second)
                or any(
                    name not in {"rbps", "wbps"} and value != "max"
                    for name, value in limits.items()
                )
            ):
                raise RuntimeError(
                    "run cgroup I/O limit does not match the benchmark contract"
                )
        cpus = (
            (self.workload / "cpuset.cpus.effective")
            .read_text(encoding="ascii")
            .strip()
        )
        if cpus != str(self.cpu):
            raise RuntimeError(f"workload cpuset is {cpus!r}, expected {self.cpu}")
        expected_housekeeping = set(self.housekeeping_cpus)
        for role, path in (("harness", self.harness), ("services", self.services)):
            effective = _parse_cpu_list(
                (path / "cpuset.cpus.effective").read_text(encoding="ascii").strip()
            )
            if set(effective) != expected_housekeeping:
                raise RuntimeError(f"{role} cpuset differs from housekeeping CPUs")
        if (self.workload / "cpu.max").read_text(encoding="ascii").strip() != (
            "100000 100000"
        ):
            raise RuntimeError("workload CPU quota does not equal one logical CPU")
        if int((self.parent / "pids.max").read_text(encoding="ascii")) != self.max_pids:
            raise RuntimeError("run PID limit changed")
        if (
            int((self.parent / "memory.max").read_text(encoding="ascii"))
            != self.max_memory_bytes
        ):
            raise RuntimeError("run memory limit changed")
        if (self.parent / "memory.swap.max").read_text(encoding="ascii").strip() != "0":
            raise RuntimeError("run swap limit changed")
        if self.nofile_limit <= 0:
            raise RuntimeError("benchmark NOFILE limit is invalid")
        if self.host_reserve_bytes <= 0:
            raise RuntimeError("benchmark host reserve is invalid")
        if not self.supervisor_socket.is_absolute():
            raise RuntimeError("cgroup supervisor socket must be absolute")
        if sys.platform == "linux":
            expected_uid, expected_gid = _unmapped_host_root_identity()
            metadata = self.supervisor_socket.lstat()
            if (
                not stat.S_ISSOCK(metadata.st_mode)
                or metadata.st_uid != expected_uid
                or metadata.st_gid != expected_gid
            ):
                raise RuntimeError(
                    "cgroup supervisor endpoint is not a root-owned socket"
                )
            control_paths = [
                self.parent / "cgroup.procs",
                self.parent / "io.max",
                self.parent / "memory.max",
                self.parent / "memory.swap.max",
                self.parent / "pids.max",
                self.harness / "cgroup.procs",
                self.services / "cgroup.procs",
                self.workload / "cgroup.procs",
                self.workload / "cpu.max",
            ]
            for control in control_paths:
                control_metadata = control.stat()
                if (
                    control_metadata.st_uid != expected_uid
                    or control_metadata.st_gid != expected_gid
                    or control_metadata.st_mode & 0o022
                ):
                    raise RuntimeError(f"cgroup control is not root-only: {control}")
                if os.access(control, os.W_OK):
                    raise RuntimeError(
                        f"benchmark user can write cgroup control: {control}"
                    )

    def snapshot(self) -> dict[str, Any]:
        return {
            "parent": str(self.parent),
            "harness": str(self.harness),
            "workload": str(self.workload),
            "services": str(self.services),
            "cpu": self.cpu,
            "housekeeping_cpus": list(self.housekeeping_cpus),
            "device": self.device,
            "backing_device": self.backing_device,
            "io_bytes_per_second": self.io_bytes_per_second,
            "max_pids": self.max_pids,
            "max_memory_bytes": self.max_memory_bytes,
            "nofile_limit": self.nofile_limit,
            "host_reserve_bytes": self.host_reserve_bytes,
            "supervisor_socket": str(self.supervisor_socket),
            "cpuset_cpus_effective": (self.workload / "cpuset.cpus.effective")
            .read_text(encoding="ascii")
            .strip(),
            "harness_cpuset_cpus_effective": (self.harness / "cpuset.cpus.effective")
            .read_text(encoding="ascii")
            .strip(),
            "services_cpuset_cpus_effective": (self.services / "cpuset.cpus.effective")
            .read_text(encoding="ascii")
            .strip(),
            "cpu_max": (self.workload / "cpu.max").read_text(encoding="ascii").strip(),
            "io_max": (self.parent / "io.max").read_text(encoding="ascii").strip(),
            "memory_max": (self.parent / "memory.max")
            .read_text(encoding="ascii")
            .strip(),
            "memory_swap_max": (self.parent / "memory.swap.max")
            .read_text(encoding="ascii")
            .strip(),
        }


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _sha256_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _finite_number(value: Any, name: str, *, positive: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RuntimeError(f"{name} must be numeric")
    number = float(value)
    if not math.isfinite(number):
        raise RuntimeError(f"{name} must be finite")
    if positive and number <= 0:
        raise RuntimeError(f"{name} must be positive")
    return number


def _reject_nonfinite_metrics(value: Any, path: str = "root") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            lowered = str(key).lower()
            key_words = set(re.split(r"[^a-z0-9]+", lowered))
            if key_words.intersection(("headroom", "ratio", "throughput")):
                if isinstance(child, bool):
                    raise RuntimeError(f"{child_path} must not be boolean")
                if isinstance(child, (int, float)) and not math.isfinite(float(child)):
                    raise RuntimeError(f"{child_path} must be finite")
            _reject_nonfinite_metrics(child, child_path)
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _reject_nonfinite_metrics(child, f"{path}[{index}]")


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
                json.dumps(
                    value,
                    sort_keys=True,
                    indent=2,
                    allow_nan=False,
                ).encode("utf-8")
            )
            stream.write(b"\n")
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


def _write_json_fd(descriptor: int, value: dict[str, Any]) -> None:
    payload = (
        json.dumps(value, sort_keys=True, indent=2, allow_nan=False).encode("utf-8")
        + b"\n"
    )
    os.ftruncate(descriptor, 0)
    os.lseek(descriptor, 0, os.SEEK_SET)
    view = memoryview(payload)
    while view:
        view = view[os.write(descriptor, view) :]
    os.fsync(descriptor)
    os.lseek(descriptor, 0, os.SEEK_SET)


def _sha256_fd(descriptor: int) -> str:
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while chunk := os.read(descriptor, 1024 * 1024):
        digest.update(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class Checkpoint:
    def __init__(self, path: Path, *, descriptor: int | None = None):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        if descriptor is None:
            self.descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            _fsync_directory(path.parent)
        else:
            self.descriptor = descriptor
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise RuntimeError("checkpoint capability is not a single regular file")
            os.ftruncate(descriptor, 0)
            os.lseek(descriptor, 0, os.SEEK_SET)
            os.fsync(descriptor)
        self.sequence = 0
        self.previous_sha256: str | None = None

    def append(self, value: dict[str, Any]) -> None:
        record = dict(value)
        record["_sequence"] = self.sequence
        record["_previous_record_sha256"] = self.previous_sha256
        canonical = json.dumps(
            record,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
        record_sha256 = hashlib.sha256(canonical).hexdigest()
        record["_record_sha256"] = record_sha256
        payload = (
            json.dumps(
                record,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
        view = memoryview(payload)
        while view:
            view = view[os.write(self.descriptor, view) :]
        os.fsync(self.descriptor)
        self.sequence += 1
        self.previous_sha256 = record_sha256

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1

    def sync(self) -> None:
        if self.descriptor < 0:
            raise RuntimeError("checkpoint capability is already closed")
        os.fsync(self.descriptor)


def _process_children() -> dict[int, list[int]]:
    children: dict[int, list[int]] = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            status = (entry / "status").read_text(encoding="ascii")
            parent = int(
                next(
                    line.split()[1]
                    for line in status.splitlines()
                    if line.startswith("PPid:")
                )
            )
        except (FileNotFoundError, PermissionError, StopIteration, ValueError):
            continue
        children.setdefault(parent, []).append(int(entry.name))
    return children


def _process_tree(roots: Sequence[int]) -> set[int]:
    children = _process_children()
    pending = list(roots)
    output: set[int] = set()
    while pending:
        pid = pending.pop()
        if pid in output:
            continue
        output.add(pid)
        pending.extend(children.get(pid, ()))
    return {pid for pid in output if Path(f"/proc/{pid}").exists()}


def _runtime_root_roles(runtime: Any) -> dict[str, int]:
    processes = {
        "application": runtime._application,
        "postgres": runtime._postgres,
        "redis": runtime._redis,
    }
    missing = [role for role, process in processes.items() if process is None]
    if missing:
        raise RuntimeError(f"managed runtime did not start process roots: {missing}")
    return {role: process.pid for role, process in processes.items()}


def _runtime_roots(runtime: Any) -> tuple[int, ...]:
    return tuple(_runtime_root_roles(runtime).values())


def _unified_cgroup(pid: int) -> str:
    for line in Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii").splitlines():
        if line.startswith("0::"):
            return line[3:]
    raise RuntimeError(f"process {pid} has no unified cgroup membership")


def _process_start_time(pid: int) -> int:
    line = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    return _parse_process_start_time(pid, line)


def _process_state(pid: int) -> str:
    line = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    fields = line[line.rfind(")") + 2 :].split()
    if not fields or len(fields[0]) != 1:
        raise RuntimeError(f"process {pid} has an invalid stat state")
    return fields[0]


def _parse_process_start_time(pid: int, line: str) -> int:
    fields = line[line.rfind(")") + 2 :].split()
    if len(fields) <= 19 or not fields[19].isdigit():
        raise RuntimeError(f"process {pid} has an invalid stat record")
    return int(fields[19])


def _request_cgroup_migration(
    layout: CgroupLayout, *, role: str, root_pid: int
) -> dict[str, Any]:
    request = (
        json.dumps(
            {
                "operation": "migrate",
                "role": role,
                "pid": root_pid,
                "start_time": _process_start_time(root_pid),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )
    if len(request) > 4_096:
        raise RuntimeError("cgroup migration request exceeded its protocol bound")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(10.0)
        connection.connect(str(layout.supervisor_socket))
        connection.sendall(request)
        response = bytearray()
        while b"\n" not in response:
            chunk = connection.recv(4_096 - len(response))
            if not chunk:
                raise RuntimeError("cgroup supervisor closed without a response")
            response.extend(chunk)
            if len(response) >= 4_096:
                raise RuntimeError(
                    "cgroup supervisor response exceeded its protocol bound"
                )
    payload = json.loads(bytes(response).split(b"\n", 1)[0])
    if not isinstance(payload, dict) or payload.get("passed") is not True:
        raise RuntimeError(f"cgroup supervisor rejected {role} migration: {payload}")
    if payload.get("role") != role or payload.get("root_pid") != root_pid:
        raise RuntimeError("cgroup supervisor returned a mismatched migration receipt")
    return payload


def _move_runtime_to_workload(runtime: Any, layout: CgroupLayout) -> dict[str, Any]:
    roots = _runtime_root_roles(runtime)
    destinations = {
        "application": layout.workload,
        "postgres": layout.services,
        "redis": layout.services,
    }
    receipts = {
        role: _request_cgroup_migration(layout, role=role, root_pid=root_pid)
        for role, root_pid in roots.items()
    }
    suffixes = {
        role: "/" + destination.relative_to("/sys/fs/cgroup").as_posix()
        for role, destination in destinations.items()
    }
    role_pids = {role: _process_tree((root_pid,)) for role, root_pid in roots.items()}
    if role_pids["application"] & (role_pids["postgres"] | role_pids["redis"]):
        raise RuntimeError("application and service process trees overlap")
    wrong = {}
    for role, pids in role_pids.items():
        for pid in pids:
            actual = _unified_cgroup(pid)
            if actual != suffixes[role]:
                wrong[pid] = {
                    "role": role,
                    "actual": actual,
                    "expected": suffixes[role],
                }
    if wrong:
        raise RuntimeError(f"runtime processes escaped role cgroups: {wrong}")
    pid_records: list[dict[str, Any]] = []
    expected_affinities = {
        "application": [layout.cpu],
        "postgres": list(layout.housekeeping_cpus),
        "redis": list(layout.housekeeping_cpus),
    }
    for role, pids in role_pids.items():
        for pid in sorted(pids):
            affinity = sorted(os.sched_getaffinity(pid))
            if affinity != expected_affinities[role]:
                raise RuntimeError(
                    f"{role} PID {pid} affinity {affinity} differs from "
                    f"{expected_affinities[role]}"
                )
            pid_records.append(
                {
                    "pid": pid,
                    "role": role,
                    "root_pid": roots[role],
                    "cgroup": suffixes[role],
                    "affinity": affinity,
                    "migrated": pid in set(receipts[role]["migrated_pids"]),
                }
            )
    return {
        "roots": roots,
        "pid_records": pid_records,
        "application_cgroup": suffixes["application"],
        "services_cgroup": suffixes["postgres"],
        "application_cpuset": [layout.cpu],
        "services_cpuset": list(layout.housekeeping_cpus),
        "supervisor_receipts": receipts,
        "root_only_migration": True,
        "all_observed_pids_migrated": all(record["migrated"] for record in pid_records),
    }


def _assert_workload_empty(layout: CgroupLayout) -> None:
    retained = {
        role: (path / "cgroup.procs").read_text(encoding="ascii").split()
        for role, path in (
            ("application", layout.workload),
            ("services", layout.services),
        )
    }
    retained = {role: pids for role, pids in retained.items() if pids}
    if retained:
        raise RuntimeError(f"runtime role cgroups retained processes: {retained}")


class FixedHistogram:
    def __init__(self, *, width_us: int, maximum_us: int):
        if width_us <= 0 or maximum_us < width_us:
            raise ValueError("histogram bounds are invalid")
        self.width_us = width_us
        self.maximum_us = maximum_us
        self.bins = array("Q", [0]) * (maximum_us // width_us + 1)
        self.count = 0
        self.overflow = 0
        self.maximum_observed_us = 0

    def record(self, value_us: int) -> None:
        value = max(0, value_us)
        self.count += 1
        self.maximum_observed_us = max(self.maximum_observed_us, value)
        if value > self.maximum_us:
            self.overflow += 1
            self.bins[-1] += 1
        else:
            self.bins[value // self.width_us] += 1

    def percentile_us(self, percentile: float) -> int:
        if self.count == 0:
            return 0
        rank = max(1, math.ceil(self.count * percentile))
        cumulative = 0
        for index, count in enumerate(self.bins):
            cumulative += count
            if cumulative >= rank:
                return min((index + 1) * self.width_us, self.maximum_us)
        return self.maximum_us

    def summary(self) -> dict[str, Any]:
        return {
            "count": self.count,
            "bin_width_us": self.width_us,
            "maximum_tracked_us": self.maximum_us,
            "overflow": self.overflow,
            "maximum_observed_us": self.maximum_observed_us,
            "p50_us_upper_bound": self.percentile_us(0.50),
            "p95_us_upper_bound": self.percentile_us(0.95),
            "p99_us_upper_bound": self.percentile_us(0.99),
        }


class MessageAccumulator:
    def __init__(self):
        self.digest = hashlib.sha256()
        self.prefix = bytearray()
        self.wire_bytes = 0

    def update(self, value: bytes) -> None:
        self.digest.update(value)
        self.wire_bytes += len(value)
        if len(self.prefix) < HEADER_CAPTURE_BYTES:
            remaining = HEADER_CAPTURE_BYTES - len(self.prefix)
            self.prefix.extend(value[:remaining])

    def finish(self) -> tuple[str, int, bytes]:
        return self.digest.hexdigest(), self.wire_bytes, bytes(self.prefix)


class RoundCapture:
    def __init__(
        self,
        *,
        expected: int,
        message_bytes: int,
        started_monotonic: float,
        started_at: str,
        persistence_gate_required: bool = True,
    ):
        if expected <= 0 or expected > 1_100_000:
            raise ValueError("SMTP capture count is outside its fixed bound")
        if message_bytes <= 0 or message_bytes > 10 * 1024 * 1024:
            raise ValueError("SMTP capture message size is outside its fixed bound")
        if not math.isfinite(started_monotonic):
            raise ValueError("SMTP capture start time must be finite")
        self.expected = expected
        self.message_bytes = message_bytes
        self.started_monotonic = started_monotonic
        self.started_at = started_at
        self.verified = 0
        self.total_wire_bytes = 0
        self.seen = bytearray(expected)
        self.round_number: int | None = None
        self.digest_xor = 0
        self.digest_sum = 0
        self.final_reply_counts = {
            "success": 0,
            "transient_failure": 0,
            "permanent_failure": 0,
            "other": 0,
        }
        self.first_samples: list[dict[str, Any]] = []
        self.last_samples: deque[dict[str, Any]] = deque(maxlen=SAMPLE_MESSAGES)
        self.failures: list[str] = []
        self.last_completed_monotonic = started_monotonic
        self.last_completed_at = started_at
        self.completion_histogram = FixedHistogram(
            width_us=10_000,
            maximum_us=MEASUREMENT_TIMEOUT_SECONDS * 1_000_000,
        )
        self.transaction_histogram = FixedHistogram(
            width_us=1_000,
            maximum_us=120 * 1_000_000,
        )

    def add(
        self,
        *,
        round_number: int,
        index: int,
        message_id: str,
        wire_sha256: str,
        wire_bytes: int,
        transaction_started: float,
        completed_monotonic: float,
    ) -> None:
        if index < 0 or index >= self.expected:
            raise RuntimeError(f"SMTP stress index is outside expected range: {index}")
        if self.seen[index]:
            raise RuntimeError(
                f"SMTP stress index was delivered more than once: {index}"
            )
        if self.round_number is None:
            self.round_number = round_number
        elif self.round_number != round_number:
            raise RuntimeError("SMTP capture observed more than one stress round")
        self.seen[index] = 1
        self.verified += 1
        self.total_wire_bytes += wire_bytes
        digest_value = int(wire_sha256, 16)
        self.digest_xor ^= digest_value
        self.digest_sum = (self.digest_sum + digest_value) % (1 << 256)
        elapsed_us = round((completed_monotonic - self.started_monotonic) * 1_000_000)
        transaction_us = round((completed_monotonic - transaction_started) * 1_000_000)
        self.completion_histogram.record(elapsed_us)
        self.transaction_histogram.record(transaction_us)
        self.last_completed_monotonic = completed_monotonic
        self.last_completed_at = _utc_now()
        sample = {
            "index": index,
            "message_id_sha256": hashlib.sha256(message_id.encode("utf-8")).hexdigest(),
            "wire_sha256": wire_sha256,
            "wire_bytes": wire_bytes,
            "completion_us": elapsed_us,
            "transaction_us": transaction_us,
        }
        if len(self.first_samples) < SAMPLE_MESSAGES:
            self.first_samples.append(sample)
        self.last_samples.append(sample)

    def record_final_reply(self, code: int) -> None:
        if 200 <= code < 300:
            name = "success"
        elif 400 <= code < 500:
            name = "transient_failure"
        elif 500 <= code < 600:
            name = "permanent_failure"
        else:
            name = "other"
        self.final_reply_counts[name] += 1

    def summary(self) -> dict[str, Any]:
        duration = self.last_completed_monotonic - self.started_monotonic
        if not math.isfinite(duration) or duration < 0:
            raise RuntimeError("SMTP capture duration is invalid")
        missing = self.expected - self.verified
        throughput = self.verified / duration if duration > 0 else 0.0
        data_throughput = (
            self.total_wire_bytes / (1024 * 1024) / duration if duration > 0 else 0.0
        )
        if not math.isfinite(throughput) or not math.isfinite(data_throughput):
            raise RuntimeError("SMTP capture throughput is not finite")
        return {
            "expected": self.expected,
            "verified": self.verified,
            "missing": missing,
            "round": self.round_number,
            "started_at": self.started_at,
            "completed_at": self.last_completed_at,
            "duration_seconds": round(duration, 6),
            "throughput_messages_per_second": round(throughput, 6),
            "data_throughput_mib_per_second": round(data_throughput, 6),
            "total_wire_bytes": self.total_wire_bytes,
            "wire_digest_xor": f"{self.digest_xor:064x}",
            "wire_digest_sum_mod_2_256": f"{self.digest_sum:064x}",
            "smtp_final_replies": dict(self.final_reply_counts),
            "retry_responses": (
                self.final_reply_counts["transient_failure"]
                + self.final_reply_counts["permanent_failure"]
                + self.final_reply_counts["other"]
            ),
            "completion_latency": self.completion_histogram.summary(),
            "smtp_transaction_latency": self.transaction_histogram.summary(),
            "first_samples": self.first_samples,
            "last_samples": list(self.last_samples),
            "failures": self.failures,
        }


class AggregateSmtpProxy:
    def __init__(self, runtime: Any):
        if runtime.ports is None:
            raise RuntimeError("SMTP proxy requires a started runtime")
        self.backend_port = runtime.ports.smtp
        self.condition = threading.Condition()
        self.connection_lock = threading.Lock()
        self.round: RoundCapture | None = None
        self.error: BaseException | None = None
        self.active_connections = 0
        self.peak_connections = 0
        self.ready = threading.Event()
        self.stop_requested = threading.Event()
        self.thread = threading.Thread(
            target=self._run, name="smtp-throughput-proxy", daemon=False
        )
        self.thread.start()
        if not self.ready.wait(10.0):
            raise TimeoutError("SMTP throughput proxy did not bind before deadline")
        if self.error is not None:
            raise RuntimeError("SMTP throughput proxy failed to start") from self.error

    def begin(
        self,
        *,
        expected: int,
        message_bytes: int,
        started_monotonic: float,
        started_at: str,
        persistence_gate_required: bool = True,
    ) -> None:
        with self.condition:
            if self.error is not None:
                raise RuntimeError("SMTP throughput proxy is failed") from self.error
            if self.round is not None:
                raise RuntimeError("previous SMTP throughput round was not finalized")
            self.round = RoundCapture(
                expected=expected,
                message_bytes=message_bytes,
                started_monotonic=started_monotonic,
                started_at=started_at,
            )
        with self.connection_lock:
            self.peak_connections = self.active_connections

    def finish(
        self,
        timeout_seconds: float,
        abort_check: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout_seconds
        with self.condition:
            while True:
                if self.error is not None:
                    raise RuntimeError("SMTP throughput proxy failed") from self.error
                if abort_check is not None:
                    abort_check()
                if (
                    self.round is not None
                    and self.round.verified == self.round.expected
                ):
                    completed = self.round
                    self.round = None
                    summary = completed.summary()
                    if summary["missing"] or summary["failures"]:
                        raise RuntimeError(
                            f"SMTP throughput verification failed: {summary}"
                        )
                    with self.connection_lock:
                        summary["peak_connections"] = self.peak_connections
                    return summary
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    observed = self.round.verified if self.round is not None else 0
                    raise TimeoutError(
                        f"SMTP throughput proxy verified {observed} messages before deadline"
                    )
                self.condition.wait(min(remaining, 1.0))

    def diagnostics(self) -> dict[str, Any]:
        with self.condition:
            round_summary = None if self.round is None else self.round.summary()
            error = self.error
        with self.connection_lock:
            active = self.active_connections
            peak = self.peak_connections
        return {
            "active_connections": active,
            "peak_connections": peak,
            "round": round_summary,
            "error": None
            if error is None
            else {"type": type(error).__name__, "message": str(error)},
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
        server = await asyncio.start_server(
            self._handle,
            SMTP_CAPTURE_ADDRESS,
            SMTP_CAPTURE_PORT,
            limit=512 * 1024,
            backlog=MAX_CAPTURE_CONNECTIONS,
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

    @staticmethod
    async def _relay_data(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        capture: MessageAccumulator,
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
                capture.update(bytes(pending[:payload_end]))
                writer.write(bytes(pending[: position + len(marker)]))
                await writer.drain()
                if pending[position + len(marker) :]:
                    raise RuntimeError(
                        "SMTP client pipelined bytes after DATA terminator"
                    )
                return
            safe = len(pending) - (len(marker) - 1)
            if safe > 0:
                value = bytes(pending[:safe])
                del pending[:safe]
                capture.update(value)
                writer.write(value)
                await writer.drain()

    async def _forward_final_reply_and_record(
        self,
        client_writer: asyncio.StreamWriter,
        final_reply: bytes,
        capture: MessageAccumulator,
        transaction_started: float,
    ) -> None:
        client_writer.write(final_reply)
        await client_writer.drain()
        self._record_final_reply(final_reply)
        if final_reply.startswith(b"250"):
            self._verify_and_record(
                capture,
                transaction_started,
                completed_monotonic=time.monotonic(),
            )

    def _record_final_reply(self, reply: bytes) -> None:
        if len(reply) < 3 or not reply[:3].isdigit():
            raise RuntimeError(
                f"SMTP backend returned an invalid final reply: {reply!r}"
            )
        with self.condition:
            if self.round is None:
                raise RuntimeError("SMTP final reply arrived outside an active round")
            self.round.record_final_reply(int(reply[:3]))
            self.condition.notify_all()

    async def _handle(
        self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter
    ) -> None:
        backend_writer: asyncio.StreamWriter | None = None
        capture: MessageAccumulator | None = None
        transaction_started: float | None = None
        try:
            with self.connection_lock:
                self.active_connections += 1
                self.peak_connections = max(
                    self.peak_connections, self.active_connections
                )
                if self.active_connections > MAX_CAPTURE_CONNECTIONS:
                    raise RuntimeError("SMTP throughput connection ceiling exceeded")
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
                if command == b"MAIL":
                    transaction_started = time.monotonic()
                elif command == b"RSET":
                    capture = None
                    transaction_started = None
                backend_writer.write(line)
                await backend_writer.drain()
                if command == b"DATA":
                    reply = await self._read_reply(backend_reader)
                    client_writer.write(reply)
                    await client_writer.drain()
                    if not reply.startswith(b"354"):
                        continue
                    capture = MessageAccumulator()
                    await self._relay_data(client_reader, backend_writer, capture)
                    final_reply = await self._read_reply(backend_reader)
                    await self._forward_final_reply_and_record(
                        client_writer,
                        final_reply,
                        capture,
                        transaction_started
                        if transaction_started is not None
                        else time.monotonic(),
                    )
                    if final_reply.startswith(b"250"):
                        capture = None
                        transaction_started = None
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
                        capture = MessageAccumulator()
                    remaining = size
                    while remaining:
                        chunk = await asyncio.wait_for(
                            client_reader.read(min(64 * 1024, remaining)),
                            timeout=120.0,
                        )
                        if not chunk:
                            raise RuntimeError("SMTP client disconnected during BDAT")
                        remaining -= len(chunk)
                        capture.update(chunk)
                        backend_writer.write(chunk)
                        await backend_writer.drain()
                    reply = await self._read_reply(backend_reader)
                    if last:
                        await self._forward_final_reply_and_record(
                            client_writer,
                            reply,
                            capture,
                            transaction_started
                            if transaction_started is not None
                            else time.monotonic(),
                        )
                    else:
                        client_writer.write(reply)
                        await client_writer.drain()
                    if last and reply.startswith(b"250"):
                        capture = None
                        transaction_started = None
                    continue
                try:
                    reply = await self._read_reply(backend_reader)
                except RuntimeError:
                    if command == b"QUIT":
                        return
                    raise
                client_writer.write(reply)
                await client_writer.drain()
                if command == b"QUIT":
                    return
        except BaseException as error:
            if not self.stop_requested.is_set():
                self.error = error
                with self.condition:
                    if self.round is not None and len(self.round.failures) < 20:
                        self.round.failures.append(f"{type(error).__name__}: {error}")
                    self.condition.notify_all()
        finally:
            client_writer.close()
            if backend_writer is not None:
                backend_writer.close()
            with self.connection_lock:
                self.active_connections -= 1

    def _verify_and_record(
        self,
        capture: MessageAccumulator,
        transaction_started: float,
        *,
        completed_monotonic: float,
    ) -> None:
        wire_sha256, wire_bytes, prefix = capture.finish()
        split = prefix.find(b"\r\n\r\n")
        if split < 0:
            raise RuntimeError("SMTP stress headers exceeded the fixed capture limit")
        headers = BytesHeaderParser(policy=policy.default).parsebytes(
            prefix[: split + 4]
        )
        subject = str(headers.get("Subject", ""))
        matched = SUBJECT_PATTERN.fullmatch(subject)
        if matched is None:
            raise RuntimeError(f"SMTP stress subject contract changed: {subject!r}")
        from_address = parseaddr(str(headers.get("From", "")))[1].lower()
        to_addresses = {
            address.lower()
            for _, address in getaddresses(headers.get_all("To", []))
            if address
        }
        message_id = str(headers.get("Message-ID", ""))
        if from_address != ENDPOINT_SENDER:
            raise RuntimeError(f"SMTP stress From changed: {from_address!r}")
        if ENDPOINT_RECEIVER not in to_addresses:
            raise RuntimeError(f"SMTP stress To changed: {to_addresses!r}")
        if not message_id:
            raise RuntimeError("SMTP stress message omitted Message-ID")
        with self.condition:
            if self.round is None:
                raise RuntimeError(
                    "SMTP message arrived outside an active benchmark round"
                )
            minimum = self.round.message_bytes
            maximum = self.round.message_bytes + 256 * 1024
            if wire_bytes < minimum or wire_bytes > maximum:
                raise RuntimeError(
                    f"SMTP wire size {wire_bytes} is outside [{minimum}, {maximum}]"
                )
            self.round.add(
                round_number=int(matched.group("round")),
                index=int(matched.group("index")),
                message_id=message_id,
                wire_sha256=wire_sha256,
                wire_bytes=wire_bytes,
                transaction_started=transaction_started,
                completed_monotonic=completed_monotonic,
            )
            self.condition.notify_all()

    def close(self) -> dict[str, Any]:
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            with self.connection_lock:
                if self.active_connections == 0:
                    break
            time.sleep(0.02)
        with self.connection_lock:
            remaining = self.active_connections
        self.stop_requested.set()
        self.thread.join(timeout=30.0)
        if self.thread.is_alive():
            raise RuntimeError("SMTP throughput proxy did not stop")
        if remaining:
            raise RuntimeError(
                f"SMTP throughput proxy retained {remaining} connections"
            )
        if self.error is not None:
            raise RuntimeError(
                "SMTP throughput proxy stopped after an error"
            ) from self.error
        return {
            "peak_connections": self.peak_connections,
            "active_connections": remaining,
        }


def _within_arm_throughput_stability(
    samples: Sequence[dict[str, int]], expected_messages: int
) -> dict[str, Any]:
    if expected_messages <= 0:
        raise ValueError("within-arm stability requires a positive message count")
    canonical: list[dict[str, int]] = [{"verified": 0, "duration_ns": 0}]
    for sample in samples:
        verified = int(sample["verified"])
        duration_ns = int(sample["duration_ns"])
        previous = canonical[-1]
        if verified < previous["verified"] or duration_ns < previous["duration_ns"]:
            raise RuntimeError("proxy progress evidence was not monotonic")
        if verified > expected_messages:
            raise RuntimeError("proxy progress exceeded the requested message count")
        if verified == previous["verified"]:
            continue
        canonical.append({"verified": verified, "duration_ns": duration_ns})
    if canonical[-1]["verified"] != expected_messages:
        raise RuntimeError("proxy progress did not reach the requested message count")
    qualification_required = expected_messages >= 20
    thresholds = [
        math.ceil(expected_messages * fraction / 4) for fraction in range(1, 5)
    ]
    milestones = [canonical[0]]
    for threshold in thresholds:
        milestones.append(
            next(sample for sample in canonical[1:] if sample["verified"] >= threshold)
        )
    segments: list[dict[str, Any]] = []
    rates: list[float] = []
    for ordinal, (before, after) in enumerate(zip(milestones, milestones[1:])):
        messages = after["verified"] - before["verified"]
        duration_ns = after["duration_ns"] - before["duration_ns"]
        rate = messages * 1_000_000_000 / duration_ns if duration_ns > 0 else 0.0
        rates.append(rate)
        segments.append(
            {
                "ordinal": ordinal,
                "messages": messages,
                "duration_ns": duration_ns,
                "messages_per_second": round(rate, 6),
            }
        )
    positive_rates = [value for value in rates if value > 0]
    median = statistics.median(positive_rates) if positive_rates else 0.0
    relative_range = (
        (max(positive_rates) - min(positive_rates)) / median
        if len(positive_rates) == 4 and median > 0
        else math.inf
    )
    passed = not qualification_required or (
        len(positive_rates) == 4 and relative_range <= MAXIMUM_WITHIN_ARM_RELATIVE_RANGE
    )
    canonical_bytes = json.dumps(
        canonical, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return {
        "qualification_required": qualification_required,
        "maximum_relative_range": MAXIMUM_WITHIN_ARM_RELATIVE_RANGE,
        "relative_range": round(relative_range, 6)
        if math.isfinite(relative_range)
        else None,
        "segments": segments,
        "progress_sample_count": len(canonical) - 1,
        "progress_samples_sha256": hashlib.sha256(canonical_bytes).hexdigest(),
        "progress_samples": canonical,
        "passed": passed,
    }


def _coordinator_quartile_diagnostics(
    records: Sequence[dict[str, Any]],
    expected_messages: int,
    *,
    maximum_stages: int = MAXIMUM_COORDINATOR_DIAGNOSTIC_STAGES,
    selected_stage_names: Sequence[str] = (),
) -> dict[str, Any]:
    if expected_messages <= 0:
        raise ValueError("coordinator diagnostics require a positive message count")
    if maximum_stages <= 0:
        raise ValueError("coordinator diagnostic stage bound must be positive")
    selected_stage_names = tuple(selected_stage_names)
    if (
        len(selected_stage_names) > MAXIMUM_COORDINATOR_SELECTED_DIAGNOSTIC_STAGES
        or len(set(selected_stage_names)) != len(selected_stage_names)
        or any(not name for name in selected_stage_names)
    ):
        raise ValueError("coordinator selected diagnostic stages are invalid")
    thresholds = [
        math.ceil(expected_messages * fraction / 4) for fraction in range(1, 5)
    ]
    result: dict[str, Any] = {
        "expected_messages": expected_messages,
        "thresholds": thresholds,
        "retained_record_count": len(records),
        "maximum_stages_per_segment": maximum_stages,
        "selected_stage_names": list(selected_stage_names),
        "segments": [],
        "complete": False,
    }
    if not records:
        result["reason"] = "no_records"
        return result

    milestones: list[dict[str, Any]] = []
    start_index = 0
    previous_completed = 0
    previous_total_ns = 0
    for threshold in thresholds:
        selected: dict[str, Any] | None = None
        for index in range(start_index, len(records)):
            record = records[index]
            try:
                completed = int(record["completed_tasks"])
                total_ns = int(record["completed_total_ns"])
                stages = record["stages"]
            except (KeyError, TypeError, ValueError):
                result["reason"] = "invalid_record"
                return result
            if (
                completed < previous_completed
                or total_ns < previous_total_ns
                or not isinstance(stages, dict)
            ):
                result["reason"] = "non_monotonic_or_invalid_record"
                return result
            previous_completed = completed
            previous_total_ns = total_ns
            if completed >= threshold:
                selected = record
                start_index = index + 1
                break
        if selected is None:
            result["reason"] = "missing_threshold"
            result["missing_threshold"] = threshold
            break
        milestones.append(selected)

    before_completed = 0
    before_total_ns = 0
    before_stages: dict[str, Any] = {}
    for ordinal, (threshold, after) in enumerate(zip(thresholds, milestones), start=1):
        after_completed = int(after["completed_tasks"])
        after_total_ns = int(after["completed_total_ns"])
        after_stages = after["stages"]
        stage_deltas: list[dict[str, Any]] = []
        stage_deltas_by_name: dict[str, dict[str, Any]] = {}
        all_stage_total_ns = 0
        for stage_name in sorted(set(before_stages) | set(after_stages)):
            before_counter = before_stages.get(
                stage_name, {"count": 0, "total_ns": 0, "max_ns": 0}
            )
            after_counter = after_stages.get(stage_name)
            if not isinstance(before_counter, dict) or not isinstance(
                after_counter, dict
            ):
                result["reason"] = "invalid_stage_counter"
                return result
            try:
                before_count = int(before_counter["count"])
                before_stage_total_ns = int(before_counter["total_ns"])
                after_count = int(after_counter["count"])
                after_stage_total_ns = int(after_counter["total_ns"])
                after_max_ns = int(after_counter["max_ns"])
            except (KeyError, TypeError, ValueError):
                result["reason"] = "invalid_stage_counter"
                return result
            if (
                after_count < before_count
                or after_stage_total_ns < before_stage_total_ns
                or after_max_ns < 0
            ):
                result["reason"] = "non_monotonic_stage_counter"
                return result
            delta_count = after_count - before_count
            delta_total_ns = after_stage_total_ns - before_stage_total_ns
            all_stage_total_ns += delta_total_ns
            stage_delta = {
                "stage": stage_name,
                "delta_count": delta_count,
                "delta_total_ns": delta_total_ns,
                "average_ns": delta_total_ns // delta_count if delta_count else None,
                "end_max_ns": after_max_ns,
            }
            stage_deltas_by_name[stage_name] = stage_delta
            if delta_count or delta_total_ns:
                stage_deltas.append(stage_delta)
        stage_deltas.sort(
            key=lambda value: (
                -int(value["delta_total_ns"]),
                -int(value["delta_count"]),
                str(value["stage"]),
            )
        )
        delta_completed = after_completed - before_completed
        delta_completed_total_ns = after_total_ns - before_total_ns
        result["segments"].append(
            {
                "ordinal": ordinal,
                "threshold": threshold,
                "start_completed_tasks": before_completed,
                "end_completed_tasks": after_completed,
                "delta_completed_tasks": delta_completed,
                "delta_completed_total_ns": delta_completed_total_ns,
                "average_completed_task_ns": (
                    delta_completed_total_ns // delta_completed
                    if delta_completed
                    else None
                ),
                "all_stage_delta_total_ns": all_stage_total_ns,
                "top_stages": stage_deltas[:maximum_stages],
                "selected_stages": [
                    stage_deltas_by_name[name]
                    for name in selected_stage_names
                    if name in stage_deltas_by_name
                ],
            }
        )
        before_completed = after_completed
        before_total_ns = after_total_ns
        before_stages = after_stages

    if len(milestones) == len(thresholds):
        result["complete"] = True
        result["reason"] = "complete"
    return result


class RustSmtpProxy:
    def __init__(
        self,
        runtime: Any,
        *,
        binary: Path,
        expected_sha256: str,
        run_id: str,
        control_root: Path | None = None,
    ):
        if runtime.ports is None or runtime.workspace is None:
            raise RuntimeError("Rust SMTP proxy requires a started runtime")
        actual_sha256 = _sha256_file(binary)
        if actual_sha256 != expected_sha256:
            raise RuntimeError(
                f"benchmark proxy binary changed: {actual_sha256}; expected {expected_sha256}"
            )
        self.binary = binary
        self.binary_sha256 = actual_sha256
        self.control = _proxy_control_path(runtime.workspace, control_root)
        self.log_path = runtime.workspace / f"smtp-proxy-{run_id}.log"
        self.log = self.log_path.open("xb")
        try:
            self.process = subprocess.Popen(
                [
                    str(binary),
                    "proxy",
                    "--listen",
                    f"{SMTP_CAPTURE_ADDRESS}:{SMTP_CAPTURE_PORT}",
                    "--backend",
                    f"127.0.0.1:{runtime.ports.smtp}",
                    "--control",
                    str(self.control),
                    "--max-connections",
                    str(MAX_CAPTURE_CONNECTIONS),
                    "--memory-budget-mib",
                    "2048",
                ],
                stdin=subprocess.DEVNULL,
                stdout=self.log,
                stderr=subprocess.STDOUT,
                close_fds=True,
            )
        except BaseException:
            self.log.close()
            raise
        self.run_id = run_id
        self.started_at: str | None = None
        self.closed = False
        self.expected_messages: int | None = None
        self.progress_samples: list[dict[str, int]] = []
        self.progress_condition = threading.Condition()
        self.progress_stop = threading.Event()
        self.progress_complete = threading.Event()
        self.progress_error: BaseException | None = None
        self.progress_thread: threading.Thread | None = None
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                returncode = self.process.returncode
                self.close()
                raise RuntimeError(
                    "Rust SMTP proxy exited during startup with "
                    f"return code {returncode}; log={self.log_path}; "
                    f"tail:\n{_bounded_file_tail(self.log_path)}"
                )
            if self.control.exists():
                try:
                    self._command({"command": "summary"}, timeout=0.2, require_ok=False)
                except (OSError, TimeoutError):
                    time.sleep(0.02)
                    continue
                return
            time.sleep(0.02)
        self.close()
        raise TimeoutError("Rust SMTP proxy control socket did not become ready")

    def _command(
        self,
        value: dict[str, Any],
        *,
        timeout: float = 30.0,
        require_ok: bool = True,
    ) -> dict[str, Any]:
        payload = (
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
            + b"\n"
        )
        if len(payload) > 64 * 1024:
            raise RuntimeError("Rust proxy control request exceeded its fixed bound")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout)
            connection.connect(str(self.control))
            connection.sendall(payload)
            response = bytearray()
            while b"\n" not in response:
                chunk = connection.recv(64 * 1024 + 1 - len(response))
                if not chunk:
                    raise RuntimeError("Rust proxy control closed without a response")
                response.extend(chunk)
                if len(response) > 64 * 1024:
                    raise RuntimeError(
                        "Rust proxy control response exceeded its fixed bound"
                    )
        decoded = json.loads(bytes(response).split(b"\n", 1)[0])
        if not isinstance(decoded, dict):
            raise RuntimeError("Rust proxy control response was not an object")
        if require_ok and decoded.get("ok") is not True:
            raise RuntimeError(f"Rust proxy control command failed: {decoded}")
        return decoded

    def _record_progress(self, round_value: dict[str, Any]) -> None:
        verified = int(round_value.get("verified", 0))
        duration_ns = int(round_value.get("progress_duration_ns") or 0)
        with self.progress_condition:
            if self.expected_messages is None:
                raise RuntimeError("Rust proxy progress monitor was not armed")
            if verified < 0 or verified > self.expected_messages:
                raise RuntimeError(
                    "Rust proxy progress escaped the requested message range"
                )
            if verified > 0 and duration_ns <= 0:
                raise RuntimeError(
                    "Rust proxy progress omitted a positive elapsed duration"
                )
            if len(self.progress_samples) >= MAXIMUM_PROXY_PROGRESS_SAMPLES:
                raise RuntimeError(
                    "Rust proxy progress evidence exceeded its fixed bound"
                )
            if self.progress_samples:
                previous = self.progress_samples[-1]
                if (
                    verified < previous["verified"]
                    or duration_ns < previous["duration_ns"]
                ):
                    raise RuntimeError("Rust proxy progress evidence was not monotonic")
                if verified == previous["verified"]:
                    return
            self.progress_samples.append(
                {"verified": verified, "duration_ns": duration_ns}
            )
            self.progress_condition.notify_all()

    def _monitor_progress(self) -> None:
        try:
            while not self.progress_stop.is_set():
                summary = self._command(
                    {"command": "summary"},
                    timeout=PROXY_PROGRESS_COMMAND_TIMEOUT_SECONDS,
                )
                round_value = summary.get("round")
                if not isinstance(round_value, dict):
                    raise RuntimeError("Rust proxy summary omitted round evidence")
                if int(round_value.get("observer_failure_count", 0)) != 0:
                    raise RuntimeError(f"Rust proxy observer failed: {round_value}")
                self._record_progress(round_value)
                expected = int(round_value.get("expected", -1))
                if expected != self.expected_messages:
                    raise RuntimeError(
                        "Rust proxy summary changed the expected message count"
                    )
                if int(round_value.get("verified", -1)) == expected:
                    self.progress_complete.set()
                    return
                self.progress_stop.wait(0.25)
        except BaseException as error:
            with self.progress_condition:
                self.progress_error = error
                self.progress_condition.notify_all()
            self.progress_complete.set()

    def _stop_progress_monitor(self) -> None:
        self.progress_stop.set()
        thread = self.progress_thread
        if thread is not None:
            thread.join(timeout=PROXY_MONITOR_JOIN_TIMEOUT_SECONDS)
            if thread.is_alive():
                raise RuntimeError("Rust proxy progress monitor did not stop")
            self.progress_thread = None

    def _reap_process(self, *, require_graceful_exit: bool) -> None:
        graceful = True
        try:
            self.process.wait(timeout=PROXY_PROCESS_EXIT_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            graceful = False
            self.process.terminate()
            try:
                self.process.wait(timeout=PROXY_PROCESS_EXIT_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=PROXY_PROCESS_EXIT_TIMEOUT_SECONDS)
        finally:
            self.closed = True
            self.log.close()
        if require_graceful_exit and not graceful:
            raise RuntimeError(
                "Rust SMTP proxy did not exit after finish acknowledgement"
            )

    def begin(
        self,
        *,
        expected: int,
        message_bytes: int,
        started_monotonic: float,
        started_at: str,
        persistence_gate_required: bool = True,
    ) -> None:
        del started_monotonic
        if self.closed or self.expected_messages is not None:
            raise RuntimeError("Rust SMTP proxy can be armed exactly once")
        if expected <= 0:
            raise ValueError("Rust SMTP proxy requires a positive message count")
        self.started_at = started_at
        response = self._command(
            {
                "command": "begin",
                "run_id": self.run_id,
                "expected_messages": expected,
                "message_bytes": message_bytes,
                "expected_sender": ENDPOINT_SENDER,
                "expected_receiver": ENDPOINT_RECEIVER,
                "persistence_gate_required": persistence_gate_required,
            }
        )
        if response.get("begin", {}).get("run_id") != self.run_id:
            raise RuntimeError("Rust proxy begin acknowledgement changed run identity")
        self.expected_messages = expected
        self.progress_thread = threading.Thread(
            target=self._monitor_progress,
            name="lmyzmail-benchmark-proxy-progress",
            daemon=False,
        )
        self.progress_thread.start()

    def wait_for_persistence_gate(self, timeout_seconds: float) -> dict[str, Any]:
        response = self._command(
            {
                "command": "wait_persistence_gate",
                "timeout_millis": int(timeout_seconds * 1_000),
            },
            timeout=timeout_seconds + 5.0,
        )
        gate = response.get("persistence_gate")
        if (
            not isinstance(gate, dict)
            or isinstance(gate.get("gate_id"), bool)
            or not isinstance(gate.get("gate_id"), int)
            or gate.get("gate_id", 0) <= 0
            or gate.get("expected_messages") != self.expected_messages
        ):
            raise RuntimeError("Rust proxy persistence gate trigger was invalid")
        return gate

    def release_persistence_gate(
        self,
        gate_id: int,
        snapshot: dict[str, Any],
    ) -> dict[str, Any]:
        response = self._command(
            {
                "command": "release_persistence_gate",
                "gate_id": gate_id,
                "snapshot": snapshot,
            },
            timeout=PERSISTENCE_GATE_TIMEOUT_SECONDS,
        )
        gate = response.get("persistence_gate")
        if not isinstance(gate, dict) or gate.get("qualified") is not False:
            # Forwarding has not started while this acknowledgement is generated.
            # The final evidence becomes qualified only after write+flush+observer ack.
            raise RuntimeError(
                "Rust proxy persistence gate release evidence was invalid"
            )
        if gate.get("status") != "released" or gate.get("gate_id") != gate_id:
            raise RuntimeError("Rust proxy persistence gate release identity changed")
        return gate

    def abort_persistence_gate(self, gate_id: int, reason: str) -> None:
        self._command(
            {
                "command": "abort_persistence_gate",
                "gate_id": gate_id,
                "reason": reason[:256],
            },
            timeout=5.0,
        )

    def finish(
        self,
        timeout_seconds: float,
        abort_check: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout_seconds
        try:
            while not self.progress_complete.wait(0.25):
                if abort_check is not None:
                    abort_check()
                if time.monotonic() >= deadline:
                    with self.progress_condition:
                        verified = (
                            self.progress_samples[-1]["verified"]
                            if self.progress_samples
                            else 0
                        )
                    raise TimeoutError(
                        f"Rust proxy verified {verified} messages before deadline"
                    )
        except BaseException as error:
            try:
                self._stop_progress_monitor()
            except BaseException as stop_error:
                error.add_note(
                    "progress monitor cleanup also failed: "
                    f"{type(stop_error).__name__}: {stop_error}"
                )
            raise
        self._stop_progress_monitor()
        with self.progress_condition:
            progress_error = self.progress_error
        if progress_error is not None:
            raise RuntimeError("Rust proxy progress monitor failed") from progress_error
        finished = self._command({"command": "finish"}, timeout=305.0)
        round_value = finished.get("round")
        proxy_value = finished.get("proxy")
        if not isinstance(round_value, dict) or not isinstance(proxy_value, dict):
            raise RuntimeError("Rust proxy finish omitted round or proxy evidence")
        if not _proxy_shutdown_evidence_is_valid(proxy_value):
            raise RuntimeError("Rust proxy finish reported invalid shutdown evidence")
        duration_ns = int(round_value.get("duration_ns") or 0)
        duration = duration_ns / 1_000_000_000
        total_wire_bytes = int(round_value.get("total_wire_bytes", 0))
        output = dict(round_value)
        output.update(
            {
                "started_at": self.started_at,
                "duration_seconds": round(duration, 6),
                "throughput_messages_per_second": round(
                    float(round_value.get("throughput_messages_per_second") or 0.0), 6
                ),
                "data_throughput_mib_per_second": round(
                    total_wire_bytes / (1024 * 1024) / duration
                    if duration > 0
                    else 0.0,
                    6,
                ),
                "failures": list(round_value.get("observer_failures", [])),
                "proxy": proxy_value,
                "proxy_binary_sha256": self.binary_sha256,
                "within_arm_throughput_stability": _within_arm_throughput_stability(
                    self.progress_samples,
                    int(round_value.get("expected", 0)),
                ),
            }
        )
        return output

    def diagnostics(self) -> dict[str, Any]:
        if self.closed:
            return {"closed": True, "binary_sha256": self.binary_sha256}
        with contextlib.suppress(BaseException):
            return self._command({"command": "summary"})
        return {"closed": False, "binary_sha256": self.binary_sha256}

    def close(self) -> dict[str, Any]:
        if self.closed:
            return {"closed": True, "binary_sha256": self.binary_sha256}
        monitor_error: BaseException | None = None
        try:
            self._stop_progress_monitor()
        except BaseException as error:
            monitor_error = error
        with contextlib.suppress(BaseException):
            self._command({"command": "shutdown"}, timeout=305.0)
        try:
            self._reap_process(require_graceful_exit=False)
        finally:
            thread = self.progress_thread
            if thread is not None:
                thread.join(timeout=PROXY_MONITOR_JOIN_TIMEOUT_SECONDS)
                if not thread.is_alive():
                    self.progress_thread = None
                elif monitor_error is None:
                    monitor_error = RuntimeError(
                        "Rust proxy progress monitor remained alive after process exit"
                    )
        if monitor_error is not None:
            raise monitor_error
        return {
            "closed": True,
            "returncode": self.process.returncode,
            "binary_sha256": self.binary_sha256,
        }


class MaildirPersistenceObserver:
    _IN_CLOSE_WRITE = 0x00000008
    _IN_MOVED_FROM = 0x00000040
    _IN_MOVED_TO = 0x00000080
    _IN_CREATE = 0x00000100
    _IN_DELETE = 0x00000200
    _IN_DELETE_SELF = 0x00000400
    _IN_MOVE_SELF = 0x00000800
    _IN_Q_OVERFLOW = 0x00004000
    _IN_IGNORED = 0x00008000
    _IN_ISDIR = 0x40000000
    _WATCH_MASK = (
        _IN_CLOSE_WRITE
        | _IN_MOVED_FROM
        | _IN_MOVED_TO
        | _IN_CREATE
        | _IN_DELETE
        | _IN_DELETE_SELF
        | _IN_MOVE_SELF
    )
    _EVENT = struct.Struct("iIII")

    def __init__(self, runtime: Any, *, expected_messages: int):
        if runtime.workspace is None:
            raise RuntimeError("Maildir observer requires a started runtime")
        if expected_messages <= 0:
            raise ValueError("Maildir observer requires a positive message count")
        self.expected_messages = expected_messages
        self.root = runtime.workspace / "maildir"
        if self.root.is_symlink():
            raise RuntimeError("Maildir observer root is aliased")
        self.root = self.root.resolve(strict=True)
        address_layout = getattr(runtime, "benchmark_maildir_address_layout", None)
        if address_layout == "java-raw":
            receiver_relative = Path(ENDPOINT_RECEIVER)
            sender_relative = Path(ENDPOINT_SENDER)
        elif address_layout == "lmyzmail-v2":
            receiver_relative = _v2_mailbox_relative_path(ENDPOINT_RECEIVER)
            sender_relative = _v2_mailbox_relative_path(ENDPOINT_SENDER)
        else:
            raise RuntimeError("Maildir observer runtime address layout is unsupported")
        self.receiver_root = self.root / receiver_relative / "inbox"
        self.sender_root = self.root / sender_relative / "sent"
        self.scope_roots = {
            f"{ENDPOINT_RECEIVER}/inbox": self.receiver_root,
            f"{ENDPOINT_SENDER}/sent": self.sender_root,
        }
        self.condition = threading.Condition()
        self.stop_requested = threading.Event()
        self.error: BaseException | None = None
        self.published = 0
        self.removed = 0
        self.last_publication_monotonic_ns: int | None = None
        self.close_write_events = 0
        self.peak_live_files = 0
        self.publication_mechanisms: dict[str, str] = {}
        self.publication_scopes: dict[str, str] = {}
        self.publications_by_parent: dict[str, set[str]] = {}
        self.removed_paths: set[str] = set()
        self.overflow_events = 0
        self.overflow_reconciliations = 0
        self.overflow_reconciled_removals = 0
        self.overflow_directory_scans = 0
        self.event_digest = hashlib.sha256()
        self.watches: dict[int, Path] = {}
        self.library = ctypes.CDLL(None, use_errno=True)
        self.library.inotify_init1.argtypes = [ctypes.c_int]
        self.library.inotify_init1.restype = ctypes.c_int
        self.library.inotify_add_watch.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint32,
        ]
        self.library.inotify_add_watch.restype = ctypes.c_int
        flags = os.O_NONBLOCK | os.O_CLOEXEC
        self.descriptor = int(self.library.inotify_init1(flags))
        if self.descriptor < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        try:
            self._add_tree(self.root)
        except BaseException:
            os.close(self.descriptor)
            raise
        self.thread = threading.Thread(
            target=self._run,
            name="smtp-throughput-maildir-persistence-observer",
            daemon=False,
        )
        self.thread.start()

    def _add_watch(self, path: Path) -> None:
        resolved = path.resolve(strict=True)
        if path.is_symlink() or not resolved.is_relative_to(self.root):
            raise RuntimeError("Maildir observer watch escaped its root")
        encoded = os.fsencode(resolved)
        watch = int(
            self.library.inotify_add_watch(self.descriptor, encoded, self._WATCH_MASK)
        )
        if watch < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error), resolved)
        self.watches[watch] = resolved
        if len(self.watches) > 100_000:
            raise RuntimeError("Maildir observer watch budget was exceeded")

    def _directory_is_relevant(self, path: Path) -> bool:
        try:
            relative = path.relative_to(self.root)
        except ValueError:
            return False
        if any(part.startswith(".lmyzmail-") for part in relative.parts):
            return False
        scope_roots = getattr(self, "scope_roots", None)
        if not scope_roots:
            return path == self.root
        return any(
            path == scope_root
            or scope_root.is_relative_to(path)
            or path.is_relative_to(scope_root)
            for scope_root in scope_roots.values()
        )

    def _add_tree(self, root: Path) -> None:
        pending = [root]
        visited: set[Path] = set()
        while pending:
            current = pending.pop()
            resolved = current.resolve(strict=True)
            if resolved in visited:
                continue
            if not self._directory_is_relevant(resolved):
                continue
            self._add_watch(current)
            visited.add(resolved)
            # Install the watch before scandir. os.walk() scans before yielding,
            # which leaves a gap where the first rename into a new subdirectory
            # is neither enumerated nor reported by inotify.
            with os.scandir(resolved) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
            for entry in entries:
                path = resolved / entry.name
                if entry.is_symlink():
                    raise RuntimeError("Maildir observer tree contains a symlink")
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    raise RuntimeError(
                        "Maildir observer tree contains a non-file entry"
                    )
                self._observe_publication(
                    path,
                    mechanism="directory_reconciliation",
                )

    def _scope_for_path(self, path: Path) -> str | None:
        scope_roots = getattr(
            self,
            "scope_roots",
            {f"{ENDPOINT_RECEIVER}/inbox": self.receiver_root},
        )
        for scope, root in scope_roots.items():
            if path.parent == root or path.parent.is_relative_to(root):
                relative = path.relative_to(root)
                if any(part.startswith(".lmyzmail-") for part in relative.parts):
                    return None
                return scope
        return None

    def _is_receiver_path(self, path: Path) -> bool:
        return self._scope_for_path(path) == f"{ENDPOINT_RECEIVER}/inbox"

    def _is_observed_path(self, path: Path) -> bool:
        return self._scope_for_path(path) is not None

    def _observe_publication(
        self,
        path: Path,
        mechanism: str = "atomic_rename",
    ) -> None:
        scope = self._scope_for_path(path)
        if scope is None:
            return
        relative = path.relative_to(self.root).as_posix()
        precedence = {
            "directory_reconciliation": 0,
            "visible_create": 1,
            "direct_close_write": 2,
            "atomic_rename": 3,
        }
        if mechanism not in precedence:
            raise RuntimeError("Maildir publication mechanism was invalid")
        previous = self.publication_mechanisms.get(relative)
        if previous is not None:
            if precedence[mechanism] > precedence[previous]:
                self.publication_mechanisms[relative] = mechanism
                self.event_digest.update(
                    f"upgrade\0{mechanism}\0{relative}\n".encode("utf-8")
                )
            return
        self.publication_mechanisms[relative] = mechanism
        publication_scopes = getattr(self, "publication_scopes", None)
        if publication_scopes is None:
            publication_scopes = {}
            self.publication_scopes = publication_scopes
        publication_scopes[relative] = scope
        parent = path.parent.relative_to(self.root).as_posix()
        publications_by_parent = getattr(self, "publications_by_parent", None)
        if publications_by_parent is None:
            publications_by_parent = {}
            self.publications_by_parent = publications_by_parent
        publications_by_parent.setdefault(parent, set()).add(relative)
        self.event_digest.update(f"publish\0{mechanism}\0{relative}\n".encode("utf-8"))
        self.published += 1
        self.last_publication_monotonic_ns = time.monotonic_ns()
        self.peak_live_files = max(self.peak_live_files, self.published - self.removed)
        expected_publications = self.expected_messages * len(
            getattr(self, "scope_roots", {"receiver": self.receiver_root})
        )
        if self.published > expected_publications:
            counts = {
                observed_scope: sum(
                    value == observed_scope for value in publication_scopes.values()
                )
                for observed_scope in sorted(set(publication_scopes.values()))
            }
            raise RuntimeError(
                "Maildir publications exceeded SMTP acceptance: "
                f"total={self.published} expected={expected_publications} "
                f"scope={scope!r} counts={counts!r} mechanism={mechanism!r} "
                f"path={relative!r}"
            )

    def _observe_removal(self, path: Path) -> None:
        if not self._is_observed_path(path):
            return
        relative = path.relative_to(self.root).as_posix()
        if (
            relative not in self.publication_mechanisms
            or relative in self.removed_paths
        ):
            return
        self.removed_paths.add(relative)
        self.removed = len(self.removed_paths)
        publications_by_parent = getattr(self, "publications_by_parent", {})
        parent = path.parent.relative_to(self.root).as_posix()
        siblings = publications_by_parent.get(parent)
        if siblings is not None:
            siblings.discard(relative)
            if not siblings:
                publications_by_parent.pop(parent, None)
        self.event_digest.update(f"remove\0{relative}\n".encode("utf-8"))

    def _observe_tree_removal(self, path: Path) -> None:
        scope_roots = tuple(
            getattr(self, "scope_roots", {"receiver": self.receiver_root}).values()
        )
        if not any(path == root or path.is_relative_to(root) for root in scope_roots):
            return
        relative = path.relative_to(self.root).as_posix()
        prefix = f"{relative}/"
        publications_by_parent = getattr(self, "publications_by_parent", {})
        matching_parents = [
            parent
            for parent in publications_by_parent
            if parent == relative or parent.startswith(prefix)
        ]
        for parent in matching_parents:
            published_paths = tuple(publications_by_parent.pop(parent, ()))
            for published in published_paths:
                self._observe_removal(self.root / published)

    def _reconcile_removals_after_overflow(self) -> None:
        scope_roots = getattr(
            self,
            "scope_roots",
            {f"{ENDPOINT_RECEIVER}/inbox": self.receiver_root},
        )
        expected_publications = self.expected_messages * len(scope_roots)
        if self.published != expected_publications:
            raise RuntimeError(
                "Maildir observer queue overflowed before all publications were observed"
            )
        removed_before = self.removed
        publications_by_parent = getattr(self, "publications_by_parent", {})
        for parent_relative, published_paths in tuple(
            publications_by_parent.items()
        ):
            parent = self.root / parent_relative
            try:
                if parent.is_symlink():
                    raise RuntimeError(
                        "Maildir overflow reconciliation found a symlinked parent"
                    )
                resolved = parent.resolve(strict=True)
            except FileNotFoundError:
                live_names: set[str] = set()
            else:
                if not resolved.is_relative_to(self.root):
                    raise RuntimeError(
                        "Maildir overflow reconciliation escaped its root"
                    )
                with os.scandir(resolved) as iterator:
                    live_names = {entry.name for entry in iterator}
                self.overflow_directory_scans = (
                    getattr(self, "overflow_directory_scans", 0) + 1
                )
            for relative in tuple(published_paths):
                if Path(relative).name not in live_names:
                    self._observe_removal(self.root / relative)
        removed_delta = self.removed - removed_before
        self.overflow_reconciliations = (
            getattr(self, "overflow_reconciliations", 0) + 1
        )
        self.overflow_reconciled_removals = (
            getattr(self, "overflow_reconciled_removals", 0) + removed_delta
        )
        self.event_digest.update(f"overflow-reconcile\0{removed_delta}\n".encode("ascii"))

    def _evidence(self, *, require_cleanup: bool) -> dict[str, Any]:
        scope_roots = getattr(
            self,
            "scope_roots",
            {f"{ENDPOINT_RECEIVER}/inbox": self.receiver_root},
        )
        publication_scopes = dict(getattr(self, "publication_scopes", {}))
        for relative in self.publication_mechanisms:
            scope = self._scope_for_path(self.root / relative)
            if scope is not None:
                publication_scopes.setdefault(relative, scope)
        publication_counts = {
            scope: sum(
                observed_scope == scope
                for observed_scope in publication_scopes.values()
            )
            for scope in scope_roots
        }
        removal_counts = {
            scope: sum(
                publication_scopes.get(relative) == scope
                for relative in self.removed_paths
            )
            for scope in scope_roots
        }
        expected_publications = self.expected_messages * len(scope_roots)
        publication_passed = bool(
            self.published == expected_publications
            and all(
                count == self.expected_messages for count in publication_counts.values()
            )
        )
        cleanup_observed = bool(
            self.removed == expected_publications
            and all(
                count == self.expected_messages for count in removal_counts.values()
            )
        )
        mechanism_counts = {
            mechanism: sum(
                observed == mechanism
                for observed in self.publication_mechanisms.values()
            )
            for mechanism in (
                "atomic_rename",
                "visible_create",
                "direct_close_write",
                "directory_reconciliation",
            )
        }
        atomic_counts_by_scope = {
            scope: sum(
                publication_scopes.get(relative) == scope
                and mechanism == "atomic_rename"
                for relative, mechanism in self.publication_mechanisms.items()
            )
            for scope in scope_roots
        }
        return {
            "profile": "lmyzmail-maildir-inotify-publication-v8",
            "watch_scope_profile": "target-mailbox-folders-only-v1",
            "watched_directories": len(getattr(self, "watches", {})),
            "unrelated_maildir_trees_excluded": True,
            "expected_messages": self.expected_messages,
            "expected_publication_events": expected_publications,
            "publication_events": self.published,
            "publication_counts_by_mailbox_folder": publication_counts,
            "removal_counts_by_mailbox_folder": removal_counts,
            "receiver_inbox_publications": publication_counts.get(
                f"{ENDPOINT_RECEIVER}/inbox", 0
            ),
            "sender_sent_publications": publication_counts.get(
                f"{ENDPOINT_SENDER}/sent", 0
            ),
            "publication_clock_id": "CLOCK_MONOTONIC",
            "last_publication_monotonic_ns": self.last_publication_monotonic_ns,
            "atomic_rename_publications": mechanism_counts["atomic_rename"],
            "atomic_rename_publications_by_mailbox_folder": atomic_counts_by_scope,
            "direct_close_write_publications": mechanism_counts["direct_close_write"],
            "visible_create_publications": mechanism_counts["visible_create"],
            "directory_reconciled_publications": mechanism_counts[
                "directory_reconciliation"
            ],
            "publication_mechanism_counts": mechanism_counts,
            "atomic_only_publication_observed": (
                mechanism_counts["atomic_rename"] == self.expected_messages
            ),
            "removal_events": self.removed,
            "close_write_events": self.close_write_events,
            "peak_live_files": self.peak_live_files,
            "event_stream_sha256": self.event_digest.hexdigest(),
            "inotify_overflow_events": getattr(self, "overflow_events", 0),
            "overflow_reconciliations": getattr(
                self, "overflow_reconciliations", 0
            ),
            "overflow_reconciled_removals": getattr(
                self, "overflow_reconciled_removals", 0
            ),
            "overflow_directory_scans": getattr(
                self, "overflow_directory_scans", 0
            ),
            "publication_overflow_fail_closed": True,
            "cleanup_overflow_recovery_read_only": True,
            "message_file_open_calls": 0,
            "message_file_stat_calls": 0,
            "message_file_read_calls": 0,
            "observer_write_syscalls": 0,
            "observer_writes_prohibited": True,
            "content_validation_source": "proxy_wire_digest_and_golden",
            "endpoint_internal_cleanup_observed": cleanup_observed,
            "publication_passed": publication_passed,
            "passed": publication_passed and (not require_cleanup or cleanup_observed),
        }

    def snapshot(self) -> dict[str, Any]:
        with self.condition:
            if self.error is not None:
                raise RuntimeError(
                    f"Maildir persistence observer failed: {self.error!r}"
                ) from self.error
            return self._evidence(require_cleanup=False)

    def _consume(self, payload: bytes) -> None:
        offset = 0
        while offset < len(payload):
            if len(payload) - offset < self._EVENT.size:
                raise RuntimeError("Maildir observer received a truncated event")
            watch, mask, _cookie, name_bytes = self._EVENT.unpack_from(payload, offset)
            offset += self._EVENT.size
            if name_bytes > len(payload) - offset:
                raise RuntimeError("Maildir observer event name exceeded its buffer")
            raw_name = payload[offset : offset + name_bytes]
            offset += name_bytes
            if mask & self._IN_Q_OVERFLOW:
                self.overflow_events = getattr(self, "overflow_events", 0) + 1
                self._reconcile_removals_after_overflow()
                continue
            parent = self.watches.get(watch)
            if parent is None:
                if mask & self._IN_IGNORED:
                    continue
                raise RuntimeError("Maildir observer received an unknown watch")
            name = os.fsdecode(raw_name.split(b"\0", 1)[0])
            path = parent / name if name else parent
            self_event = bool(mask & (self._IN_DELETE_SELF | self._IN_MOVE_SELF))
            if self_event:
                self._observe_tree_removal(parent)
            if mask & self._IN_IGNORED:
                self.watches.pop(watch, None)
            if mask & self._IN_ISDIR:
                if mask & (self._IN_CREATE | self._IN_MOVED_TO):
                    if self._directory_is_relevant(path):
                        self._add_tree(path)
                if mask & (
                    self._IN_DELETE
                    | self._IN_MOVED_FROM
                    | self._IN_DELETE_SELF
                    | self._IN_MOVE_SELF
                ):
                    self._observe_tree_removal(path)
                continue
            if self_event or mask & self._IN_IGNORED:
                continue
            if mask & self._IN_MOVED_TO:
                self._observe_publication(path, mechanism="atomic_rename")
            if mask & self._IN_CREATE:
                self._observe_publication(path, mechanism="visible_create")
            if self._is_observed_path(path) and mask & self._IN_CLOSE_WRITE:
                self.close_write_events += 1
                self._observe_publication(path, mechanism="direct_close_write")
            if self._is_observed_path(path) and mask & (
                self._IN_DELETE | self._IN_MOVED_FROM
            ):
                self._observe_removal(path)

    def _run(self) -> None:
        try:
            while not self.stop_requested.is_set():
                readable, _, _ = select.select([self.descriptor], [], [], 0.05)
                if not readable:
                    continue
                while True:
                    try:
                        payload = os.read(self.descriptor, 1024 * 1024)
                    except BlockingIOError:
                        break
                    if not payload:
                        raise RuntimeError(
                            "Maildir observer descriptor closed unexpectedly"
                        )
                    with self.condition:
                        self._consume(payload)
                        self.condition.notify_all()
        except BaseException as error:
            with self.condition:
                self.error = error
                self.condition.notify_all()

    def wait_for_publications(
        self,
        timeout_seconds: float,
        abort_check: Callable[[], None] | None = None,
    ) -> None:
        deadline = time.monotonic() + timeout_seconds
        with self.condition:
            expected_publications = self.expected_messages * len(
                getattr(self, "scope_roots", {"receiver": self.receiver_root})
            )
            while self.published != expected_publications:
                if self.error is not None:
                    raise RuntimeError(
                        f"Maildir persistence observer failed: {self.error!r}"
                    ) from self.error
                if abort_check is not None:
                    abort_check()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    counts = self._evidence(require_cleanup=False)[
                        "publication_counts_by_mailbox_folder"
                    ]
                    raise TimeoutError(
                        "Maildir publications did not match SMTP acceptance: "
                        f"{self.published} != {expected_publications}; "
                        f"counts={counts!r}"
                    )
                self.condition.wait(min(remaining, 0.25))

    def wait_for_removals(self, timeout_seconds: float) -> None:
        deadline = time.monotonic() + timeout_seconds
        with self.condition:
            expected_removals = self.expected_messages * len(
                getattr(self, "scope_roots", {"receiver": self.receiver_root})
            )
            while self.removed != expected_removals:
                if self.error is not None:
                    raise RuntimeError(
                        f"Maildir persistence observer failed: {self.error!r}"
                    ) from self.error
                if getattr(self, "overflow_events", 0):
                    self._reconcile_removals_after_overflow()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    counts = self._evidence(require_cleanup=False)[
                        "removal_counts_by_mailbox_folder"
                    ]
                    raise TimeoutError(
                        "Maildir removals did not match endpoint cleanup: "
                        f"{self.removed} != {expected_removals}; counts={counts!r}"
                    )
                self.condition.wait(min(remaining, 0.25))

    def stop(self) -> dict[str, Any]:
        self.stop_requested.set()
        self.thread.join(timeout=10.0)
        if self.thread.is_alive():
            os.close(self.descriptor)
            self.thread.join(timeout=5.0)
        else:
            os.close(self.descriptor)
        if self.thread.is_alive():
            raise RuntimeError("Maildir persistence observer did not stop")
        if self.error is not None:
            raise RuntimeError(
                f"Maildir persistence observer failed: {self.error!r}"
            ) from self.error
        return self._evidence(require_cleanup=True)


class PostgresPersistenceGateSnapshot:
    def __init__(self, runtime: Any, *, before_rows: int, expected_messages: int):
        if runtime.ports is None:
            raise RuntimeError("PostgreSQL gate snapshot requires a started runtime")
        self.before_rows = before_rows
        self.expected_rows = before_rows + expected_messages
        self.expected_messages = expected_messages
        self.connection = base.psycopg.connect(
            host="127.0.0.1",
            port=runtime.ports.postgres,
            dbname="lmyzmail",
            user="lmyzmail_test",
            password="",
            connect_timeout=5,
            autocommit=False,
        )
        self.closed = False

    def capture(self) -> dict[str, Any]:
        if self.closed:
            raise RuntimeError("PostgreSQL gate snapshot connection is closed")
        snapshot_started = time.monotonic_ns()
        try:
            self.connection.execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
            query_started = time.monotonic_ns()
            row = self.connection.execute(
                "SELECT count(*) FROM outbound_mail_queue"
            ).fetchone()
            query_completed = time.monotonic_ns()
        except BaseException:
            with contextlib.suppress(BaseException):
                self.connection.rollback()
            raise
        self.connection.commit()
        snapshot_completed = time.monotonic_ns()
        if row is None or isinstance(row[0], bool) or not isinstance(row[0], int):
            raise RuntimeError("PostgreSQL gate snapshot count was invalid")
        rows = int(row[0])
        row_delta = rows - self.before_rows
        return {
            "clock_id": "CLOCK_MONOTONIC",
            "snapshot_started_monotonic_ns": snapshot_started,
            "snapshot_completed_monotonic_ns": snapshot_completed,
            "postgres_query_duration_ns": query_completed - query_started,
            "transaction_isolation": "repeatable_read",
            "transaction_read_only": True,
            "postgres_before_rows": self.before_rows,
            "postgres_rows": rows,
            "postgres_expected_rows": self.expected_rows,
            "postgres_row_delta": row_delta,
            "expected_messages": self.expected_messages,
            "qualified": rows == self.expected_rows
            and row_delta == self.expected_messages,
        }

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.connection.close()


def _parse_flat_stat(path: Path) -> dict[str, int]:
    output: dict[str, int] = {}
    for line in path.read_text(encoding="ascii").splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1].isdigit():
            output[fields[0]] = int(fields[1])
    return output


def _parse_io_stat(path: Path, device: str) -> dict[str, int]:
    for line in path.read_text(encoding="ascii").splitlines():
        fields = line.split()
        if fields and fields[0] == device:
            output: dict[str, int] = {}
            for field in fields[1:]:
                name, separator, raw = field.partition("=")
                if separator and raw.isdigit():
                    output[name] = int(raw)
            return output
    return {}


def _io_stats_by_device(
    path: Path, devices: Sequence[str]
) -> dict[str, dict[str, int]]:
    return {device: _parse_io_stat(path, device) for device in devices}


def _io_stat_delta(
    before: dict[str, dict[str, int]], after: dict[str, dict[str, int]]
) -> dict[str, dict[str, int]]:
    names = ("rbytes", "wbytes", "rios", "wios")
    return {
        device: {
            name: after.get(device, {}).get(name, 0)
            - before.get(device, {}).get(name, 0)
            for name in names
        }
        for device in set(before) | set(after)
    }


def _select_io_accounting_device(
    phases: Sequence[dict[str, Any]], *, devices: Sequence[str], logical_bytes: int
) -> str:
    if logical_bytes <= 0 or not phases:
        raise RuntimeError("I/O accounting calibration is empty")
    qualified: list[tuple[float, int, str]] = []
    for device in devices:
        ratios = [
            phase["delta"].get(device, {}).get("wbytes", 0) / logical_bytes
            for phase in phases
        ]
        if all(ratio >= IO_ACCOUNTING_MINIMUM_RATIO for ratio in ratios):
            qualified.append((min(ratios), int(device == devices[-1]), device))
    if not qualified:
        raise RuntimeError(
            "neither loop nor backing device accounted for at least 95 percent "
            "of both direct and buffered calibration writes"
        )
    return max(qualified)[2]


def _calibrate_io_accounting(layout: CgroupLayout, workspace: Path) -> dict[str, Any]:
    devices = (layout.device, layout.backing_device)
    phases: list[dict[str, Any]] = []
    specifications = (
        ("direct_fsync", ("oflag=direct", "conv=fsync")),
        ("buffered_fsync", ("conv=fsync",)),
    )
    for name, flags in specifications:
        path = workspace / f".lmyzmail-io-calibration-{name}-{uuid.uuid4().hex}"
        before = _io_stats_by_device(layout.parent / "io.stat", devices)
        try:
            subprocess.run(
                [
                    "dd",
                    "if=/dev/zero",
                    f"of={path}",
                    "bs=1048576",
                    f"count={IO_CALIBRATION_BYTES // 1_048_576}",
                    *flags,
                    "status=none",
                ],
                check=True,
                timeout=120.0,
            )
        finally:
            path.unlink(missing_ok=True)
        after = _io_stats_by_device(layout.parent / "io.stat", devices)
        phases.append(
            {
                "name": name,
                "logical_bytes": IO_CALIBRATION_BYTES,
                "before": before,
                "after": after,
                "delta": _io_stat_delta(before, after),
            }
        )
    accounting_device = _select_io_accounting_device(
        phases, devices=devices, logical_bytes=IO_CALIBRATION_BYTES
    )
    return {
        "passed": True,
        "minimum_accounted_ratio": IO_ACCOUNTING_MINIMUM_RATIO,
        "accounting_device": accounting_device,
        "loop_device": layout.device,
        "backing_device": layout.backing_device,
        "phases": phases,
    }


def _filesystem_used(path: Path) -> int:
    status = os.statvfs(path)
    return (status.f_blocks - status.f_bfree) * status.f_frsize


def _filesystem_free(path: Path) -> int:
    status = os.statvfs(path)
    return status.f_bavail * status.f_frsize


def _fd_counts(pids: Sequence[int]) -> dict[int, int]:
    output: dict[int, int] = {}
    for pid in pids:
        try:
            output[pid] = sum(1 for _ in Path(f"/proc/{pid}/fd").iterdir())
        except (FileNotFoundError, PermissionError):
            continue
    return output


def _process_memory_status(pids: Sequence[int]) -> dict[int, dict[str, int]]:
    output: dict[int, dict[str, int]] = {}
    for pid in pids:
        try:
            lines = Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines()
        except (FileNotFoundError, PermissionError):
            continue
        values: dict[str, int] = {}
        for line in lines:
            name, separator, raw = line.partition(":")
            if not separator or name not in {"VmRSS", "VmHWM"}:
                continue
            fields = raw.split()
            if len(fields) != 2 or fields[1] != "kB" or not fields[0].isdigit():
                raise RuntimeError(f"PID {pid} exposed malformed {name} evidence")
            values[name] = int(fields[0]) * 1024
        if set(values) != {"VmRSS", "VmHWM"}:
            raise RuntimeError(f"PID {pid} omitted VmRSS or VmHWM evidence")
        output[pid] = {
            "rss_bytes": values["VmRSS"],
            "hwm_bytes": values["VmHWM"],
        }
    return output


_PROCESS_IO_FIELDS = ("wchar", "syscw", "read_bytes", "write_bytes")


def _process_io_status(
    pids: Sequence[int], *, proc_root: Path = Path("/proc")
) -> dict[int, dict[str, int]]:
    output: dict[int, dict[str, int]] = {}
    for pid in pids:
        process_root = proc_root / str(pid)
        try:
            stat_before = (process_root / "stat").read_text(encoding="ascii")
            lines = (process_root / "io").read_text(encoding="ascii").splitlines()
            stat_after = (process_root / "stat").read_text(encoding="ascii")
        except PermissionError as error:
            raise RuntimeError(
                f"PID {pid} denied process I/O evidence capture"
            ) from error
        except (FileNotFoundError, ProcessLookupError):
            continue
        start_time = _parse_process_start_time(pid, stat_before)
        if _parse_process_start_time(pid, stat_after) != start_time:
            raise RuntimeError(f"PID {pid} changed identity during process I/O capture")
        values: dict[str, int] = {}
        for line in lines:
            name, separator, raw = line.partition(":")
            if not separator or name not in _PROCESS_IO_FIELDS:
                continue
            raw = raw.strip()
            if name in values or not raw.isdigit():
                raise RuntimeError(f"PID {pid} exposed malformed {name} I/O evidence")
            values[name] = int(raw)
        if set(values) != set(_PROCESS_IO_FIELDS):
            missing = sorted(set(_PROCESS_IO_FIELDS) - set(values))
            raise RuntimeError(f"PID {pid} omitted process I/O evidence: {missing}")
        values["start_time_ticks"] = start_time
        output[pid] = values
    return output


def _process_io_lifecycle_delta(samples: Sequence[dict[str, Any]]) -> dict[str, Any]:
    by_role = {
        role: {name: 0 for name in _PROCESS_IO_FIELDS}
        for role in ("application", "services", "harness", "total")
    }
    previous: dict[tuple[int, int], tuple[str, dict[str, int]]] = {}
    lifecycles: set[tuple[int, int]] = set()
    for sample_index, sample in enumerate(samples):
        role_by_pid = sample.get("process_role_by_pid")
        io_by_pid = sample.get("process_io_by_pid")
        unavailable_by_pid = sample.get("process_io_unavailable_by_pid", {})
        if not isinstance(role_by_pid, dict) or not isinstance(io_by_pid, dict):
            raise RuntimeError("resource sample omitted process PID/role I/O evidence")
        if not isinstance(unavailable_by_pid, dict):
            raise RuntimeError("resource sample has malformed unavailable I/O evidence")
        if set(io_by_pid) & set(unavailable_by_pid):
            raise RuntimeError("process I/O availability sets overlap")
        if set(role_by_pid) != set(io_by_pid) | set(unavailable_by_pid):
            raise RuntimeError(
                "process PID/role and I/O availability sample sets differ"
            )
        for raw_pid, raw_values in io_by_pid.items():
            if not isinstance(raw_pid, str) or not raw_pid.isdigit():
                raise RuntimeError("process I/O sample contains a malformed PID")
            pid = int(raw_pid)
            role = role_by_pid[raw_pid]
            if role not in {"application", "services", "harness"}:
                raise RuntimeError(f"PID {pid} has an invalid process role: {role!r}")
            if not isinstance(raw_values, dict):
                raise RuntimeError(f"PID {pid} has malformed process I/O counters")
            start_time = raw_values.get("start_time_ticks")
            if not isinstance(start_time, int) or start_time < 0:
                raise RuntimeError(f"PID {pid} has an invalid process start time")
            counters: dict[str, int] = {}
            for name in _PROCESS_IO_FIELDS:
                value = raw_values.get(name)
                if not isinstance(value, int) or value < 0:
                    raise RuntimeError(
                        f"PID {pid} has an invalid {name} process I/O counter"
                    )
                counters[name] = value
            identity = (pid, start_time)
            prior = previous.get(identity)
            if prior is None:
                delta = (
                    {name: 0 for name in _PROCESS_IO_FIELDS}
                    if sample_index == 0
                    else counters
                )
                lifecycles.add(identity)
            else:
                prior_role, prior_counters = prior
                if role != prior_role:
                    raise RuntimeError(
                        f"PID {pid} lifecycle changed role from {prior_role} to {role}"
                    )
                delta = {}
                for name in _PROCESS_IO_FIELDS:
                    if counters[name] < prior_counters[name]:
                        raise RuntimeError(
                            f"PID {pid} lifecycle {name} counter decreased"
                        )
                    delta[name] = counters[name] - prior_counters[name]
            for name, value in delta.items():
                by_role[role][name] += value
                by_role["total"][name] += value
            previous[identity] = (role, counters)
    return {
        "profile": "lmyzmail-proc-pid-io-lifecycle-v1",
        "lifecycle_count": len(lifecycles),
        "role_immutability_verified": True,
        "counter_monotonicity_verified": True,
        "by_role": by_role,
    }


def _persistence_io_sources(
    cgroup_io: dict[str, int], process_io: dict[str, int]
) -> dict[str, bool]:
    cgroup_observed = cgroup_io.get("wbytes", 0) > 0 and cgroup_io.get("wios", 0) > 0
    process_observed = (
        process_io.get("write_bytes", 0) > 0 and process_io.get("syscw", 0) > 0
    )
    return {
        "cgroup_observed": cgroup_observed,
        "process_observed": process_observed,
        "observed": cgroup_observed or process_observed,
    }


def _cgroup_memory(path: Path) -> dict[str, int]:
    memory_stat = _parse_flat_stat(path / "memory.stat")
    return {
        "current_bytes": int((path / "memory.current").read_text(encoding="ascii")),
        "anon_bytes": memory_stat.get("anon", 0),
        "file_bytes": memory_stat.get("file", 0),
    }


def _temperature_snapshot(
    thermal_root: Path = Path("/sys/class/thermal"),
    hwmon_root: Path = Path("/sys/class/hwmon"),
) -> dict[str, Any]:
    sensors: list[dict[str, Any]] = []
    if thermal_root.is_dir():
        for zone in sorted(thermal_root.glob("thermal_zone*")):
            temperature = zone / "temp"
            if not temperature.is_file():
                continue
            raw = temperature.read_text(encoding="ascii").strip()
            if not re.fullmatch(r"-?[0-9]+", raw):
                raise RuntimeError(
                    f"thermal sensor returned a malformed value: {temperature}"
                )
            sensor_type = zone.name
            with contextlib.suppress(OSError):
                sensor_type = (zone / "type").read_text(encoding="ascii").strip()
            sensors.append(
                {
                    "source": str(temperature),
                    "label": sensor_type,
                    "millicelsius": int(raw),
                }
            )
    if hwmon_root.is_dir():
        for hwmon in sorted(hwmon_root.glob("hwmon*")):
            device_name = hwmon.name
            with contextlib.suppress(OSError):
                device_name = (hwmon / "name").read_text(encoding="ascii").strip()
            for temperature in sorted(hwmon.glob("temp*_input")):
                raw = temperature.read_text(encoding="ascii").strip()
                if not re.fullmatch(r"-?[0-9]+", raw):
                    raise RuntimeError(
                        f"hardware monitor returned a malformed value: {temperature}"
                    )
                stem = temperature.name.removesuffix("_input")
                label = device_name
                with contextlib.suppress(OSError):
                    label = (
                        temperature.with_name(f"{stem}_label")
                        .read_text(encoding="ascii")
                        .strip()
                    )
                sensors.append(
                    {
                        "source": str(temperature),
                        "label": label,
                        "millicelsius": int(raw),
                    }
                )
    for sensor in sensors:
        if not -50_000 <= sensor["millicelsius"] <= 150_000:
            raise RuntimeError(
                f"temperature sensor value is outside its sane bound: {sensor}"
            )
    maximum = max((sensor["millicelsius"] for sensor in sensors), default=None)
    return {
        "available": bool(sensors),
        "sensor_count": len(sensors),
        "maximum_millicelsius": maximum,
        "limit_millicelsius": MAXIMUM_RECORDED_TEMPERATURE_MILLICELSIUS,
        "within_limit": maximum is None
        or maximum <= MAXIMUM_RECORDED_TEMPERATURE_MILLICELSIUS,
        "unavailable_is_reported_not_fabricated": not sensors,
        "sensors": sensors,
    }


def _role_process_memory(
    role_pids: dict[str, set[int]], process_memory: dict[int, dict[str, int]]
) -> dict[str, dict[str, int]]:
    output = {
        role: {
            "rss_bytes": sum(process_memory[pid]["rss_bytes"] for pid in pids),
            "hwm_bytes": sum(process_memory[pid]["hwm_bytes"] for pid in pids),
        }
        for role, pids in role_pids.items()
    }
    output["total"] = {
        "rss_bytes": sum(value["rss_bytes"] for value in process_memory.values()),
        "hwm_bytes": sum(value["hwm_bytes"] for value in process_memory.values()),
    }
    return output


def _stable_process_evidence(
    role_pids: dict[str, set[int]],
    *,
    required_identity_pids: set[int],
    fd_counts: dict[int, int],
    process_memory: dict[int, dict[str, int]],
    process_io: dict[int, dict[str, int]],
    process_io_required_pids: set[int] | None = None,
) -> tuple[dict[str, set[int]], list[int]]:
    enumerated = set().union(*role_pids.values())
    required_io = (
        set(enumerated)
        if process_io_required_pids is None
        else set(process_io_required_pids)
    )
    if not required_io <= enumerated:
        raise RuntimeError("process I/O required PID set exceeds cgroup membership")
    optional_io = enumerated - required_io
    captured = set(fd_counts) & set(process_memory) & (set(process_io) | optional_io)
    vanished = enumerated - captured
    missing_required = sorted(required_identity_pids & vanished)
    if missing_required:
        missing_channels = {
            pid: [
                name
                for name, evidence in (
                    ("fd", fd_counts),
                    ("rss", process_memory),
                    ("process_io", process_io),
                )
                if pid not in evidence and (name != "process_io" or pid in required_io)
            ]
            for pid in missing_required
        }
        raise RuntimeError(
            "required benchmark process omitted FD/RSS/I/O evidence: "
            f"{missing_channels}"
        )
    still_present = sorted(pid for pid in vanished if Path(f"/proc/{pid}").exists())
    if still_present:
        raise RuntimeError(
            "benchmark process omitted FD, RSS, or I/O evidence while still alive: "
            f"{still_present}"
        )
    return (
        {role: pids & captured for role, pids in role_pids.items()},
        sorted(vanished),
    )


def _membership_audit(
    runtime: Any,
    layout: CgroupLayout,
    role_pids: dict[str, set[int]],
    harness_auxiliary_roots: dict[int, int],
    *,
    require_harness_auxiliaries: bool,
) -> dict[str, Any]:
    parent_members = (
        (layout.parent / "cgroup.procs").read_text(encoding="ascii").split()
    )
    if parent_members:
        raise RuntimeError(f"run parent cgroup has direct members: {parent_members}")
    roots = _runtime_root_roles(runtime)
    process_trees = {role: _process_tree((pid,)) for role, pid in roots.items()}
    if process_trees["application"] & (
        process_trees["postgres"] | process_trees["redis"]
    ):
        raise RuntimeError(
            "application and service process trees overlap during measurement"
        )
    auxiliary_trees: set[int] = set()
    missing_auxiliaries: list[int] = []
    for pid, expected_start_time in harness_auxiliary_roots.items():
        try:
            actual_start_time = _process_start_time(pid)
        except (FileNotFoundError, ProcessLookupError):
            missing_auxiliaries.append(pid)
            continue
        if actual_start_time != expected_start_time:
            missing_auxiliaries.append(pid)
            continue
        auxiliary_trees.update(_process_tree((pid,)))
    if require_harness_auxiliaries and missing_auxiliaries:
        raise RuntimeError(
            "auxiliary harness process disappeared or changed identity: "
            f"{missing_auxiliaries}"
        )
    expected = {
        "application": process_trees["application"],
        "services": process_trees["postgres"] | process_trees["redis"],
        "harness": {os.getpid()} | auxiliary_trees,
    }
    required_identity_pids = set(roots.values()) | {os.getpid()}
    if require_harness_auxiliaries:
        required_identity_pids.update(harness_auxiliary_roots)
    suffixes = {
        "application": "/" + layout.workload.relative_to("/sys/fs/cgroup").as_posix(),
        "services": "/" + layout.services.relative_to("/sys/fs/cgroup").as_posix(),
        "harness": "/" + layout.harness.relative_to("/sys/fs/cgroup").as_posix(),
    }
    vanished_during_reconciliation: dict[str, list[int]] = {
        role: [] for role in expected
    }
    appeared_during_reconciliation: dict[str, list[int]] = {
        role: [] for role in expected
    }
    stable_membership: dict[str, set[int]] = {}
    for role in expected:
        missing_from_tree = role_pids[role] - expected[role]
        appeared_in_tree = expected[role] - role_pids[role]
        difference = missing_from_tree | appeared_in_tree
        missing_required = sorted(difference & required_identity_pids)
        if missing_required:
            raise RuntimeError(
                "required benchmark cgroup membership changed: "
                f"role={role}, pids={missing_required}"
            )
        unexpected_live_members: list[int] = []
        vanished: list[int] = []
        for pid in sorted(missing_from_tree):
            if not Path(f"/proc/{pid}").exists():
                vanished.append(pid)
                continue
            try:
                state = _process_state(pid)
            except (FileNotFoundError, ProcessLookupError):
                vanished.append(pid)
                continue
            if state in {"Z", "X", "x"}:
                vanished.append(pid)
                continue
            unexpected_live_members.append(pid)
        if unexpected_live_members:
            raise RuntimeError(
                "continuous cgroup membership changed for live processes: "
                f"role={role}, pids={unexpected_live_members}"
            )

        appeared: list[int] = []
        for pid in sorted(appeared_in_tree):
            try:
                state = _process_state(pid)
                actual_cgroup = _unified_cgroup(pid)
            except (FileNotFoundError, ProcessLookupError):
                vanished.append(pid)
                continue
            if state in {"Z", "X", "x"}:
                vanished.append(pid)
                continue
            if actual_cgroup != suffixes[role]:
                raise RuntimeError(f"PID {pid} escaped its {role} cgroup")
            appeared.append(pid)

        vanished_during_reconciliation[role] = sorted(vanished)
        appeared_during_reconciliation[role] = appeared
        stable_membership[role] = (role_pids[role] & expected[role]) | set(appeared)
    vanished_during_verification: dict[str, list[int]] = {
        role: [] for role in stable_membership
    }
    for role, pids in stable_membership.items():
        for pid in pids:
            try:
                actual_cgroup = _unified_cgroup(pid)
            except (FileNotFoundError, ProcessLookupError):
                if pid in required_identity_pids:
                    raise RuntimeError(
                        f"required {role} PID {pid} disappeared during cgroup verification"
                    )
                vanished_during_verification[role].append(pid)
                continue
            if actual_cgroup != suffixes[role]:
                raise RuntimeError(f"PID {pid} escaped its {role} cgroup")
    return {
        "passed": True,
        "continuous_membership": True,
        "roles": {role: sorted(pids) for role, pids in stable_membership.items()},
        "harness_auxiliary_roots": {
            str(pid): start_time
            for pid, start_time in sorted(harness_auxiliary_roots.items())
        },
        "missing_harness_auxiliaries": sorted(missing_auxiliaries),
        "harness_auxiliaries_required": require_harness_auxiliaries,
        "required_identity_pids": sorted(required_identity_pids),
        "vanished_during_membership_reconciliation": (vanished_during_reconciliation),
        "appeared_during_membership_reconciliation": (appeared_during_reconciliation),
        "vanished_during_cgroup_verification": {
            role: sorted(pids) for role, pids in vanished_during_verification.items()
        },
        "cgroups": suffixes,
        "parent_direct_members": [],
    }


class ResourceMonitor:
    def __init__(
        self,
        runtime: Any,
        layout: CgroupLayout,
        *,
        expected_messages: int,
        disk_budget_bytes: int,
        harness_auxiliary_roots: dict[int, int],
    ):
        if runtime.workspace is None or runtime.ports is None:
            raise RuntimeError("resource monitor requires a started runtime")
        self.runtime = runtime
        self.layout = layout
        self.expected_messages = expected_messages
        self.disk_budget_bytes = disk_budget_bytes
        self.harness_auxiliary_roots = dict(harness_auxiliary_roots)
        self.workspace = runtime.workspace
        self.io_calibration = _calibrate_io_accounting(layout, self.workspace)
        self.accounting_device = str(self.io_calibration["accounting_device"])
        self.memory_events_baseline = _parse_flat_stat(layout.parent / "memory.events")
        self.pids_events_baseline = _parse_flat_stat(layout.parent / "pids.events")
        self.filesystem_baseline = _filesystem_used(self.workspace)
        self.stop_requested = threading.Event()
        self.ready = threading.Event()
        self.started_monotonic = time.monotonic()
        self.samples: list[dict[str, Any]] = []
        self.error: BaseException | None = None
        self.redis = base.redis.Redis(
            host="127.0.0.1",
            port=runtime.ports.redis,
            db=0,
            socket_connect_timeout=2.0,
            socket_timeout=2.0,
        )
        self.thread = threading.Thread(
            target=self._run, name="smtp-throughput-resource-monitor", daemon=False
        )
        self.thread.start()
        if not self.ready.wait(10.0):
            self.stop_requested.set()
            self.thread.join(timeout=5.0)
            self.redis.close()
            raise TimeoutError("stress resource monitor did not become ready")
        if self.error is not None:
            self.thread.join(timeout=5.0)
            self.redis.close()
            raise RuntimeError(
                "stress resource monitor failed before measurement"
            ) from self.error

    def _sample(self, *, require_harness_auxiliaries: bool = True) -> dict[str, Any]:
        cgroup = self.layout.workload
        run_cgroup = self.layout.parent
        role_pids = {
            role: {
                int(value)
                for value in (path / "cgroup.procs").read_text(encoding="ascii").split()
            }
            for role, path in (
                ("application", self.layout.workload),
                ("services", self.layout.services),
                ("harness", self.layout.harness),
            )
        }
        pids = sorted(set().union(*role_pids.values()))
        if not pids:
            raise RuntimeError("run cgroup became empty during measurement")
        filesystem_used = _filesystem_used(self.workspace)
        filesystem_free = _filesystem_free(self.workspace)
        cpu = _parse_flat_stat(run_cgroup / "cpu.stat")
        candidate_cpu = _parse_flat_stat(cgroup / "cpu.stat")
        services_cpu = _parse_flat_stat(self.layout.services / "cpu.stat")
        memory_events = _parse_flat_stat(run_cgroup / "memory.events")
        pids_events = _parse_flat_stat(run_cgroup / "pids.events")
        io_by_device = _io_stats_by_device(
            run_cgroup / "io.stat", (self.layout.device, self.layout.backing_device)
        )
        io = io_by_device[self.accounting_device]
        role_cgroups = {
            "application": self.layout.workload,
            "services": self.layout.services,
            "harness": self.layout.harness,
        }
        io_by_role = {
            role: _io_stats_by_device(
                path / "io.stat", (self.layout.device, self.layout.backing_device)
            )
            for role, path in role_cgroups.items()
        }
        io_by_role["total"] = io_by_device
        cgroup_memory_by_role = {
            role: _cgroup_memory(path) for role, path in role_cgroups.items()
        }
        cgroup_memory_by_role["total"] = _cgroup_memory(run_cgroup)
        membership = _membership_audit(
            self.runtime,
            self.layout,
            role_pids,
            self.harness_auxiliary_roots,
            require_harness_auxiliaries=require_harness_auxiliaries,
        )
        reconciled_roles = membership.get("roles")
        if isinstance(reconciled_roles, dict):
            role_pids = {
                role: {int(pid) for pid in reconciled_roles[role]}
                for role in ("application", "services", "harness")
            }
            pids = sorted(set().union(*role_pids.values()))
        fd_counts = _fd_counts(pids)
        process_memory = _process_memory_status(pids)
        process_io: dict[int, dict[str, int]] = {}
        process_io_unavailable: dict[int, str] = {}
        for role, role_members in role_pids.items():
            for pid in sorted(role_members):
                try:
                    process_io.update(_process_io_status((pid,)))
                except RuntimeError as error:
                    if role == "harness" and isinstance(
                        error.__cause__, PermissionError
                    ):
                        process_io_unavailable[pid] = (
                            "permission_denied_at_security_boundary"
                        )
                        continue
                    error.add_note(f"process I/O capture role={role}")
                    raise
        process_io_required_pids = role_pids["application"] | role_pids["services"]
        stable_role_pids, process_evidence_vanished_pids = _stable_process_evidence(
            role_pids,
            required_identity_pids=set(membership.get("required_identity_pids", [])),
            fd_counts=fd_counts,
            process_memory=process_memory,
            process_io=process_io,
            process_io_required_pids=process_io_required_pids,
        )
        stable_pids = sorted(set().union(*stable_role_pids.values()))
        fd_counts = {pid: fd_counts[pid] for pid in stable_pids}
        process_memory = {pid: process_memory[pid] for pid in stable_pids}
        process_io = {pid: process_io[pid] for pid in stable_pids if pid in process_io}
        for pid in stable_pids:
            if pid not in process_io:
                process_io_unavailable.setdefault(
                    pid, "vanished_during_process_io_capture"
                )
        process_io_unavailable = {
            pid: process_io_unavailable[pid]
            for pid in stable_pids
            if pid in process_io_unavailable
        }
        process_memory_by_role = _role_process_memory(stable_role_pids, process_memory)
        process_role_by_pid = {
            str(pid): role
            for role, role_members in stable_role_pids.items()
            for pid in sorted(role_members)
        }
        temperature = _temperature_snapshot()
        queue_pending = int(self.redis.llen(base.QUEUE_PREFIX + "pending"))
        sample = {
            "elapsed_millis": round(
                (time.monotonic() - self.started_monotonic) * 1_000
            ),
            "process_count": len(stable_pids),
            "process_count_by_role": {
                role: len(values) for role, values in stable_role_pids.items()
            },
            "process_evidence_vanished_pids": process_evidence_vanished_pids,
            "task_count": int(
                (run_cgroup / "pids.current").read_text(encoding="ascii")
            ),
            "fd_count": sum(fd_counts.values()),
            "fd_count_by_pid": {
                str(pid): count for pid, count in sorted(fd_counts.items())
            },
            "process_memory_by_pid": {
                str(pid): value for pid, value in sorted(process_memory.items())
            },
            "process_memory_by_role": process_memory_by_role,
            "process_role_by_pid": process_role_by_pid,
            "process_io_by_pid": {
                str(pid): value for pid, value in sorted(process_io.items())
            },
            "process_io_unavailable_by_pid": {
                str(pid): reason
                for pid, reason in sorted(process_io_unavailable.items())
            },
            "memory_current_bytes": int(
                (run_cgroup / "memory.current").read_text(encoding="ascii")
            ),
            "memory_swap_current_bytes": int(
                (run_cgroup / "memory.swap.current").read_text(encoding="ascii")
            ),
            "memory_events": memory_events,
            "pids_events": pids_events,
            "cpu_usage_usec": cpu.get("usage_usec", 0),
            "cpu_user_usec": cpu.get("user_usec", 0),
            "cpu_system_usec": cpu.get("system_usec", 0),
            "candidate_cpu_usage_usec": candidate_cpu.get("usage_usec", 0),
            "services_cpu_usage_usec": services_cpu.get("usage_usec", 0),
            "io_read_bytes": io.get("rbytes", 0),
            "io_write_bytes": io.get("wbytes", 0),
            "io_read_operations": io.get("rios", 0),
            "io_write_operations": io.get("wios", 0),
            "io_accounting_device": self.accounting_device,
            "io_by_device": io_by_device,
            "io_by_role": io_by_role,
            "cgroup_memory_by_role": cgroup_memory_by_role,
            "temperature": temperature,
            "membership": membership,
            "queue_pending": queue_pending,
            "filesystem_used_bytes": filesystem_used,
            "filesystem_delta_bytes": filesystem_used - self.filesystem_baseline,
            "filesystem_free_bytes": filesystem_free,
        }
        if sample["task_count"] > self.layout.max_pids:
            raise RuntimeError("workload exceeded the cgroup PID ceiling")
        if any(count > self.layout.nofile_limit for count in fd_counts.values()):
            raise RuntimeError("a benchmark process exceeded the NOFILE ceiling")
        if sample["memory_current_bytes"] > self.layout.max_memory_bytes:
            raise RuntimeError("run exceeded the benchmark memory ceiling")
        if sample["memory_swap_current_bytes"] != 0:
            raise RuntimeError("run used swap despite the zero-swap policy")
        if temperature["within_limit"] is not True:
            raise RuntimeError("recorded host temperature exceeded the benchmark limit")
        if any(
            memory_events.get(name, 0) > self.memory_events_baseline.get(name, 0)
            for name in ("max", "oom", "oom_kill")
        ):
            raise RuntimeError("run hit the cgroup memory ceiling or OOM path")
        if pids_events.get("max", 0) > self.pids_events_baseline.get("max", 0):
            raise RuntimeError("run hit the cgroup PID ceiling")
        if sample["queue_pending"] > self.expected_messages:
            raise RuntimeError("outbound queue exceeded the requested message count")
        if sample["filesystem_delta_bytes"] > self.disk_budget_bytes:
            raise RuntimeError("workload exceeded the hard disk-space budget")
        if sample["filesystem_free_bytes"] < MINIMUM_FILESYSTEM_FREE_BYTES:
            raise RuntimeError("filesystem free space fell below the safety reserve")
        return sample

    def _run(self) -> None:
        try:
            self.samples.append(self._sample())
            self.ready.set()
            while not self.stop_requested.wait(RESOURCE_SAMPLE_SECONDS):
                if len(self.samples) >= MAXIMUM_RESOURCE_SAMPLES:
                    raise RuntimeError(
                        "stress resource samples exceeded their fixed bound"
                    )
                self.samples.append(self._sample())
        except BaseException as error:
            self.error = error
            self.ready.set()

    def raise_if_failed(self) -> None:
        if self.error is not None:
            raise RuntimeError("stress resource monitor failed") from self.error

    def stop(self) -> dict[str, Any]:
        self.stop_requested.set()
        self.thread.join(timeout=10.0)
        if self.thread.is_alive():
            self.redis.close()
            self.thread.join(timeout=5.0)
            if self.thread.is_alive():
                raise RuntimeError("stress resource monitor did not stop")
        try:
            self.raise_if_failed()
            self.samples.append(self._sample(require_harness_auxiliaries=False))
        finally:
            self.redis.close()
        if not self.samples:
            raise RuntimeError("stress resource monitor captured no samples")
        samples = self.samples
        first = samples[0]
        final = samples[-1]
        io_by_device_delta = _io_stat_delta(
            first["io_by_device"], final["io_by_device"]
        )
        io_by_role_delta = {
            role: _io_stat_delta(first["io_by_role"][role], final["io_by_role"][role])
            for role in ("application", "services", "harness", "total")
        }
        process_io = _process_io_lifecycle_delta(samples)
        process_io_by_role = process_io["by_role"]
        process_memory_by_role = {
            role: {
                "rss_first_bytes": first["process_memory_by_role"][role]["rss_bytes"],
                "rss_final_bytes": final["process_memory_by_role"][role]["rss_bytes"],
                "rss_peak_bytes": max(
                    sample["process_memory_by_role"][role]["rss_bytes"]
                    for sample in samples
                ),
                "hwm_final_bytes": final["process_memory_by_role"][role]["hwm_bytes"],
                "hwm_peak_bytes": max(
                    sample["process_memory_by_role"][role]["hwm_bytes"]
                    for sample in samples
                ),
            }
            for role in ("application", "services", "harness", "total")
        }
        cgroup_memory_by_role = {
            role: {
                f"{metric}_{suffix}_bytes": value
                for metric in ("current", "anon", "file")
                for suffix, value in (
                    ("first", first["cgroup_memory_by_role"][role][f"{metric}_bytes"]),
                    ("final", final["cgroup_memory_by_role"][role][f"{metric}_bytes"]),
                    (
                        "peak",
                        max(
                            sample["cgroup_memory_by_role"][role][f"{metric}_bytes"]
                            for sample in samples
                        ),
                    ),
                )
            }
            for role in ("application", "services", "harness", "total")
        }
        application_io = io_by_role_delta["application"][self.accounting_device]
        services_io = io_by_role_delta["services"][self.accounting_device]
        application_io_sources = _persistence_io_sources(
            application_io, process_io_by_role["application"]
        )
        services_io_sources = _persistence_io_sources(
            services_io, process_io_by_role["services"]
        )
        recorded_temperatures = [
            sample["temperature"]["maximum_millicelsius"]
            for sample in samples
            if sample["temperature"]["maximum_millicelsius"] is not None
        ]
        return {
            "sample_interval_seconds": RESOURCE_SAMPLE_SECONDS,
            "samples": len(samples),
            "memory_first_bytes": first["memory_current_bytes"],
            "memory_final_bytes": final["memory_current_bytes"],
            "memory_peak_bytes": max(
                sample["memory_current_bytes"] for sample in samples
            ),
            "process_memory_by_role": process_memory_by_role,
            "cgroup_memory_by_role": cgroup_memory_by_role,
            "fd_first": first["fd_count"],
            "fd_final": final["fd_count"],
            "fd_peak": max(sample["fd_count"] for sample in samples),
            "task_first": first["task_count"],
            "task_final": final["task_count"],
            "task_peak": max(sample["task_count"] for sample in samples),
            "queue_first": first["queue_pending"],
            "queue_final": final["queue_pending"],
            "queue_peak": max(sample["queue_pending"] for sample in samples),
            "filesystem_delta_peak_bytes": max(
                sample["filesystem_delta_bytes"] for sample in samples
            ),
            "filesystem_delta_final_bytes": final["filesystem_delta_bytes"],
            "filesystem_free_min_bytes": min(
                sample["filesystem_free_bytes"] for sample in samples
            ),
            "cpu_usage_seconds": round(
                (final["cpu_usage_usec"] - first["cpu_usage_usec"]) / 1_000_000,
                6,
            ),
            "cpu_user_seconds": round(
                (final["cpu_user_usec"] - first["cpu_user_usec"]) / 1_000_000,
                6,
            ),
            "cpu_system_seconds": round(
                (final["cpu_system_usec"] - first["cpu_system_usec"]) / 1_000_000,
                6,
            ),
            "candidate_cpu_usage_seconds": round(
                (final["candidate_cpu_usage_usec"] - first["candidate_cpu_usage_usec"])
                / 1_000_000,
                6,
            ),
            "services_cpu_usage_seconds": round(
                (final["services_cpu_usage_usec"] - first["services_cpu_usage_usec"])
                / 1_000_000,
                6,
            ),
            "io_read_bytes": final["io_read_bytes"] - first["io_read_bytes"],
            "io_write_bytes": final["io_write_bytes"] - first["io_write_bytes"],
            "io_read_operations": (
                final["io_read_operations"] - first["io_read_operations"]
            ),
            "io_write_operations": (
                final["io_write_operations"] - first["io_write_operations"]
            ),
            "io_accounting_device": self.accounting_device,
            "io_accounting_calibration": self.io_calibration,
            "io_by_device": io_by_device_delta,
            "io_by_role": io_by_role_delta,
            "process_io": process_io,
            "process_io_by_role": process_io_by_role,
            "application_io_write_bytes": application_io.get("wbytes", 0),
            "application_io_write_operations": application_io.get("wios", 0),
            "services_io_write_bytes": services_io.get("wbytes", 0),
            "services_io_write_operations": services_io.get("wios", 0),
            "application_process_io_write_bytes": process_io_by_role["application"][
                "write_bytes"
            ],
            "application_process_io_write_syscalls": process_io_by_role["application"][
                "syscw"
            ],
            "services_process_io_write_bytes": process_io_by_role["services"][
                "write_bytes"
            ],
            "services_process_io_write_syscalls": process_io_by_role["services"][
                "syscw"
            ],
            "application_persistence_io_sources": application_io_sources,
            "services_persistence_io_sources": services_io_sources,
            "application_persistence_io_observed": (
                application_io.get("wbytes", 0) > 0
                and application_io.get("wios", 0) > 0
            ),
            "services_persistence_io_observed": services_io_sources["observed"],
            "temperature": {
                "available": bool(recorded_temperatures),
                "samples_with_sensor_data": len(recorded_temperatures),
                "samples_total": len(samples),
                "maximum_millicelsius": (
                    max(recorded_temperatures) if recorded_temperatures else None
                ),
                "limit_millicelsius": MAXIMUM_RECORDED_TEMPERATURE_MILLICELSIUS,
                "within_limit": all(
                    sample["temperature"]["within_limit"] is True for sample in samples
                ),
                "unavailable_is_reported_not_fabricated": not recorded_temperatures,
            },
            "continuous_membership": all(
                sample["membership"]["continuous_membership"] is True
                for sample in samples
            ),
            "samples_all": samples,
        }


_REQUIRED_STRESS_TABLES = ("email_index", "outbound_mail_queue")
_OPTIONAL_STRESS_TABLES = (
    "lmyzmail_outbound_delivery_recipient",
    "lmyzmail_outbound_spool",
    "lmyzmail_outbound_delivery_attempt",
    "lmyzmail_outbound_dsn",
)
_REDIS_TRANSIENT_KEYS = frozenset(
    f"botmail:mail:queue:{suffix}"
    for suffix in (
        "pending",
        "processing",
        "processing_time",
        "retry",
        "archive",
        "status_updates",
    )
)
_REDIS_TRANSIENT_PREFIXES = (
    "botmail:mail:queue:task:",
    "lmyzmail:mail:queue:lease:",
    "lmyzmail:mail:queue:attempt:",
)
_AUTHENTICATION_DNS_CACHE_KEYS = frozenset(
    {
        "dns:ptr:127.0.0.1",
        "dns:spf:lmyz.net",
        "dns:dmarc:lmyz.net",
    }
)
_AUTHENTICATION_DNS_CACHE_MAX_TTL_MS = 30 * 60 * 1_000
_REDIS_CLEANUP_KEYS_PER_MESSAGE = 2  # domains audit + settlement receipt
_REDIS_CLEANUP_FIXED_KEY_ALLOWANCE = (
    len(_AUTHENTICATION_DNS_CACHE_KEYS)
    + 1  # dns:mx:lmyz.net
    + 1  # botmail:mail:queue:seq
    + 2  # sender/receiver mail:count keys
    + 1  # lmyzmail:mail:queue:settlement-index
)
_DATABASE_GROUP_COLUMNS = {
    "outbound_mail_queue": "status",
    "lmyzmail_outbound_delivery_recipient": "state",
    "lmyzmail_outbound_spool": "cleanup_state",
    "lmyzmail_outbound_delivery_attempt": "phase",
    "lmyzmail_outbound_dsn": "state",
}


def _database_snapshot(runtime: Any) -> dict[str, Any]:
    if runtime.ports is None:
        raise RuntimeError("PostgreSQL snapshot requires a started runtime")
    tables: dict[str, dict[str, Any]] = {}
    with base.psycopg.connect(
        host="127.0.0.1",
        port=runtime.ports.postgres,
        dbname="lmyzmail",
        user="lmyzmail_test",
        password="",
        connect_timeout=5,
        autocommit=True,
    ) as connection:
        connection.execute("SET statement_timeout = '30s'")
        for table in (*_REQUIRED_STRESS_TABLES, *_OPTIONAL_STRESS_TABLES):
            relation = connection.execute(
                "SELECT to_regclass(%s)", (f"public.{table}",)
            ).fetchone()
            present = relation is not None and relation[0] is not None
            count = 0
            groups: dict[str, int] = {}
            if present:
                if table == "email_index":
                    groups = {
                        f"{mailbox}/{folder}": int(rows)
                        for mailbox, folder, rows in connection.execute(
                            "SELECT mailbox_address,folder,count(*) FROM email_index "
                            "WHERE mailbox_address IN (%s,%s) "
                            "GROUP BY mailbox_address,folder",
                            (ENDPOINT_SENDER, ENDPOINT_RECEIVER),
                        ).fetchall()
                    }
                    count = sum(groups.values())
                else:
                    group_column = _DATABASE_GROUP_COLUMNS.get(table)
                    if group_column is None:
                        count = int(
                            connection.execute(
                                f"SELECT count(*) FROM {table}"
                            ).fetchone()[0]
                        )
                    else:
                        groups = {
                            str(name): int(rows)
                            for name, rows in connection.execute(
                                f"SELECT {group_column},count(*) FROM {table} "
                                f"GROUP BY {group_column}"
                            ).fetchall()
                        }
                        count = sum(groups.values())
            tables[table] = {
                "present": present,
                "rows": count,
                "groups": groups,
            }
        connection.execute("SELECT pg_stat_clear_snapshot()")
        mutation_row = connection.execute(
            "SELECT s.relid::bigint,s.n_tup_ins,s.n_tup_del,s.n_tup_upd,"
            "d.xact_rollback,d.stats_reset "
            "FROM pg_stat_user_tables s "
            "JOIN pg_stat_database d ON d.datname=current_database() "
            "WHERE s.relid='public.email_index'::regclass"
        ).fetchone()
        if mutation_row is None:
            raise RuntimeError("PostgreSQL email_index mutation counters were missing")
        stats_reset = mutation_row[5]
        email_index_mutations = {
            "profile": "postgresql-cumulative-email-index-mutations-v1",
            "relation_oid": int(mutation_row[0]),
            "n_tup_ins": int(mutation_row[1]),
            "n_tup_del": int(mutation_row[2]),
            "n_tup_upd": int(mutation_row[3]),
            "database_xact_rollback": int(mutation_row[4]),
            "database_stats_reset": (
                None
                if stats_reset is None
                else stats_reset.isoformat()
                if hasattr(stats_reset, "isoformat")
                else str(stats_reset)
            ),
        }
    completed_rows = (
        tables["outbound_mail_queue"]["groups"].get("SENT", 0)
        + tables["lmyzmail_outbound_delivery_recipient"]["groups"].get("DELIVERED", 0)
        + tables["lmyzmail_outbound_delivery_attempt"]["groups"].get("PROJECTED", 0)
    )
    transient_rows = (
        tables["email_index"]["rows"]
        + tables["outbound_mail_queue"]["rows"]
        - tables["outbound_mail_queue"]["groups"].get("SENT", 0)
        + tables["lmyzmail_outbound_delivery_recipient"]["rows"]
        - tables["lmyzmail_outbound_delivery_recipient"]["groups"].get("DELIVERED", 0)
        + tables["lmyzmail_outbound_spool"]["rows"]
        + tables["lmyzmail_outbound_delivery_attempt"]["rows"]
        - tables["lmyzmail_outbound_delivery_attempt"]["groups"].get("PROJECTED", 0)
        + tables["lmyzmail_outbound_dsn"]["rows"]
    )
    return {
        "tables": tables,
        "email_index_mutations": email_index_mutations,
        "completed_audit_rows": completed_rows,
        "transient_residual_rows": transient_rows,
    }


def _redis_snapshot(runtime: Any) -> dict[str, Any]:
    return v2._redis_snapshot(runtime)


def _maildir_snapshot(runtime: Any) -> dict[str, Any]:
    return v2._maildir_snapshot(runtime)


def _cleanup_state(runtime: Any, phase: str = "cleanup") -> dict[str, Any]:
    snapshot = {
        "phase": phase,
        "captured_at": _utc_now(),
        "database": _database_snapshot(runtime),
        "redis": _redis_snapshot(runtime),
        "maildir": _maildir_snapshot(runtime),
    }
    snapshot["state_sha256"] = hashlib.sha256(
        json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return snapshot


def _redis_cleanup_readiness(
    runtime: Any,
    before: dict[str, Any],
    expected_messages: int,
) -> dict[str, Any]:
    if runtime.ports is None:
        raise RuntimeError("Redis cleanup readiness requires a started runtime")
    client = base.redis.Redis(
        host="127.0.0.1",
        port=runtime.ports.redis,
        db=0,
        socket_timeout=5.0,
        socket_connect_timeout=5.0,
    )
    try:
        key_count = int(client.dbsize())
    finally:
        client.close()
    baseline_key_count = int(before["redis"]["dbsize_after"])
    # The Java endpoint retains a domains:<queue-id> audit key per message, and
    # the Rust endpoint additionally retains one settlement receipt. Final
    # readiness still performs complete value/type/TTL checks; this count-only
    # probe merely avoids those expensive reads before bounded state converges.
    message_key_allowance = expected_messages * _REDIS_CLEANUP_KEYS_PER_MESSAGE
    maximum_ready_key_count = (
        baseline_key_count
        + message_key_allowance
        + _REDIS_CLEANUP_FIXED_KEY_ALLOWANCE
    )
    return {
        "profile": "redis-cleanup-readiness-v2",
        "key_count": key_count,
        "baseline_key_count": baseline_key_count,
        "expected_message_key_allowance": message_key_allowance,
        "fixed_key_allowance": _REDIS_CLEANUP_FIXED_KEY_ALLOWANCE,
        "maximum_ready_key_count": maximum_ready_key_count,
        "ready": key_count <= maximum_ready_key_count,
        "full_values_read": False,
    }


def _automatic_cleanup_readiness(
    runtime: Any,
    before: dict[str, Any],
    expected_messages: int,
) -> dict[str, Any]:
    database = _database_snapshot(runtime)
    redis = _redis_cleanup_readiness(runtime, before, expected_messages)
    maildir = _maildir_snapshot(runtime)
    database_ready = database["transient_residual_rows"] == 0
    maildir_ready = all(tree["files"] == 0 for tree in maildir.values())
    return {
        "captured_at": _utc_now(),
        "database_transient_residual_rows": database["transient_residual_rows"],
        "redis": redis,
        "maildir_file_counts": {
            name: int(tree["files"]) for name, tree in maildir.items()
        },
        "database_ready": database_ready,
        "maildir_ready": maildir_ready,
        "ready": database_ready and redis["ready"] is True and maildir_ready,
    }


def _cleanup_state_semantic(state: dict[str, Any]) -> dict[str, Any]:
    return v2._state_semantic(state)


def _cleanup_semantic_sha256(state: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            _cleanup_state_semantic(state),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _redis_state_is_clean(state: dict[str, Any]) -> bool:
    redis = state["redis"]
    if not redis["scan_complete_and_stable"] or not redis["ttl_contract_passed"]:
        return False
    legacy_records: list[dict[str, Any]] = []
    authentication_dns_records = 0
    for record in redis["keys"]:
        key = record["key"]
        if key in _AUTHENTICATION_DNS_CACHE_KEYS:
            pttl_ms = int(record["pttl_ms"])
            if (
                record["type"] != "string"
                or int(record["cardinality"]) != 1
                or not 0 <= pttl_ms <= _AUTHENTICATION_DNS_CACHE_MAX_TTL_MS
                or not 1 <= int(record["value_bytes"]) <= 4_096
            ):
                return False
            authentication_dns_records += 1
            continue
        legacy_records.append(record)
        if key in _REDIS_TRANSIENT_KEYS or key.startswith(_REDIS_TRANSIENT_PREFIXES):
            if int(record["cardinality"]) != 0:
                return False
    legacy_state = {
        **state,
        "redis": {
            **redis,
            "keys": legacy_records,
            "key_count": len(legacy_records),
            "dbsize_before": int(redis["dbsize_before"]) - authentication_dns_records,
            "dbsize_after": int(redis["dbsize_after"]) - authentication_dns_records,
        },
    }
    return v2._redis_stress_contract(legacy_state)


def _state_is_clean(state: dict[str, Any]) -> bool:
    tables = state["database"]["tables"]
    required_present = all(tables[name]["present"] for name in _REQUIRED_STRESS_TABLES)
    database_clean = state["database"]["transient_residual_rows"] == 0
    maildir_clean = all(tree["files"] == 0 for tree in state["maildir"].values())
    return (
        required_present
        and database_clean
        and maildir_clean
        and _redis_state_is_clean(state)
    )


def _automatic_cleanup_delta(
    before: dict[str, Any],
    after: dict[str, Any],
    expected_messages: int,
    *,
    expected_email_index_rows: int = 0,
    expected_email_index_groups: dict[str, int] | None = None,
) -> dict[str, Any]:
    before_tables = before["database"]["tables"]
    after_tables = after["database"]["tables"]
    row_deltas = {
        name: after_tables[name]["rows"] - before_tables[name]["rows"]
        for name in (*_REQUIRED_STRESS_TABLES, *_OPTIONAL_STRESS_TABLES)
    }
    expected_deltas = {
        "email_index": expected_email_index_rows,
        "outbound_mail_queue": expected_messages,
        "lmyzmail_outbound_spool": 0,
        "lmyzmail_outbound_dsn": 0,
    }
    for name in (
        "lmyzmail_outbound_delivery_recipient",
        "lmyzmail_outbound_delivery_attempt",
    ):
        if before_tables[name]["present"] and after_tables[name]["present"]:
            expected_deltas[name] = expected_messages
        elif before_tables[name]["present"] != after_tables[name]["present"]:
            expected_deltas[name] = -1
    mismatches = {
        name: {"expected": expected, "actual": row_deltas[name]}
        for name, expected in expected_deltas.items()
        if row_deltas[name] != expected
    }
    before_email_groups = before_tables["email_index"]["groups"]
    after_email_groups = after_tables["email_index"]["groups"]
    email_group_deltas = {
        name: int(after_email_groups.get(name, 0))
        - int(before_email_groups.get(name, 0))
        for name in sorted(set(before_email_groups) | set(after_email_groups))
        if int(after_email_groups.get(name, 0)) - int(before_email_groups.get(name, 0))
        != 0
    }
    expected_email_groups = expected_email_index_groups or {}
    email_group_mismatches = {
        name: {
            "expected": expected_email_groups.get(name, 0),
            "actual": email_group_deltas.get(name, 0),
        }
        for name in sorted(set(expected_email_groups) | set(email_group_deltas))
        if expected_email_groups.get(name, 0) != email_group_deltas.get(name, 0)
    }
    before_mutations = before["database"].get("email_index_mutations")
    after_mutations = after["database"].get("email_index_mutations")
    mutation_evidence: dict[str, Any]
    if not isinstance(before_mutations, dict) or not isinstance(after_mutations, dict):
        mutation_evidence = {
            "available": False,
            "passed": False,
            "failure": "PostgreSQL email_index mutation counters were unavailable",
        }
    else:
        counter_names = (
            "n_tup_ins",
            "n_tup_del",
            "n_tup_upd",
            "database_xact_rollback",
        )
        counter_deltas = {
            name: int(after_mutations[name]) - int(before_mutations[name])
            for name in counter_names
        }
        lifecycle_complete = expected_email_index_rows == 0
        expected_counter_deltas = {
            "n_tup_ins": expected_messages * 2,
            "n_tup_del": expected_messages * 2 if lifecycle_complete else 0,
            "database_xact_rollback": 0,
        }
        counter_mismatches = {
            name: {"expected": expected, "actual": counter_deltas[name]}
            for name, expected in expected_counter_deltas.items()
            if counter_deltas[name] != expected
        }
        identity_passed = bool(
            before_mutations.get("profile")
            == "postgresql-cumulative-email-index-mutations-v1"
            and after_mutations.get("profile") == before_mutations.get("profile")
            and after_mutations.get("relation_oid")
            == before_mutations.get("relation_oid")
            and after_mutations.get("database_stats_reset")
            == before_mutations.get("database_stats_reset")
        )
        mutation_evidence = {
            "available": True,
            "lifecycle_complete": lifecycle_complete,
            "before": before_mutations,
            "after": after_mutations,
            "counter_deltas": counter_deltas,
            "expected_counter_deltas": expected_counter_deltas,
            "counter_mismatches": counter_mismatches,
            "identity_passed": identity_passed,
            "rollback_free": counter_deltas["database_xact_rollback"] == 0,
            "passed": identity_passed and not counter_mismatches,
        }
    return {
        "expected_messages": expected_messages,
        "row_deltas": row_deltas,
        "expected_row_deltas": expected_deltas,
        "mismatches": mismatches,
        "email_index_group_deltas": email_group_deltas,
        "expected_email_index_group_deltas": expected_email_groups,
        "email_index_group_mismatches": email_group_mismatches,
        "email_index_mutation_evidence": mutation_evidence,
        "persistence_audit_observed": (
            row_deltas["outbound_mail_queue"] == expected_messages
            and mutation_evidence["passed"] is True
        ),
        "passed": (
            not mismatches
            and not email_group_mismatches
            and row_deltas["outbound_mail_queue"] == expected_messages
            and mutation_evidence["passed"] is True
        ),
    }


def _queue_counter_evidence(
    log: dict[str, Any], expected_messages: int
) -> tuple[dict[str, int] | None, bool]:
    records = log.get("queue_counter_records", [])
    counter_match_count = int(log.get("queue_counter_match_count", 0))
    counters = records[0] if counter_match_count == 1 and len(records) == 1 else None
    passed = bool(
        isinstance(counters, dict)
        and counters.get("queued") == expected_messages
        and counters.get("success") == expected_messages
        and all(
            counters.get(name) == 0
            for name in ("failed", "exceptions", "oom", "rate_limited")
        )
    )
    return counters, passed


def _received_counter_evidence(
    log: dict[str, Any], expected_messages: int
) -> tuple[int | None, bool]:
    records = log.get("received_counter_records", [])
    match_count = int(log.get("received_counter_match_count", 0))
    received = records[0] if match_count == 1 and len(records) == 1 else None
    return received, received == expected_messages


def _postgres_persistence_barrier(runtime: Any) -> dict[str, Any]:
    if runtime.ports is None:
        raise RuntimeError("PostgreSQL persistence barrier requires a started runtime")
    started = time.monotonic()
    with base.psycopg.connect(
        host="127.0.0.1",
        port=runtime.ports.postgres,
        dbname="lmyzmail",
        user="lmyzmail_test",
        password="",
        connect_timeout=5,
        autocommit=True,
    ) as connection:
        connection.execute("SET statement_timeout = '30s'")
        settings = {
            name: str(connection.execute(f"SHOW {name}").fetchone()[0]).lower()
            for name in ("fsync", "synchronous_commit", "full_page_writes")
        }
        arm_end = connection.execute(
            "SELECT pg_current_wal_insert_lsn()::text"
        ).fetchone()
        if arm_end is None or not arm_end[0]:
            raise RuntimeError("PostgreSQL persistence barrier returned no arm-end LSN")
        deadline = time.monotonic() + 30.0
        flush = None
        while time.monotonic() < deadline:
            flush = connection.execute(
                "SELECT pg_current_wal_flush_lsn()::text, "
                "pg_wal_lsn_diff(pg_current_wal_flush_lsn(), %s) >= 0",
                (str(arm_end[0]),),
            ).fetchone()
            if flush is not None and flush[1] is True:
                break
            time.sleep(0.01)
    settings_passed = settings == {
        "fsync": "on",
        "synchronous_commit": "on",
        "full_page_writes": "on",
    }
    if not settings_passed or flush is None or flush[1] is not True:
        raise RuntimeError("PostgreSQL WAL flush did not reach the accepted arm end")
    return {
        "settings": settings,
        "settings_passed": settings_passed,
        "arm_end_wal_insert_lsn": str(arm_end[0]),
        "wal_flush_lsn": str(flush[0]),
        "flush_reached_arm_end": True,
        "forced_checkpoint": False,
        "observer_elapsed_millis": round((time.monotonic() - started) * 1_000, 3),
        "passed": True,
    }


def _redis_persistence_barrier(runtime: Any) -> dict[str, Any]:
    if runtime.ports is None:
        raise RuntimeError("Redis persistence barrier requires a started runtime")
    started = time.monotonic()
    client = base.redis.Redis(
        host="127.0.0.1",
        port=runtime.ports.redis,
        db=0,
        decode_responses=True,
        socket_connect_timeout=5,
        socket_timeout=30,
    )
    try:
        persistence = client.info("persistence")
        waitaof_supported = False
        waitaof_local = None
        if int(persistence.get("aof_enabled", 0)) == 1:
            try:
                waitaof = client.execute_command("WAITAOF", 1, 0, 30_000)
                if isinstance(waitaof, (list, tuple)) and len(waitaof) == 2:
                    waitaof_supported = True
                    waitaof_local = int(waitaof[0])
            except base.redis.ResponseError as error:
                if "unknown" not in str(error).lower():
                    raise
            persistence = client.info("persistence")
    finally:
        client.close()
    aof_enabled = int(persistence.get("aof_enabled", 0)) == 1
    pending_fsync = int(persistence.get("aof_pending_bio_fsync", 0))
    pending_rewrite = int(persistence.get("aof_rewrite_in_progress", 0))
    pending_rdb = int(persistence.get("rdb_bgsave_in_progress", 0))
    passed = bool(
        pending_fsync == 0
        and pending_rewrite == 0
        and pending_rdb == 0
        and (not waitaof_supported or waitaof_local is not None and waitaof_local >= 1)
    )
    if not passed:
        raise RuntimeError("Redis configured persistence still had pending disk work")
    return {
        "aof_enabled": aof_enabled,
        "aof_pending_bio_fsync": pending_fsync,
        "aof_rewrite_in_progress": pending_rewrite,
        "rdb_bgsave_in_progress": pending_rdb,
        "rdb_last_bgsave_status": persistence.get("rdb_last_bgsave_status"),
        "waitaof_supported": waitaof_supported,
        "waitaof_local_acknowledgements": waitaof_local,
        "forced_save": False,
        "observer_elapsed_millis": round((time.monotonic() - started) * 1_000, 3),
        "passed": True,
    }


def _wait_for_delivery_database_visibility(
    runtime: Any,
    *,
    before: dict[str, Any],
    expected_messages: int,
    timeout_seconds: float = MAXIMUM_POST_FINAL_PERSISTENCE_LAG_SECONDS,
    capture_boundary: str = "persistence_barrier",
) -> dict[str, Any]:
    if capture_boundary not in {"persistence_barrier", "immediate_after_final_250"}:
        raise ValueError("database visibility capture boundary is invalid")
    started = time.monotonic()
    deadline = started + timeout_seconds
    database_visibility_polls = 0
    while True:
        database_visibility_polls += 1
        database = _database_snapshot(runtime)
        database_delta = _automatic_cleanup_delta(
            before,
            {"database": database},
            expected_messages,
            expected_email_index_rows=expected_messages * 2,
            expected_email_index_groups={
                f"{ENDPOINT_RECEIVER}/inbox": expected_messages,
                f"{ENDPOINT_SENDER}/sent": expected_messages,
            },
        )
        if database_delta.get("passed") is True:
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(PERSISTENCE_VISIBILITY_POLL_SECONDS, remaining))
    return {
        "database": database,
        "database_delta": database_delta,
        "expected_messages": expected_messages,
        "polls": database_visibility_polls,
        "wait_millis": round((time.monotonic() - started) * 1_000, 3),
        "timeout_seconds": timeout_seconds,
        "capture_boundary": capture_boundary,
        "passed": database_delta.get("passed") is True,
    }


def _establish_persistence_barrier(
    runtime: Any,
    *,
    before: dict[str, Any],
    capture: dict[str, Any],
    maildir: dict[str, Any],
    cleanup: dict[str, Any],
    log: dict[str, Any],
    expected_messages: int,
    timeout_seconds: float = MAXIMUM_POST_FINAL_PERSISTENCE_LAG_SECONDS,
    database_visibility: dict[str, Any] | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    if database_visibility is None:
        database_visibility = _wait_for_delivery_database_visibility(
            runtime,
            before=before,
            expected_messages=expected_messages,
            timeout_seconds=timeout_seconds,
        )
    if database_visibility.get("expected_messages") != expected_messages:
        raise RuntimeError("database visibility evidence message count changed")
    if database_visibility.get("capture_boundary") not in {
        "persistence_barrier",
        "immediate_after_final_250",
    }:
        raise RuntimeError("database visibility evidence boundary changed")
    database = database_visibility.get("database")
    if not isinstance(database, dict):
        raise RuntimeError("database visibility evidence omitted its snapshot")
    database_delta = _automatic_cleanup_delta(
        before,
        {"database": database},
        expected_messages,
        expected_email_index_rows=expected_messages * 2,
        expected_email_index_groups={
            f"{ENDPOINT_RECEIVER}/inbox": expected_messages,
            f"{ENDPOINT_SENDER}/sent": expected_messages,
        },
    )
    if database_visibility.get("database_delta") != database_delta:
        raise RuntimeError("database visibility evidence delta changed")
    cleanup_delta = cleanup.get("database_delta")
    if not isinstance(cleanup_delta, dict):
        raise RuntimeError("automatic cleanup omitted its PostgreSQL delta")
    mutation_evidence = cleanup_delta.get("email_index_mutation_evidence")
    if not isinstance(mutation_evidence, dict):
        raise RuntimeError("automatic cleanup omitted email_index mutation evidence")
    received_counter, received_counter_passed = _received_counter_evidence(
        log, expected_messages
    )
    smtp_success = int(capture.get("smtp_final_replies", {}).get("success", -1))
    receiver_scope = f"{ENDPOINT_RECEIVER}/inbox"
    sender_scope = f"{ENDPOINT_SENDER}/sent"
    receiver_publications = int(
        maildir.get("publication_counts_by_mailbox_folder", {}).get(receiver_scope, -1)
    )
    sender_publications = int(
        maildir.get("publication_counts_by_mailbox_folder", {}).get(sender_scope, -1)
    )
    exact_delivery_counts = {
        "requested": expected_messages,
        "observer_verified": int(capture.get("verified", -1)),
        "smtp_successful_final_replies": smtp_success,
        "endpoint_receiver_inbox_query": (
            -1 if received_counter is None else received_counter
        ),
        "maildir_receiver_inbox_publications": receiver_publications,
        "maildir_sender_sent_publications": sender_publications,
        "postgres_outbound_audit_rows": int(
            database_delta.get("row_deltas", {}).get("outbound_mail_queue", -1)
        ),
    }
    direct_receiver_rows = int(
        database_delta.get("email_index_group_deltas", {}).get(receiver_scope, -1)
    )
    direct_sender_rows = int(
        database_delta.get("email_index_group_deltas", {}).get(sender_scope, -1)
    )
    direct_total_rows = int(database_delta.get("row_deltas", {}).get("email_index", -1))
    transient_snapshot_exact = bool(
        database_delta.get("passed") is True
        and direct_receiver_rows == expected_messages
        and direct_sender_rows == expected_messages
        and direct_total_rows == expected_messages * 2
    )
    mutation_deltas = mutation_evidence.get("counter_deltas", {})
    lifecycle_exact = bool(
        cleanup_delta.get("passed") is True
        and mutation_evidence.get("passed") is True
        and mutation_evidence.get("lifecycle_complete") is True
        and mutation_deltas.get("n_tup_ins") == expected_messages * 2
        and mutation_deltas.get("n_tup_del") == expected_messages * 2
        and mutation_deltas.get("database_xact_rollback") == 0
    )
    email_index_evidence_mode = (
        "transient_exact_snapshot"
        if transient_snapshot_exact
        else "committed_lifecycle_counters"
        if lifecycle_exact
        else "unqualified"
    )
    exact_counts = {
        **exact_delivery_counts,
        "postgres_receiver_inbox_rows_at_transient_snapshot": direct_receiver_rows,
        "postgres_sender_sent_rows_at_transient_snapshot": direct_sender_rows,
        "postgres_total_index_rows_at_transient_snapshot": direct_total_rows,
        "postgres_total_index_inserts": int(mutation_deltas.get("n_tup_ins", -1)),
        "postgres_total_index_deletes": int(mutation_deltas.get("n_tup_del", -1)),
        "postgres_database_transaction_rollbacks": int(
            mutation_deltas.get("database_xact_rollback", -1)
        ),
    }
    exact_count_equality = (
        len(set(exact_delivery_counts.values())) == 1
        and received_counter_passed
        and (transient_snapshot_exact or lifecycle_exact)
    )
    preconditions = {
        "smtp_proxy_qualified": capture.get("qualification") is True,
        "smtp_expected_count_matched": (
            int(capture.get("expected", -1)) == expected_messages
        ),
        "exact_count_equality": exact_count_equality,
        "postgres_outbound_audit_exact": exact_delivery_counts[
            "postgres_outbound_audit_rows"
        ]
        == expected_messages,
        "email_index_evidence_qualified": email_index_evidence_mode != "unqualified",
        "endpoint_received_counter_exact": received_counter_passed,
        "automatic_cleanup_exact": cleanup_delta.get("passed") is True,
        "maildir_publication_passed": maildir.get("passed") is True,
        "maildir_receiver_and_sender_exact": (
            receiver_publications == expected_messages
            and sender_publications == expected_messages
            and maildir.get("publication_events") == expected_messages * 2
        ),
        "maildir_observer_made_no_writes": (
            maildir.get("observer_write_syscalls") == 0
            and maildir.get("observer_writes_prohibited") is True
        ),
    }
    preconditions_passed = all(preconditions.values())
    if not preconditions_passed:
        raise RuntimeError(
            "persistence barrier preconditions did not prove exact request, SMTP, "
            "Maildir, and PostgreSQL equality: "
            f"counts={exact_counts}, preconditions={preconditions}, "
            f"database_mismatches={database_delta.get('mismatches')}, "
            f"mutation_mismatches={mutation_evidence.get('counter_mismatches')}, "
            "proxy="
            f"{{'missing': {capture.get('missing')}, "
            f"'duplicates': {capture.get('duplicates')}, "
            f"'observer_failure_count': {capture.get('observer_failure_count')}, "
            f"'observer_failures': {capture.get('observer_failures')}, "
            f"'final_250_boundary': {capture.get('final_250_boundary')}, "
            f"'persistence_gate': {capture.get('persistence_gate')}, "
            f"'retry_responses': {capture.get('retry_responses')}, "
            f"'smtp_final_replies': {capture.get('smtp_final_replies')}}}"
        )

    postgres = _postgres_persistence_barrier(runtime)
    redis = _redis_persistence_barrier(runtime)
    if (
        maildir.get("passed") is not True
        or maildir.get("publication_events") != expected_messages * 2
        or receiver_publications != expected_messages
        or sender_publications != expected_messages
        or maildir.get("observer_write_syscalls") != 0
    ):
        raise RuntimeError(
            "Maildir passive publication evidence did not match acceptance"
        )
    passed = bool(
        postgres["passed"]
        and redis["passed"]
        and maildir["passed"]
        and exact_count_equality
        and cleanup_delta["passed"]
    )
    if not passed:
        raise RuntimeError("timed persistence visibility barrier was incomplete")
    return {
        "profile": "lmyzmail-smtp-post-final-persistence-audit-v3",
        "audit_requires": [
            "final_250_forwarded",
            "exact_smtp_endpoint_maildir_and_postgresql_lifecycle_counts",
            "redis_configured_persistence_has_no_pending_fsync",
            "postgresql_synchronous_commit_wal_flush_reaches_arm_end",
            "maildir_atomic_rename_publication_observed_without_writes",
        ],
        "exact_counts": exact_counts,
        "exact_count_equality": exact_count_equality,
        "email_index_evidence_mode": email_index_evidence_mode,
        "transient_snapshot_exact": transient_snapshot_exact,
        "postgresql_email_index_mutations": mutation_evidence,
        "postgresql_audit_delta": database_delta,
        "postgresql_cleanup_delta": cleanup_delta,
        "database_visibility_polls": database_visibility.get("polls"),
        "database_visibility_wait_millis": database_visibility.get("wait_millis"),
        "database_visibility_timeout_seconds": database_visibility.get(
            "timeout_seconds"
        ),
        "database_visibility_capture_boundary": database_visibility.get(
            "capture_boundary"
        ),
        "postgresql": postgres,
        "redis": redis,
        "maildir": maildir,
        "observer_elapsed_millis": round((time.monotonic() - started) * 1_000, 3),
        "automatic_cleanup_excluded_from_timing": True,
        "log_parsing_excluded_from_timing": True,
        "observer_shutdown_excluded_from_timing": True,
        "excluded_from_throughput_denominator": True,
        "passed": True,
    }


def _wait_for_automatic_cleanup(
    runtime: Any,
    *,
    before: dict[str, Any],
    expected_messages: int,
    timeout_seconds: float = CLEANUP_TIMEOUT_SECONDS,
    abort_check: Callable[[], None] | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    deadline = started + timeout_seconds
    stable = 0
    samples: deque[dict[str, Any]] = deque(maxlen=32)
    readiness_samples: deque[dict[str, Any]] = deque(maxlen=32)
    last: dict[str, Any] | None = None
    last_semantic_sha256: str | None = None
    while time.monotonic() < deadline:
        if abort_check is not None:
            abort_check()
        try:
            readiness = _automatic_cleanup_readiness(
                runtime,
                before,
                expected_messages,
            )
            readiness_samples.append(
                {
                    "elapsed_millis": round((time.monotonic() - started) * 1_000),
                    "probe": readiness,
                }
            )
            if readiness["ready"] is not True:
                stable = 0
                time.sleep(0.25)
                continue
            last = _cleanup_state(runtime, "automatic_cleanup")
        except (base.psycopg.Error, base.redis.RedisError, OSError):
            time.sleep(0.25)
            continue
        semantic_sha256 = _cleanup_semantic_sha256(last)
        samples.append(
            {
                "elapsed_millis": round((time.monotonic() - started) * 1_000),
                "semantic_sha256": semantic_sha256,
                "state": last,
            }
        )
        cleanup_delta = _automatic_cleanup_delta(before, last, expected_messages)
        mutation_evidence = cleanup_delta["email_index_mutation_evidence"]
        rollback_delta = mutation_evidence.get("counter_deltas", {}).get(
            "database_xact_rollback"
        )
        if mutation_evidence.get("available") is True and rollback_delta is not None:
            if rollback_delta > 0:
                raise RuntimeError(
                    "stress automatic cleanup cannot satisfy the rollback-free gate: "
                    f"database_xact_rollback delta={rollback_delta}"
                )
        if _state_is_clean(last) and cleanup_delta["passed"]:
            stable = stable + 1 if semantic_sha256 == last_semantic_sha256 else 1
            if stable >= STATE_STABLE_POLLS:
                return {
                    "duration_seconds": round(time.monotonic() - started, 6),
                    "stable_polls": stable,
                    "semantic_sha256": semantic_sha256,
                    "database_delta": cleanup_delta,
                    "final": last,
                    "samples": list(samples),
                    "readiness_samples": list(readiness_samples),
                    "full_value_snapshots": len(samples),
                }
        else:
            stable = 0
        last_semantic_sha256 = semantic_sha256
        time.sleep(0.25)
    raise TimeoutError(f"stress automatic cleanup did not finish: last={last}")


def _expected_stress_concurrency(email_size_kib: int) -> int:
    if email_size_kib >= 10_000:
        return 80
    if email_size_kib >= 5_000:
        return 120
    if email_size_kib >= 1_000:
        return 200
    if email_size_kib >= 100:
        return 400
    if email_size_kib >= 10:
        return 1_000
    return 1_500


@dataclass(slots=True)
class PendingStartRound:
    stream: blackbox_protocols.BoundedSocket
    requested_at: str
    started_monotonic: float
    invocation: dict[str, Any]
    expected_mode: str
    expected_count: int
    expected_size_kib: int
    completed: bool = False

    def close(self) -> None:
        if self.completed:
            return
        self.completed = True
        with contextlib.suppress(OSError):
            self.stream.sock.shutdown(socket.SHUT_RDWR)
        self.stream.sock.close()


def _start_round_response_record(
    response: Any,
    *,
    requested_at: str,
    started_monotonic: float,
    invocation: dict[str, Any],
    expected_mode: str,
    expected_count: int,
    expected_size_kib: int,
) -> dict[str, Any]:
    endpoint_returned_monotonic_ns = time.monotonic_ns()
    try:
        body = json.loads(response.body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("stress endpoint returned invalid JSON") from error
    record = {
        "requested_at": requested_at,
        "completed_at": _utc_now(),
        "duration_ms": round((time.monotonic() - started_monotonic) * 1_000, 3),
        "status_code": response.status_code,
        "body_sha256": hashlib.sha256(response.body).hexdigest(),
        "body": body,
        "invocation": invocation,
        "endpoint_returned_monotonic_ns": endpoint_returned_monotonic_ns,
        "endpoint_response_is_spawn_ack_not_completion_boundary": True,
    }
    if response.status_code != 200:
        raise RuntimeError(f"stress start failed: {record}")
    expected = {
        "mode": expected_mode,
        "emailCount": expected_count,
        "emailSizeKB": expected_size_kib,
        "maxConcurrency": _expected_stress_concurrency(expected_size_kib),
        "inMemoryMode": expected_size_kib <= 20,
    }
    if not isinstance(body, dict) or any(
        body.get(key) != value for key, value in expected.items()
    ):
        raise RuntimeError(f"stress start response contract changed: {record}")
    if not isinstance(body.get("round"), int) or body["round"] <= 0:
        raise RuntimeError("stress start response omitted its positive round number")
    return record


def _start_round(
    runtime: Any,
    *,
    expected_mode: str,
    expected_count: int,
    expected_size_kib: int,
    invocation_event: Callable[[dict[str, Any]], None] | None = None,
    prepared_invocation: dict[str, Any] | None = None,
    defer_response: bool = False,
) -> dict[str, Any] | PendingStartRound:
    if runtime.ports is None:
        raise RuntimeError("stress start requires a started runtime")
    requested_at = _utc_now()
    started = time.monotonic()
    invocation = prepared_invocation or _start_invocation_record(requested_at)
    if invocation.get("at") != requested_at and prepared_invocation is None:
        raise RuntimeError("stress invocation identity was not preserved")
    requested_at = str(invocation["at"])
    if invocation_event is not None:
        if prepared_invocation is not None:
            raise RuntimeError(
                "prepared stress invocation was journaled more than once"
            )
        invocation_event(invocation)
    if defer_response:
        stream = blackbox_protocols.connect_bounded(
            "127.0.0.1",
            runtime.ports.http,
            timeout=MEASUREMENT_TIMEOUT_SECONDS,
            max_received=8 * 1024 * 1024,
        )
        try:
            stream.sendall(
                blackbox_protocols.build_http_request(
                    "POST",
                    "/api/stress/start",
                    host=f"127.0.0.1:{runtime.ports.http}",
                    headers=(("X-API-Key", base.API_KEY),),
                )
            )
        except BaseException:
            stream.sock.close()
            raise
        return PendingStartRound(
            stream=stream,
            requested_at=requested_at,
            started_monotonic=started,
            invocation=invocation,
            expected_mode=expected_mode,
            expected_count=expected_count,
            expected_size_kib=expected_size_kib,
        )
    response = base.http_exchange(
        "127.0.0.1",
        runtime.ports.http,
        "POST",
        "/api/stress/start",
        headers=(("X-API-Key", base.API_KEY),),
        timeout=MEASUREMENT_TIMEOUT_SECONDS,
    )
    return _start_round_response_record(
        response,
        requested_at=requested_at,
        started_monotonic=started,
        invocation=invocation,
        expected_mode=expected_mode,
        expected_count=expected_count,
        expected_size_kib=expected_size_kib,
    )


def _finish_start_round(
    pending: dict[str, Any] | PendingStartRound,
) -> dict[str, Any]:
    if isinstance(pending, dict):
        return pending
    if pending.completed:
        raise RuntimeError("stress endpoint response was already consumed or cancelled")
    try:
        response = blackbox_protocols.read_http_response(
            pending.stream,
            request_method="POST",
            max_header_bytes=64 * 1024,
            max_body_bytes=8 * 1024 * 1024,
        )
        return _start_round_response_record(
            response,
            requested_at=pending.requested_at,
            started_monotonic=pending.started_monotonic,
            invocation=pending.invocation,
            expected_mode=pending.expected_mode,
            expected_count=pending.expected_count,
            expected_size_kib=pending.expected_size_kib,
        )
    finally:
        pending.close()


def _start_invocation_record(requested_at: str | None = None) -> dict[str, Any]:
    return {
        "endpoint": "/api/stress/start",
        "method": "POST",
        "attempt": 1,
        "maximum_attempts": 1,
        "automatic_retries": 0,
        "uncertain_outcome_policy": "fail_closed_and_restart_as_a_new_benchmark_run",
        "at": requested_at or _utc_now(),
    }


def _log_cursor(runtime: Any) -> LogCursor:
    if runtime._application is None:
        raise RuntimeError("application log cursor requires a started runtime")
    path = runtime._application.log_path
    try:
        metadata = path.stat()
    except FileNotFoundError:
        return LogCursor(path=path, offset=0, device=None, inode=None)
    return LogCursor(
        path=path,
        offset=metadata.st_size,
        device=metadata.st_dev,
        inode=metadata.st_ino,
    )


def _log_evidence(
    cursor: LogCursor,
    *,
    read_chunk_bytes: int = 64 * 1024,
    maximum_line_bytes: int = 64 * 1024,
) -> dict[str, Any]:
    if read_chunk_bytes <= 0 or maximum_line_bytes <= 0:
        raise ValueError("application log parser bounds must be positive")
    path, offset = cursor.path, cursor.offset
    if not path.exists():
        return {
            "present": False,
            "path_name": path.name,
            "offset": offset,
            "end_offset": offset,
            "bytes": 0,
            "sha256": hashlib.sha256(b"").hexdigest(),
            "truncated": True,
            "parse_complete": False,
            "stable_extent": False,
            "rotation_detected": cursor.inode is not None,
            "line_count": 0,
            "relevant_line_count": 0,
            "line_overflow_count": 0,
            "queue_counter_records": [],
            "queue_counter_match_count": 0,
            "received_counter_records": [],
            "received_counter_match_count": 0,
            "coordinator_observer_record_count": 0,
            "coordinator_observer_parse_failure_count": 0,
            "coordinator_observer_records": [],
            "coordinator_observer_last": None,
            "failure_line_count": 0,
            "missing_dkim_configuration_line_count": 0,
            "async_drop_line_count": 0,
            "result_lines": [],
            "failure_lines": [],
            "missing_dkim_configuration_lines": [],
            "async_drop_lines": [],
        }
    initial = path.stat()
    rotation_detected = (
        (cursor.device is not None and initial.st_dev != cursor.device)
        or (cursor.inode is not None and initial.st_ino != cursor.inode)
        or initial.st_size < offset
    )
    digest = hashlib.sha256()
    bytes_read = 0
    line_count = 0
    relevant_line_count = 0
    line_overflow_count = 0
    queue_counter_match_count = 0
    queue_counter_records: list[dict[str, int]] = []
    received_counter_match_count = 0
    received_counter_records: list[int] = []
    coordinator_observer_record_count = 0
    coordinator_observer_parse_failure_count = 0
    coordinator_observer_last_sequence = 0
    coordinator_observer_records: deque[dict[str, Any]] = deque(maxlen=64)
    result_lines: deque[str] = deque(maxlen=64)
    failure_lines: deque[str] = deque(maxlen=64)
    failure_line_count = 0
    missing_dkim_configuration_lines: deque[str] = deque(maxlen=64)
    missing_dkim_configuration_line_count = 0
    async_drop_lines: deque[str] = deque(maxlen=64)
    async_drop_line_count = 0
    pending = bytearray()
    dropping_oversized_line = False

    def consume_line(raw_line: bytes) -> None:
        nonlocal line_count, relevant_line_count, queue_counter_match_count
        nonlocal received_counter_match_count
        nonlocal failure_line_count, missing_dkim_configuration_line_count
        nonlocal async_drop_line_count
        nonlocal coordinator_observer_record_count
        nonlocal coordinator_observer_parse_failure_count
        nonlocal coordinator_observer_last_sequence
        line_count += 1
        line = raw_line.rstrip(b"\r").decode("utf-8", errors="replace")
        lowered = line.lower()
        if line.startswith(COORDINATOR_OBSERVER_PREFIX):
            try:
                record = json.loads(line[len(COORDINATOR_OBSERVER_PREFIX) :])
                sequence = int(record["sequence"])
                completed_tasks = int(record["completed_tasks"])
                stages = record["stages"]
                if (
                    record.get("schema") != "lmyzmail.coordinator-stage-observation.v1"
                    or sequence <= coordinator_observer_last_sequence
                    or completed_tasks <= 0
                    or not isinstance(stages, dict)
                    or not stages
                    or any(
                        not isinstance(counters, dict)
                        or any(
                            not isinstance(counters.get(name), int)
                            or counters[name] < 0
                            for name in ("count", "total_ns", "max_ns")
                        )
                        for counters in stages.values()
                    )
                ):
                    raise ValueError("invalid coordinator observer record")
            except (KeyError, TypeError, ValueError):
                coordinator_observer_parse_failure_count += 1
            else:
                coordinator_observer_record_count += 1
                coordinator_observer_last_sequence = sequence
                coordinator_observer_records.append(record)
        relevant = (
            "[RESULT]" in line
            or "stress round" in lowered
            or "stress enqueue failed" in lowered
            or "queue completed" in lowered
            or "critical failure" in lowered
        )
        if relevant:
            relevant_line_count += 1
            result_lines.append(line)
        matched = JAVA_QUEUE_RESULT_PATTERN.search(line)
        if matched is not None:
            queue_counter_match_count += 1
            if len(queue_counter_records) < 16:
                queue_counter_records.append(
                    {name: int(value) for name, value in matched.groupdict().items()}
                )
        received_match = JAVA_RECEIVED_RESULT_PATTERN.search(line)
        if received_match is not None:
            received_counter_match_count += 1
            if len(received_counter_records) < 16:
                received_counter_records.append(int(received_match.group("received")))
        failed = (
            "critical failure" in lowered
            or "failed before completion" in lowered
            or "stress enqueue failed" in lowered
        )
        if failed:
            failure_line_count += 1
            failure_lines.append(line)
        if MISSING_DKIM_LOG_PREFIX.lower() in lowered:
            missing_dkim_configuration_line_count += 1
            missing_dkim_configuration_lines.append(line)
        if ASYNC_DROP_LOG_PREFIX.lower() in lowered:
            async_drop_line_count += 1
            async_drop_lines.append(line)

    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        rotation_detected = rotation_detected or (
            opened.st_dev != initial.st_dev
            or opened.st_ino != initial.st_ino
            or (cursor.device is not None and opened.st_dev != cursor.device)
            or (cursor.inode is not None and opened.st_ino != cursor.inode)
            or opened.st_size < offset
        )
        stream.seek(offset)
        while chunk := stream.read(read_chunk_bytes):
            digest.update(chunk)
            bytes_read += len(chunk)
            parts = chunk.split(b"\n")
            final_part_index = len(parts) - 1
            for index, part in enumerate(parts):
                terminated = index < final_part_index
                if dropping_oversized_line:
                    if terminated:
                        dropping_oversized_line = False
                    continue
                if len(pending) + len(part) > maximum_line_bytes:
                    line_overflow_count += 1
                    pending.clear()
                    dropping_oversized_line = not terminated
                    continue
                pending.extend(part)
                if terminated:
                    consume_line(bytes(pending))
                    pending.clear()
        if pending and not dropping_oversized_line:
            consume_line(bytes(pending))
        final_opened = os.fstat(stream.fileno())
    final_path = path.stat()
    stable_extent = (
        opened.st_dev == final_opened.st_dev == final_path.st_dev
        and opened.st_ino == final_opened.st_ino == final_path.st_ino
        and opened.st_size == final_opened.st_size == final_path.st_size
        and bytes_read == max(0, opened.st_size - offset)
    )
    parse_complete = (
        not rotation_detected
        and stable_extent
        and line_overflow_count == 0
        and queue_counter_match_count <= len(queue_counter_records)
        and received_counter_match_count <= len(received_counter_records)
        and coordinator_observer_parse_failure_count == 0
    )
    return {
        "present": True,
        "path_name": path.name,
        "offset": offset,
        "end_offset": opened.st_size,
        "bytes": bytes_read,
        "truncated": not parse_complete,
        "parse_complete": parse_complete,
        "stable_extent": stable_extent,
        "rotation_detected": rotation_detected,
        "line_count": line_count,
        "relevant_line_count": relevant_line_count,
        "line_overflow_count": line_overflow_count,
        "queue_counter_records": queue_counter_records,
        "queue_counter_match_count": queue_counter_match_count,
        "received_counter_records": received_counter_records,
        "received_counter_match_count": received_counter_match_count,
        "coordinator_observer_record_count": coordinator_observer_record_count,
        "coordinator_observer_parse_failure_count": (
            coordinator_observer_parse_failure_count
        ),
        "coordinator_observer_records": list(coordinator_observer_records),
        "coordinator_observer_last": (
            coordinator_observer_records[-1] if coordinator_observer_records else None
        ),
        "failure_line_count": failure_line_count,
        "missing_dkim_configuration_line_count": (
            missing_dkim_configuration_line_count
        ),
        "async_drop_line_count": async_drop_line_count,
        "sha256": digest.hexdigest(),
        "result_lines": list(result_lines),
        "failure_lines": list(failure_lines),
        "missing_dkim_configuration_lines": list(missing_dkim_configuration_lines),
        "async_drop_lines": list(async_drop_lines),
    }


def _endpoint_outcome(
    capture: dict[str, Any],
    resource: dict[str, Any] | None,
    cleanup: dict[str, Any],
    log: dict[str, Any],
    *,
    application_io_requirement: str = "cgroup-block-write",
) -> dict[str, Any]:
    if application_io_requirement not in {
        "cgroup-block-write",
        "process-write-with-fsync-disabled",
    }:
        raise ValueError("unknown application persistence I/O requirement")
    queue_counters, counter_contract_passed = _queue_counter_evidence(
        log, int(capture["expected"])
    )
    received_counter, received_counter_contract_passed = _received_counter_evidence(
        log, int(capture["expected"])
    )
    application_failure_lines = list(log.get("failure_lines", []))
    evidence_failures: list[str] = []
    if log.get("parse_complete") is not True or log.get("truncated") is not False:
        evidence_failures.append("application log was not parsed completely")
    if not counter_contract_passed:
        evidence_failures.append("endpoint queue counters were missing or invalid")
    if not received_counter_contract_passed:
        evidence_failures.append("endpoint received counter was missing or invalid")
    retry_count = int(capture["retry_responses"])
    if retry_count != 0:
        evidence_failures.append("SMTP retry/failure responses were observed")
    if capture.get("qualification") is not True:
        evidence_failures.append("Rust SMTP observer did not qualify the round")
    if int(log.get("missing_dkim_configuration_line_count", 0)) != 0:
        evidence_failures.append("outbound messages bypassed DKIM signing")
    if int(log.get("async_drop_line_count", 0)) != 0:
        evidence_failures.append("inbound verification asynchronously dropped messages")
    final_replies = capture.get("smtp_final_replies")
    if not isinstance(final_replies, dict) or final_replies.get("success") != int(
        capture["expected"]
    ):
        evidence_failures.append(
            "SMTP successful final reply count did not match request"
        )
    final_state = cleanup["final"]
    queue_evidence_required = int(capture["expected"]) >= 20
    queue_observed = None if resource is None else resource["queue_peak"] > 0
    if resource is None:
        application_io_observed = None
    elif application_io_requirement == "process-write-with-fsync-disabled":
        application_io_observed = resource.get(
            "application_persistence_io_sources", {}
        ).get("process_observed")
    else:
        application_io_observed = resource.get("application_persistence_io_observed")
    services_io_observed = (
        None if resource is None else resource.get("services_persistence_io_observed")
    )
    database_persistence_observed = (
        cleanup["database_delta"].get("persistence_audit_observed") is True
    )
    if resource is not None and application_io_observed is not True:
        evidence_failures.append("application persistence I/O was not observed")
    if resource is not None and services_io_observed is not True:
        evidence_failures.append("service persistence I/O was not observed")
    if not database_persistence_observed:
        evidence_failures.append("PostgreSQL persistence audit delta was not observed")
    failure_count = (
        int(capture["missing"])
        + len(capture["failures"])
        + int(log.get("failure_line_count", len(application_failure_lines)))
        + len(evidence_failures)
    )
    return {
        "requested": int(capture["expected"]),
        "delivered": int(capture["verified"]),
        "failure_count": failure_count,
        "retry_count": retry_count,
        "smtp_final_replies": capture["smtp_final_replies"],
        "capture_failures": list(capture["failures"]),
        "application_failure_lines": application_failure_lines,
        "queue_counters": queue_counters,
        "queue_counter_contract_passed": counter_contract_passed,
        "received_counter": received_counter,
        "received_counter_contract_passed": received_counter_contract_passed,
        "log_parse_complete": log.get("parse_complete") is True,
        "evidence_failures": evidence_failures,
        "queue_scheduler_observed": queue_observed,
        "queue_scheduler_evidence_required": queue_evidence_required,
        "application_persistence_io_observed": application_io_observed,
        "application_persistence_io_requirement": application_io_requirement,
        "services_persistence_io_observed": services_io_observed,
        "database_persistence_observed": database_persistence_observed,
        "cleanup_stable_polls": cleanup["stable_polls"],
        "cleanup_semantic_sha256": cleanup["semantic_sha256"],
        "cleanup_database_delta": cleanup["database_delta"],
        "residual_state": final_state,
        "residual_clean": _state_is_clean(final_state),
        "passed": (
            failure_count == 0
            and retry_count == 0
            and capture["verified"] == capture["expected"]
            and counter_contract_passed
            and received_counter_contract_passed
            and log.get("parse_complete") is True
            and log.get("truncated") is False
            and cleanup["stable_polls"] >= STATE_STABLE_POLLS
            and _state_is_clean(final_state)
        ),
    }


def _round_contract_checks(record: dict[str, Any]) -> dict[str, bool]:
    outcome = record["endpoint_outcome"]
    measured = record["measured"] is True
    resource = record.get("resource")
    measured_resource = resource if isinstance(resource, dict) else {}
    return {
        "endpoint_outcome": outcome["passed"] is True,
        "zero_retries": outcome["retry_count"] == 0,
        "queue_counters": outcome["queue_counter_contract_passed"] is True,
        "received_counter": outcome["received_counter_contract_passed"] is True,
        "complete_log": outcome["log_parse_complete"] is True,
        "clean_residual": outcome["residual_clean"] is True,
        "cleanup_database_delta": outcome["cleanup_database_delta"]["passed"] is True,
        "persistence_barrier": record.get("persistence_barrier", {}).get("passed")
        is True,
        "maildir_observer": record.get("maildir_observer", {}).get("passed") is True,
        "maildir_observer_read_only": record.get("maildir_observer", {}).get(
            "observer_write_syscalls"
        )
        == 0,
        "maildir_cleanup": record.get("maildir_observer", {}).get(
            "endpoint_internal_cleanup_observed"
        )
        is True,
        "measured_resource_present": not measured or isinstance(resource, dict),
        "queue_scheduler": not measured
        or outcome["queue_scheduler_evidence_required"] is False
        or outcome["queue_scheduler_observed"] is True,
        "application_persistence_io": not measured
        or outcome["application_persistence_io_observed"] is True,
        "services_persistence_io": not measured
        or outcome["services_persistence_io_observed"] is True,
        "database_persistence": not measured
        or outcome["database_persistence_observed"] is True,
        "continuous_membership": not measured
        or measured_resource.get("continuous_membership") is True,
        "io_accounting_calibration": not measured
        or measured_resource.get("io_accounting_calibration", {}).get("passed") is True,
        "candidate_cpu_observed": not measured
        or measured_resource.get("candidate_cpu_usage_seconds", 0) > 0,
        "services_cpu_observed": not measured
        or measured_resource.get("services_cpu_usage_seconds", 0) > 0,
        "temperature_within_limit": not measured
        or measured_resource.get("temperature", {}).get("within_limit") is True,
        "within_arm_throughput_stability": not measured
        or record.get("smtp", {})
        .get("within_arm_throughput_stability", {})
        .get("passed")
        is True,
    }


def _round_contract_passed(record: dict[str, Any]) -> bool:
    return all(_round_contract_checks(record).values())


def _apply_persistence_completion_timing(
    capture: dict[str, Any],
    *,
    started_monotonic: float,
    final_250_completed_monotonic: float,
    persistence_completed_monotonic: float,
    persistence_barrier: dict[str, Any],
) -> None:
    if persistence_completed_monotonic < final_250_completed_monotonic:
        raise RuntimeError("persistence completion preceded final SMTP acceptance")
    if final_250_completed_monotonic <= started_monotonic:
        raise RuntimeError("final SMTP acceptance preceded the measurement start")
    forwarding_duration = float(capture.get("duration_seconds") or 0.0)
    if forwarding_duration <= 0:
        raise RuntimeError("SMTP forwarding duration was not positive")
    forwarding_throughput = float(capture.get("throughput_messages_per_second") or 0.0)
    forwarding_data_throughput = float(
        capture.get("data_throughput_mib_per_second") or 0.0
    )
    tail_seconds = persistence_completed_monotonic - final_250_completed_monotonic
    capture.update(
        {
            "smtp_forwarding_duration_seconds": forwarding_duration,
            "smtp_forwarding_throughput_messages_per_second": forwarding_throughput,
            "smtp_forwarding_data_throughput_mib_per_second": (
                forwarding_data_throughput
            ),
            "persistence_audit_duration_seconds": round(tail_seconds, 6),
            "persistence_tail_seconds": round(tail_seconds, 6),
            "measurement_completion_boundary": "final_250_forwarded",
            "persistence_audit_excluded_from_throughput_denominator": True,
            "persistence_barrier": persistence_barrier,
        }
    )


def _run_round(
    runtime: Any,
    proxy: RustSmtpProxy,
    layout: CgroupLayout,
    *,
    mode: str,
    count: int,
    message_bytes: int,
    disk_budget_bytes: int,
    measured: bool,
    persistence_gate_required: bool = True,
    invocation_event: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    maildir_observer = MaildirPersistenceObserver(runtime, expected_messages=count)
    postgres_gate_snapshot: PostgresPersistenceGateSnapshot | None = None
    try:
        before = _cleanup_state(runtime, "before_round")
        if not _state_is_clean(before):
            raise RuntimeError(
                "stress runtime was not clean before a single endpoint invocation"
            )
        log_cursor = _log_cursor(runtime)
        if persistence_gate_required:
            postgres_gate_snapshot = PostgresPersistenceGateSnapshot(
                runtime,
                before_rows=int(
                    before["database"]["tables"]["outbound_mail_queue"]["rows"]
                ),
                expected_messages=count,
            )
    except BaseException:
        if postgres_gate_snapshot is not None:
            with contextlib.suppress(BaseException):
                postgres_gate_snapshot.close()
        with contextlib.suppress(BaseException):
            maildir_observer.stop()
        raise
    monitor: ResourceMonitor | None = None
    resource: dict[str, Any] | None = None
    capture: dict[str, Any] | None = None
    cleanup: dict[str, Any] | None = None
    log: dict[str, Any] | None = None
    persistence_barrier: dict[str, Any] | None = None
    database_visibility: dict[str, Any] | None = None
    maildir_evidence: dict[str, Any] | None = None
    maildir_timed_evidence: dict[str, Any] | None = None
    maildir_lag_seconds: float | None = None
    gate_trigger: dict[str, Any] | None = None
    gate_snapshot: dict[str, Any] | None = None
    gate_released = False
    started_monotonic: float | None = None
    final_250_completed_monotonic: float | None = None
    endpoint_invocation_started = False
    primary_error: BaseException | None = None
    invocation = _start_invocation_record()
    start_call: dict[str, Any] | PendingStartRound | None = None
    start_response: dict[str, Any] | None = None
    try:
        # Durable invocation journaling precedes the measurement clock, but it
        # remains inside the resource-lifetime guard so callback failure cannot
        # leak the Maildir observer.
        if invocation_event is not None:
            invocation_event(invocation)
        if measured:
            monitor = ResourceMonitor(
                runtime,
                layout,
                expected_messages=count,
                disk_budget_bytes=disk_budget_bytes,
                harness_auxiliary_roots={
                    proxy.process.pid: _process_start_time(proxy.process.pid)
                },
            )
        # The proxy server and the first resource sample are ready. Start the
        # measurement immediately before arming capture and issuing the POST.
        started_monotonic = time.monotonic()
        started_at = _utc_now()
        proxy.begin(
            expected=count,
            message_bytes=message_bytes,
            started_monotonic=started_monotonic,
            started_at=started_at,
            persistence_gate_required=persistence_gate_required,
        )
        endpoint_invocation_started = True
        start_call = _start_round(
            runtime,
            expected_mode=mode,
            expected_count=count,
            expected_size_kib=message_bytes // 1024,
            prepared_invocation=invocation,
            defer_response=persistence_gate_required,
        )
        if persistence_gate_required:
            gate_trigger = proxy.wait_for_persistence_gate(
                MEASUREMENT_TIMEOUT_SECONDS if measured else 10 * 60
            )
            if postgres_gate_snapshot is None:
                raise RuntimeError("PostgreSQL gate snapshot was not initialized")
            snapshot_started = time.monotonic_ns()
            postgres_snapshot = postgres_gate_snapshot.capture()
            maildir_snapshot_started = time.monotonic_ns()
            maildir_at_gate = maildir_observer.snapshot()
            maildir_snapshot_completed = time.monotonic_ns()
            snapshot_completed = time.monotonic_ns()
            gate_snapshot = {
                **postgres_snapshot,
                "snapshot_started_monotonic_ns": snapshot_started,
                "snapshot_completed_monotonic_ns": snapshot_completed,
                "maildir_snapshot_duration_ns": (
                    maildir_snapshot_completed - maildir_snapshot_started
                ),
                "maildir_atomic_rename_publications": int(
                    maildir_at_gate["atomic_rename_publications_by_mailbox_folder"].get(
                        f"{ENDPOINT_RECEIVER}/inbox", -1
                    )
                ),
                "maildir_sender_sent_publications": int(
                    maildir_at_gate["publication_counts_by_mailbox_folder"].get(
                        f"{ENDPOINT_SENDER}/sent", -1
                    )
                ),
            }
            gate_snapshot["qualified"] = bool(
                postgres_snapshot["qualified"] is True
                and gate_snapshot["maildir_atomic_rename_publications"] == count
                and gate_snapshot["maildir_sender_sent_publications"] == count
                and maildir_at_gate.get("publication_passed") is True
            )
            gate_id = int(gate_trigger["gate_id"])
            if gate_snapshot["qualified"] is not True:
                proxy.abort_persistence_gate(
                    gate_id,
                    "pre-final-250 persistence snapshot lacked exact PostgreSQL or Maildir visibility",
                )
                raise RuntimeError(
                    "pre-final-250 persistence gate lacked exact PostgreSQL or Maildir visibility"
                )
            proxy.release_persistence_gate(gate_id, gate_snapshot)
            gate_released = True
        start_response = _finish_start_round(start_call)
        capture = proxy.finish(
            MEASUREMENT_TIMEOUT_SECONDS if measured else 10 * 60,
            None if monitor is None else monitor.raise_if_failed,
        )
        final_250_completed_monotonic = time.monotonic()
        database_visibility = _wait_for_delivery_database_visibility(
            runtime,
            before=before,
            expected_messages=count,
            timeout_seconds=0.0,
            capture_boundary="immediate_after_final_250",
        )
        gate_evidence = capture.get("persistence_gate")
        final_boundary = capture.get("final_250_boundary")
        duration_ns = int(capture.get("duration_ns") or 0)
        if not isinstance(gate_evidence, dict) or not isinstance(final_boundary, dict):
            raise RuntimeError("final-250 persistence gate evidence was missing")
        if persistence_gate_required:
            proxy_times = [
                gate_evidence.get("triggered_at_proxy_monotonic_ns"),
                gate_evidence.get("release_received_at_proxy_monotonic_ns"),
                gate_evidence.get("forwarding_started_at_proxy_monotonic_ns"),
                gate_evidence.get("forwarding_completed_at_proxy_monotonic_ns"),
            ]
            gate_hold_ns = int(gate_evidence.get("gate_hold_ns") or -1)
            gate_duration_fraction = (
                gate_hold_ns / duration_ns if duration_ns > 0 else 1.0
            )
            gate_evidence["maximum_gate_hold_ns"] = MAXIMUM_PERSISTENCE_GATE_HOLD_NS
            gate_evidence["maximum_duration_fraction"] = (
                MAXIMUM_PERSISTENCE_GATE_DURATION_FRACTION
            )
            gate_evidence["duration_fraction"] = gate_duration_fraction
            gate_evidence["duration_fraction_enforced"] = count >= 50
            gate_evidence["hard_overhead_gate_passed"] = bool(
                0 <= gate_hold_ns <= MAXIMUM_PERSISTENCE_GATE_HOLD_NS
                and (
                    count < 50
                    or gate_duration_fraction
                    <= MAXIMUM_PERSISTENCE_GATE_DURATION_FRACTION
                )
            )
            gate_passed = bool(
                gate_evidence.get("qualified") is True
                and gate_evidence.get("status") == "forwarded"
                and gate_evidence.get("proxy_clock_domain") == "observer_origin_elapsed"
                and gate_evidence.get("snapshot") == gate_snapshot
                and not any(
                    isinstance(value, bool) or not isinstance(value, int)
                    for value in proxy_times
                )
                and proxy_times == sorted(proxy_times)
                and gate_evidence.get("forwarding_completed_at_proxy_monotonic_ns")
                == final_boundary.get("completed_at_monotonic_ns")
                and gate_evidence["hard_overhead_gate_passed"] is True
            )
        else:
            gate_passed = bool(
                gate_evidence.get("required") is False
                and gate_evidence.get("qualified") is True
                and gate_evidence.get("status") == "disabled"
                and gate_evidence.get("proxy_clock_domain") == "observer_origin_elapsed"
                and gate_evidence.get("snapshot") is None
                and all(
                    gate_evidence.get(name) is None
                    for name in (
                        "gate_id",
                        "triggered_at_proxy_monotonic_ns",
                        "release_received_at_proxy_monotonic_ns",
                        "forwarding_started_at_proxy_monotonic_ns",
                        "forwarding_completed_at_proxy_monotonic_ns",
                        "gate_hold_ns",
                    )
                )
            )
        if not gate_passed:
            raise RuntimeError("final-250 persistence gate failed causal qualification")
        if capture["round"] != start_response["body"]["round"]:
            raise RuntimeError("captured SMTP round differed from the HTTP response")
    except BaseException as error:
        if gate_trigger is not None and not gate_released:
            with contextlib.suppress(BaseException):
                proxy.abort_persistence_gate(int(gate_trigger["gate_id"]), str(error))
        if isinstance(start_call, PendingStartRound):
            with contextlib.suppress(BaseException):
                start_call.close()
        primary_error = error
    if postgres_gate_snapshot is not None:
        try:
            postgres_gate_snapshot.close()
        except BaseException as error:
            if primary_error is None:
                primary_error = error
            else:
                primary_error.add_note(
                    "PostgreSQL gate snapshot cleanup also failed: "
                    f"{type(error).__name__}: {error}"
                )
    if monitor is not None:
        try:
            resource = monitor.stop()
        except BaseException as error:
            if primary_error is None:
                primary_error = error
            else:
                primary_error.add_note(
                    f"resource monitor cleanup also failed: {type(error).__name__}: {error}"
                )
    if primary_error is None:
        try:
            if (
                capture is None
                or start_response is None
                or started_monotonic is None
                or final_250_completed_monotonic is None
                or (persistence_gate_required and gate_snapshot is None)
            ):
                raise RuntimeError("final-250 measurement evidence was incomplete")
            maildir_observer.wait_for_publications(
                MAXIMUM_POST_FINAL_PERSISTENCE_LAG_SECONDS
            )
            maildir_timed_evidence = maildir_observer.snapshot()
            last_publication_ns = maildir_timed_evidence.get(
                "last_publication_monotonic_ns"
            )
            if (
                maildir_timed_evidence.get("publication_clock_id") != "CLOCK_MONOTONIC"
                or isinstance(last_publication_ns, bool)
                or not isinstance(last_publication_ns, int)
                or last_publication_ns <= 0
            ):
                raise RuntimeError("Maildir publication timestamp evidence was invalid")
            maildir_completed_monotonic = last_publication_ns / 1_000_000_000
            maildir_lag_seconds = max(
                0.0,
                maildir_completed_monotonic - final_250_completed_monotonic,
            )
            if maildir_lag_seconds > MAXIMUM_POST_FINAL_PERSISTENCE_LAG_SECONDS:
                raise RuntimeError(
                    "Maildir publication lag exceeded its qualification limit"
                )
        except BaseException as error:
            primary_error = error
    try:
        cleanup = _wait_for_automatic_cleanup(
            runtime,
            before=before,
            expected_messages=count if endpoint_invocation_started else 0,
            abort_check=None,
        )
    except BaseException as error:
        if primary_error is None:
            primary_error = error
        else:
            primary_error.add_note(
                f"automatic endpoint cleanup also failed: {type(error).__name__}: {error}"
            )
    try:
        log = _log_evidence(log_cursor)
    except BaseException as error:
        if primary_error is None:
            primary_error = error
        else:
            primary_error.add_note(
                f"application log evidence also failed: {type(error).__name__}: {error}"
            )
    if endpoint_invocation_started:
        try:
            maildir_observer.wait_for_removals(10.0)
        except BaseException as error:
            if primary_error is None:
                primary_error = error
            else:
                primary_error.add_note(
                    "Maildir cleanup observation also failed: "
                    f"{type(error).__name__}: {error}"
                )
    try:
        maildir_evidence = maildir_observer.stop()
    except BaseException as error:
        if primary_error is None:
            primary_error = error
        else:
            primary_error.add_note(
                f"Maildir persistence observer also failed: {type(error).__name__}: {error}"
            )
    if primary_error is None:
        try:
            if (
                capture is None
                or cleanup is None
                or log is None
                or maildir_evidence is None
                or maildir_timed_evidence is None
                or database_visibility is None
                or started_monotonic is None
                or final_250_completed_monotonic is None
                or maildir_lag_seconds is None
            ):
                raise RuntimeError("persistence lifecycle evidence was incomplete")
            persistence_barrier = _establish_persistence_barrier(
                runtime,
                before=before,
                capture=capture,
                maildir=maildir_evidence,
                cleanup=cleanup,
                log=log,
                expected_messages=count,
                database_visibility=database_visibility,
            )
            persistence_completed_monotonic = time.monotonic()
            persistence_barrier.update(
                {
                    "pre_final_persistence_snapshot_performed": (
                        persistence_gate_required
                    ),
                    "maildir_publications_pre_final_250_gate": (
                        int(gate_snapshot["maildir_atomic_rename_publications"])
                        if gate_snapshot is not None
                        else None
                    ),
                    "postgres_outbound_audit_delta_pre_final_250_gate": (
                        gate_snapshot["postgres_row_delta"]
                        if gate_snapshot is not None
                        else None
                    ),
                    "maildir_post_final_lag_seconds": round(maildir_lag_seconds, 6),
                    "maximum_post_final_persistence_lag_seconds": (
                        MAXIMUM_POST_FINAL_PERSISTENCE_LAG_SECONDS
                    ),
                    "persistence_audit_duration_seconds": round(
                        persistence_completed_monotonic - final_250_completed_monotonic,
                        6,
                    ),
                }
            )
            _apply_persistence_completion_timing(
                capture,
                started_monotonic=started_monotonic,
                final_250_completed_monotonic=final_250_completed_monotonic,
                persistence_completed_monotonic=persistence_completed_monotonic,
                persistence_barrier=persistence_barrier,
            )
        except BaseException as error:
            primary_error = error
    if primary_error is not None:
        raise primary_error
    if (
        capture is None
        or cleanup is None
        or log is None
        or persistence_barrier is None
        or maildir_evidence is None
        or maildir_timed_evidence is None
    ):
        raise RuntimeError("round produced incomplete persistence evidence")
    filesystem_fsync_mode = getattr(runtime, "filesystem_fsync_mode", None)
    endpoint_outcome = _endpoint_outcome(
        capture,
        resource,
        cleanup,
        log,
        application_io_requirement=(
            "process-write-with-fsync-disabled"
            if filesystem_fsync_mode == "off"
            else "cgroup-block-write"
        ),
    )
    result = {
        "mode": mode,
        "rust_filesystem_fsync": filesystem_fsync_mode,
        "measured": measured,
        "persistence_gate_mode": "on" if persistence_gate_required else "off",
        "count": count,
        "message_bytes": message_bytes,
        "single_start_invocation": True,
        "endpoint_start_invocation_count": 1,
        "endpoint_start_automatic_retries": 0,
        "uncertain_start_outcome_policy": (
            "fail_closed_and_restart_as_a_new_benchmark_run"
        ),
        "start_response": start_response,
        "before_state": before,
        "smtp": capture,
        "persistence_barrier": persistence_barrier,
        "maildir_observer": maildir_evidence,
        "endpoint_outcome": endpoint_outcome,
        "cleanup": cleanup,
        "application_log": log,
    }
    if resource is not None:
        result["resource"] = resource
    contract_checks = _round_contract_checks(result)
    if not all(contract_checks.values()):
        within_arm_stability = dict(
            capture.get("within_arm_throughput_stability", {})
        )
        within_arm_stability.pop("progress_samples", None)
        diagnostic = {
            "failed_checks": [
                name for name, passed in contract_checks.items() if not passed
            ],
            "endpoint_failure_count": endpoint_outcome.get("failure_count"),
            "endpoint_evidence_failures": endpoint_outcome.get("evidence_failures"),
            "retry_count": endpoint_outcome.get("retry_count"),
            "queue_counters": endpoint_outcome.get("queue_counters"),
            "stress_timing_lines": [
                line[:512]
                for line in log.get("result_lines", ())
                if "[RESULT]" in line or "queue completed" in line.lower()
            ][-16:],
            "cleanup_database_mismatches": endpoint_outcome.get(
                "cleanup_database_delta", {}
            ).get("mismatches"),
            "cleanup_email_index_group_mismatches": endpoint_outcome.get(
                "cleanup_database_delta", {}
            ).get("email_index_group_mismatches"),
            "maildir_publications": maildir_evidence.get("publication_events"),
            "maildir_removals": maildir_evidence.get("removal_events"),
            "within_arm_throughput_stability": within_arm_stability,
            "coordinator_quartile_diagnostics": _coordinator_quartile_diagnostics(
                log.get("coordinator_observer_records", ()),
                count,
                selected_stage_names=_coordinator_selected_diagnostic_stages(),
            ),
            "resource_io": (
                None
                if resource is None
                else {
                    "samples": resource.get("samples"),
                    "accounting_device": resource.get("io_accounting_device"),
                    "application_write_bytes": resource.get(
                        "application_io_write_bytes"
                    ),
                    "application_write_operations": resource.get(
                        "application_io_write_operations"
                    ),
                    "services_write_bytes": resource.get("services_io_write_bytes"),
                    "services_write_operations": resource.get(
                        "services_io_write_operations"
                    ),
                    "application_process_write_bytes": resource.get(
                        "application_process_io_write_bytes"
                    ),
                    "application_process_write_syscalls": resource.get(
                        "application_process_io_write_syscalls"
                    ),
                    "services_process_write_bytes": resource.get(
                        "services_process_io_write_bytes"
                    ),
                    "services_process_write_syscalls": resource.get(
                        "services_process_io_write_syscalls"
                    ),
                    "application_persistence_io_sources": resource.get(
                        "application_persistence_io_sources"
                    ),
                    "services_persistence_io_sources": resource.get(
                        "services_persistence_io_sources"
                    ),
                    "io_by_role": resource.get("io_by_role"),
                    "process_io_by_role": resource.get("process_io_by_role"),
                }
            ),
        }
        raise RuntimeError(
            f"{mode} round failed its endpoint evidence contract: "
            f"{json.dumps(diagnostic, sort_keys=True, separators=(',', ':'))}"
        )
    return result


def _runtime_for(
    target: str,
    plan: BenchmarkPlan,
    *,
    benchmark_cpu: int,
    dns_port: int,
    dkim_private_key_bytes: bytes,
    candidate_path: Path | None = None,
    rust_filesystem_fsync: str | None = None,
) -> Any:
    if target == "java-oracle":
        return JavaStressRuntime(
            startup_timeout=120.0,
            shutdown_timeout=60.0,
            shutdown_kill_timeout=5.0,
            production_count=plan.total_messages,
            warmup_count=0,
            warmup_rounds=0,
            email_size_kb=plan.message_bytes // 1024,
            benchmark_cpu=benchmark_cpu,
            benchmark_dkim_private_key_bytes=dkim_private_key_bytes,
        )
    if target == "rust-candidate":
        if rust_filesystem_fsync not in ("on", "off"):
            raise ValueError(
                "Rust candidate requires an explicit filesystem fsync mode"
            )
        candidate = candidate_path or CANDIDATE_RELEASE
        runtime = RustStressRuntime(
            command_template=(str(candidate), "--config", "{config}"),
            startup_timeout=90.0,
            shutdown_timeout=60.0,
            shutdown_kill_timeout=5.0,
            benchmark_warmup_rounds=0,
            benchmark_dkim_private_key_bytes=dkim_private_key_bytes,
            filesystem_fsync_mode=rust_filesystem_fsync,
            benchmark_cpu=benchmark_cpu,
        )
        runtime.production_count = plan.total_messages
        runtime.warmup_count = 0
        runtime.email_size_kb = plan.message_bytes // 1024
        runtime.spf_dns_port = dns_port
        runtime.coordinator_observer = (
            candidate.resolve() == CANDIDATE_PROFILING_RELEASE.resolve()
        )
        return runtime
    raise ValueError(f"unknown benchmark target: {target}")


def _attested_candidate_path(started_attestation: dict[str, Any]) -> Path:
    relative = str(
        started_attestation.get(
            "candidate_release_path", CANDIDATE_RELEASE.relative_to(REPOSITORY)
        )
    )
    allowed = {
        CANDIDATE_RELEASE.relative_to(REPOSITORY).as_posix(): CANDIDATE_RELEASE,
        CANDIDATE_PROFILING_RELEASE.relative_to(REPOSITORY).as_posix(): (
            CANDIDATE_PROFILING_RELEASE
        ),
    }
    try:
        return allowed[relative]
    except KeyError as error:
        raise RuntimeError(
            f"attested candidate path is not an allowed fixed artifact: {relative}"
        ) from error


def _verify_target_artifact(
    target: str, started_attestation: dict[str, Any], phase: str
) -> dict[str, Any]:
    if target == "java-oracle":
        path = REPOSITORY / "oracle/artifacts/lmyzmail-java-oracle.jar"
        expected = str(started_attestation["java_oracle_sha256"])
    elif target == "rust-candidate":
        path = _attested_candidate_path(started_attestation)
        expected = str(started_attestation["candidate_release_sha256"])
    else:
        raise ValueError(f"unknown benchmark target: {target}")
    actual = _sha256_file(path)
    if actual != expected:
        raise RuntimeError(
            f"{target} artifact changed {phase}: {actual}; expected {expected}"
        )
    return {
        "phase": phase,
        "path": str(path.relative_to(REPOSITORY)),
        "sha256": actual,
        "expected_started_sha256": expected,
        "unchanged": True,
    }


def _run_attested_round(
    runtime: Any,
    proxy: RustSmtpProxy,
    layout: CgroupLayout,
    *,
    target: str,
    tier: str,
    phase: str,
    ordinal: int,
    mode: str,
    count: int,
    message_bytes: int,
    disk_budget_bytes: int,
    measured: bool,
    started_attestation: dict[str, Any],
    checkpoint_event: Callable[[dict[str, Any]], None],
    persistence_gate_required: bool = True,
    rust_filesystem_fsync: str | None = None,
) -> dict[str, Any]:
    before = _verify_definition_attestation(started_attestation)
    checkpoint_event(
        {
            "event": "round_definition_attestation",
            "target": target,
            "tier": tier,
            "phase": phase,
            "ordinal": ordinal,
            "rust_filesystem_fsync": rust_filesystem_fsync,
            "boundary": "before",
            "definition": before,
        }
    )
    primary_error: BaseException | None = None
    result: dict[str, Any] | None = None
    try:

        def record_invocation(invocation: dict[str, Any]) -> None:
            checkpoint_event(
                {
                    "event": "endpoint_start_attempt",
                    "target": target,
                    "tier": tier,
                    "phase": phase,
                    "ordinal": ordinal,
                    "rust_filesystem_fsync": rust_filesystem_fsync,
                    "invocation": invocation,
                }
            )

        result = _run_round(
            runtime,
            proxy,
            layout,
            mode=mode,
            count=count,
            message_bytes=message_bytes,
            disk_budget_bytes=disk_budget_bytes,
            measured=measured,
            persistence_gate_required=persistence_gate_required,
            invocation_event=record_invocation,
        )
    except BaseException as error:
        primary_error = error
    try:
        after = _verify_definition_attestation(started_attestation)
        checkpoint_event(
            {
                "event": "round_definition_attestation",
                "target": target,
                "tier": tier,
                "phase": phase,
                "ordinal": ordinal,
                "rust_filesystem_fsync": rust_filesystem_fsync,
                "boundary": "after",
                "definition": after,
            }
        )
    except BaseException as error:
        if primary_error is None:
            primary_error = error
        else:
            primary_error.add_note(
                f"after-round definition attestation also failed: {type(error).__name__}: {error}"
            )
        after = None
    if primary_error is not None:
        primary_error.add_note(
            f"benchmark arm target={target} tier={tier} phase={phase} ordinal={ordinal}"
        )
        raise primary_error
    if result is None or after is None:
        raise RuntimeError("attested round produced no result")
    result["definition_attestation"] = {"before": before, "after": after}
    return result


def _real_gate_calibration_report(
    label: str,
    rounds: Sequence[dict[str, Any]],
    *,
    binding: dict[str, Any],
) -> dict[str, Any]:
    try:
        messages, message_bytes, concurrency = REAL_GATE_CALIBRATION_SHAPES[label]
    except KeyError as error:
        raise ValueError(f"unknown real gate calibration tier: {label}") from error
    if len(rounds) != len(REAL_GATE_CALIBRATION_SEQUENCE):
        raise RuntimeError("real gate calibration round vector changed")
    compact_rounds: list[dict[str, Any]] = []
    rates: dict[str, list[float]] = {"off": [], "on": []}
    mode_ordinals = {"off": 0, "on": 0}
    for sequence_index, (mode, record) in enumerate(
        zip(REAL_GATE_CALIBRATION_SEQUENCE, rounds, strict=True)
    ):
        smtp = record.get("smtp")
        start_response = record.get("start_response")
        barrier = record.get("persistence_barrier")
        outcome = record.get("endpoint_outcome")
        if not all(
            isinstance(value, dict)
            for value in (smtp, start_response, barrier, outcome)
        ):
            raise RuntimeError("real gate calibration round evidence is incomplete")
        gate = smtp.get("persistence_gate")
        proxy = smtp.get("proxy")
        body = start_response.get("body")
        if (
            not isinstance(gate, dict)
            or not isinstance(proxy, dict)
            or not isinstance(body, dict)
        ):
            raise RuntimeError("real gate calibration SMTP evidence is incomplete")
        duration = _finite_number(
            smtp.get("duration_seconds"),
            f"{label} real gate {mode} duration",
            positive=True,
        )
        rate = _finite_number(
            smtp.get("throughput_messages_per_second"),
            f"{label} real gate {mode} rate",
            positive=True,
        )
        snapshot = gate.get("snapshot")
        gate_mode_passed = gate.get("qualified") is True and (
            (
                mode == "on"
                and gate.get("required") is True
                and gate.get("status") == "forwarded"
                and isinstance(snapshot, dict)
                and snapshot.get("transaction_isolation") == "repeatable_read"
                and snapshot.get("transaction_read_only") is True
                and snapshot.get("postgres_row_delta") == messages
                and snapshot.get("maildir_atomic_rename_publications") == messages
                and snapshot.get("qualified") is True
            )
            or (
                mode == "off"
                and gate.get("required") is False
                and gate.get("status") == "disabled"
                and snapshot is None
                and gate.get("gate_id") is None
                and gate.get("gate_hold_ns") is None
            )
        )
        round_passed = bool(
            record.get("persistence_gate_mode") == mode
            and record.get("measured") is False
            and record.get("count") == messages
            and record.get("message_bytes") == message_bytes
            and record.get("single_start_invocation") is True
            and record.get("endpoint_start_invocation_count") == 1
            and record.get("endpoint_start_automatic_retries") == 0
            and start_response.get("endpoint") == "/api/stress/start"
            and start_response.get("status_code") == 200
            and body.get("emailCount") == messages
            and body.get("emailSizeKB") == message_bytes // 1024
            and body.get("maxConcurrency") == concurrency
            and smtp.get("qualification") is True
            and smtp.get("expected") == messages
            and smtp.get("verified") == messages
            and smtp.get("missing") == 0
            and smtp.get("duplicates") == 0
            and smtp.get("retry_responses") == 0
            and _proxy_memory_evidence_is_valid(proxy)
            and gate_mode_passed
            and barrier.get("passed") is True
            and barrier.get("pre_final_persistence_snapshot_performed")
            is (mode == "on")
            and outcome.get("passed") is True
            and duration >= MINIMUM_REAL_GATE_CALIBRATION_DURATION_SECONDS
        )
        compact = {
            "mode": mode,
            "mode_ordinal": mode_ordinals[mode],
            "sequence_index": sequence_index,
            "messages": messages,
            "message_bytes": message_bytes,
            "concurrency": concurrency,
            "duration_seconds": duration,
            "messages_per_second": rate,
            "minimum_duration_seconds": MINIMUM_REAL_GATE_CALIBRATION_DURATION_SECONDS,
            "start_response": start_response,
            "persistence_gate": gate,
            "proxy": proxy,
            "persistence_barrier": barrier,
            "endpoint_outcome": outcome,
            "definition_attestation": record.get("definition_attestation"),
            "passed": round_passed,
        }
        compact["sha256"] = _canonical_json_sha256(compact)
        compact_rounds.append(compact)
        rates[mode].append(rate)
        mode_ordinals[mode] += 1
    medians = {mode: statistics.median(values) for mode, values in rates.items()}
    spreads = {
        mode: (max(values) - min(values)) / medians[mode]
        for mode, values in rates.items()
    }
    paired_ratios = [
        rates["on"][ordinal] / rates["off"][ordinal] for ordinal in range(4)
    ]
    median_ratio = medians["on"] / medians["off"]
    qualification = bool(
        all(round_["passed"] is True for round_ in compact_rounds)
        and all(
            spread <= MAXIMUM_REAL_GATE_CALIBRATION_SPREAD
            for spread in spreads.values()
        )
        and median_ratio >= MINIMUM_REAL_GATE_CALIBRATION_MEDIAN_RATIO
        and all(
            ratio >= MINIMUM_REAL_GATE_CALIBRATION_PAIRED_RATIO
            for ratio in paired_ratios
        )
    )
    report = {
        "schema_version": 1,
        "profile": "lmyzmail-real-persistence-gate-overhead-calibration-v1",
        "rust_filesystem_fsync": binding.get("rust_filesystem_fsync"),
        "synthetic_no_postgres_or_maildir": False,
        "tier": label,
        "messages": messages,
        "message_bytes": message_bytes,
        "concurrency": concurrency,
        "rounds_per_mode": 4,
        "sequence": list(REAL_GATE_CALIBRATION_SEQUENCE),
        "rounds": compact_rounds,
        "off_median_messages_per_second": medians["off"],
        "on_median_messages_per_second": medians["on"],
        "off_round_spread": spreads["off"],
        "on_round_spread": spreads["on"],
        "median_on_to_off_ratio": median_ratio,
        "paired_on_to_off_ratios": paired_ratios,
        "maximum_round_spread": MAXIMUM_REAL_GATE_CALIBRATION_SPREAD,
        "minimum_median_on_to_off_ratio": (MINIMUM_REAL_GATE_CALIBRATION_MEDIAN_RATIO),
        "minimum_paired_on_to_off_ratio": (MINIMUM_REAL_GATE_CALIBRATION_PAIRED_RATIO),
        "minimum_round_duration_seconds": (
            MINIMUM_REAL_GATE_CALIBRATION_DURATION_SECONDS
        ),
        "binding": binding,
        "qualification": qualification,
    }
    report["sha256"] = _canonical_json_sha256(report)
    return report


def _run_real_gate_calibration_tier(
    label: str,
    layout: CgroupLayout,
    *,
    dns_port: int,
    dkim_private_key_bytes: bytes,
    disk_budget_bytes: int,
    started_attestation: dict[str, Any],
    quota_mount_root: Path,
    checkpoint_event: Callable[[dict[str, Any]], None],
    rust_filesystem_fsync: str = "on",
) -> dict[str, Any]:
    messages, message_bytes, _concurrency = REAL_GATE_CALIBRATION_SHAPES[label]
    plan = BenchmarkPlan(label, message_bytes, messages)
    runtime = _runtime_for(
        "rust-candidate",
        plan,
        benchmark_cpu=layout.cpu,
        dns_port=dns_port,
        dkim_private_key_bytes=dkim_private_key_bytes,
        candidate_path=_attested_candidate_path(started_attestation),
        rust_filesystem_fsync=rust_filesystem_fsync,
    )
    runtime_started = False
    proxy: RustSmtpProxy | None = None
    cleanup_errors: list[str] = []
    primary_error: BaseException | None = None
    report: dict[str, Any] | None = None
    artifact_before = _verify_target_artifact(
        "rust-candidate", started_attestation, "before-real-gate-calibration"
    )
    try:
        runtime.start()
        runtime_started = True
        if runtime.workspace is None:
            raise RuntimeError("real gate calibration runtime omitted its workspace")
        workspace = runtime.workspace.resolve(strict=True)
        mount_root = quota_mount_root.resolve(strict=True)
        workspace_device = workspace.stat().st_dev
        workspace_device_name = (
            f"{os.major(workspace_device)}:{os.minor(workspace_device)}"
        )
        if (
            not workspace.is_relative_to(mount_root)
            or workspace_device_name != layout.device
        ):
            raise RuntimeError("real gate calibration escaped quota/I/O topology")
        placement = _move_runtime_to_workload(runtime, layout)
        initial_state = _cleanup_state(runtime)
        if not _state_is_clean(initial_state):
            raise RuntimeError("real gate calibration runtime did not start cleanly")
        runtime_instance_id = uuid.uuid4().hex
        rounds: list[dict[str, Any]] = []
        for sequence_index, gate_mode in enumerate(REAL_GATE_CALIBRATION_SEQUENCE):
            proxy = RustSmtpProxy(
                runtime,
                binary=BENCHMARK_PROXY_BINARY,
                expected_sha256=str(
                    started_attestation["benchmark_proxy_release_sha256"]
                ),
                run_id=(
                    f"real-gate-{label.lower()}-{sequence_index}-{runtime_instance_id}"
                ),
            )
            try:
                record = _run_attested_round(
                    runtime,
                    proxy,
                    layout,
                    target="rust-candidate",
                    tier=label,
                    phase=f"real-gate-calibration-{gate_mode}",
                    ordinal=sequence_index,
                    mode="PRODUCTION",
                    count=messages,
                    message_bytes=message_bytes,
                    disk_budget_bytes=disk_budget_bytes,
                    measured=False,
                    started_attestation=started_attestation,
                    checkpoint_event=checkpoint_event,
                    persistence_gate_required=gate_mode == "on",
                    rust_filesystem_fsync=rust_filesystem_fsync,
                )
            finally:
                proxy.close()
                proxy = None
            rounds.append(record)
            checkpoint_event(
                {
                    "event": "real_gate_calibration_round_complete",
                    "tier": label,
                    "rust_filesystem_fsync": rust_filesystem_fsync,
                    "mode": gate_mode,
                    "sequence_index": sequence_index,
                    "throughput_messages_per_second": record["smtp"][
                        "throughput_messages_per_second"
                    ],
                }
            )
        binding = {
            "runner_sha256": started_attestation["runner_sha256"],
            "candidate_release_sha256": started_attestation["candidate_release_sha256"],
            "benchmark_proxy_release_sha256": started_attestation[
                "benchmark_proxy_release_sha256"
            ],
            "benchmark_proxy_source_tree_sha256": started_attestation[
                "benchmark_proxy_source_tree_sha256"
            ],
            "host_boot_id": started_attestation["host_boot_id"],
            "runtime_instance_id": runtime_instance_id,
            "same_candidate_runtime_for_all_rounds": True,
            "rust_filesystem_fsync": rust_filesystem_fsync,
            "fresh_one_shot_proxy_per_round": True,
            "original_http_stress_endpoint": "/api/stress/start",
            "synthetic_backend": False,
            "workload_placement": placement,
            "quota_mount_root": str(mount_root),
            "workspace_device": workspace_device_name,
            "cgroup": layout.snapshot(),
            "artifact_before": artifact_before,
        }
        report = _real_gate_calibration_report(label, rounds, binding=binding)
        if report["qualification"] is not True:
            raise RuntimeError(f"real gate calibration did not qualify: {label}")
    except BaseException as error:
        primary_error = error
    finally:
        if proxy is not None:
            with contextlib.suppress(BaseException):
                proxy.close()
        if runtime_started:
            try:
                runtime.stop()
            except BaseException as error:
                cleanup_errors.append(f"real gate runtime stop: {error}")
        try:
            _assert_workload_empty(layout)
        except BaseException as error:
            cleanup_errors.append(f"real gate workload cleanup: {error}")
    try:
        artifact_after = _verify_target_artifact(
            "rust-candidate", started_attestation, "after-real-gate-calibration"
        )
    except BaseException as error:
        if primary_error is None:
            primary_error = error
        else:
            primary_error.add_note(
                "post-calibration artifact verification also failed: "
                f"{type(error).__name__}: {error}"
            )
    else:
        if report is not None:
            report["binding"]["artifact_after"] = artifact_after
            report["sha256"] = _canonical_json_sha256(
                {key: value for key, value in report.items() if key != "sha256"}
            )
    if cleanup_errors:
        cleanup_error = RuntimeError("; ".join(cleanup_errors))
        if primary_error is None:
            primary_error = cleanup_error
        else:
            primary_error.add_note(str(cleanup_error))
    if primary_error is not None:
        raise primary_error
    if report is None:
        raise RuntimeError("real gate calibration produced no report")
    return report


def _run_target_tier(
    target: str,
    plan: BenchmarkPlan,
    layout: CgroupLayout,
    *,
    arm_ordinal: int,
    dns_port: int,
    dkim_private_key_bytes: bytes,
    disk_budget_bytes: int,
    started_attestation: dict[str, Any],
    quota_mount_root: Path | None,
    checkpoint_event: Callable[[dict[str, Any]], None],
    rust_filesystem_fsync: str | None = "on",
) -> dict[str, Any]:
    artifact_before = _verify_target_artifact(target, started_attestation, "before")
    checkpoint_event(
        {
            "event": "target_artifact_verified",
            "target": target,
            "tier": plan.label,
            "rust_filesystem_fsync": (
                rust_filesystem_fsync if target == "rust-candidate" else None
            ),
            "artifact": artifact_before,
        }
    )
    runtime = _runtime_for(
        target,
        plan,
        benchmark_cpu=layout.cpu,
        dns_port=dns_port,
        dkim_private_key_bytes=dkim_private_key_bytes,
        candidate_path=_attested_candidate_path(started_attestation),
        rust_filesystem_fsync=rust_filesystem_fsync,
    )
    proxy: RustSmtpProxy | None = None
    primary_error: BaseException | None = None
    cleanup_errors: list[str] = []
    output: dict[str, Any] | None = None
    artifact_after: dict[str, Any] | None = None
    quota_placement: dict[str, Any] | None = None
    dkim_fixture: dict[str, Any] | None = None
    runtime_started = False
    try:
        runtime.start()
        runtime_started = True
        if isinstance(runtime, BenchmarkDkimFixtureMixin):
            dkim_fixture = runtime._benchmark_dkim_fixture_attestation()
            checkpoint_event(
                {
                    "event": "dkim_fixture_attested",
                    "target": target,
                    "tier": plan.label,
                    "arm_ordinal": arm_ordinal,
                    "rust_filesystem_fsync": (
                        rust_filesystem_fsync if target == "rust-candidate" else None
                    ),
                    "dkim_fixture": dkim_fixture,
                }
            )
        if runtime.workspace is None:
            raise RuntimeError("started runtime did not expose its workspace")
        if quota_mount_root is not None:
            workspace = runtime.workspace.resolve(strict=True)
            mount_root = quota_mount_root.resolve(strict=True)
            workspace_device = workspace.stat().st_dev
            workspace_device_name = (
                f"{os.major(workspace_device)}:{os.minor(workspace_device)}"
            )
            if not workspace.is_relative_to(mount_root):
                raise RuntimeError(
                    f"runtime workspace escaped hard quota mount: {workspace}"
                )
            if workspace_device_name != layout.device:
                raise RuntimeError(
                    "runtime workspace device differs from the throttled quota device: "
                    f"{workspace_device_name} != {layout.device}"
                )
            quota_placement = {
                "workspace": str(workspace),
                "mount_root": str(mount_root),
                "device": workspace_device_name,
                "passed": True,
            }
        placement = _move_runtime_to_workload(runtime, layout)
        initial_state = _cleanup_state(runtime)
        if not _state_is_clean(initial_state):
            raise RuntimeError(
                f"isolated runtime did not start cleanly: {initial_state}"
            )
        proxy_run_id = (
            f"{target}-{plan.label.lower()}-arm-{arm_ordinal}-{uuid.uuid4().hex}"
        )
        proxy = RustSmtpProxy(
            runtime,
            binary=BENCHMARK_PROXY_BINARY,
            expected_sha256=str(started_attestation["benchmark_proxy_release_sha256"]),
            run_id=proxy_run_id,
            control_root=quota_mount_root,
        )
        record = _run_attested_round(
            runtime,
            proxy,
            layout,
            target=target,
            tier=plan.label,
            phase="measurement",
            ordinal=arm_ordinal,
            mode="PRODUCTION",
            count=plan.total_messages,
            message_bytes=plan.message_bytes,
            disk_budget_bytes=disk_budget_bytes,
            measured=True,
            started_attestation=started_attestation,
            checkpoint_event=checkpoint_event,
            # Measurement must preserve the frozen endpoint's SMTP timing. The
            # exact post-final Maildir/PostgreSQL/WAL/AOF barriers still gate
            # qualification without delaying or aborting the oracle's 250.
            persistence_gate_required=False,
            rust_filesystem_fsync=(
                rust_filesystem_fsync if target == "rust-candidate" else None
            ),
        )
        throughput = float(record["smtp"]["throughput_messages_per_second"])
        checkpoint_event(
            {
                "event": "measurement_arm_complete",
                "target": target,
                "tier": plan.label,
                "arm_ordinal": arm_ordinal,
                "rust_filesystem_fsync": (
                    rust_filesystem_fsync if target == "rust-candidate" else None
                ),
                "verified": record["smtp"]["verified"],
                "throughput_messages_per_second": throughput,
                "duration_seconds": record["smtp"]["duration_seconds"],
                "memory_peak_bytes": record["resource"]["memory_peak_bytes"],
                "rss_peak_bytes": record["resource"]["process_memory_by_role"]["total"][
                    "rss_peak_bytes"
                ],
                "fd_peak": record["resource"]["fd_peak"],
                "task_peak": record["resource"]["task_peak"],
                "queue_peak": record["resource"]["queue_peak"],
                "io_write_bytes": record["resource"]["io_write_bytes"],
                "application_io_write_bytes": record["resource"][
                    "application_io_write_bytes"
                ],
                "services_io_write_bytes": record["resource"][
                    "services_io_write_bytes"
                ],
                "application_cpu_usage_seconds": record["resource"][
                    "candidate_cpu_usage_seconds"
                ],
                "services_cpu_usage_seconds": record["resource"][
                    "services_cpu_usage_seconds"
                ],
                "temperature": record["resource"]["temperature"],
                "filesystem_delta_peak_bytes": record["resource"][
                    "filesystem_delta_peak_bytes"
                ],
            }
        )
        output = {
            "target": target,
            "rust_filesystem_fsync": (
                rust_filesystem_fsync if target == "rust-candidate" else None
            ),
            "arm_ordinal": arm_ordinal,
            "tier": {
                "label": plan.label,
                "message_bytes": plan.message_bytes,
                "total_messages": plan.total_messages,
            },
            "placement": placement,
            "quota_placement": quota_placement,
            "dkim_fixture": dkim_fixture,
            "initial_state": initial_state,
            "warmups": [],
            "measurement": record,
            "endpoint_start_invocations": 1,
            "endpoint_invocations": 1,
            "harness_batches": 0,
            "endpoint_requested_messages": plan.total_messages,
            "observer_verified_messages": int(record["smtp"]["verified"]),
            "requested_equals_observer_verified": (
                plan.total_messages == int(record["smtp"]["verified"])
            ),
            "throughput_messages_per_second": throughput,
            "proxy_identity": {
                "binary_sha256": proxy.binary_sha256,
                "source_tree_sha256": started_attestation[
                    "benchmark_proxy_source_tree_sha256"
                ],
            },
        }
    except BaseException as error:
        primary_error = error
    finally:
        if proxy is not None:
            try:
                proxy.close()
            except BaseException as error:
                cleanup_errors.append(f"SMTP proxy stop: {error}")
        if runtime_started:
            try:
                runtime.stop()
            except BaseException as error:
                cleanup_errors.append(f"runtime stop: {error}")
        try:
            _assert_workload_empty(layout)
        except BaseException as error:
            cleanup_errors.append(f"workload cgroup cleanup: {error}")
        try:
            artifact_after = _verify_target_artifact(
                target, started_attestation, "after"
            )
            checkpoint_event(
                {
                    "event": "target_artifact_verified",
                    "target": target,
                    "tier": plan.label,
                    "rust_filesystem_fsync": (
                        rust_filesystem_fsync if target == "rust-candidate" else None
                    ),
                    "artifact": artifact_after,
                }
            )
        except BaseException as error:
            cleanup_errors.append(f"target artifact after-run verification: {error}")
    if primary_error is not None:
        if cleanup_errors:
            primary_error.add_note("; ".join(cleanup_errors))
        raise primary_error
    if cleanup_errors:
        raise RuntimeError("; ".join(cleanup_errors))
    if output is None:
        raise RuntimeError("benchmark target produced no result")
    output["artifact"] = {"before": artifact_before, "after": artifact_after}
    return output


def _aggregate_arm_rows(
    arms: Sequence[dict[str, Any]],
    plans: Sequence[BenchmarkPlan],
    *,
    expected_ordinals: tuple[int, ...] = (0, 1),
) -> list[dict[str, Any]]:
    if (
        not expected_ordinals
        or tuple(sorted(set(expected_ordinals))) != expected_ordinals
    ):
        raise ValueError("expected arm ordinals must be unique and increasing")
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for arm in arms:
        key = (str(arm["target"]), str(arm["tier"]["label"]))
        grouped.setdefault(key, []).append(arm)
    rows: list[dict[str, Any]] = []
    target_order = ("java-oracle", "rust-candidate")
    for plan in plans:
        for target in target_order:
            values = grouped.get((target, plan.label))
            if not values:
                continue
            values = sorted(values, key=lambda value: int(value["arm_ordinal"]))
            ordinals = [int(value["arm_ordinal"]) for value in values]
            if ordinals != list(expected_ordinals):
                raise RuntimeError(
                    f"{target} {plan.label} arm ordinals changed: "
                    f"expected {list(expected_ordinals)}, got {ordinals}"
                )
            throughputs = [
                _finite_number(
                    value["throughput_messages_per_second"],
                    f"{target} {plan.label} arm throughput",
                    positive=True,
                )
                for value in values
            ]
            measurements = [value["measurement"] for value in values]
            rows.append(
                {
                    "target": target,
                    "tier": {
                        "label": plan.label,
                        "message_bytes": plan.message_bytes,
                        "total_messages": plan.total_messages,
                    },
                    "arm_count": len(values),
                    "arms": values,
                    "warmups": [],
                    "measurements": measurements,
                    "endpoint_start_invocations": sum(
                        int(value["endpoint_start_invocations"]) for value in values
                    ),
                    "endpoint_invocations": sum(
                        int(value["endpoint_invocations"]) for value in values
                    ),
                    "harness_batches": sum(
                        int(value["harness_batches"]) for value in values
                    ),
                    "requested_equals_observer_verified": all(
                        value["requested_equals_observer_verified"] is True
                        for value in values
                    ),
                    "throughput": {
                        "runs": throughputs,
                        "equally_weighted_arms": len(values) > 1,
                        "median_messages_per_second": round(
                            statistics.median(throughputs), 6
                        ),
                        "minimum_messages_per_second": round(min(throughputs), 6),
                        "maximum_messages_per_second": round(max(throughputs), 6),
                        "variation": _throughput_stability(throughputs),
                    },
                }
            )
    if sum(len(values) for values in grouped.values()) != sum(
        row["arm_count"] for row in rows
    ):
        raise RuntimeError("arm aggregation encountered an unknown target or tier")
    return rows


def _plans(
    *,
    smoke: bool,
    disk_budget_bytes: int,
    tier: str,
    profiler_messages: int | None = None,
) -> list[BenchmarkPlan]:
    if profiler_messages is not None:
        if smoke or tier != "10kb":
            raise ValueError("bounded profiler plans require non-smoke 10KB")
        return [BenchmarkPlan("10KB", 10 * 1024, profiler_messages)]
    if smoke:
        values = [
            BenchmarkPlan("1KB", 1 * 1024, 8),
            BenchmarkPlan("10KB", 10 * 1024, 8),
            BenchmarkPlan("10MB", 10 * 1024 * 1024, 2),
        ]
    else:
        large_size = 10 * 1024 * 1024
        large_count = (disk_budget_bytes // (large_size * 4) // 50) * 50
        large_count = max(50, min(1_000, large_count))
        values = [
            BenchmarkPlan("1KB", 1 * 1024, 500_000),
            BenchmarkPlan("10KB", 10 * 1024, 500_000),
            BenchmarkPlan("10MB", large_size, large_count),
        ]
    if tier == "all":
        return values
    label = {"1kb": "1KB", "10kb": "10KB", "10mb": "10MB"}[tier]
    return [value for value in values if value.label == label]


def _java_small_baseline_plans() -> tuple[BenchmarkPlan, ...]:
    return (
        BenchmarkPlan("1KB", 1 * 1024, 200_000),
        BenchmarkPlan("10KB", 10 * 1024, 200_000),
    )


def _targets(value: str) -> tuple[str, ...]:
    if value == "both":
        return ("java-oracle", "rust-candidate")
    if value == "java":
        return ("java-oracle",)
    if value == "rust":
        return ("rust-candidate",)
    raise ValueError(value)


def _execution_matrix(
    targets: Sequence[str], plans: Sequence[BenchmarkPlan]
) -> tuple[tuple[str, BenchmarkPlan, int], ...]:
    selected = set(targets)
    unknown = selected - {"java-oracle", "rust-candidate"}
    if unknown:
        raise ValueError(f"unknown benchmark targets: {sorted(unknown)}")
    output: list[tuple[str, BenchmarkPlan, int]] = []
    for plan in plans:
        if plan.label == "10MB":
            if "rust-candidate" in selected:
                output.extend(
                    (
                        ("rust-candidate", plan, 0),
                        ("rust-candidate", plan, 1),
                    )
                )
            continue
        for target, arm_ordinal in (
            ("java-oracle", 0),
            ("rust-candidate", 0),
            ("rust-candidate", 1),
            ("java-oracle", 1),
        ):
            if target in selected:
                output.append((target, plan, arm_ordinal))
    return tuple(output)


def _java_small_baseline_execution_matrix(
    plans: Sequence[BenchmarkPlan],
) -> tuple[tuple[str, BenchmarkPlan, int], ...]:
    expected = _java_small_baseline_plans()
    expected_by_label = {plan.label: plan for plan in expected}
    if not plans or any(plan != expected_by_label.get(plan.label) for plan in plans):
        raise ValueError("Java-small baseline plan contract changed")
    labels = [plan.label for plan in plans]
    if labels != [plan.label for plan in expected if plan.label in labels]:
        raise ValueError("Java-small baseline tier order changed")
    return tuple(("java-oracle", plan, 0) for plan in plans)


def _throughput_stability(values: Sequence[float]) -> dict[str, Any]:
    if not values:
        raise ValueError("throughput stability requires at least one run")
    finite_values = [
        _finite_number(value, f"throughput run {index}", positive=True)
        for index, value in enumerate(values)
    ]
    median = statistics.median(finite_values)
    deviations = [abs(value - median) for value in finite_values]
    mean = statistics.fmean(finite_values)
    standard_deviation = (
        statistics.pstdev(finite_values) if len(finite_values) > 1 else 0.0
    )
    return {
        "runs": len(finite_values),
        "all_runs_messages_per_second": finite_values,
        "mean_messages_per_second": round(mean, 6),
        "median_absolute_deviation": round(statistics.median(deviations), 6),
        "relative_median_absolute_deviation": round(
            statistics.median(deviations) / median if median > 0 else 0.0, 6
        ),
        "population_standard_deviation": round(standard_deviation, 6),
        "coefficient_of_variation": round(
            standard_deviation / mean if mean > 0 else 0.0, 6
        ),
        "relative_range": round((max(finite_values) - min(finite_values)) / median, 6),
    }


def _comparison(
    rows: Sequence[dict[str, Any]],
    *,
    smoke: bool,
    proxy_headroom: dict[str, Any] | None = None,
) -> dict[str, Any]:
    by_key = {(row["target"], row["tier"]["label"]): row for row in rows}
    tiers = sorted({row["tier"]["label"] for row in rows})
    comparisons: list[dict[str, Any]] = []
    pair_completeness_passed = bool(tiers)
    performance_passed = True
    for tier in tiers:
        java = by_key.get(("java-oracle", tier))
        rust = by_key.get(("rust-candidate", tier))
        if tier == "10MB":
            rust_by_ordinal = (
                {
                    int(arm["arm_ordinal"]): _finite_number(
                        arm["throughput_messages_per_second"],
                        f"{tier} Rust arm {arm['arm_ordinal']} throughput",
                        positive=True,
                    )
                    for arm in rust["arms"]
                }
                if rust is not None
                else {}
            )
            candidate_only_complete = bool(
                java is None and rust is not None and set(rust_by_ordinal) == {0, 1}
            )
            pair_completeness_passed = (
                pair_completeness_passed and candidate_only_complete
            )
            performance_passed = performance_passed and candidate_only_complete
            comparisons.append(
                {
                    "tier": tier,
                    "pair_complete": False,
                    "candidate_only_complete": candidate_only_complete,
                    "java_present": java is not None,
                    "rust_present": rust is not None,
                    "rust_arm_messages_per_second": rust_by_ordinal,
                    "java_comparison_intentionally_excluded": True,
                    "passed": candidate_only_complete,
                    "gate": (
                        "10MB is a Rust-only durability and stability tier; Java "
                        "10MB execution is prohibited because the oracle can hang"
                    ),
                }
            )
            continue
        if java is None or rust is None:
            pair_completeness_passed = False
            performance_passed = False
            comparisons.append(
                {
                    "tier": tier,
                    "pair_complete": False,
                    "java_present": java is not None,
                    "rust_present": rust is not None,
                    "passed": False,
                    "gate": "every tier requires a Java/Rust pair",
                }
            )
            continue
        java_median = _finite_number(
            java["throughput"]["median_messages_per_second"],
            f"{tier} Java median throughput",
            positive=True,
        )
        rust_median = _finite_number(
            rust["throughput"]["median_messages_per_second"],
            f"{tier} Rust median throughput",
            positive=True,
        )
        ratio = _finite_number(
            rust_median / java_median,
            f"{tier} Rust-to-Java throughput ratio",
            positive=True,
        )
        required_ratio = 0.95 if tier == "10MB" else MINIMUM_CLEAR_IMPROVEMENT
        java_by_ordinal = {
            int(arm["arm_ordinal"]): _finite_number(
                arm["throughput_messages_per_second"],
                f"{tier} Java arm {arm['arm_ordinal']} throughput",
                positive=True,
            )
            for arm in java["arms"]
        }
        rust_by_ordinal = {
            int(arm["arm_ordinal"]): _finite_number(
                arm["throughput_messages_per_second"],
                f"{tier} Rust arm {arm['arm_ordinal']} throughput",
                positive=True,
            )
            for arm in rust["arms"]
        }
        paired_complete = set(java_by_ordinal) == {0, 1} and set(rust_by_ordinal) == {
            0,
            1,
        }
        paired_ratios = (
            [
                _finite_number(
                    rust_by_ordinal[ordinal] / java_by_ordinal[ordinal],
                    f"{tier} paired arm {ordinal} Rust-to-Java ratio",
                    positive=True,
                )
                for ordinal in (0, 1)
            ]
            if paired_complete
            else []
        )
        conservative_ratio = _finite_number(
            min(rust_by_ordinal.values()) / max(java_by_ordinal.values()),
            f"{tier} conservative Rust-to-Java ratio",
            positive=True,
        )
        passed = smoke or (
            paired_complete
            and all(value >= required_ratio for value in paired_ratios)
            and conservative_ratio >= required_ratio
        )
        performance_passed = performance_passed and passed
        comparisons.append(
            {
                "tier": tier,
                "pair_complete": True,
                "java_median_messages_per_second": java_median,
                "rust_median_messages_per_second": rust_median,
                "rust_to_java_ratio": round(ratio, 6),
                "java_arm_messages_per_second": java_by_ordinal,
                "rust_arm_messages_per_second": rust_by_ordinal,
                "paired_ratios": [
                    {
                        "arm_ordinal": ordinal,
                        "rust_to_java_ratio": round(paired_ratios[ordinal], 6),
                        "passed": paired_ratios[ordinal] >= required_ratio,
                    }
                    for ordinal in range(len(paired_ratios))
                ],
                "conservative_min_rust_over_max_java_ratio": round(
                    conservative_ratio, 6
                ),
                "conservative_ratio_passed": conservative_ratio >= required_ratio,
                "required_ratio": required_ratio,
                "passed": passed,
                "gate": (
                    "both ordinal-paired ratios and min(Rust)/max(Java) must meet "
                    "the tier threshold; medians are reported but are not sufficient"
                ),
            }
        )
    arm_completeness_passed = bool(rows) and all(
        row.get("arm_count") == 2
        and row.get("endpoint_start_invocations") == 2
        and row.get("endpoint_invocations") == 2
        and row.get("harness_batches") == 0
        and row.get("requested_equals_observer_verified") is True
        and len(row.get("arms", ())) == 2
        and all(
            arm.get("endpoint_start_invocations") == 1
            and arm.get("endpoint_invocations") == 1
            and arm.get("harness_batches") == 0
            and arm.get("endpoint_requested_messages")
            == arm.get("observer_verified_messages")
            and arm.get("requested_equals_observer_verified") is True
            for arm in row["arms"]
        )
        for row in rows
    )
    measurement_evidence_passed = bool(rows) and all(
        row.get("measurements")
        and all(
            _round_contract_passed(measurement) for measurement in row["measurements"]
        )
        for row in rows
    )
    within_arm_stability_passed = bool(rows) and all(
        measurement.get("smtp", {})
        .get("within_arm_throughput_stability", {})
        .get("passed")
        is True
        for row in rows
        for measurement in row.get("measurements", ())
    )
    operational_evidence_passed = (
        arm_completeness_passed
        and measurement_evidence_passed
        and within_arm_stability_passed
    )
    abba_stability_gates: list[dict[str, Any]] = []
    for row in rows:
        values = [
            _finite_number(
                arm["throughput_messages_per_second"],
                f"{row['target']} {row['tier']['label']} arm throughput",
                positive=True,
            )
            for arm in row.get("arms", ())
        ]
        observed = _throughput_stability(values)
        recorded = row.get("throughput", {}).get("variation")
        if recorded != observed:
            raise RuntimeError("ABBA arm variation evidence does not match raw arms")
        passed = smoke or (
            observed["runs"] == 2
            and observed["relative_range"] <= MAXIMUM_ABBA_ARM_RELATIVE_RANGE
        )
        abba_stability_gates.append(
            {
                "target": row["target"],
                "tier": row["tier"]["label"],
                "raw_arm_messages_per_second": values,
                "maximum_relative_range": MAXIMUM_ABBA_ARM_RELATIVE_RANGE,
                "observed": observed,
                "passed": passed,
            }
        )
    abba_stability_passed = bool(abba_stability_gates) and all(
        gate["passed"] for gate in abba_stability_gates
    )
    proxy_headroom_gates: list[dict[str, Any]] = []
    proxy_headroom_passed = smoke
    if proxy_headroom is not None:
        proxy_tiers = proxy_headroom.get("tiers")
        if not isinstance(proxy_tiers, dict):
            raise RuntimeError("proxy headroom evidence omitted its tier map")
        proxy_headroom_passed = bool(rows)
        for tier in tiers:
            tier_rows = [row for row in rows if row["tier"]["label"] == tier]
            maximum_arm_throughput = max(
                _finite_number(
                    arm["throughput_messages_per_second"],
                    f"{tier} maximum observed arm throughput",
                    positive=True,
                )
                for row in tier_rows
                for arm in row["arms"]
            )
            tier_evidence = proxy_tiers.get(tier)
            if not isinstance(tier_evidence, dict):
                raise RuntimeError(f"proxy headroom evidence is missing for {tier}")
            sustained = _finite_number(
                tier_evidence.get("sustained_messages_per_second"),
                f"{tier} sustained proxy capacity",
                positive=True,
            )
            observed_ratio = sustained / maximum_arm_throughput
            passed = observed_ratio >= MINIMUM_PROXY_HEADROOM_RATIO
            proxy_headroom_passed = proxy_headroom_passed and passed
            proxy_headroom_gates.append(
                {
                    "tier": tier,
                    "sustained_proxy_messages_per_second": sustained,
                    "maximum_observed_arm_messages_per_second": maximum_arm_throughput,
                    "observed_headroom_ratio": round(observed_ratio, 6),
                    "required_headroom_ratio": MINIMUM_PROXY_HEADROOM_RATIO,
                    "attested_ratio_ignored": tier_evidence.get(
                        "sustained_headroom_ratio"
                    ),
                    "passed": passed,
                }
            )
    all_passed = (
        pair_completeness_passed
        and performance_passed
        and operational_evidence_passed
        and abba_stability_passed
    )
    return {
        "comparisons": comparisons,
        "all_passed": all_passed,
        "required_topology_passed": pair_completeness_passed,
        "pair_completeness_passed": pair_completeness_passed,
        "performance_passed": performance_passed,
        "operational_evidence_passed": operational_evidence_passed,
        "arm_completeness_passed": arm_completeness_passed,
        "measurement_evidence_passed": measurement_evidence_passed,
        "within_arm_stability_passed": within_arm_stability_passed,
        "zero_retry_gate_passed": all(
            record["endpoint_outcome"]["retry_count"] == 0
            for row in rows
            for record in row.get("measurements", ())
        ),
        "abba_stability_passed": abba_stability_passed,
        "abba_stability_gates": abba_stability_gates,
        "proxy_headroom_passed": proxy_headroom_passed,
        "proxy_headroom_gates": proxy_headroom_gates,
        "primary_tier": "10KB",
        "remembered_java_reference_messages_per_second": 1_500,
        "remembered_reference_is_not_the_gate": True,
    }


def _java_small_baseline_comparison(
    rows: Sequence[dict[str, Any]], plans: Sequence[BenchmarkPlan]
) -> dict[str, Any]:
    expected_plans = tuple(plans)
    _java_small_baseline_execution_matrix(expected_plans)
    expected_labels = [plan.label for plan in expected_plans]
    observed_labels = [str(row.get("tier", {}).get("label")) for row in rows]
    plan_order_passed = observed_labels == expected_labels
    comparisons: list[dict[str, Any]] = []
    for plan, row in zip(expected_plans, rows, strict=False):
        arms = row.get("arms") if isinstance(row, dict) else None
        arm = arms[0] if isinstance(arms, list) and len(arms) == 1 else None
        measurement = arm.get("measurement") if isinstance(arm, dict) else None
        outcome = (
            measurement.get("endpoint_outcome")
            if isinstance(measurement, dict)
            else None
        )
        throughput = _finite_number(
            row.get("throughput", {}).get("median_messages_per_second"),
            f"{plan.label} Java-small baseline throughput",
            positive=True,
        )
        passed = bool(
            row.get("target") == "java-oracle"
            and row.get("tier")
            == {
                "label": plan.label,
                "message_bytes": plan.message_bytes,
                "total_messages": plan.total_messages,
            }
            and row.get("arm_count") == 1
            and row.get("endpoint_start_invocations") == 1
            and row.get("endpoint_invocations") == 1
            and row.get("harness_batches") == 0
            and row.get("requested_equals_observer_verified") is True
            and isinstance(arm, dict)
            and arm.get("arm_ordinal") == 0
            and arm.get("endpoint_requested_messages") == plan.total_messages
            and arm.get("observer_verified_messages") == plan.total_messages
            and arm.get("requested_equals_observer_verified") is True
            and arm.get("endpoint_start_invocations") == 1
            and arm.get("endpoint_invocations") == 1
            and arm.get("harness_batches") == 0
            and isinstance(measurement, dict)
            and _round_contract_passed(measurement)
            and isinstance(outcome, dict)
            and outcome.get("failure_count") == 0
            and outcome.get("retry_count") == 0
            and outcome.get("queue_scheduler_observed") is True
        )
        comparisons.append(
            {
                "tier": plan.label,
                "target": "java-oracle",
                "requested_messages": plan.total_messages,
                "observer_verified_messages": (
                    arm.get("observer_verified_messages")
                    if isinstance(arm, dict)
                    else None
                ),
                "throughput_messages_per_second": round(throughput, 6),
                "single_endpoint_invocation": True,
                "queue_scheduler_observed": (
                    outcome.get("queue_scheduler_observed")
                    if isinstance(outcome, dict)
                    else False
                ),
                "passed": passed,
            }
        )
    row_count_passed = len(rows) == len(expected_plans)
    operational_evidence_passed = row_count_passed and all(
        comparison["passed"] for comparison in comparisons
    )
    zero_retry_gate_passed = row_count_passed and all(
        arm.get("measurement", {}).get("endpoint_outcome", {}).get("retry_count") == 0
        for row in rows
        for arm in row.get("arms", ())
    )
    return {
        "comparisons": comparisons,
        "all_passed": (
            row_count_passed
            and plan_order_passed
            and operational_evidence_passed
            and zero_retry_gate_passed
        ),
        "baseline_complete_passed": row_count_passed and plan_order_passed,
        "plan_order_passed": plan_order_passed,
        "operational_evidence_passed": operational_evidence_passed,
        "zero_retry_gate_passed": zero_retry_gate_passed,
        "java_only_passed": row_count_passed
        and all(row.get("target") == "java-oracle" for row in rows),
        "single_arm_per_tier_passed": row_count_passed
        and all(row.get("arm_count") == 1 for row in rows),
        "ten_megabyte_excluded": all(
            row.get("tier", {}).get("message_bytes", 0) < 10 * 1024 * 1024
            for row in rows
        ),
        "remembered_java_reference_messages_per_second": 1_500,
        "remembered_reference_is_not_the_gate": True,
    }


def _hardware_evidence(layout: CgroupLayout) -> dict[str, Any]:
    cpuinfo = Path("/proc/cpuinfo").read_text(encoding="ascii", errors="replace")
    model = next(
        (
            line.split(":", 1)[1].strip()
            for line in cpuinfo.splitlines()
            if line.startswith("model name")
        ),
        "unknown",
    )
    mount = subprocess.run(
        ["findmnt", "-T", str(REPOSITORY), "-n", "-o", "SOURCE,FSTYPE,MAJ:MIN"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return {
        "platform": platform.platform(),
        "kernel": platform.release(),
        "machine": platform.machine(),
        "cpu_model": model,
        "visible_logical_cpus": os.cpu_count(),
        "selected_logical_cpu": layout.cpu,
        "workspace_mount": mount,
        "cgroup": layout.snapshot(),
    }


def _git_value(*arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=REPOSITORY,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _definition_attestation() -> dict[str, Any]:
    source_root = (REPOSITORY / "blackbox/src").resolve(strict=True)
    sources: dict[str, dict[str, Any]] = {}

    def add_source(path: Path, origin: str) -> None:
        resolved = path.resolve(strict=True)
        if not resolved.is_file():
            raise RuntimeError(f"benchmark definition source is not a file: {resolved}")
        relative = resolved.relative_to(REPOSITORY).as_posix()
        entry = sources.setdefault(
            relative,
            {
                "path": relative,
                "bytes": resolved.stat().st_size,
                "sha256": _sha256_file(resolved),
                "origins": [],
            },
        )
        if origin not in entry["origins"]:
            entry["origins"].append(origin)

    def add_tree(path: Path, origin: str) -> None:
        root = path.resolve(strict=True)
        if not root.is_dir() or not root.is_relative_to(REPOSITORY):
            raise RuntimeError(f"benchmark definition tree is invalid: {root}")
        for directory, directory_names, file_names in os.walk(root, followlinks=False):
            current = Path(directory)
            for name in directory_names:
                candidate = current / name
                if candidate.is_symlink():
                    raise RuntimeError(
                        f"benchmark definition tree contains a symlink: {candidate}"
                    )
            directory_names[:] = sorted(
                name for name in directory_names if name != "__pycache__"
            )
            for name in sorted(file_names):
                candidate = current / name
                if candidate.is_symlink():
                    raise RuntimeError(
                        f"benchmark definition tree contains a symlink: {candidate}"
                    )
                if candidate.suffix in {".pyc", ".pyo"}:
                    continue
                add_source(candidate, origin)

    add_source(V2_SOURCE, "smtp-self-stress-v2")
    add_source(Path(v2.BASE_SOURCE), "smtp-self-stress-v1")
    add_source(Path(__file__), "smtp-endpoint-throughput-runner")
    add_source(
        Path(__file__).with_name("run-smtp-endpoint-throughput-v1.sh"),
        "smtp-endpoint-throughput-launcher",
    )
    add_source(JAVA_FROZEN_CONFIG, "java-frozen-production-configuration")
    add_tree(REPOSITORY / "blackbox/src/lmyzmail_blackbox", "blackbox-source-tree")
    add_tree(REPOSITORY / "blackbox/fixtures", "blackbox-fixtures")
    add_tree(REPOSITORY / "blackbox/manifests", "blackbox-manifests")
    add_tree(REPOSITORY / "config", "runtime-config-resources")
    add_tree(BENCHMARK_PROXY_SOURCE, "benchmark-proxy-source-tree")
    for name, module in sorted(sys.modules.items()):
        if name != "lmyzmail_blackbox" and not name.startswith("lmyzmail_blackbox."):
            continue
        origin = getattr(getattr(module, "__spec__", None), "origin", None)
        if not isinstance(origin, str) or origin in {"built-in", "frozen"}:
            continue
        source = Path(origin)
        if source.suffix in {".pyc", ".pyo"}:
            source = Path(importlib.util.source_from_cache(str(source)))
        resolved = source.resolve(strict=True)
        if not resolved.is_relative_to(source_root):
            raise RuntimeError(
                f"loaded black-box helper escaped its source tree: {name}={resolved}"
            )
        add_source(resolved, name)
    ordered = sorted(sources.values(), key=lambda entry: entry["path"])
    for entry in ordered:
        entry["origins"].sort()
    proxy_sources = [
        {
            "path": entry["path"],
            "bytes": entry["bytes"],
            "sha256": entry["sha256"],
        }
        for entry in ordered
        if "benchmark-proxy-source-tree" in entry["origins"]
    ]
    proxy_canonical = json.dumps(
        proxy_sources,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    canonical = json.dumps(
        ordered,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return {
        "profile": "lmyzmail-smtp-throughput-definition-v1",
        "source_files": ordered,
        "source_file_count": len(ordered),
        "sha256": hashlib.sha256(canonical).hexdigest(),
        "benchmark_proxy_source_tree": {
            "path": BENCHMARK_PROXY_SOURCE.relative_to(REPOSITORY).as_posix(),
            "source_files": proxy_sources,
            "source_file_count": len(proxy_sources),
            "sha256": hashlib.sha256(proxy_canonical).hexdigest(),
        },
    }


def _cgroup_mount_is_read_only() -> bool:
    expected = Path("/sys/fs/cgroup")
    for line in Path("/proc/self/mountinfo").read_text(encoding="ascii").splitlines():
        left, separator, right = line.partition(" - ")
        fields = left.split()
        filesystem = right.split()
        if not separator or len(fields) < 6 or len(filesystem) < 3:
            continue
        if Path(fields[4]) != expected:
            continue
        return "ro" in fields[5].split(",") or "ro" in filesystem[2].split(",")
    return False


def _nofile_evidence(layout: CgroupLayout) -> dict[str, Any]:
    resource_module = importlib.import_module("resource")
    soft, hard = resource_module.getrlimit(resource_module.RLIMIT_NOFILE)
    passed = soft == hard == layout.nofile_limit
    if not passed:
        raise RuntimeError(
            f"NOFILE limit differs from benchmark policy: {(soft, hard)} != "
            f"{layout.nofile_limit}"
        )
    return {"soft": soft, "hard": hard, "passed": True}


def _runner_process_hardening(*, apply: bool) -> dict[str, Any]:
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    prctl.restype = ctypes.c_int
    if apply:
        if prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        status = Path("/proc/self/status").read_text(encoding="ascii")
        bounding = int(
            next(
                line.split()[1]
                for line in status.splitlines()
                if line.startswith("CapBnd:")
            ),
            16,
        )
        if bounding & (1 << CAP_SYS_PTRACE):
            if prctl(PR_CAPBSET_DROP, CAP_SYS_PTRACE, 0, 0, 0) != 0:
                error = ctypes.get_errno()
                raise OSError(error, os.strerror(error))
    dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0)
    if dumpable < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    status = Path("/proc/self/status").read_text(encoding="ascii")
    bounding = int(
        next(
            line.split()[1]
            for line in status.splitlines()
            if line.startswith("CapBnd:")
        ),
        16,
    )
    passed = dumpable == 0 and not bounding & (1 << CAP_SYS_PTRACE)
    if not passed:
        raise RuntimeError(
            "benchmark runner remained ptrace-accessible to candidate children"
        )
    return {
        "dumpable": dumpable,
        "cap_sys_ptrace_in_bounding_set": bool(bounding & (1 << CAP_SYS_PTRACE)),
        "passed": True,
    }


def _isolation_policy_attestation(
    layout: CgroupLayout, *, smoke: bool, disk_budget_bytes: int
) -> dict[str, Any]:
    expected = {
        "schema_version": 1,
        "profile": "lmyzmail-smtp-throughput-formal-isolation-v1",
        "image_bytes": FORMAL_DISK_BUDGET_BYTES,
        "minimum_host_reserve_bytes": FORMAL_HOST_RESERVE_BYTES,
        "io_bytes_per_second_per_device": FORMAL_IO_BYTES_PER_SECOND,
        "io_devices": "loop-and-backing",
        "memory_max_bytes": FORMAL_MAX_MEMORY_BYTES,
        "memory_swap_max_bytes": 0,
        "pids_max": FORMAL_MAX_PIDS,
        "nofile_soft_and_hard": FORMAL_NOFILE_LIMIT,
        "application_cpu_count": 1,
        "housekeeping_excludes_application_cpu": True,
        "role_topology": {
            "application": "workload",
            "postgres": "services",
            "redis": "services",
            "runner_and_proxy": "harness",
            "watchdog_and_supervisor": "persistent-housekeeping",
        },
        "cgroup_control_owner": "host-root",
        "runtime_cgroupfs": "read-only-bind-mount",
        "runner_process": "non-dumpable-without-CAP_SYS_PTRACE",
    }
    canonical = json.dumps(
        expected, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    nofile = _nofile_evidence(layout)
    runner_hardening = _runner_process_hardening(apply=False)
    cgroupfs_read_only = _cgroup_mount_is_read_only()
    observed = {
        "profile": "smoke" if smoke else "formal",
        "image_bytes": disk_budget_bytes,
        "host_reserve_bytes": layout.host_reserve_bytes,
        "io_bytes_per_second_per_device": layout.io_bytes_per_second,
        "memory_max_bytes": layout.max_memory_bytes,
        "memory_swap_max_bytes": int(
            (layout.parent / "memory.swap.max").read_text(encoding="ascii").strip()
        ),
        "pids_max": layout.max_pids,
        "nofile": nofile,
        "application_cpus": [layout.cpu],
        "housekeeping_cpus": list(layout.housekeeping_cpus),
        "cgroupfs_read_only": cgroupfs_read_only,
        "root_only_cgroup_control_verified": True,
        "runner_process_hardening": runner_hardening,
    }
    formal_policy_matched = bool(
        not smoke
        and disk_budget_bytes == FORMAL_DISK_BUDGET_BYTES
        and layout.host_reserve_bytes >= FORMAL_HOST_RESERVE_BYTES
        and layout.io_bytes_per_second == FORMAL_IO_BYTES_PER_SECOND
        and layout.max_memory_bytes == FORMAL_MAX_MEMORY_BYTES
        and layout.max_pids == FORMAL_MAX_PIDS
        and layout.nofile_limit == FORMAL_NOFILE_LIMIT
        and layout.cpu not in layout.housekeeping_cpus
        and len({layout.cpu}) == 1
        and cgroupfs_read_only
        and runner_hardening["passed"]
    )
    return {
        "expected": expected,
        "observed": observed,
        "canonical_policy_sha256": hashlib.sha256(canonical).hexdigest(),
        "formal_policy_matched": formal_policy_matched,
        "passed": formal_policy_matched,
    }


def _attestation(
    layout: CgroupLayout,
    *,
    smoke: bool,
    disk_budget_bytes: int,
    candidate: Path = CANDIDATE_RELEASE,
    rust_filesystem_fsync: str | None = None,
) -> dict[str, Any]:
    if candidate not in (CANDIDATE_RELEASE, CANDIDATE_PROFILING_RELEASE):
        raise RuntimeError(f"candidate is not an allowed fixed artifact: {candidate}")
    oracle = REPOSITORY / "oracle/artifacts/lmyzmail-java-oracle.jar"
    manifest_path = REPOSITORY / "evidence/freeze/java-oracle/baseline.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected_oracle = str(manifest["oracle_jar"]["selected_sha256"]).lower()
    actual_oracle = _sha256_file(oracle)
    if actual_oracle != expected_oracle:
        raise RuntimeError(
            f"Java oracle hash changed: {actual_oracle}; expected {expected_oracle}"
        )
    status = _git_value("status", "--porcelain=v1", "--untracked-files=all")
    definition = _definition_attestation()
    return {
        "captured_at_unix_seconds": int(time.time()),
        "host_boot_id": Path("/proc/sys/kernel/random/boot_id")
        .read_text(encoding="ascii")
        .strip(),
        "git_head": _git_value("rev-parse", "HEAD"),
        "git_status_sha256": hashlib.sha256(status.encode("utf-8")).hexdigest(),
        "git_status_entries": len(status.splitlines()),
        "candidate_release_path": candidate.relative_to(REPOSITORY).as_posix(),
        "candidate_release_profile": (
            "release-with-debug"
            if candidate == CANDIDATE_PROFILING_RELEASE
            else "release"
        ),
        "candidate_release_sha256": _sha256_file(candidate),
        "rust_filesystem_fsync": rust_filesystem_fsync,
        "benchmark_proxy_release_sha256": _sha256_file(BENCHMARK_PROXY_BINARY),
        "java_oracle_sha256": actual_oracle,
        "java_oracle_expected_sha256": expected_oracle,
        "java_manifest_sha256": _sha256_file(manifest_path),
        "cargo_lock_sha256": _sha256_file(REPOSITORY / "Cargo.lock"),
        "benchmark_definition": definition,
        "isolation_policy": _isolation_policy_attestation(
            layout, smoke=smoke, disk_budget_bytes=disk_budget_bytes
        ),
        "runner_sha256": _sha256_file(Path(__file__).resolve()),
        "launcher_sha256": _sha256_file(
            Path(__file__).with_name("run-smtp-endpoint-throughput-v1.sh")
        ),
        "benchmark_proxy_source_tree_sha256": definition["benchmark_proxy_source_tree"][
            "sha256"
        ],
    }


def _verify_definition_attestation(started: dict[str, Any]) -> dict[str, Any]:
    current = _definition_attestation()
    expected = started["benchmark_definition"]
    if current != expected:
        raise RuntimeError(
            "benchmark definition sources changed or new helpers were imported "
            "after the started attestation"
        )
    proxy_sha256 = _sha256_file(BENCHMARK_PROXY_BINARY)
    if proxy_sha256 != started["benchmark_proxy_release_sha256"]:
        raise RuntimeError("benchmark proxy release binary changed after attestation")
    return {
        "sha256": current["sha256"],
        "source_file_count": current["source_file_count"],
        "benchmark_proxy_release_sha256": proxy_sha256,
        "benchmark_proxy_source_tree_sha256": current["benchmark_proxy_source_tree"][
            "sha256"
        ],
        "unchanged": True,
    }


def _host_id_is_mapped(mapping: str, host_id: int) -> bool:
    for line in mapping.splitlines():
        fields = line.split()
        if len(fields) != 3 or not all(field.isdigit() for field in fields):
            raise RuntimeError("benchmark user namespace ID map is invalid")
        _, outside, length = (int(field) for field in fields)
        if length <= 0:
            raise RuntimeError("benchmark user namespace ID map is empty")
        if outside <= host_id < outside + length:
            return True
    return False


def _unmapped_host_root_identity() -> tuple[int, int]:
    uid_map = Path("/proc/self/uid_map").read_text(encoding="ascii")
    gid_map = Path("/proc/self/gid_map").read_text(encoding="ascii")
    if _host_id_is_mapped(uid_map, 0) or _host_id_is_mapped(gid_map, 0):
        raise RuntimeError("host root must remain unmapped in the benchmark namespace")
    overflow_uid = int(
        Path("/proc/sys/kernel/overflowuid").read_text(encoding="ascii").strip()
    )
    overflow_gid = int(
        Path("/proc/sys/kernel/overflowgid").read_text(encoding="ascii").strip()
    )
    if overflow_uid <= 0 or overflow_gid <= 0:
        raise RuntimeError("kernel overflow identity is invalid")
    return overflow_uid, overflow_gid


def _validate_external_metadata(
    metadata: os.stat_result,
    *,
    expected_uid: int,
    expected_gid: int,
    kind: str,
) -> None:
    if metadata.st_uid != expected_uid or metadata.st_gid != expected_gid:
        raise RuntimeError(f"external prerequisite {kind} is not host-root-owned")
    if kind == "directory":
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & 0o022:
            raise RuntimeError(
                "external prerequisite directory is not a protected directory"
            )
        return
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o222:
        raise RuntimeError("external prerequisite is not an immutable regular file")
    if metadata.st_nlink != 1:
        raise RuntimeError("external prerequisite must have one filesystem link")


def _canonical_json_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _proxy_shutdown_evidence_is_valid(proxy: dict[str, Any]) -> bool:
    integer_fields = (
        proxy.get("active_connections"),
        proxy.get("shutdown_grace_ns"),
        proxy.get("shutdown_wait_ns"),
        proxy.get("shutdown_forced_connections"),
    )
    if any(
        isinstance(value, bool) or not isinstance(value, int)
        for value in integer_fields
    ):
        return False
    active, grace_ns, wait_ns, forced = integer_fields
    exceeded = proxy.get("shutdown_grace_exceeded")
    if not isinstance(exceeded, bool):
        return False
    if active != 0 or grace_ns <= 0 or wait_ns < 0 or forced < 0:
        return False
    if exceeded:
        return forced > 0 and wait_ns >= grace_ns
    return forced == 0


def _proxy_memory_evidence_is_valid(proxy: dict[str, Any]) -> bool:
    fields = (
        proxy.get("pump_buffer_bytes"),
        proxy.get("configured_max_connections"),
        proxy.get("backend_reply_block_limit_bytes"),
        proxy.get("accounted_backend_reply_buffer_bytes"),
        proxy.get("memory_permit_quantum_bytes"),
        proxy.get("memory_budget_bytes"),
        proxy.get("usable_memory_budget_bytes"),
        proxy.get("required_memory_budget_bytes"),
        proxy.get("memory_budget_headroom_bytes"),
        proxy.get("accounted_connection_bytes"),
        proxy.get("observer_round_reserve_bytes"),
        proxy.get("control_runtime_reserve_bytes"),
    )
    if any(isinstance(value, bool) or not isinstance(value, int) for value in fields):
        return False
    (
        pump_buffer_bytes,
        configured_max_connections,
        block_limit_bytes,
        accounted_reply_buffer_bytes,
        permit_quantum_bytes,
        memory_budget_bytes,
        usable_memory_budget_bytes,
        required_memory_budget_bytes,
        memory_budget_headroom_bytes,
        accounted_connection_bytes,
        observer_round_reserve_bytes,
        control_runtime_reserve_bytes,
    ) = fields
    positive_fields = fields[:8] + fields[9:]
    if any(value <= 0 for value in positive_fields) or memory_budget_headroom_bytes < 0:
        return False
    expected_reply_buffer_bytes = 1 << (block_limit_bytes - 1).bit_length()
    expected_usable_budget_bytes = (
        memory_budget_bytes // permit_quantum_bytes * permit_quantum_bytes
    )
    expected_required_budget_bytes = (
        accounted_connection_bytes * configured_max_connections
        + observer_round_reserve_bytes
        + control_runtime_reserve_bytes
    )
    return bool(
        pump_buffer_bytes == 64 * 1024
        and block_limit_bytes == 128 * 1024
        and accounted_reply_buffer_bytes == expected_reply_buffer_bytes
        and permit_quantum_bytes == 64 * 1024
        and accounted_connection_bytes % permit_quantum_bytes == 0
        and observer_round_reserve_bytes % permit_quantum_bytes == 0
        and control_runtime_reserve_bytes % permit_quantum_bytes == 0
        and accounted_connection_bytes
        >= 2 * pump_buffer_bytes + accounted_reply_buffer_bytes
        and usable_memory_budget_bytes == expected_usable_budget_bytes
        and required_memory_budget_bytes == expected_required_budget_bytes
        and memory_budget_headroom_bytes
        == usable_memory_budget_bytes - required_memory_budget_bytes
        and memory_budget_headroom_bytes >= 0
    )


def _validate_gate_overhead_calibration(
    gate: Any,
    *,
    label: str,
    message_bytes: int,
    expected_environment: dict[str, Any],
    proxy: dict[str, Any],
) -> str:
    expected_shapes = {
        "1KB": (24_000, 1_500),
        "10KB": (8_000, 1_000),
        "10MB": (100, 20),
    }
    messages, concurrency = expected_shapes[label]
    if not isinstance(gate, dict):
        raise RuntimeError(f"gate overhead calibration is missing: {label}")
    sequence = ["off", "on", "on", "off", "on", "off", "off", "on"]
    off_rounds = gate.get("off_rounds")
    on_rounds = gate.get("on_rounds")
    if not isinstance(off_rounds, list) or not isinstance(on_rounds, list):
        raise RuntimeError(f"gate overhead raw rounds are missing: {label}")
    if len(off_rounds) != 4 or len(on_rounds) != 4:
        raise RuntimeError(f"gate overhead raw round count changed: {label}")

    def rates(rounds: list[Any], mode: str) -> list[float]:
        values: list[float] = []
        for ordinal, round_ in enumerate(rounds):
            if not isinstance(round_, dict):
                raise RuntimeError(f"gate overhead raw round is invalid: {label}")
            measurement = round_.get("measurement")
            observer = round_.get("observer")
            raw_proxy = round_.get("proxy")
            if not all(
                isinstance(value, dict) for value in (measurement, observer, raw_proxy)
            ):
                raise RuntimeError(f"gate overhead raw proof is incomplete: {label}")
            duration_ns = measurement.get("duration_ns")
            rate = _finite_number(
                measurement.get("messages_per_second"),
                f"{label} gate {mode} raw rate",
                positive=True,
            )
            if (
                isinstance(duration_ns, bool)
                or not isinstance(duration_ns, int)
                or duration_ns <= 0
                or measurement.get("messages") != messages
                or measurement.get("message_bytes") != message_bytes
                or not math.isclose(rate, messages * 1_000_000_000 / duration_ns)
                or isinstance(measurement.get("process_scheduled_cpu_ns"), bool)
                or not isinstance(measurement.get("process_scheduled_cpu_ns"), int)
                or measurement.get("process_scheduled_cpu_ns") < 0
                or round_.get("mode") != mode
                or round_.get("mode_ordinal") != ordinal
                or round_.get("sequence_index")
                != [index for index, value in enumerate(sequence) if value == mode][
                    ordinal
                ]
                or observer.get("qualification") is not True
                or observer.get("expected") != messages
                or observer.get("verified") != messages
                or observer.get("missing") != 0
                or observer.get("duplicates") != 0
                or not isinstance(observer.get("persistence_gate"), dict)
                or observer["persistence_gate"].get("required") is (mode == "off")
                or observer["persistence_gate"].get("qualified") is not True
                or raw_proxy.get("failed_connections") != 0
                or raw_proxy.get("active_connections") != 0
                or not _proxy_memory_evidence_is_valid(raw_proxy)
            ):
                raise RuntimeError(f"gate overhead raw round did not qualify: {label}")
            values.append(rate)
        return values

    off_rates = rates(off_rounds, "off")
    on_rates = rates(on_rounds, "on")
    off_median = statistics.median(off_rates)
    on_median = statistics.median(on_rates)
    off_spread = (max(off_rates) - min(off_rates)) / off_median
    on_spread = (max(on_rates) - min(on_rates)) / on_median
    paired = [on_rates[index] / off_rates[index] for index in range(4)]
    gate_timings: list[tuple[float, int, int]] = []
    for round_ in on_rounds:
        measurement = round_["measurement"]
        persistence = round_["observer"]["persistence_gate"]
        snapshot = persistence.get("snapshot")
        triggered = persistence.get("triggered_at_proxy_monotonic_ns")
        released = persistence.get("release_received_at_proxy_monotonic_ns")
        forwarding_started = persistence.get("forwarding_started_at_proxy_monotonic_ns")
        forwarding_completed = persistence.get(
            "forwarding_completed_at_proxy_monotonic_ns"
        )
        gate_hold_ns = persistence.get("gate_hold_ns")
        timing_fields = (
            triggered,
            released,
            forwarding_started,
            forwarding_completed,
            gate_hold_ns,
        )
        if (
            any(
                isinstance(value, bool) or not isinstance(value, int) or value < 0
                for value in timing_fields
            )
            or not triggered <= released <= forwarding_started <= forwarding_completed
            or gate_hold_ns != released - triggered
            or persistence.get("proxy_clock_domain") != "observer_origin_elapsed"
            or persistence.get("status") != "forwarded"
            or not isinstance(snapshot, dict)
            or snapshot.get("clock_id") != "CLOCK_MONOTONIC"
            or snapshot.get("snapshot_started_monotonic_ns") != 1
            or snapshot.get("snapshot_completed_monotonic_ns") != 2
            or snapshot.get("postgres_query_duration_ns") != 0
            or snapshot.get("maildir_snapshot_duration_ns") != 0
            or snapshot.get("transaction_isolation") != "repeatable_read"
            or snapshot.get("transaction_read_only") is not True
            or snapshot.get("expected_messages") != messages
            or snapshot.get("postgres_before_rows") != 0
            or snapshot.get("postgres_rows") != messages
            or snapshot.get("postgres_expected_rows") != messages
            or snapshot.get("postgres_row_delta") != messages
            or snapshot.get("maildir_atomic_rename_publications") != messages
            or snapshot.get("qualified") is not True
        ):
            raise RuntimeError(f"gate overhead timing evidence is invalid: {label}")
        gate_timings.append(
            (
                gate_hold_ns / measurement["duration_ns"],
                forwarding_started - released,
                forwarding_completed - forwarding_started,
            )
        )
    maximum_gate_hold_fraction = max(timing[0] for timing in gate_timings)
    maximum_release_to_forwarding_ns = max(timing[1] for timing in gate_timings)
    maximum_forwarding_ns = max(timing[2] for timing in gate_timings)
    expected_binding = {
        "common": {
            "runner_sha256": proxy.get("runner_sha256"),
            "binary_sha256": proxy.get("binary_sha256"),
            "source_tree_sha256": proxy.get("source_tree_sha256"),
            "host_boot_id": expected_environment["host_boot_id"],
            "benchmark_cpu": expected_environment["benchmark_cpu"],
            "calibration_cpus": expected_environment["calibration_cpus"],
            "cgroup_parent": expected_environment["cgroup_parent"],
            "process_cgroup": expected_environment["process_cgroup"],
            "io_max_sha256": expected_environment["io_max_sha256"],
            "nofile_soft_and_hard": expected_environment["nofile_soft_and_hard"],
        },
        "tier": label,
        "message_bytes": message_bytes,
        "messages": messages,
        "concurrency": concurrency,
    }
    if not (
        gate.get("schema_version") == 2
        and gate.get("profile") == "lmyzmail-persistence-gate-overhead-calibration-v2"
        and gate.get("qualification_basis") == "direct-gate-timing"
        and gate.get("synthetic_no_postgres_or_maildir") is True
        and gate.get("messages") == messages
        and gate.get("message_bytes") == message_bytes
        and gate.get("concurrency") == concurrency
        and gate.get("rounds_per_mode") == 4
        and gate.get("sequence") == sequence
        and gate.get("binding") == expected_binding
        and gate.get("maximum_round_spread") == 0.01
        and gate.get("minimum_median_on_to_off_ratio") == 0.995
        and gate.get("minimum_paired_on_to_off_ratio") == 0.99
        and gate.get("maximum_gate_hold_fraction") == 0.01
        and gate.get("maximum_release_to_forwarding_ns") == 5_000_000
        and gate.get("maximum_forwarding_ns") == 1_000_000
        and math.isclose(
            gate.get("off_median", {}).get("messages_per_second", -1), off_median
        )
        and math.isclose(
            gate.get("on_median", {}).get("messages_per_second", -1), on_median
        )
        and math.isclose(gate.get("off_round_spread", -1), off_spread)
        and math.isclose(gate.get("on_round_spread", -1), on_spread)
        and math.isclose(gate.get("median_on_to_off_ratio", -1), on_median / off_median)
        and len(gate.get("paired_on_to_off_ratios", ())) == 4
        and all(
            math.isclose(recorded, observed)
            for recorded, observed in zip(
                gate["paired_on_to_off_ratios"], paired, strict=True
            )
        )
        and math.isclose(
            gate.get("observed_maximum_gate_hold_fraction", -1),
            maximum_gate_hold_fraction,
        )
        and gate.get("observed_maximum_release_to_forwarding_ns")
        == maximum_release_to_forwarding_ns
        and gate.get("observed_maximum_forwarding_ns") == maximum_forwarding_ns
        and maximum_gate_hold_fraction <= 0.01
        and maximum_release_to_forwarding_ns <= 5_000_000
        and maximum_forwarding_ns <= 1_000_000
        and gate.get("qualification") is True
    ):
        raise RuntimeError(f"gate overhead calibration did not recompute: {label}")
    return _canonical_json_sha256(gate)


def _io_max_lines_match_fixed_limits(
    lines: Any,
    *,
    devices: set[str],
    bytes_per_second: int,
) -> bool:
    if not isinstance(lines, list) or len(lines) != len(devices):
        return False
    seen: set[str] = set()
    for line in lines:
        if not isinstance(line, str):
            return False
        fields = line.split()
        if not fields or fields[0] not in devices or fields[0] in seen:
            return False
        seen.add(fields[0])
        settings: dict[str, str] = {}
        for field in fields[1:]:
            if "=" not in field:
                return False
            key, value = field.split("=", 1)
            if key in settings or key not in {"rbps", "wbps", "riops", "wiops"}:
                return False
            settings[key] = value
        if settings.get("rbps") != str(bytes_per_second) or settings.get("wbps") != str(
            bytes_per_second
        ):
            return False
        iops = (settings.get("riops"), settings.get("wiops"))
        if iops not in ((None, None), ("max", "max")):
            return False
    return seen == devices


def _validate_proxy_headroom_raw(
    proxy: dict[str, Any],
    *,
    layout: CgroupLayout,
    started_attestation: dict[str, Any],
) -> None:
    started = proxy.get("attestation_started_at_unix_seconds")
    completed = proxy.get("attestation_completed_at_unix_seconds")
    runner_captured = started_attestation.get("captured_at_unix_seconds")
    if any(
        isinstance(value, bool) or not isinstance(value, int)
        for value in (started, completed, runner_captured)
    ) or not (started <= completed <= runner_captured <= completed + 15 * 60):
        raise RuntimeError("proxy headroom attestation is stale or from a future run")
    environment = proxy.get("environment")
    if not isinstance(environment, dict):
        raise RuntimeError("proxy headroom environment is missing")
    io_max_payload = (layout.parent / "io.max").read_bytes()
    io_max_lines = sorted(
        line.strip()
        for line in io_max_payload.decode("ascii").splitlines()
        if line.strip()
    )
    expected_environment = {
        "host_boot_id": started_attestation.get("host_boot_id"),
        "benchmark_cpu": layout.cpu,
        "calibration_cpus": (layout.harness / "cpuset.cpus.effective")
        .read_text(encoding="ascii")
        .strip(),
        "cgroup_parent": str(layout.parent.resolve(strict=True)),
        "process_cgroup": str(layout.harness.resolve(strict=True)),
        "cpuset_cpus_effective": (layout.harness / "cpuset.cpus.effective")
        .read_text(encoding="ascii")
        .strip(),
        "io_bytes_per_second_per_device": layout.io_bytes_per_second,
        "io_device": layout.device,
        "backing_device": layout.backing_device,
        "io_max_lines": io_max_lines,
        "io_max_sha256": hashlib.sha256(io_max_payload).hexdigest(),
        "memory_max_bytes": layout.max_memory_bytes,
        "memory_swap_max_bytes": 0,
        "pids_max": layout.max_pids,
        "nofile_soft_and_hard": layout.nofile_limit,
        "nofile_required": 4 * 1_500 + 512,
        "nofile_reserve": 512,
    }
    if environment != expected_environment or not _io_max_lines_match_fixed_limits(
        io_max_lines,
        devices={layout.device, layout.backing_device},
        bytes_per_second=layout.io_bytes_per_second,
    ):
        raise RuntimeError("proxy headroom environment differs from this run")
    expected_tiers = {
        "1KB": (1024, 250_000, 1_500),
        "10KB": (10 * 1024, 250_000, 1_000),
        "10MB": (10 * 1024 * 1024, 2_000, 80),
    }
    tiers = proxy.get("tiers")
    if not isinstance(tiers, dict) or set(tiers) != set(expected_tiers):
        raise RuntimeError("proxy headroom tier set is incomplete")
    calibration_hashes: dict[str, str] = {}
    observed_peak_connections = 0
    for label, (message_bytes, messages, concurrency) in expected_tiers.items():
        tier = tiers.get(label)
        if not isinstance(tier, dict):
            raise RuntimeError(f"proxy headroom tier is invalid: {label}")
        raw = tier.get("raw_calibration")
        if not isinstance(raw, dict):
            raise RuntimeError(f"proxy headroom raw calibration is missing: {label}")
        raw_sha = _canonical_json_sha256(raw)
        gate = tier.get("gate_overhead_calibration")
        gate_sha = _validate_gate_overhead_calibration(
            gate,
            label=label,
            message_bytes=message_bytes,
            expected_environment=expected_environment,
            proxy=proxy,
        )
        calibration_hashes[label] = _canonical_json_sha256(
            {
                "raw_calibration_sha256": raw_sha,
                "gate_overhead_calibration_sha256": gate_sha,
            }
        )
        direct_rounds = raw.get("direct_rounds")
        proxied_rounds = raw.get("proxied_rounds")
        if (
            not isinstance(direct_rounds, list)
            or not isinstance(proxied_rounds, list)
            or len(direct_rounds) != 4
            or len(proxied_rounds) != 4
            or not all(
                isinstance(round_, dict) for round_ in (*direct_rounds, *proxied_rounds)
            )
        ):
            raise RuntimeError(f"proxy headroom raw rounds are invalid: {label}")
        direct_rates = [
            _finite_number(
                round_.get("messages_per_second"),
                f"{label} direct raw rate",
                positive=True,
            )
            for round_ in direct_rounds
        ]
        proxied_rates = [
            _finite_number(
                round_.get("messages_per_second"),
                f"{label} proxied raw rate",
                positive=True,
            )
            for round_ in proxied_rounds
        ]
        direct_median = statistics.median(direct_rates)
        proxied_median = statistics.median(proxied_rates)
        direct_spread = (max(direct_rates) - min(direct_rates)) / direct_median
        proxied_spread = (max(proxied_rates) - min(proxied_rates)) / proxied_median
        observer = raw.get("observer")
        control_proxy = raw.get("control_proxy")
        raw_proxy = raw.get("proxy")
        expected_observed = messages * 4
        expected_connections = concurrency * 4
        if not all(
            isinstance(value, dict) for value in (observer, control_proxy, raw_proxy)
        ):
            raise RuntimeError(f"proxy headroom raw proof is incomplete: {label}")
        raw_passed = bool(
            raw.get("schema_version") == 4
            and raw.get("control_topology") == "bounded-unobserved-proxy"
            and raw.get("observed_topology") == "bounded-observing-proxy"
            and raw.get("equal_tcp_hop_topology") is True
            and raw.get("mode") == "data"
            and raw.get("messages") == messages
            and raw.get("message_bytes") == message_bytes
            and raw.get("concurrency") == concurrency
            and raw.get("rounds_per_arm") == 4
            and raw.get("sequence") == ["direct", "proxied", "proxied", "direct"] * 2
            and all(
                round_.get("messages") == messages
                and round_.get("message_bytes") == message_bytes
                for round_ in (*direct_rounds, *proxied_rounds)
            )
            and math.isclose(
                _finite_number(
                    raw.get("direct", {}).get("messages_per_second"),
                    f"{label} direct median",
                    positive=True,
                ),
                direct_median,
            )
            and math.isclose(
                _finite_number(
                    raw.get("proxied", {}).get("messages_per_second"),
                    f"{label} proxied median",
                    positive=True,
                ),
                proxied_median,
            )
            and math.isclose(
                _finite_number(
                    raw.get("proxy_to_direct_ratio"),
                    f"{label} proxy ratio",
                    positive=True,
                ),
                proxied_median / direct_median,
            )
            and raw.get("proxy_to_direct_ratio", 0) >= 0.90
            and raw.get("minimum_proxy_to_direct_ratio") == 0.90
            and _finite_number(
                raw.get("estimated_observer_cpu_ns_per_message"),
                f"{label} observer CPU overhead",
            )
            >= 0
            and raw.get("maximum_round_spread") == 0.20
            and math.isclose(raw.get("direct_round_spread", -1), direct_spread)
            and math.isclose(raw.get("proxied_round_spread", -1), proxied_spread)
            and direct_spread <= 0.20
            and proxied_spread <= 0.20
            and observer.get("qualification") is True
            and observer.get("expected") == expected_observed
            and observer.get("verified") == expected_observed
            and observer.get("missing") == 0
            and observer.get("duplicates") == 0
            and control_proxy.get("accepted_connections") == expected_connections
            and control_proxy.get("completed_connections") == expected_connections
            and control_proxy.get("failed_connections") == 0
            and control_proxy.get("active_connections") == 0
            and control_proxy.get("peak_connections") == concurrency
            and _proxy_memory_evidence_is_valid(control_proxy)
            and raw_proxy.get("accepted_connections") == expected_connections
            and raw_proxy.get("completed_connections") == expected_connections
            and raw_proxy.get("failed_connections") == 0
            and raw_proxy.get("active_connections") == 0
            and raw_proxy.get("peak_connections") == concurrency
            and _proxy_memory_evidence_is_valid(raw_proxy)
            and raw.get("qualification") is True
        )
        tier_passed = bool(
            tier.get("message_bytes") == message_bytes
            and tier.get("messages_per_round") == messages
            and tier.get("concurrency") == concurrency
            and tier.get("rounds_per_arm") == 4
            and tier.get("raw_calibration_schema_version") == 4
            and tier.get("raw_calibration_sha256") == raw_sha
            and tier.get("gate_overhead_calibration_schema_version") == 2
            and tier.get("gate_overhead_calibration_sha256") == gate_sha
            and isinstance(gate, dict)
            and gate.get("qualification") is True
            and math.isclose(
                _finite_number(
                    tier.get("sustained_messages_per_second"),
                    f"{label} sustained proxy capacity",
                    positive=True,
                ),
                min(proxied_rates),
            )
            and tier.get("passed") is True
            and raw_passed
        )
        if not tier_passed:
            raise RuntimeError(f"proxy headroom raw qualification failed: {label}")
        peak_connections = raw_proxy.get("peak_connections")
        if isinstance(peak_connections, bool) or not isinstance(peak_connections, int):
            raise RuntimeError(f"proxy headroom peak is invalid: {label}")
        observed_peak_connections = max(observed_peak_connections, peak_connections)
    if not (
        proxy.get("calibration_bundle_sha256")
        == _canonical_json_sha256(calibration_hashes)
        and proxy.get("max_active_connections") == observed_peak_connections
        and observed_peak_connections >= 1_500
        and proxy.get("minimum_product_headroom_ratio") == 2.0
        and proxy.get("semantic_transparency_passed") is True
        and proxy.get("passed") is True
    ):
        raise RuntimeError("proxy aggregate headroom proof did not recompute")


def _external_prerequisites(
    *,
    path: Path | None,
    expected_sha256: str | None,
    plans: Sequence[BenchmarkPlan],
    disk_budget_bytes: int,
    layout: CgroupLayout,
    started_attestation: dict[str, Any],
) -> dict[str, Any]:
    if path is None and expected_sha256 is None:
        return {
            "provided": False,
            "passed": False,
            "requirements": (
                "root-owned content-addressed proxy headroom/transparency and "
                "hard disk quota attestation"
            ),
        }
    if path is None or expected_sha256 is None:
        raise RuntimeError(
            "external prerequisite path and SHA-256 must be supplied together"
        )
    expected_sha256 = expected_sha256.lower()
    if re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
        raise RuntimeError("external prerequisite SHA-256 is invalid")
    trusted_root = Path("/run/lmyzmail-benchmark-attestations")
    expected_name = f"{expected_sha256}.json"
    if (
        not path.is_absolute()
        or path.parent != trusted_root
        or path.name != expected_name
    ):
        raise RuntimeError(
            "external prerequisite must be a direct content-addressed child of "
            f"{trusted_root}: {path}"
        )
    expected_uid, expected_gid = _unmapped_host_root_identity()
    root_descriptor = os.open(
        trusted_root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        root_metadata = os.fstat(root_descriptor)
        _validate_external_metadata(
            root_metadata,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            kind="directory",
        )
        descriptor = os.open(
            path.name,
            os.O_RDONLY | os.O_NOFOLLOW,
            dir_fd=root_descriptor,
        )
        try:
            metadata = os.fstat(descriptor)
            _validate_external_metadata(
                metadata,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
                kind="file",
            )
            if metadata.st_size <= 0 or metadata.st_size > 1024 * 1024:
                raise RuntimeError("external prerequisite size is outside its bound")
            payload = bytearray()
            while len(payload) <= 1024 * 1024:
                chunk = os.read(
                    descriptor,
                    min(64 * 1024, 1024 * 1024 + 1 - len(payload)),
                )
                if not chunk:
                    break
                payload.extend(chunk)
        finally:
            os.close(descriptor)
    finally:
        os.close(root_descriptor)
    actual_sha256 = hashlib.sha256(payload).hexdigest()
    if actual_sha256 != expected_sha256:
        raise RuntimeError(
            f"external prerequisite hash changed: {actual_sha256}; expected {expected_sha256}"
        )
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("external prerequisite is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise RuntimeError("external prerequisite root must be an object")
    _reject_nonfinite_metrics(value, "external_prerequisite")
    if (
        value.get("schema_version") != 1
        or value.get("profile") != EXTERNAL_PREREQUISITE_PROFILE
        or value.get("launcher_sha256") != started_attestation["launcher_sha256"]
    ):
        raise RuntimeError("external prerequisite identity does not match this run")
    proxy = value.get("proxy_headroom")
    quota = value.get("hard_disk_quota")
    isolation = value.get("isolation_policy")
    if (
        not isinstance(proxy, dict)
        or not isinstance(quota, dict)
        or not isinstance(isolation, dict)
    ):
        raise RuntimeError("external prerequisite sections are missing")
    _validate_proxy_headroom_raw(
        proxy,
        layout=layout,
        started_attestation=started_attestation,
    )
    tiers = proxy.get("tiers")
    if not isinstance(tiers, dict):
        raise RuntimeError("proxy headroom tier evidence is missing")
    for plan in plans:
        tier = tiers.get(plan.label)
        if not isinstance(tier, dict):
            raise RuntimeError(f"proxy headroom is missing for {plan.label}")
        _finite_number(
            tier.get("sustained_messages_per_second"),
            f"{plan.label} sustained proxy capacity",
            positive=True,
        )
    max_active_connections = proxy.get("max_active_connections")
    if isinstance(max_active_connections, bool) or not isinstance(
        max_active_connections, int
    ):
        raise RuntimeError("proxy maximum active connections must be an integer")
    proxy_passed = (
        proxy.get("passed") is True
        and proxy.get("semantic_transparency_passed") is True
        and proxy.get("runner_sha256") == started_attestation["runner_sha256"]
        and proxy.get("binary_sha256")
        == started_attestation["benchmark_proxy_release_sha256"]
        and proxy.get("source_tree_sha256")
        == started_attestation["benchmark_proxy_source_tree_sha256"]
        and max_active_connections >= 1_500
    )
    mount_root_raw = quota.get("mount_root")
    if not isinstance(mount_root_raw, str):
        raise RuntimeError("hard disk quota mount root is missing")
    mount_root = Path(mount_root_raw)
    temporary_root = Path(tempfile.gettempdir()).resolve()
    quota_passed = (
        quota.get("passed") is True
        and quota.get("enforcement")
        in {"loopback", "project-quota", "filesystem-quota"}
        and quota.get("limit_bytes") == disk_budget_bytes
        and quota.get("device") == layout.device
        and quota.get("backing_device") == layout.backing_device
        and quota.get("host_reserve_bytes") == layout.host_reserve_bytes
        and mount_root.is_absolute()
        and temporary_root.is_relative_to(mount_root.resolve(strict=True))
    )
    started_policy = started_attestation["isolation_policy"]
    isolation_passed = (
        isolation.get("passed") is True
        and isolation.get("expected") == started_policy["expected"]
        and isolation.get("canonical_policy_sha256")
        == started_policy["canonical_policy_sha256"]
    )
    if not proxy_passed or not quota_passed or not isolation_passed:
        raise RuntimeError("external benchmark prerequisites did not pass")
    return {
        "provided": True,
        "passed": True,
        "path": str(path),
        "sha256": actual_sha256,
        "launcher_sha256": value["launcher_sha256"],
        "host_root_identity_observed": {
            "uid": metadata.st_uid,
            "gid": metadata.st_gid,
        },
        "proxy_headroom": proxy,
        "hard_disk_quota": quota,
        "isolation_policy": isolation,
        "quota_mount_root": str(mount_root.resolve(strict=True)),
    }


def _qualified(
    *,
    smoke: bool,
    target: str,
    tier: str,
    disk_budget_bytes: int,
    layout: CgroupLayout,
    external_prerequisites_passed: bool,
    isolation_policy_passed: bool,
) -> bool:
    return (
        not smoke
        and target == "both"
        and tier == "all"
        and disk_budget_bytes == FORMAL_DISK_BUDGET_BYTES
        and layout.host_reserve_bytes >= FORMAL_HOST_RESERVE_BYTES
        and layout.io_bytes_per_second == FORMAL_IO_BYTES_PER_SECOND
        and layout.max_memory_bytes == FORMAL_MAX_MEMORY_BYTES
        and layout.max_pids == FORMAL_MAX_PIDS
        and layout.nofile_limit == FORMAL_NOFILE_LIMIT
        and external_prerequisites_passed
        and isolation_policy_passed
    )


def _resolve_output(value: Path) -> Path:
    output = value if value.is_absolute() else REPOSITORY / value
    output = output.resolve(strict=False)
    evidence_root = (REPOSITORY / "evidence/performance").resolve()
    if not output.is_relative_to(evidence_root):
        raise ValueError(f"benchmark output must stay under {evidence_root}")
    if output.suffix != ".json":
        raise ValueError("benchmark output must use a .json suffix")
    return output


def _canonical_uuid4(value: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError) as error:
        raise argparse.ArgumentTypeError(
            "launcher run identity must be a UUID"
        ) from error
    canonical = str(parsed)
    if parsed.version != 4 or value != canonical:
        raise argparse.ArgumentTypeError(
            "launcher run identity must be a canonical UUIDv4"
        )
    return canonical


def _artifact_descriptor(value: str) -> int:
    try:
        descriptor = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "artifact descriptor must be an integer"
        ) from error
    if descriptor < 3:
        raise argparse.ArgumentTypeError("artifact descriptor must not alias stdio")
    return descriptor


def _seal_artifact_capabilities(output_fd: int, checkpoint_fd: int) -> None:
    if output_fd == checkpoint_fd:
        raise RuntimeError("output and checkpoint capabilities must be distinct")
    import fcntl

    identities: set[tuple[int, int]] = set()
    for descriptor, label in (
        (output_fd, "output"),
        (checkpoint_fd, "checkpoint"),
    ):
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise RuntimeError(f"{label} capability is not a single regular file")
        identity = (metadata.st_dev, metadata.st_ino)
        if identity in identities:
            raise RuntimeError("output and checkpoint capabilities alias one inode")
        identities.add(identity)
        flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
        if flags & os.O_ACCMODE != os.O_RDWR:
            raise RuntimeError(f"{label} capability is not read-write")
        os.set_inheritable(descriptor, False)
        if os.get_inheritable(descriptor):
            raise RuntimeError(f"{label} capability remained inheritable")


def _checkpointed_finalization(
    checkpoint: Checkpoint,
    run_id: str,
    phase: str,
    action: Callable[[], Any],
) -> Any:
    try:
        return action()
    except BaseException as error:
        with contextlib.suppress(BaseException):
            checkpoint.append(
                {
                    "event": "finalization_failed",
                    "at": _utc_now(),
                    "run_id": run_id,
                    "phase": phase,
                    "error": {
                        "type": type(error).__name__,
                        "message": str(error),
                    },
                }
            )
        with contextlib.suppress(BaseException):
            checkpoint.close()
        raise


def _complete_checkpoint_noreplace(source: Path, destination: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(source, flags)
    try:
        before = os.fstat(descriptor)
        source_before = source.lstat()
        identity = (before.st_dev, before.st_ino)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise RuntimeError("running checkpoint is not a single regular file")
        if (source_before.st_dev, source_before.st_ino) != identity:
            raise RuntimeError("running checkpoint path changed before completion")
        # Linking /proc/self/fd/<fd> crosses procfs on WSL and fails with EXDEV.
        # The real source path remains create-only, while the open descriptor and
        # the checks below reject any path replacement before or after the link.
        os.link(source, destination, follow_symlinks=False)
        linked = os.fstat(descriptor)
        source_linked = source.lstat()
        destination_linked = destination.lstat()
        if not (
            (linked.st_dev, linked.st_ino) == identity
            and (source_linked.st_dev, source_linked.st_ino) == identity
            and (destination_linked.st_dev, destination_linked.st_ino) == identity
            and linked.st_nlink == before.st_nlink + 1
            and source_linked.st_nlink == linked.st_nlink
            and destination_linked.st_nlink == linked.st_nlink
        ):
            raise RuntimeError("completed checkpoint hardlink identity changed")
        _fsync_directory(destination.parent)
        if os.name == "nt":
            # Windows denies unlinking a pathname while this validation handle
            # is open. Production is Linux; retain identity by reopening the
            # create-only destination after the source unlink in mock tests.
            os.close(descriptor)
            descriptor = -1
        source.unlink()
        _fsync_directory(destination.parent)
        destination_after = destination.lstat()
        descriptor_after = os.open(destination, flags)
        try:
            after = os.fstat(descriptor_after)
        finally:
            os.close(descriptor_after)
        if not (
            (after.st_dev, after.st_ino) == identity
            and (destination_after.st_dev, destination_after.st_ino) == identity
            and after.st_nlink == before.st_nlink
            and destination_after.st_nlink == before.st_nlink
        ):
            raise RuntimeError("completed checkpoint identity changed after unlink")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _run_benchmark(args: argparse.Namespace, layout: CgroupLayout) -> dict[str, Any]:
    disk_budget_bytes = round(args.disk_budget_gib * 1024**3)
    dkim_material = _generate_benchmark_dkim_material()
    java_small_baseline = getattr(args, "profile", "abba") == "java-small"
    rust_filesystem_fsync = getattr(
        args, "rust_filesystem_fsync", None if java_small_baseline else "on"
    )
    if java_small_baseline:
        plans = list(_java_small_baseline_plans())
        if args.tier != "all":
            plans = [plan for plan in plans if plan.label.lower() == args.tier]
        targets = ("java-oracle",)
        execution_matrix = _java_small_baseline_execution_matrix(plans)
    else:
        plans = _plans(
            smoke=args.smoke,
            disk_budget_bytes=disk_budget_bytes,
            tier=args.tier,
            profiler_messages=getattr(args, "profiler_messages", None),
        )
        targets = _targets(args.target)
        execution_matrix = _execution_matrix(targets, plans)
    output_path = _resolve_output(args.output)
    checkpoint_path = output_path.with_name(output_path.name + ".running.jsonl")
    complete_checkpoint_path = output_path.with_name(
        output_path.name + ".complete.jsonl"
    )
    for path in (output_path, checkpoint_path, complete_checkpoint_path):
        if os.path.lexists(path):
            raise FileExistsError(f"benchmark evidence already exists: {path}")
    checkpoint = Checkpoint(checkpoint_path, descriptor=args.checkpoint_fd)
    run_id = str(uuid.uuid4())
    try:
        candidate = (
            CANDIDATE_PROFILING_RELEASE
            if getattr(args, "profiler_candidate", False)
            else CANDIDATE_RELEASE
        )
        attestation = _attestation(
            layout,
            smoke=args.smoke,
            disk_budget_bytes=disk_budget_bytes,
            candidate=candidate,
            rust_filesystem_fsync=rust_filesystem_fsync,
        )
        external_prerequisites = _external_prerequisites(
            path=args.external_prerequisites,
            expected_sha256=args.external_prerequisites_sha256,
            plans=plans,
            disk_budget_bytes=disk_budget_bytes,
            layout=layout,
            started_attestation=attestation,
        )
        quota_mount_root = Path(tempfile.gettempdir()).resolve(strict=True)
        if not quota_mount_root.is_dir():
            raise RuntimeError("active hard-quota temporary root is not a directory")
        if external_prerequisites["passed"]:
            attested_quota_mount_root = Path(
                external_prerequisites["quota_mount_root"]
            ).resolve(strict=True)
            if quota_mount_root != attested_quota_mount_root:
                raise RuntimeError(
                    "active hard-quota temporary root differs from its attestation"
                )
        qualification_prerequisites_passed = (
            False
            if java_small_baseline
            else _qualified(
                smoke=args.smoke,
                target=args.target,
                tier=args.tier,
                disk_budget_bytes=disk_budget_bytes,
                layout=layout,
                external_prerequisites_passed=external_prerequisites["passed"],
                isolation_policy_passed=attestation["isolation_policy"]["passed"],
            )
        )
        started_at = _utc_now()
        started_monotonic = time.monotonic()
        checkpoint.append(
            {
                "event": "started",
                "at": started_at,
                "run_id": run_id,
                "launcher_run_id": args.launcher_run_id,
                "argv": sys.argv,
                "targets": list(targets),
                "rust_filesystem_fsync": rust_filesystem_fsync,
                "benchmark_profile": (
                    JAVA_SMALL_BASELINE_PROFILE
                    if java_small_baseline
                    else BENCHMARK_PROFILE
                ),
                "execution_order": (
                    (
                        "1KB Java once, then 10KB Java once"
                        if len(plans) == 2
                        else f"{plans[0].label} Java once"
                    )
                    if java_small_baseline
                    else "1KB/10KB ABBA; 10MB Rust-only"
                ),
                "plans": [
                    {
                        "label": plan.label,
                        "message_bytes": plan.message_bytes,
                        "total_messages": plan.total_messages,
                        "single_endpoint_invocation": True,
                    }
                    for plan in plans
                ],
                "arms_per_target_per_tier": 1 if java_small_baseline else 2,
                "warmup_endpoint_invocations": 0,
                "disk_budget_bytes": disk_budget_bytes,
                "qualified": False,
                "qualification_prerequisites_passed": (
                    qualification_prerequisites_passed
                ),
                "attestation": attestation,
                "java_stress_runtime_profile": (
                    _java_frozen_stress_profile() if "java-oracle" in targets else None
                ),
                "dkim_material": dkim_material.attestation(),
                "external_prerequisites": external_prerequisites,
                "cgroup": layout.snapshot(),
            }
        )
    except BaseException as error:
        with contextlib.suppress(BaseException):
            checkpoint.append(
                {
                    "event": "initialization_failed",
                    "at": _utc_now(),
                    "run_id": run_id,
                    "error": {
                        "type": type(error).__name__,
                        "message": str(error),
                    },
                }
            )
        with contextlib.suppress(BaseException):
            checkpoint.close()
        raise
    arms: list[dict[str, Any]] = []
    real_gate_calibration: dict[str, Any] = {
        "required_for_qualification": (
            qualification_prerequisites_passed and not args.smoke
        ),
        "performed": False,
        "tiers": {},
        "bundle_sha256": None,
        "passed": False,
    }
    dns: Any | None = None
    dns_fixture: dict[str, Any] | None = None
    primary_error: BaseException | None = None
    failure_recorded = False
    try:
        dns = BenchmarkDnsServer(dkim_material)
        if (
            not java_small_baseline
            and qualification_prerequisites_passed
            and not args.smoke
        ):
            gate_tiers: dict[str, dict[str, Any]] = {}
            for label in REAL_GATE_CALIBRATION_SHAPES:
                gate_tiers[label] = _run_real_gate_calibration_tier(
                    label,
                    layout,
                    dns_port=dns.port,
                    dkim_private_key_bytes=dkim_material.private_key_bytes,
                    disk_budget_bytes=disk_budget_bytes,
                    started_attestation=attestation,
                    quota_mount_root=quota_mount_root,
                    rust_filesystem_fsync=rust_filesystem_fsync,
                    checkpoint_event=checkpoint.append,
                )
            gate_hashes = {
                label: report["sha256"] for label, report in gate_tiers.items()
            }
            real_gate_calibration = {
                "required_for_qualification": True,
                "performed": True,
                "tiers": gate_tiers,
                "bundle_sha256": _canonical_json_sha256(gate_hashes),
                "passed": all(
                    report.get("qualification") is True
                    for report in gate_tiers.values()
                ),
            }
            checkpoint.append(
                {
                    "event": "real_gate_calibration_complete",
                    "rust_filesystem_fsync": rust_filesystem_fsync,
                    "bundle_sha256": real_gate_calibration["bundle_sha256"],
                    "passed": real_gate_calibration["passed"],
                }
            )
        for target, plan, arm_ordinal in execution_matrix:
            arm = _run_target_tier(
                target,
                plan,
                layout,
                arm_ordinal=arm_ordinal,
                dns_port=dns.port,
                dkim_private_key_bytes=dkim_material.private_key_bytes,
                disk_budget_bytes=disk_budget_bytes,
                started_attestation=attestation,
                quota_mount_root=quota_mount_root,
                rust_filesystem_fsync=rust_filesystem_fsync,
                checkpoint_event=checkpoint.append,
            )
            arms.append(arm)
            checkpoint.append(
                {
                    "event": "target_tier_arm_complete",
                    "target": target,
                    "tier": plan.label,
                    "arm_ordinal": arm_ordinal,
                    "rust_filesystem_fsync": (
                        rust_filesystem_fsync if target == "rust-candidate" else None
                    ),
                    "throughput_messages_per_second": arm[
                        "throughput_messages_per_second"
                    ],
                }
            )
    except BaseException as error:
        primary_error = error
        try:
            checkpoint.append(
                {
                    "event": "failed",
                    "at": _utc_now(),
                    "error": {
                        "type": type(error).__name__,
                        "message": str(error),
                    },
                    "completed_target_tier_arms": [
                        {
                            "target": arm["target"],
                            "tier": arm["tier"]["label"],
                            "arm_ordinal": arm["arm_ordinal"],
                        }
                        for arm in arms
                    ],
                }
            )
            failure_recorded = True
        except BaseException:
            pass
    finally:
        if dns is not None:
            try:
                dns_fixture = dns.attestation()
                dns.close()
            except BaseException as error:
                if primary_error is None:
                    primary_error = error
                else:
                    primary_error.add_note(
                        f"DNS cleanup also failed: {type(error).__name__}: {error}"
                    )
    if primary_error is not None:
        if not failure_recorded:
            with contextlib.suppress(BaseException):
                checkpoint.append(
                    {
                        "event": "failed",
                        "at": _utc_now(),
                        "error": {
                            "type": type(primary_error).__name__,
                            "message": str(primary_error),
                        },
                        "completed_target_tier_arms": [
                            {
                                "target": arm["target"],
                                "tier": arm["tier"]["label"],
                                "arm_ordinal": arm["arm_ordinal"],
                            }
                            for arm in arms
                        ],
                    }
                )
        with contextlib.suppress(BaseException):
            checkpoint.close()
        raise primary_error
    if (
        dns_fixture is None
        or dns_fixture.get("passed") is not True
        or dns_fixture.get("dkim", {}).get("public_key_spki_sha256")
        != dkim_material.public_key_spki_sha256
        or int(dns_fixture.get("dkim_txt_query_count", 0)) < len(arms)
        or int(dns_fixture.get("dmarc_txt_query_count", 0)) < len(arms)
    ):
        raise RuntimeError(
            "benchmark DNS did not prove DKIM and DMARC evaluation for every arm"
        )
    rows = _aggregate_arm_rows(
        arms,
        plans,
        expected_ordinals=(0,) if java_small_baseline else (0, 1),
    )
    definition_after = _checkpointed_finalization(
        checkpoint,
        run_id,
        "definition_attestation_after",
        lambda: _verify_definition_attestation(attestation),
    )
    checkpoint.append(
        {
            "event": "definition_attestation_verified",
            "at": _utc_now(),
            "definition": definition_after,
        }
    )
    comparison = (
        _java_small_baseline_comparison(rows, plans)
        if java_small_baseline
        else _comparison(
            rows,
            smoke=args.smoke,
            proxy_headroom=(
                external_prerequisites["proxy_headroom"]
                if external_prerequisites["passed"]
                else None
            ),
        )
    )
    qualified = (
        False
        if java_small_baseline
        else (
            qualification_prerequisites_passed
            and comparison["all_passed"]
            and comparison["zero_retry_gate_passed"]
            and comparison["pair_completeness_passed"]
            and comparison["arm_completeness_passed"]
            and comparison["proxy_headroom_passed"]
            and real_gate_calibration["passed"]
        )
    )
    status = "passed" if comparison["all_passed"] else "failed"
    hardware = _checkpointed_finalization(
        checkpoint,
        run_id,
        "hardware_evidence",
        lambda: _hardware_evidence(layout),
    )
    result = {
        "schema_version": 1,
        "profile": (
            JAVA_SMALL_BASELINE_PROFILE if java_small_baseline else BENCHMARK_PROFILE
        ),
        "run_id": run_id,
        "launcher_run_id": args.launcher_run_id,
        "status": status,
        "qualified": qualified,
        "rust_filesystem_fsync": rust_filesystem_fsync,
        "qualification_prerequisites_passed": qualification_prerequisites_passed,
        "started_at": started_at,
        "completed_at": _utc_now(),
        "duration_seconds": round(time.monotonic() - started_monotonic, 6),
        "endpoint_invocations": 1,
        "endpoint_invocation_scope": "per_arm",
        "harness_batches": 0,
        "total_endpoint_invocations": len(arms),
        "real_gate_calibration_endpoint_invocations": (
            len(REAL_GATE_CALIBRATION_SHAPES) * len(REAL_GATE_CALIBRATION_SEQUENCE)
            if real_gate_calibration["performed"]
            else 0
        ),
        "endpoint_requested_messages": [
            arm["endpoint_requested_messages"] for arm in arms
        ],
        "observer_verified_messages": [
            arm["observer_verified_messages"] for arm in arms
        ],
        "endpoint_requested_messages_match_observer_verified": all(
            arm["requested_equals_observer_verified"] is True for arm in arms
        ),
        "execution_order": [
            {
                "target": target,
                "tier": plan.label,
                "arm_ordinal": arm_ordinal,
            }
            for target, plan, arm_ordinal in execution_matrix
        ],
        "methodology": {
            "rust_filesystem_fsync": rust_filesystem_fsync,
            "one_rust_filesystem_fsync_mode_per_evidence_file": True,
            "per_tier_order": (
                "1KB then 10KB"
                if java_small_baseline and len(plans) == 2
                else (
                    plans[0].label
                    if java_small_baseline
                    else "1KB/10KB ABBA; 10MB Rust-only"
                )
            ),
            "per_tier_arms": (
                ["java-oracle"]
                if java_small_baseline
                else {
                    "1KB/10KB": [
                        "java-oracle",
                        "rust-candidate",
                        "rust-candidate",
                        "java-oracle",
                    ],
                    "10MB": ["rust-candidate", "rust-candidate"],
                }
            ),
            "one_large_start_invocation_per_arm": True,
            "stress_start_maximum_attempts_per_arm": 1,
            "stress_start_automatic_retries": 0,
            "uncertain_start_outcome": "fail_closed_and_restart_as_a_new_benchmark_run",
            "harness_batching": False,
            "automatic_endpoint_cleanup_only": True,
            "warmup_endpoint_invocations": 0,
            "repetition_loop": False,
            "fresh_runtime_database_redis_workspace_and_proxy_per_arm": True,
            "same_cgroup_reused_only_after_empty_proof": True,
            "single_logical_cpu_for_application": True,
            "postgres_and_redis_on_housekeeping_cpuset": True,
            "capture_proxy_outside_workload_cpu_cgroup": True,
            "io_limit_bytes_per_second_read_and_write": layout.io_bytes_per_second,
            "hard_disk_budget_bytes": disk_budget_bytes,
            "external_prerequisites_are_content_addressed": not java_small_baseline,
            "proxy_headroom_and_semantic_transparency_attested": (
                external_prerequisites["passed"]
            ),
            "proxy_headroom_computed_against_maximum_observed_arm": (
                not java_small_baseline
            ),
            "real_gate_calibration_uses_original_endpoint": not java_small_baseline,
            "real_gate_calibration_same_runtime_per_tier": not java_small_baseline,
            "real_gate_calibration_fresh_proxy_per_round": not java_small_baseline,
            "real_gate_calibration_synthetic": False,
            "performance_gate_uses_both_ordinal_pairs": not java_small_baseline,
            "performance_gate_uses_min_rust_over_max_java": not java_small_baseline,
            "performance_comparison_tiers": (
                [] if java_small_baseline else ["1KB", "10KB"]
            ),
            "candidate_only_stability_tiers": (
                [] if java_small_baseline else ["10MB"]
            ),
            "cross_arm_relative_range_limit": (
                None if java_small_baseline else MAXIMUM_ABBA_ARM_RELATIVE_RANGE
            ),
            "hard_disk_quota_attested": external_prerequisites["passed"],
            "java_small_baseline_is_not_qualification_evidence": java_small_baseline,
            "throughput_window": (
                "immediately before POST /api/stress/start through the final self-SMTP "
                "250 response after inbound Maildir and PostgreSQL persistence"
            ),
            "cleanup_excluded_from_throughput": True,
            "java_stress_runtime_profile": (
                _java_frozen_stress_profile() if "java-oracle" in targets else None
            ),
        },
        "plans": [
            {
                "label": plan.label,
                "message_bytes": plan.message_bytes,
                "total_messages": plan.total_messages,
            }
            for plan in plans
        ],
        "hardware": hardware,
        "attestation": attestation,
        "dns_fixture": dns_fixture,
        "external_prerequisites": external_prerequisites,
        "real_gate_calibration": real_gate_calibration,
        "rows": rows,
        "comparison": comparison,
        "acceptance": {
            "passed": status == "passed",
            "qualified": qualified,
            "qualification_prerequisites_passed": (qualification_prerequisites_passed),
            "rust_primary_tiers_require_20_percent_improvement": (
                not java_small_baseline
            ),
            "both_paired_ratios_must_pass": not java_small_baseline,
            "conservative_min_rust_over_max_java_must_pass": (not java_small_baseline),
            "cross_arm_stability_must_pass": not java_small_baseline,
            "no_batching": True,
            "per_tier_abba": (
                not java_small_baseline
                and args.target == "both"
                and all(plan.label != "10MB" for plan in plans)
            ),
            "small_message_tiers_abba": (
                not java_small_baseline and args.target == "both"
            ),
            "ten_megabyte_java_prohibited": not java_small_baseline,
            "ten_megabyte_rust_only": (
                not java_small_baseline
                and any(plan.label == "10MB" for plan in plans)
                and "rust-candidate" in targets
            ),
            "two_equally_weighted_arms_per_target_tier": not java_small_baseline,
            "java_small_baseline": java_small_baseline,
            "java_only": java_small_baseline,
            "one_arm_per_tier": java_small_baseline,
            "one_endpoint_invocation_per_tier": java_small_baseline,
            "one_kib_then_ten_kib": java_small_baseline and len(plans) == 2,
            "two_hundred_thousand_messages_per_tier": java_small_baseline,
            "ten_megabyte_excluded": java_small_baseline,
            "not_qualification_evidence": java_small_baseline,
            "no_warmup_endpoint_calls": True,
            "no_repetition_loop": True,
            "no_stress_start_retries": True,
            "external_prerequisites_passed": external_prerequisites["passed"],
            "real_gate_calibration_passed": real_gate_calibration["passed"],
        },
    }
    _checkpointed_finalization(
        checkpoint,
        run_id,
        "output_create",
        lambda: _write_json_fd(args.output_fd, result),
    )
    output_sha256 = _checkpointed_finalization(
        checkpoint,
        run_id,
        "output_hash",
        lambda: _sha256_fd(args.output_fd),
    )
    _checkpointed_finalization(
        checkpoint,
        run_id,
        "completed_checkpoint",
        lambda: checkpoint.append(
            {
                "event": "completed",
                "at": _utc_now(),
                "run_id": run_id,
                "launcher_run_id": args.launcher_run_id,
                "status": status,
                "qualified": qualified,
                "rust_filesystem_fsync": rust_filesystem_fsync,
                "output": str(output_path.relative_to(REPOSITORY)),
                "output_sha256": output_sha256,
                "comparison": comparison,
            }
        ),
    )
    _checkpointed_finalization(
        checkpoint,
        run_id,
        "checkpoint_rename",
        checkpoint.sync,
    )
    _checkpointed_finalization(
        checkpoint,
        run_id,
        "evidence_directory_fsync",
        lambda: os.fsync(args.output_fd),
    )
    _checkpointed_finalization(
        checkpoint,
        run_id,
        "checkpoint_close",
        checkpoint.close,
    )
    result["output"] = str(output_path)
    result["output_sha256"] = output_sha256
    return result


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run Java/Rust ABBA arms for 1KB and 10KB plus Rust-only 10MB "
            "arms using one original stress-endpoint invocation and a fresh "
            "isolated runtime per arm."
        )
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--launcher-run-id", required=True, type=_canonical_uuid4)
    parser.add_argument("--output-fd", required=True, type=_artifact_descriptor)
    parser.add_argument("--checkpoint-fd", required=True, type=_artifact_descriptor)
    parser.add_argument("--profile", choices=("abba", "java-small"), default="abba")
    parser.add_argument("--target", choices=("both", "java", "rust"), default="both")
    parser.add_argument(
        "--rust-filesystem-fsync",
        choices=("on", "off"),
        help=(
            "candidate filesystem durability mode; required for formal Rust runs, "
            "defaults to on for smoke"
        ),
    )
    parser.add_argument("--tier", choices=("all", "1kb", "10kb", "10mb"), default="all")
    parser.add_argument("--disk-budget-gib", type=float, default=20.0)
    parser.add_argument("--external-prerequisites", type=Path)
    parser.add_argument("--external-prerequisites-sha256")
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument(
        "--profiler-candidate", action="store_true", help=argparse.SUPPRESS
    )
    parser.add_argument("--profiler-messages", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not math.isfinite(args.disk_budget_gib) or not 5 <= args.disk_budget_gib <= 100:
        parser.error("--disk-budget-gib must be finite and between 5 and 100")
    if (args.external_prerequisites is None) != (
        args.external_prerequisites_sha256 is None
    ):
        parser.error(
            "--external-prerequisites and --external-prerequisites-sha256 must be supplied together"
        )
    if args.profile == "java-small":
        if args.target != "java":
            parser.error("--profile java-small requires --target java")
        if args.tier not in ("all", "1kb", "10kb"):
            parser.error(
                "--profile java-small supports all, 1kb, or 10kb; 10mb is excluded"
            )
        if args.smoke:
            parser.error("--profile java-small does not permit reduced smoke counts")
        if args.disk_budget_gib != 20.0:
            parser.error("--profile java-small requires --disk-budget-gib 20")
        if args.external_prerequisites is not None:
            parser.error(
                "--profile java-small does not consume Rust proxy qualification evidence"
            )
        if args.rust_filesystem_fsync is not None:
            parser.error("--profile java-small does not accept a Rust fsync mode")
    elif args.target == "java":
        if args.tier == "10mb":
            parser.error("Java 10MB execution is prohibited; use --target rust")
        if args.rust_filesystem_fsync is not None:
            parser.error("--target java does not accept a Rust fsync mode")
    elif args.rust_filesystem_fsync is None:
        if args.smoke:
            args.rust_filesystem_fsync = "on"
        else:
            parser.error("formal Rust runs require --rust-filesystem-fsync on or off")
    if args.profiler_candidate and (
        args.profile != "abba"
        or args.target != "rust"
        or args.tier != "10kb"
        or args.smoke
    ):
        parser.error("--profiler-candidate requires non-smoke abba/rust/10kb selection")
    if args.profiler_messages is not None:
        if not args.profiler_candidate:
            parser.error("--profiler-messages requires --profiler-candidate")
        if not 64 <= args.profiler_messages <= 500_000:
            parser.error("--profiler-messages must be between 64 and 500000")
    return args


def _enter_isolated_namespace() -> None:
    if os.environ.get(NAMESPACE_ENV) == "1":
        return
    environment = dict(os.environ)
    environment[NAMESPACE_ENV] = "1"
    unshare = base._required_command("unshare")
    arguments = [
        unshare,
        "--user",
        f"--map-user={os.getuid()}",
        f"--map-group={os.getgid()}",
        "--keep-caps",
        "--net",
        "--mount",
        "--propagation",
        "private",
        str(Path(sys.executable).absolute()),
        str(Path(__file__).resolve()),
        *sys.argv[1:],
    ]
    os.execve(unshare, arguments, environment)


def main() -> int:
    args = _parse_args()
    _enter_isolated_namespace()
    _seal_artifact_capabilities(args.output_fd, args.checkpoint_fd)
    layout = CgroupLayout.from_environment()
    expected_harness = "/" + layout.harness.relative_to("/sys/fs/cgroup").as_posix()
    actual_harness = _unified_cgroup(os.getpid())
    if actual_harness != expected_harness:
        raise RuntimeError(
            f"benchmark runner is in cgroup {actual_harness}, expected {expected_harness}"
        )
    actual_affinity = tuple(sorted(os.sched_getaffinity(0)))
    if actual_affinity != layout.housekeeping_cpus:
        raise RuntimeError(
            f"benchmark runner affinity {actual_affinity} differs from housekeeping "
            f"CPUs {layout.housekeeping_cpus}"
        )
    _nofile_evidence(layout)
    try:
        with tempfile.TemporaryDirectory(
            prefix="lmyzmail-smtp-throughput-namespace-"
        ) as root:
            base._configure_isolated_namespace(Path(root))
            _runner_process_hardening(apply=True)
            try:
                result = _run_benchmark(args, layout)
            except KeyboardInterrupt:
                return 130
    finally:
        for descriptor in (args.output_fd, args.checkpoint_fd):
            with contextlib.suppress(OSError):
                os.close(descriptor)
    summary = {
        "status": result["status"],
        "qualified": result["qualified"],
        "output": result["output"],
        "output_sha256": result["output_sha256"],
        "comparisons": result["comparison"]["comparisons"],
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
