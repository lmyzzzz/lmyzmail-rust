from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import psycopg
import pytest
import redis

from lmyzmail_blackbox.differential import RuntimeTarget
from lmyzmail_blackbox.persistent_runtime import PersistentJavaOracleRuntime
from lmyzmail_blackbox.ports import PortSet
from lmyzmail_blackbox.protocols import RawHttpResponse, http_exchange
from lmyzmail_blackbox.report_contract import (
    _drain_report_dns_queries,
    _expect_json,
    _redis_pending,
    _report_database_state,
    _report_message_snapshot,
    _sent_files,
    _task_snapshot,
    report_dns_server,
)
from lmyzmail_blackbox.runtime import API_KEY, CandidateRuntime
from lmyzmail_blackbox.scripted_dns import DnsQuery, ScriptedDnsServer

_HOST = "127.0.0.1"
_REPORT_DATE = "2024-01-01"
_DMARC_DOMAIN = "sender.example"
_REPORT_SENDER = "qa@example.test"
_REDIS_QUEUE_PREFIX = "botmail:mail:queue:"
_FAULT_MARKER = b"lmyzmail blackbox deterministic Maildir fault\n"
_EXPECTED_DNS_QUERIES = (
    "_dmarc.sender.example",
    "sender.example._report._dmarc.example.test",
)
_SEEDED_DELIVERY_GOLDEN = Path(
    "blackbox/golden/java/managed-reports-v23/observations/http/reports/seeded-delivery.json"
)
_SEEDED_DELIVERY_GOLDEN_SHA256 = (
    "887abea00d415a4b283b5611f6902b125c6928c67c94226f8a2ef45239d4e366"
)
_NORMALIZED_REDIS_TTLS = frozenset(
    {
        "botmail:mail:queue:task:2101",
        "botmail:mail:queue:domains:2101",
    }
)


class _MaildirFailureMixin:
    report_dns: ScriptedDnsServer
    workspace: Path | None
    ports: PortSet | None
    _application: Any

    @property
    def application_pid_for_test(self) -> int:
        if self._application is None:
            raise RuntimeError("application is not running")
        return cast(int, self._application.pid)

    def drain_report_dns_queries(self) -> tuple[DnsQuery, ...]:
        return self.report_dns.drain_queries()


class _MaildirFailureJavaRuntime(_MaildirFailureMixin, PersistentJavaOracleRuntime):
    def __init__(self, workspace: Path, dns: ScriptedDnsServer) -> None:
        super().__init__(workspace)
        self.report_dns = dns

    def _application_arguments(self) -> list[str]:
        arguments = super()._application_arguments()
        jar_index = arguments.index("-jar")
        arguments[jar_index:jar_index] = [
            f"-Ddns.server={self.report_dns.host}:{self.report_dns.port}",
            "-Dbotmail.reporting.dmarc-report-sender-address=qa@example.test",
            "-Dbotmail.reporting.tls-report-sender-address=qa@example.test",
            "-Dbotmail.reporting.organization-name=Blackbox Reports",
            "-Dbotmail.reporting.organization-email=reports@example.test",
            "-Dbotmail.queue.poll-interval-ms=60000",
        ]
        return arguments


class _MaildirFailureCandidateRuntime(_MaildirFailureMixin, CandidateRuntime):
    def __init__(self, *, command_template: tuple[str, ...], dns: ScriptedDnsServer) -> None:
        super().__init__(command_template=command_template)
        self.report_dns = dns

    @property
    def requires_qa_account(self) -> bool:
        return False

    def _candidate_configuration(self) -> Path:
        path = super()._candidate_configuration()
        value = json.loads(path.read_text(encoding="utf-8"))
        value["reporting"] = {
            "enabled": True,
            "auto_send_enabled": False,
            "dns_server": f"{self.report_dns.host}:{self.report_dns.port}",
            "dmarc_report_sender_address": "qa@example.test",
            "tls_report_sender_address": "qa@example.test",
            "organization_name": "Blackbox Reports",
            "organization_email": "reports@example.test",
            "http_delivery_enabled": False,
        }
        path.write_text(
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        return path

    def _application_arguments(self) -> list[str]:
        return [
            *super()._application_arguments(),
            "--lmyzmail.reporting.enabled=true",
            "--lmyzmail.queue.poll-interval-ms=60000",
            "--lmyzmail.maildir.max-files-per-directory=1",
        ]

    def _start_postgres(self) -> None:
        super()._start_postgres()
        workspace, ports = self._require_state()
        psql = self.paths.runtime / "postgres-root/usr/lib/postgresql/16/bin/psql"
        seed = self.paths.repository / "blackbox/fixtures/legacy/postgres-seed.sql"
        self._run_checked(
            [
                str(psql),
                "--host=127.0.0.1",
                f"--port={ports.postgres}",
                "--username=lmyzmail_test",
                "--dbname=lmyzmail",
                "--single-transaction",
                "--set=ON_ERROR_STOP=1",
                f"--file={seed}",
            ],
            env=self._postgres_env(),
            log_path=workspace / "postgres-seed.log",
        )


@dataclass(frozen=True, slots=True)
class _OracleTarget:
    runtime: _MaildirFailureJavaRuntime

    @property
    def target_kind(self) -> str:
        return "java-oracle"

    @property
    def workspace(self) -> Path | None:
        return self.runtime.workspace

    @property
    def ports(self) -> PortSet | None:
        return self.runtime.ports

    def drain_report_dns_queries(self) -> tuple[DnsQuery, ...]:
        return self.runtime.drain_report_dns_queries()


def _candidate(repository: Path, dns: ScriptedDnsServer) -> _MaildirFailureCandidateRuntime:
    configured = os.environ.get("LMYZMAIL_CANDIDATE_COMMAND_JSON")
    command_template = (
        CandidateRuntime.from_environment().command_template
        if configured is not None
        else (
            str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
            "--config",
            "{config}",
        )
    )
    return _MaildirFailureCandidateRuntime(command_template=command_template, dns=dns)


def _connect_postgres(target: RuntimeTarget) -> psycopg.Connection[tuple[Any, ...]]:
    if target.ports is None:
        raise AssertionError("report Maildir failure target is not started")
    connection = psycopg.connect(
        host=_HOST,
        port=target.ports.postgres,
        user="lmyzmail_test",
        dbname="lmyzmail",
        connect_timeout=5,
        autocommit=False,
    )
    connection.execute("SET statement_timeout = '5s'")
    connection.execute("SET lock_timeout = '5s'")
    return connection


def _outbound_database_state(target: RuntimeTarget) -> dict[str, Any]:
    with _connect_postgres(target) as connection:
        rows = connection.execute(
            """
            SELECT id, status, retry_count, max_retries, sender_address,
                   recipients_json, sent_file_name, sent_subdirectory,
                   message_id, last_error
            FROM outbound_mail_queue
            ORDER BY id
            """
        ).fetchall()
        sequence = connection.execute(
            "SELECT last_value, is_called FROM outbound_mail_queue_id_seq"
        ).fetchone()
        email_index_count = connection.execute(
            "SELECT count(*) FROM email_index WHERE mailbox_address=%s AND folder='sent'",
            (_REPORT_SENDER,),
        ).fetchone()
    if sequence is None or email_index_count is None:
        raise AssertionError("outbound database state query returned no row")
    return {
        "rows": [
            {
                "id": row[0],
                "status": row[1],
                "retryCount": row[2],
                "maxRetries": row[3],
                "senderAddress": row[4],
                "recipientsJson": json.loads(cast(str, row[5])),
                "sentFileName": row[6],
                "sentSubdirectory": row[7],
                "messageId": row[8],
                "lastError": row[9],
            }
            for row in rows
        ],
        "sequence": {"lastValue": sequence[0], "isCalled": sequence[1]},
        "sentIndexCount": cast(int, email_index_count[0]),
    }


def _redis_client(target: RuntimeTarget) -> redis.Redis:
    if target.ports is None:
        raise AssertionError("report Maildir failure target is not started")
    return cast(
        redis.Redis,
        redis.Redis(
            host=_HOST,
            port=target.ports.redis,
            decode_responses=False,
            socket_connect_timeout=2.0,
            socket_timeout=2.0,
        ),
    )


def _redis_value(client: redis.Redis, key: str, redis_type: str) -> Any:
    if redis_type == "string":
        value = cast(bytes, client.get(key))
        if key.startswith(_REDIS_QUEUE_PREFIX + "task:"):
            return json.loads(value)
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return {"base64": base64.b64encode(value).decode("ascii")}
    if redis_type == "list":
        list_values = cast(list[bytes], client.lrange(key, 0, -1))
        return [base64.b64encode(value).decode("ascii") for value in list_values]
    if redis_type == "set":
        set_values = cast(set[bytes], client.smembers(key))
        return sorted(base64.b64encode(value).decode("ascii") for value in set_values)
    if redis_type == "zset":
        zset_values = cast(
            list[tuple[bytes, float]], client.zrange(key, 0, -1, withscores=True)
        )
        return [
            [base64.b64encode(value).decode("ascii"), score]
            for value, score in zset_values
        ]
    if redis_type == "hash":
        hash_values = cast(dict[bytes, bytes], client.hgetall(key))
        return [
            [base64.b64encode(field).decode("ascii"), base64.b64encode(value).decode("ascii")]
            for field, value in sorted(hash_values.items())
        ]
    raise AssertionError(f"unsupported Redis type in Maildir failure snapshot: {redis_type}")


def _redis_state(target: RuntimeTarget) -> dict[str, Any]:
    client = _redis_client(target)
    try:
        keys = sorted(cast(bytes, key).decode("utf-8") for key in client.scan_iter())
        result: dict[str, Any] = {}
        for key in keys:
            raw_type = cast(bytes, client.type(key))
            redis_type = raw_type.decode("ascii")
            ttl = cast(int, client.ttl(key))
            result[key] = {
                "type": redis_type,
                "ttl": "positive" if key in _NORMALIZED_REDIS_TTLS and ttl > 0 else ttl,
                "value": _redis_value(client, key, redis_type),
            }
        return result
    finally:
        client.close()


def _path_identity(path: Path) -> dict[str, Any]:
    metadata = path.lstat()
    if stat.S_ISDIR(metadata.st_mode):
        kind = "directory"
        digest = None
    elif stat.S_ISREG(metadata.st_mode):
        kind = "file"
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    else:
        raise AssertionError(f"unsupported Maildir entry during failure snapshot: {path}")
    return {
        "kind": kind,
        "mode": stat.S_IMODE(metadata.st_mode),
        "size": metadata.st_size,
        "sha256": digest,
    }


def _filesystem_state(target: RuntimeTarget) -> dict[str, Any]:
    if target.workspace is None:
        raise AssertionError("report Maildir failure target is not started")
    roots = {
        "maildir": target.workspace / "maildir",
        "javaTmp": target.workspace / "java-tmp",
        "candidateOutbound": target.workspace / "maildir/.lmyzmail-outbound",
    }
    result: dict[str, Any] = {}
    for label, root in roots.items():
        if not root.exists():
            result[label] = {}
            continue
        if root.is_symlink() or not root.is_dir():
            raise AssertionError(f"snapshot root is not a real directory: {root}")
        entries: dict[str, Any] = {}
        for path in sorted(root.rglob("*")):
            if path.is_symlink():
                raise AssertionError(f"snapshot root contains a symlink: {path}")
            entries[path.relative_to(root).as_posix()] = _path_identity(path)
        result[label] = entries
    return result


def _storage_state(target: RuntimeTarget) -> dict[str, Any]:
    return {
        "sourceDatabase": _report_database_state(target),
        "outboundDatabase": _outbound_database_state(target),
        "redis": _redis_state(target),
        "filesystem": _filesystem_state(target),
    }


def _sent_root(target: RuntimeTarget) -> Path:
    if target.workspace is None:
        raise AssertionError("report Maildir failure target is not started")
    return target.workspace / "maildir" / _REPORT_SENDER / "sent"


def _install_fault(target: RuntimeTarget) -> None:
    sent = _sent_root(target)
    sent.parent.mkdir(parents=True, exist_ok=True)
    if sent.exists():
        if sent.is_symlink() or not sent.is_dir() or any(sent.iterdir()):
            raise AssertionError("report Maildir fault requires an absent or empty real Sent directory")
        sent.rmdir()
    sent.write_bytes(_FAULT_MARKER)
    if not sent.is_file() or sent.read_bytes() != _FAULT_MARKER:
        raise AssertionError("report Maildir fault marker was not installed exactly")


def _remove_fault(target: RuntimeTarget) -> None:
    sent = _sent_root(target)
    if sent.is_symlink() or not sent.is_file() or sent.read_bytes() != _FAULT_MARKER:
        raise AssertionError("report Maildir fault marker changed before recovery")
    sent.unlink()
    sent.mkdir()


def _request(target: RuntimeTarget) -> RawHttpResponse:
    if target.ports is None:
        raise AssertionError("report Maildir failure target ports are unavailable")
    return http_exchange(
        _HOST,
        target.ports.http,
        "POST",
        f"/api/reports/domain/{_DMARC_DOMAIN}?date={_REPORT_DATE}",
        headers=(("X-API-Key", API_KEY),),
        timeout=15.0,
        max_response=1 * 1024 * 1024,
    )


def _success_response(response: RawHttpResponse) -> dict[str, Any]:
    return _expect_json(
        response,
        status=200,
        body={
            "domain": _DMARC_DOMAIN,
            "date": _REPORT_DATE,
            "dmarc": {
                "results": [
                    {"success": True, "method": "email", "target": _REPORT_SENDER}
                ],
                "error": "none",
            },
            "tls": {"results": [], "error": "No TLS data for this domain/date"},
        },
    )


def _capture_single_publication(
    target: RuntimeTarget,
    client: redis.Redis,
    before_pending: list[int],
    before_files: dict[str, Path],
) -> tuple[list[str], dict[str, dict[str, Any]], dict[str, dict[str, Any]], dict[str, Path]]:
    pending = _redis_pending(client)
    files = _sent_files(target)
    if pending[: len(before_pending)] != before_pending or len(pending) != len(before_pending) + 1:
        raise AssertionError("Maildir recovery did not append exactly one pending task")
    added_files = {key: path for key, path in files.items() if key not in before_files}
    if len(added_files) != 1 or len(files) != len(before_files) + 1:
        raise AssertionError("Maildir recovery did not add exactly one Sent file")
    label, task = _task_snapshot(client, pending[-1])
    if label != "dmarc":
        raise AssertionError(f"Maildir recovery queue task was not DMARC: {label!r}")
    message = _report_message_snapshot(next(iter(added_files.values())).read_bytes())
    if message != task["message"]:
        raise AssertionError("Maildir recovery Redis and Maildir bytes differed")
    return [label], {label: task}, {label: message}, added_files


def _assert_active_dmarc_golden(
    response: dict[str, Any],
    tasks: dict[str, dict[str, Any]],
    maildir_messages: dict[str, dict[str, Any]],
) -> None:
    repository = Path(__file__).resolve().parents[3]
    path = repository / _SEEDED_DELIVERY_GOLDEN
    actual_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual_sha256 != _SEEDED_DELIVERY_GOLDEN_SHA256:
        raise AssertionError(
            "active seeded report delivery golden changed: "
            f"actual={actual_sha256}, expected={_SEEDED_DELIVERY_GOLDEN_SHA256}"
        )
    golden = json.loads(path.read_text(encoding="utf-8"))["observation"]
    expected = {
        "response": golden["responses"]["dmarc"],
        "task": golden["queue"]["tasks"]["dmarc"],
        "maildir": golden["maildir"]["messages"]["dmarc"],
    }
    actual = {
        "response": response,
        "task": tasks["dmarc"],
        "maildir": maildir_messages["dmarc"],
    }
    if actual != expected:
        raise AssertionError(
            f"recovered report publication changed from the active golden: "
            f"actual={actual!r}, expected={expected!r}"
        )


def _failure_response(response: RawHttpResponse) -> dict[str, Any]:
    return _expect_json(
        response,
        status=200,
        body={
            "domain": _DMARC_DOMAIN,
            "date": _REPORT_DATE,
            "dmarc": {
                "results": [
                    {
                        "success": False,
                        "method": "email",
                        "target": _REPORT_SENDER,
                        "error": "outbound queue unavailable",
                    }
                ],
                "error": "none",
            },
            "tls": {"results": [], "error": "No TLS data for this domain/date"},
        },
    )


def _state_without_allocators(state: dict[str, Any]) -> dict[str, Any]:
    value = json.loads(json.dumps(state))
    value["redis"].pop(_REDIS_QUEUE_PREFIX + "seq", None)
    value["outboundDatabase"].pop("sequence", None)
    # Rust creates bounded internal roots lazily during startup/materialization.
    # Empty internal directories are not queued messages or temporary artifacts;
    # files below these roots remain visible and are compared strictly.
    maildir = cast(dict[str, Any], value["filesystem"]["maildir"])
    for path, identity in list(maildir.items()):
        if (
            identity.get("kind") == "directory"
            and (path == ".lmyzmail" or path.startswith(".lmyzmail/")
                 or path == ".lmyzmail-outbound" or path.startswith(".lmyzmail-outbound/"))
        ):
            maildir.pop(path, None)
    return cast(dict[str, Any], value)


def _internal_empty_roots(state: dict[str, Any]) -> dict[str, Any]:
    value = json.loads(json.dumps(state))
    for root_name in ("maildir", "candidateOutbound", "javaTmp"):
        entries = cast(dict[str, Any], value["filesystem"][root_name])
        for path in list(entries):
            if entries[path]["kind"] == "directory":
                entries.pop(path, None)
    return cast(dict[str, Any], value)


def _assert_java_partial_publication(
    target: RuntimeTarget,
    before: dict[str, Any],
    after: dict[str, Any],
    before_pending: list[int],
) -> dict[str, Any]:
    if after["sourceDatabase"] != before["sourceDatabase"]:
        raise AssertionError("Java Maildir failure mutated source report rows")
    if after["outboundDatabase"] != before["outboundDatabase"]:
        raise AssertionError("Java Maildir failure mutated PostgreSQL outbound state")
    if after["filesystem"] != before["filesystem"]:
        raise AssertionError("Java Maildir failure left a filesystem side effect")
    client = _redis_client(target)
    try:
        pending = _redis_pending(client)
        if pending[: len(before_pending)] != before_pending or len(pending) != len(before_pending) + 1:
            raise AssertionError("Java Maildir failure did not append exactly one partial task")
        task_id = pending[-1]
        label, task = _task_snapshot(client, task_id)
    finally:
        client.close()
    if label != "dmarc" or task["sentFilePresent"] or task["sentSubdirectory"] is not None:
        raise AssertionError(f"Java Maildir partial task shape changed: {label!r}, {task!r}")

    sequence_key = _REDIS_QUEUE_PREFIX + "seq"
    pending_key = _REDIS_QUEUE_PREFIX + "pending"
    task_key = f"{_REDIS_QUEUE_PREFIX}task:{task_id}"
    domains_key = f"{_REDIS_QUEUE_PREFIX}domains:{task_id}"
    allowed = {sequence_key, pending_key, task_key, domains_key}
    before_redis = cast(dict[str, Any], before["redis"])
    after_redis = cast(dict[str, Any], after["redis"])
    before_other = {key: value for key, value in before_redis.items() if key not in allowed}
    after_other = {key: value for key, value in after_redis.items() if key not in allowed}
    if after_other != before_other:
        raise AssertionError(
            "Java Maildir failure changed Redis outside sequence/pending/task/domain state: "
            f"before={before_other!r}, after={after_other!r}"
        )
    added = set(after_redis).difference(before_redis)
    expected_added = {task_key, domains_key}
    if pending_key not in before_redis:
        expected_added.add(pending_key)
    if added != expected_added:
        raise AssertionError(
            f"Java Maildir failure Redis key delta changed: added={added!r}, "
            f"expected={expected_added!r}"
        )
    return {
        "taskIdPresent": task_id > 0,
        "pendingAppended": True,
        "task": task,
        "sentFileMissing": True,
        "sentSubdirectoryMissing": True,
    }


def _assert_candidate_no_publication(
    before: dict[str, Any],
    after: dict[str, Any],
) -> None:
    if _state_without_allocators(after) != _state_without_allocators(before):
        raise AssertionError(
            "Rust Maildir failure left partial durable state beyond ID allocators: "
            f"before={before!r}, after={after!r}"
        )


def _normalized_added_outbound_rows(
    rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for row in rows:
        normalized.append(
            {
                **row,
                "id": "<queue-id>",
                "messageId": "<message-id>",
                "sentFileName": "<sent-file>",
            }
        )
    return normalized


def _capture(runtime: _MaildirFailureMixin, target: RuntimeTarget) -> dict[str, Any]:
    if _drain_report_dns_queries(target):
        raise AssertionError("report Maildir failure DNS trace was not initially empty")
    before_files = _sent_files(target)
    client = _redis_client(target)
    try:
        before_pending = _redis_pending(client)
    finally:
        client.close()
    application_pid = runtime.application_pid_for_test
    _install_fault(target)
    faulted_before = _storage_state(target)
    try:
        raw_failure_response = _request(target)
        failure_queries = _drain_report_dns_queries(target)
        faulted_after = _storage_state(target)
    finally:
        _remove_fault(target)
    if runtime.application_pid_for_test != application_pid:
        raise AssertionError("application restarted during report Maildir failure")
    if target.target_kind == "java-oracle":
        failure_response = _success_response(raw_failure_response)
        failure_publication = _assert_java_partial_publication(
            target,
            faulted_before,
            faulted_after,
            before_pending,
        )
    else:
        failure_response = _failure_response(raw_failure_response)
        _assert_candidate_no_publication(faulted_before, faulted_after)
        failure_publication = None
    internal_before = _internal_empty_roots(faulted_before)["filesystem"]
    internal_after = _internal_empty_roots(faulted_after)["filesystem"]
    if target.target_kind != "java-oracle" and internal_after != internal_before:
        raise AssertionError(
            "Rust Maildir failure changed internal files outside the faulted Sent path: "
            f"before={internal_before!r}, after={internal_after!r}"
        )

    client = _redis_client(target)
    try:
        recovery_pending = _redis_pending(client)
        recovery_response = _success_response(_request(target))
        recovery_queries = _drain_report_dns_queries(target)
        pending_order, tasks, maildir_messages, added_files = _capture_single_publication(
            target,
            client,
            recovery_pending,
            before_files,
        )
    finally:
        client.close()
    _assert_active_dmarc_golden(recovery_response, tasks, maildir_messages)

    after = _storage_state(target)
    if after["sourceDatabase"] != faulted_before["sourceDatabase"]:
        raise AssertionError("report Maildir recovery mutated source report rows")
    expected_failure_queries = _EXPECTED_DNS_QUERIES
    if tuple(query.qname for query in failure_queries) != expected_failure_queries:
        raise AssertionError(f"report Maildir failure DNS order changed: {failure_queries!r}")
    if recovery_queries:
        raise AssertionError(f"report Maildir recovery unexpectedly queried DNS: {recovery_queries!r}")
    return {
        "maildirFault": "replace absent or empty qa@example.test/sent directory with a regular file",
        "applicationPidUnchanged": True,
        "failureDnsQueries": [query.qname for query in failure_queries],
        "failureResponse": failure_response,
        "failurePublication": failure_publication,
        "failureState": {
            "redisSequenceBefore": faulted_before["redis"].get(_REDIS_QUEUE_PREFIX + "seq"),
            "redisSequenceAfter": faulted_after["redis"].get(_REDIS_QUEUE_PREFIX + "seq"),
            "postgresSequenceBefore": faulted_before["outboundDatabase"]["sequence"],
            "postgresSequenceAfter": faulted_after["outboundDatabase"]["sequence"],
            "redisMutationScope": (
                ["sequence", "pending", "task", "domains"]
                if target.target_kind == "java-oracle"
                else ["sequence"]
            ),
            "queuePublicationCount": len(recovery_pending) - len(before_pending),
            "noOutboundRows": faulted_after["outboundDatabase"]["rows"]
            == faulted_before["outboundDatabase"]["rows"],
            "noSentIndexRows": faulted_after["outboundDatabase"]["sentIndexCount"]
            == faulted_before["outboundDatabase"]["sentIndexCount"],
            "noResidualSpoolOrTemporaryFiles": internal_after == internal_before,
        },
        "recoveryResponse": recovery_response,
        "recoveryDnsQueries": [query.qname for query in recovery_queries],
        "publication": {
            "pendingOrder": pending_order,
            "maildirAddedCount": len(added_files),
            "redisMaildirByteEquivalent": True,
            "activeGoldenPath": _SEEDED_DELIVERY_GOLDEN.as_posix(),
            "activeGoldenSha256": _SEEDED_DELIVERY_GOLDEN_SHA256,
            "activeGoldenDmarcMatched": True,
        },
        "sourceDatabaseUnchanged": True,
        "outboundDatabaseAddedAfterRecovery": _normalized_added_outbound_rows(
            after["outboundDatabase"]["rows"][
                len(faulted_before["outboundDatabase"]["rows"]) :
            ]
        ),
    }


def _freeze_or_assert(name: str, observation: dict[str, Any], *, record_env: str) -> None:
    path = Path(__file__).with_name(name)
    if os.environ.get(record_env) == "1":
        if path.exists():
            raise AssertionError(f"refusing to overwrite frozen observation: {path}")
        path.write_text(
            json.dumps(observation, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        return
    if not path.exists():
        raise AssertionError(f"frozen observation is missing: {path}")
    expected = json.loads(path.read_text(encoding="utf-8"))
    if observation != expected:
        raise AssertionError(
            f"report Maildir failure observation changed: "
            f"actual={observation!r}, expected={expected!r}"
        )


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(120)
def test_observe_java_report_trigger_maildir_failure(tmp_path: Path) -> None:
    with report_dns_server() as dns:
        with _MaildirFailureJavaRuntime(tmp_path / "java-report-maildir-failure", dns) as runtime:
            observation = _capture(runtime, _OracleTarget(runtime))
    _freeze_or_assert(
        "java-observation.json",
        observation,
        record_env="LMYZMAIL_RECORD_JAVA_GOLDEN",
    )
    print(json.dumps(observation, ensure_ascii=False, sort_keys=True, indent=2))


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(120)
def test_observe_rust_report_trigger_maildir_failure() -> None:
    repository = Path(__file__).resolve().parents[3]
    with report_dns_server() as dns:
        with _candidate(repository, dns) as runtime:
            observation = _capture(runtime, runtime)
    _freeze_or_assert(
        "candidate-observation.json",
        observation,
        record_env="LMYZMAIL_RECORD_CANDIDATE_EVIDENCE",
    )
    print(json.dumps(observation, ensure_ascii=False, sort_keys=True, indent=2))
