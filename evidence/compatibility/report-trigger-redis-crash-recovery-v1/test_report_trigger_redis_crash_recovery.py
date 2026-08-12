from __future__ import annotations

import importlib.util
import json
import os
import sys
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import pytest
import redis

from lmyzmail_blackbox.differential import RuntimeTarget
from lmyzmail_blackbox.ports import PortSet
from lmyzmail_blackbox.protocols import RawHttpResponse
from lmyzmail_blackbox.runtime import CandidateRuntime
from lmyzmail_blackbox.scripted_dns import DnsQuery, ScriptedDnsServer

_SOURCE = Path(__file__).resolve().parents[1] / "report-trigger-redis-outage-v1" / (
    "test_report_trigger_redis_outage.py"
)
_SPEC = importlib.util.spec_from_file_location("report_trigger_redis_outage_contract", _SOURCE)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError(f"unable to load frozen Redis outage contract: {_SOURCE}")
_CONTRACT = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _CONTRACT
_SPEC.loader.exec_module(_CONTRACT)

_HOST = "127.0.0.1"
_PAUSED_SECONDS = 12.0


def _redis_pid(runtime: Any) -> int:
    if runtime._redis is None:
        raise RuntimeError("Redis is not running")
    return cast(int, runtime._redis.pid)


def _persist_redis(runtime: Any) -> None:
    if runtime._redis is None or runtime.ports is None:
        raise RuntimeError("Redis is not running")
    client: redis.Redis = redis.Redis(
        host=_HOST, port=runtime.ports.redis, decode_responses=True
    )
    try:
        if not cast(bool, client.config_set("appendonly", "yes")):
            raise AssertionError("Redis refused CONFIG SET appendonly yes")
        if not cast(bool, client.config_set("appendfsync", "always")):
            raise AssertionError("Redis refused CONFIG SET appendfsync always")
        if not cast(bool, client.save()):
            raise AssertionError("Redis SAVE did not report success")
    finally:
        client.close()


def _kill_redis(runtime: Any) -> None:
    if runtime._redis is None:
        raise RuntimeError("Redis is not running")
    runtime._redis.kill(timeout=5.0)


def _restart_redis(runtime: Any) -> None:
    if runtime._redis is None:
        raise RuntimeError("Redis process object is unavailable")
    _, ports = runtime._require_state()
    runtime._redis.start()
    runtime._redis.wait_for_tcp(_HOST, ports.redis, timeout=10.0)
    client: redis.Redis = redis.Redis(host=_HOST, port=ports.redis, socket_connect_timeout=2.0)
    try:
        client.ping()
    finally:
        client.close()


@dataclass(frozen=True, slots=True)
class _OracleTarget:
    runtime: Any

    @property
    def target_kind(self) -> str:
        return "java-oracle"

    @property
    def workspace(self) -> Path | None:
        return cast(Path | None, self.runtime.workspace)

    @property
    def ports(self) -> PortSet | None:
        return cast(PortSet | None, self.runtime.ports)

    def drain_report_dns_queries(self) -> tuple[DnsQuery, ...]:
        return cast(tuple[DnsQuery, ...], self.runtime.drain_report_dns_queries())


def _candidate(repository: Path, dns: ScriptedDnsServer) -> Any:
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
    runtime = _CONTRACT._RedisOutageCandidateRuntime(
        command_template=command_template, dns=dns
    )
    return runtime


def _redis_client(target: RuntimeTarget) -> redis.Redis:
    if target.ports is None:
        raise AssertionError("Redis crash recovery target is not started")
    return cast(redis.Redis, redis.Redis(
        host=_HOST,
        port=target.ports.redis,
        decode_responses=False,
        socket_connect_timeout=2.0,
        socket_timeout=2.0,
    ))


def _capture(runtime: Any, target: RuntimeTarget) -> dict[str, Any]:
    contract = cast(Any, _CONTRACT)
    if contract._drain_report_dns_queries(target):
        raise AssertionError("Redis crash recovery DNS trace was not initially empty")
    before = contract._durable_state(target)
    before_files = contract._sent_files(target)
    client = _redis_client(target)
    try:
        before_pending = contract._redis_pending(client)
    finally:
        client.close()
    application_pid = runtime.application_pid_for_test
    redis_pid = _redis_pid(runtime)
    _persist_redis(runtime)
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="report-redis-crash") as executor:
        first: Future[RawHttpResponse] = executor.submit(contract._long_request, target)
        outage_queries = contract._wait_for_dns_queries(target)
        _kill_redis(runtime)
        deadline = time.monotonic() + _PAUSED_SECONDS
        while not first.done() and time.monotonic() < deadline:
            time.sleep(0.025)
        completed_while_down = first.done()
        _restart_redis(runtime)
        first_response = first.result(timeout=15.0)

    if runtime.application_pid_for_test != application_pid:
        raise AssertionError("application restarted during Redis crash recovery")
    recovered_pid = _redis_pid(runtime)
    if recovered_pid == redis_pid:
        raise AssertionError("Redis PID did not change after SIGKILL recovery")
    client = _redis_client(target)
    try:
        client.ping()
        pending_after_restart = contract._redis_pending(client)
        pending_prefix_preserved = pending_after_restart[: len(before_pending)] == before_pending
        if completed_while_down:
            outage_response = contract._failure_response(first_response)
            recovery_response = contract._success_response(contract._long_request(target))
        else:
            outage_response = None
            recovery_response = contract._success_response(first_response)
        pending_order, tasks, maildir_messages, added_files = contract._capture_single_publication(
            target,
            client,
            before_pending,
            before_files,
        )
    finally:
        client.close()
    contract._assert_active_dmarc_golden(target, recovery_response, tasks, maildir_messages)
    after = contract._durable_state(target)
    if after["sourceDatabase"] != before["sourceDatabase"]:
        raise AssertionError("Redis crash recovery mutated source report rows")
    if len(after["maildir"]) != len(before["maildir"]) + 1:
        raise AssertionError("Redis crash recovery did not create exactly one Sent file")
    return {
        "redisFault": "SIGKILL process group after durable RDB/AOF SAVE",
        "completedWhileRedisDown": completed_while_down,
        "pausedObservationSeconds": _PAUSED_SECONDS,
        "applicationPidUnchanged": True,
        "redisPidChanged": True,
        "outageDnsQueries": [query.qname for query in outage_queries],
        "outageResponse": outage_response,
        "pendingPrefixPreservedAfterRedisRestart": pending_prefix_preserved,
        "recoveryResponse": recovery_response,
        "recoveryDnsQueries": [
            query.qname for query in contract._drain_report_dns_queries(target)
        ],
        "publication": {
            "pendingOrder": pending_order,
            "maildirAddedCount": len(added_files),
            "noTemporaryFiles": not any(".tmp" in key for key in added_files),
            "redisMaildirByteEquivalent": True,
            "activeGoldenDmarcMatched": True,
        },
        "sourceDatabaseUnchanged": True,
    }


def _freeze_or_assert(name: str, observation: dict[str, Any], record_env: str) -> None:
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
        raise AssertionError(f"Redis crash recovery observation changed: {observation!r}")


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(120)
def test_observe_java_report_trigger_redis_crash_recovery(tmp_path: Path) -> None:
    with _CONTRACT.report_dns_server() as dns:
        with _CONTRACT._RedisOutageJavaRuntime(tmp_path / "java-report-redis-crash", dns) as runtime:
            observation = _capture(runtime, _OracleTarget(runtime))
    _freeze_or_assert("java-observation.json", observation, "LMYZMAIL_RECORD_JAVA_GOLDEN")


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(120)
def test_observe_rust_report_trigger_redis_crash_recovery() -> None:
    repository = Path(__file__).resolve().parents[3]
    with _CONTRACT.report_dns_server() as dns:
        with _candidate(repository, dns) as runtime:
            observation = _capture(runtime, runtime)
    _freeze_or_assert(
        "candidate-observation.json", observation, "LMYZMAIL_RECORD_CANDIDATE_EVIDENCE"
    )
