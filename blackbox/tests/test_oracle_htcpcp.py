from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from lmyzmail_blackbox.differential import DifferentialRunner
from lmyzmail_blackbox.htcpcp_contract import (
    HTCPCP_ORACLE_EVIDENCE_SCENARIOS,
    HTCPCP_SCENARIOS,
    htcpcp_exchange,
)
from lmyzmail_blackbox.protocols import build_http_request, connect_bounded, read_http_response
from lmyzmail_blackbox.runtime import CandidateRuntime, JavaOracleRuntime

_PROFILE = "managed-htcpcp"
_GOLDEN = "blackbox/golden/java/managed-htcpcp-v16"
_ORACLE_EVIDENCE_GOLDEN = "blackbox/golden/java/managed-htcpcp-oracle-evidence-v13"


class _RestartableJavaRuntime(JavaOracleRuntime):
    def restart_application(self) -> None:
        if self._application is None:
            raise RuntimeError("Java oracle application is not running")
        self._application.stop(
            timeout=self.shutdown_timeout,
            kill_timeout=self.shutdown_kill_timeout,
        )
        self._application = None
        JavaOracleRuntime._start_application(self)


class _RestartableCandidateRuntime(CandidateRuntime):
    def restart_application(self) -> None:
        if self._application is None:
            raise RuntimeError("candidate application is not running")
        self._application.stop(
            timeout=self.shutdown_timeout,
            kill_timeout=self.shutdown_kill_timeout,
        )
        self._application = None
        CandidateRuntime._start_application(self)


def _candidate(repository: Path) -> _RestartableCandidateRuntime:
    if os.environ.get("LMYZMAIL_CANDIDATE_COMMAND_JSON") is not None:
        runtime = _RestartableCandidateRuntime.from_environment()
        assert isinstance(runtime, _RestartableCandidateRuntime)
        return runtime
    return _RestartableCandidateRuntime(
        command_template=(
            str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
            "--config",
            "{config}",
        )
    )


def _assert_restart_resets_pot(
    runtime: _RestartableJavaRuntime | _RestartableCandidateRuntime,
) -> None:
    assert runtime.ports is not None
    started = htcpcp_exchange(
        runtime,
        "BREW",
        "/pot-0",
        content_type="message/coffeepot",
        body=b"start",
    )
    assert started.status_code == 200
    before = json.loads(htcpcp_exchange(runtime, "GET", "/pot-0").body)
    assert before["state"] == "BREWING"

    runtime.restart_application()

    after = json.loads(htcpcp_exchange(runtime, "GET", "/pot-0").body)
    assert after["state"] == "IDLE"
    assert after["generation"] == 0
    assert after["currentAdditions"] == []


def _assert_candidate_honors_connection_close(runtime: _RestartableCandidateRuntime) -> None:
    assert runtime.ports is not None
    port = runtime.ports.htcpcp
    stream = connect_bounded("127.0.0.1", port, timeout=2.0, max_received=128 * 1024)
    try:
        stream.sendall(
            build_http_request("GET", "/pot-0", host=f"127.0.0.1:{port}")
        )
        response = read_http_response(stream, request_method="GET")
        assert response.status_code == 200
        stream.sock.settimeout(0.25)
        assert stream.sock.recv(1) == b""
    finally:
        stream.sock.close()


def _assert_candidate_rejects_ambiguous_framing(runtime: _RestartableCandidateRuntime) -> None:
    assert runtime.ports is not None
    port = runtime.ports.htcpcp
    requests = (
        (
            b"BREW /pot-0 HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n"
            b"Content-Type: message/coffeepot\r\nContent-Length: 5\r\n"
            b"Content-Length: 5\r\n\r\nstart"
        ),
        (
            b"BREW /pot-0 HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n"
            b"Content-Type: message/coffeepot\r\nContent-Length: 5\r\n"
            b"Content-Length: 4\r\n\r\nstart"
        ),
        (
            b"BREW /pot-0 HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n"
            b"Content-Type: message/coffeepot\r\nTransfer-Encoding: gzip\r\n\r\nstart"
        ),
        (
            b"BREW /pot-0 HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n"
            b"Content-Type: message/coffeepot\r\n"
            b"Transfer-Encoding: chunked, gzip\r\n\r\n5\r\nstart\r\n0\r\n\r\n"
        ),
        (
            b"BREW /pot-0 HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n"
            b"Content-Type: message/coffeepot\r\nTransfer-Encoding: chunked\r\n"
            b"Content-Length: 5\r\nExpect: 100-continue\r\n\r\n"
        ),
    )
    expected = (
        b"HTTP/1.1 400 Bad Request\r\n"
        b"content-length: 0\r\n"
        b"connection: close\r\n\r\n"
    )
    for request in requests:
        stream = connect_bounded("127.0.0.1", port, timeout=2.0, max_received=4096)
        try:
            stream.sendall(request)
            response = read_http_response(stream, request_method="BREW")
            assert response.raw == expected
            stream.sock.settimeout(0.25)
            assert stream.sock.recv(1) == b""
        finally:
            stream.sock.close()


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(240)
def test_frozen_java_htcpcp_golden(record_java_golden: bool) -> None:
    repository = Path(__file__).resolve().parents[2]
    runner = DifferentialRunner(
        repository,
        repository / _GOLDEN,
        _PROFILE,
        record_java=record_java_golden,
    )
    evidence_runner = DifferentialRunner(
        repository,
        repository / _ORACLE_EVIDENCE_GOLDEN,
        f"{_PROFILE}-oracle-evidence",
        record_java=record_java_golden,
    )
    with JavaOracleRuntime() as oracle:
        if record_java_golden:
            runner.record_from_java(HTCPCP_SCENARIOS, oracle)
            evidence_runner.record_from_java(HTCPCP_ORACLE_EVIDENCE_SCENARIOS, oracle)
        else:
            runner.verify_java(HTCPCP_SCENARIOS, oracle)
            evidence_runner.verify_java(HTCPCP_ORACLE_EVIDENCE_SCENARIOS, oracle)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(240)
def test_rust_candidate_htcpcp_matches_frozen_java_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        DifferentialRunner(
            repository,
            repository / _GOLDEN,
            _PROFILE,
        ).verify_candidate(HTCPCP_SCENARIOS, candidate)
        _assert_candidate_honors_connection_close(candidate)
        _assert_candidate_rejects_ambiguous_framing(candidate)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(150)
def test_frozen_java_htcpcp_state_is_process_local() -> None:
    with _RestartableJavaRuntime() as oracle:
        _assert_restart_resets_pot(oracle)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(150)
def test_rust_candidate_htcpcp_state_is_process_local() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        _assert_restart_resets_pot(candidate)
