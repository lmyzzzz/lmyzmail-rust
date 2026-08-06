from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest

from lmyzmail_blackbox import runtime as runtime_module
from lmyzmail_blackbox.errors import HarnessError, ProcessStartError, ProtocolError
from lmyzmail_blackbox.ports import PortSet
from lmyzmail_blackbox.runtime import JavaOracleRuntime, JavaOracleTlsRuntime


@dataclass
class _FakeSocket:
    closed: bool = False

    def close(self) -> None:
        self.closed = True


@dataclass
class _FakeStream:
    sock: _FakeSocket


class _FakeProcess:
    def __init__(self, *_args: object, **_kwargs: object) -> None:
        self.started = False
        self.wait_timeout: float | None = None

    def start(self) -> None:
        self.started = True

    def wait_for_tcp(self, _host: str, _port: int, *, timeout: float) -> None:
        self.wait_timeout = timeout

    def log_tail(self) -> str:
        return "fake log"


class _FakeResponse:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


class _FakeHttpClient:
    def __init__(self, *, trust_env: bool, timeout: float) -> None:
        assert trust_env is False
        assert timeout == 1.0
        self.calls: list[tuple[str, float]] = []

    def __enter__(self) -> _FakeHttpClient:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def get(self, url: str, *, timeout: float) -> _FakeResponse:
        self.calls.append((url, timeout))
        return _FakeResponse(200)


class _FakeAllocator:
    def __init__(self) -> None:
        self.released: list[int] = []

    def release_port(self, port: int) -> None:
        self.released.append(port)


def _runtime(tmp_path: Path) -> JavaOracleRuntime:
    runtime = JavaOracleRuntime(startup_timeout=5.0)
    runtime.workspace = tmp_path
    runtime.ports = PortSet(15432, 16379, 18080, 1025, 18888, 25575, tuple(range(20000, 20008)))
    runtime._port_allocator = _FakeAllocator()  # type: ignore[assignment]
    return runtime


def test_start_application_requires_http_and_smtp_readiness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = _runtime(tmp_path)
    monkeypatch.setattr(runtime_module, "ManagedProcess", _FakeProcess)
    # Keep the test focused on the readiness sequence, not Java argv construction.
    monkeypatch.setattr(JavaOracleRuntime, "_application_arguments", lambda _self: ["fake-java"])
    monkeypatch.setattr(JavaOracleRuntime, "_application_environment", lambda _self: {})
    monkeypatch.setattr(httpx, "Client", _FakeHttpClient)

    probes: list[tuple[str, int, float]] = []

    def fake_smtp_probe(host: str, port: int, *, timeout: float) -> None:
        probes.append((host, port, timeout))

    monkeypatch.setattr(JavaOracleRuntime, "_probe_smtp_readiness", staticmethod(fake_smtp_probe))

    runtime._start_application()

    assert runtime._application is not None
    assert isinstance(runtime._application, _FakeProcess)
    assert runtime._application.started
    assert runtime._application.wait_timeout is not None
    assert 0 < runtime._application.wait_timeout <= runtime.startup_timeout
    assert probes
    assert runtime.ports is not None
    assert probes[0][0:2] == ("127.0.0.1", runtime.ports.smtp)
    assert 0 < probes[0][2] <= runtime._application.wait_timeout


@pytest.mark.parametrize("reply", [b"250 not a greeting\r\n"])
def test_smtp_readiness_probe_rejects_non_220_or_incomplete_greeting(
    reply: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    stream = _FakeStream(_FakeSocket())
    monkeypatch.setattr(
        runtime_module,
        "connect_bounded",
        lambda _host, _port, *, timeout, max_received: stream,
    )
    monkeypatch.setattr(runtime_module, "read_smtp_reply", lambda _stream: (reply,))

    with pytest.raises(ProtocolError, match="220"):
        JavaOracleRuntime._probe_smtp_readiness("127.0.0.1", 1025, timeout=1.0)

    assert stream.sock.closed


def test_smtp_readiness_probe_closes_connection_when_parser_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = _FakeStream(_FakeSocket())
    monkeypatch.setattr(
        runtime_module,
        "connect_bounded",
        lambda _host, _port, *, timeout, max_received: stream,
    )

    def fail_parser(_stream: _FakeStream) -> tuple[bytes, ...]:
        raise ProtocolError("invalid SMTP continuation")

    monkeypatch.setattr(runtime_module, "read_smtp_reply", fail_parser)

    with pytest.raises(ProtocolError, match="continuation"):
        JavaOracleRuntime._probe_smtp_readiness("127.0.0.1", 1025, timeout=1.0)

    assert stream.sock.closed


def test_smtp_readiness_probe_accepts_220_and_closes_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = _FakeStream(_FakeSocket())
    monkeypatch.setattr(
        runtime_module,
        "connect_bounded",
        lambda _host, _port, *, timeout, max_received: stream,
    )
    monkeypatch.setattr(
        runtime_module,
        "read_smtp_reply",
        lambda _stream: (b"220 example.test ESMTP\r\n",),
    )

    JavaOracleRuntime._probe_smtp_readiness("127.0.0.1", 1025, timeout=1.0)

    assert stream.sock.closed


def test_start_application_fails_when_http_health_is_not_ready(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = _runtime(tmp_path)
    runtime.startup_timeout = 0.01
    monkeypatch.setattr(runtime_module, "ManagedProcess", _FakeProcess)
    monkeypatch.setattr(JavaOracleRuntime, "_application_arguments", lambda _self: ["fake-java"])
    monkeypatch.setattr(JavaOracleRuntime, "_application_environment", lambda _self: {})

    class _UnhealthyClient(_FakeHttpClient):
        def get(self, url: str, *, timeout: float) -> _FakeResponse:
            self.calls.append((url, timeout))
            return _FakeResponse(503)

    monkeypatch.setattr(httpx, "Client", _UnhealthyClient)
    smtp_probed = False

    def fail_if_probed(_host: str, _port: int, *, timeout: float) -> None:
        nonlocal smtp_probed
        smtp_probed = True

    monkeypatch.setattr(JavaOracleRuntime, "_probe_smtp_readiness", staticmethod(fail_if_probed))

    with pytest.raises(ProcessStartError, match="HTTP health"):
        runtime._start_application()

    assert not smtp_probed


def test_tls_runtime_replaces_disabled_flag_with_ephemeral_keystore(tmp_path: Path) -> None:
    runtime = JavaOracleTlsRuntime()
    runtime.workspace = tmp_path
    runtime.ports = PortSet(15432, 16379, 18080, 1025, 18888, 25575, tuple(range(20000, 20008)))

    arguments = runtime._application_arguments()

    assert "--botmail.ssl.use-custom-certificate=false" not in arguments
    assert "--botmail.ssl.use-custom-certificate=true" in arguments
    assert f"--botmail.ssl.keystore-path={runtime.tls_keystore_path}" in arguments
    assert not any(
        argument.startswith("--botmail.ssl.keystore-password=") for argument in arguments
    )
    environment = runtime._application_environment()
    assert len(environment["BOTMAIL_SSL_KEYSTORE_PASSWORD"]) >= 32
    assert runtime.tls_keystore_path.is_file()
    assert runtime.tls_certificate_pem.startswith(b"-----BEGIN CERTIFICATE-----\n")

    runtime.stop()
    with pytest.raises(HarnessError, match="not started"):
        _ = runtime.tls_certificate_pem
