from __future__ import annotations

import os
import re
import socket
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

from lmyzmail_blackbox.protocols import BoundedSocket, read_smtp_reply
from lmyzmail_blackbox.runtime import CandidateRuntime, JavaOracleRuntime

_JAVA_GRAMMAR_SAMPLES = 256
_C_DISTRIBUTION_SAMPLES = 2_048
_NATIVE_CANONICAL = b"Skibidi dop dop dop yes yes!"
_GREETING = re.compile(
    rb"220 (?P<hostname>[^\s]+) ESMTP lmyzmail SMTP Server 2\.8\.0 - "
    rb"(?P<expression>(?:Brrrrr )?Skibidi (?:[dD][oO][pPmM] ){1,5}"
    rb"(?:(?:[yY][eE][sS] [yY][eE][sS])|(?:[nN][oO] [nN][oO]))!)\r\n"
)


@dataclass(frozen=True, slots=True)
class GreetingSample:
    sample_count: int
    canonical_count: int
    distinct_count: int
    hostnames: frozenset[bytes]

    @property
    def canonical_rate(self) -> float:
        return self.canonical_count / self.sample_count


def _candidate(repository: Path) -> CandidateRuntime:
    if os.environ.get("LMYZMAIL_CANDIDATE_COMMAND_JSON") is not None:
        return CandidateRuntime.from_environment()
    return CandidateRuntime(
        command_template=(
            str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
            "--config",
            "{config}",
        )
    )


def _connect_from_loopback_alias(port: int, index: int) -> BoundedSocket:
    source = f"127.1.{index // 254 + 1}.{index % 254 + 1}"
    timeout = 10.0
    deadline = time.monotonic() + timeout
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.bind((source, 0))
        sock.connect(("127.0.0.1", port))
    except Exception:
        sock.close()
        raise
    return BoundedSocket(sock, deadline=deadline)


def _sample(
    runtime: JavaOracleRuntime,
    *,
    sample_count: int,
    canonical: bytes | None,
) -> GreetingSample:
    if runtime.ports is None:
        raise AssertionError("SMTP runtime is not started")

    expressions: set[bytes] = set()
    hostnames: set[bytes] = set()
    canonical_count = 0
    for index in range(sample_count):
        stream = _connect_from_loopback_alias(runtime.ports.smtp, index)
        try:
            greeting = read_smtp_reply(stream)
            assert len(greeting) == 1
            matched = _GREETING.fullmatch(greeting[0])
            assert matched is not None, greeting[0]
            expression = matched.group("expression")
            hostname = matched.group("hostname")
            expressions.add(expression)
            hostnames.add(hostname)
            if canonical is not None:
                canonical_count += expression == canonical

            stream.sendall(b"QUIT\r\n")
            assert read_smtp_reply(stream) == (
                b"221 2.0.0 " + hostname + b" closing connection\r\n",
            )
        finally:
            stream.sock.close()

    return GreetingSample(
        sample_count=sample_count,
        canonical_count=canonical_count,
        distinct_count=len(expressions),
        hostnames=frozenset(hostnames),
    )


def _assert_wire_grammar(sample: GreetingSample, *, minimum_distinct: int) -> None:
    assert sample.distinct_count >= minimum_distinct, sample
    assert len(sample.hostnames) == 1, sample


def _assert_frozen_probability_contract(sample: GreetingSample) -> None:
    # At n=2048 and p=0.4 this is wider than 5.5 standard deviations. It is
    # stable for the frozen C generator selected through the Rust wrapper while
    # rejecting the wrong canonical expression, a constant banner, and gross
    # RNG bias.
    _assert_wire_grammar(sample, minimum_distinct=64)
    assert 0.34 <= sample.canonical_rate <= 0.46, sample


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(240)
def test_java_smtp_greeting_preserves_frozen_wire_grammar() -> None:
    with JavaOracleRuntime() as oracle:
        sample = _sample(
            oracle,
            sample_count=_JAVA_GRAMMAR_SAMPLES,
            canonical=None,
        )
        _assert_wire_grammar(sample, minimum_distinct=16)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(240)
def test_rust_smtp_greeting_uses_frozen_c_probability_contract() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        sample = _sample(
            candidate,
            sample_count=_C_DISTRIBUTION_SAMPLES,
            canonical=_NATIVE_CANONICAL,
        )
        _assert_frozen_probability_contract(sample)
