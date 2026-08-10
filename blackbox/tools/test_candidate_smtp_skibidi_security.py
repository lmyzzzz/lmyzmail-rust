# ruff: noqa: S101 - external pytest module outside the frozen definition tree.
from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

from lmyzmail_blackbox.protocols import RawSmtpClient
from lmyzmail_blackbox.runtime import CandidateRuntime

_WATCH = b"SKIBIDITOILET WATCHSKIBIDITOILET WIDTH=10 FPS=20\r\n"
_BUSY = (
    b"451 4.3.0 Another session is already watching Skibidi Toilet. "
    b"Max 1 concurrent viewer. Cope and try later.\r\n"
)


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


def _endpoint(candidate: CandidateRuntime) -> tuple[str, int]:
    if candidate.ports is None:
        raise AssertionError("candidate SMTP runtime is not started")
    return "127.0.0.1", candidate.ports.smtp


def _first_watch_line(client: RawSmtpClient, barrier: Barrier) -> bytes:
    barrier.wait(timeout=10.0)
    client.stream.sendall(_WATCH)
    return client.stream.read_line()


def _wait_for_released_viewer(host: str, port: int) -> None:
    deadline = time.monotonic() + 5.0
    last_line = b""
    while time.monotonic() < deadline:
        with RawSmtpClient.connect(host, port, timeout=10.0) as client:
            client.stream.sendall(_WATCH)
            last_line = client.stream.read_line()
            if last_line == b"250-\x1b[2J\x1b[H\r\n":
                return
        time.sleep(0.05)
    raise AssertionError(f"SMTP viewer permit was not released after disconnect: {last_line!r}")


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_candidate_smtp_skibidi_rejects_non_finite_inputs_and_bounds_admission() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        host, port = _endpoint(candidate)
        with RawSmtpClient.connect(host, port, timeout=10.0) as client:
            invalid = {
                b"FPS=NaN": b"501 5.5.4 Invalid FPS value.\r\n",
                b"CONTRAST=NaN": b"501 5.5.4 Invalid CONTRAST value.\r\n",
                b"BRIGHTNESS=NaN": b"501 5.5.4 Invalid BRIGHTNESS value.\r\n",
                b"GAMMA=NaN": b"501 5.5.4 Invalid GAMMA value.\r\n",
                b"ASPECT=NaN": b"501 5.5.4 Invalid ASPECT value.\r\n",
            }
            for argument, expected in invalid.items():
                reply = client.command(
                    b"SKIBIDITOILET WATCHSKIBIDITOILET " + argument
                )
                assert reply == (expected,)

            for argument in (
                b"CONTRAST=9",
                b"BRIGHTNESS=256",
                b"GAMMA=9",
                b"ASPECT=9",
            ):
                reply = client.command(
                    b"SKIBIDITOILET WATCHSKIBIDITOILET " + argument
                )
                assert reply == (
                    b"501 5.5.4 ASCII transform parameter exceeds the safe processing budget.\r\n",
                )

        clients = [RawSmtpClient.connect(host, port, timeout=30.0) for _ in range(32)]
        try:
            barrier = Barrier(len(clients))
            with ThreadPoolExecutor(max_workers=len(clients)) as executor:
                lines = list(
                    executor.map(
                        lambda client: _first_watch_line(client, barrier),
                        clients,
                    )
                )
            assert lines.count(b"250-\x1b[2J\x1b[H\r\n") == 1
            assert lines.count(_BUSY) == len(clients) - 1
        finally:
            for client in clients:
                client.close()

        _wait_for_released_viewer(host, port)
