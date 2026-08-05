from __future__ import annotations

import contextlib
import math
import os
import signal
import socket
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from .errors import ProcessStartError, ProcessStopError

_STOP_POLL_INTERVAL = 0.02


@dataclass(slots=True)
class ManagedProcess:
    name: str
    argv: Sequence[str]
    log_path: Path
    cwd: Path | None = None
    env: Mapping[str, str] | None = None
    inherit_env: bool = True
    _process: subprocess.Popen[bytes] | None = field(default=None, init=False, repr=False)
    _log: BinaryIO | None = field(default=None, init=False, repr=False)

    def start(self) -> None:
        if self._process is not None:
            raise RuntimeError(f"{self.name} already started")
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._log = self.log_path.open("wb")
        process_env = os.environ.copy() if self.inherit_env else {}
        if self.env:
            process_env.update(self.env)
        # Launch adapters construct argv from trusted local manifests; no shell is involved.
        try:
            self._process = subprocess.Popen(  # noqa: S603
                list(self.argv),
                cwd=self.cwd,
                env=process_env,
                stdin=subprocess.DEVNULL,
                stdout=self._log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        except BaseException:
            self._log.close()
            self._log = None
            raise

    @property
    def pid(self) -> int:
        if self._process is None:
            raise RuntimeError(f"{self.name} has not started")
        return self._process.pid

    def wait_for_tcp(self, host: str, port: int, *, timeout: float) -> None:
        if self._process is None:
            raise RuntimeError(f"{self.name} has not started")
        deadline = time.monotonic() + timeout
        last_error: OSError | None = None
        while time.monotonic() < deadline:
            exit_code = self._process.poll()
            if exit_code is not None:
                raise ProcessStartError(
                    f"{self.name} exited with {exit_code}; tail:\n{self.log_tail()}"
                )
            try:
                with socket.create_connection((host, port), timeout=0.25):
                    return
            except OSError as error:
                last_error = error
                time.sleep(0.05)
        raise ProcessStartError(
            f"{self.name} did not listen on {host}:{port} within {timeout}s: {last_error}; "
            f"tail:\n{self.log_tail()}"
        )

    def log_tail(self, *, max_bytes: int = 16_384) -> str:
        if not self.log_path.exists():
            return "<no log>"
        with self.log_path.open("rb") as stream:
            stream.seek(0, os.SEEK_END)
            size = stream.tell()
            stream.seek(max(0, size - max_bytes))
            return stream.read(max_bytes).decode("utf-8", errors="replace")

    def wait(self, *, timeout: float) -> int:
        if self._process is None:
            raise RuntimeError(f"{self.name} has not started")
        return self._process.wait(timeout=timeout)

    def _signal_group(self, group_signal: signal.Signals) -> None:
        process = self._process
        if process is None:
            return
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, group_signal)

    def _is_stopped(self) -> bool:
        process = self._process
        if process is None:
            return True
        process.poll()  # Reap the group leader before probing for remaining descendants.
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return process.returncode is not None
        except PermissionError:
            return False
        return False

    def _finalize_if_stopped(self) -> bool:
        if not self._is_stopped():
            return False
        if self._log is not None:
            self._log.close()
        self._process = None
        self._log = None
        return True

    def stop(self, *, timeout: float = 5.0, kill_timeout: float = 2.0) -> None:
        stop_managed_processes((self,), grace_timeout=timeout, kill_timeout=kill_timeout)

    def kill(self, *, timeout: float = 2.0) -> None:
        kill_managed_processes((self,), kill_timeout=timeout)

    def __enter__(self) -> ManagedProcess:
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()


def stop_managed_processes(
    processes: Sequence[ManagedProcess],
    *,
    grace_timeout: float = 5.0,
    kill_timeout: float = 2.0,
) -> None:
    """Stop process groups concurrently within shared TERM and KILL budgets."""
    for label, value in (
        ("grace_timeout", grace_timeout),
        ("kill_timeout", kill_timeout),
    ):
        if not math.isfinite(value) or value < 0:
            raise ValueError(f"{label} must be a finite non-negative value")

    started = tuple(process for process in processes if process._process is not None)
    active = tuple(process for process in started if not process._finalize_if_stopped())
    if not active:
        return

    signal_errors: list[str] = []
    interruption: BaseException | None = None
    try:
        for process in active:
            try:
                process._signal_group(signal.SIGTERM)
            except OSError as error:
                signal_errors.append(f"{process.name} SIGTERM failed: {error}")

        grace_deadline = time.monotonic() + grace_timeout
        while any(not process._is_stopped() for process in active):
            remaining = grace_deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(_STOP_POLL_INTERVAL, remaining))
    except BaseException as error:
        # Cancellation must not bypass the force-kill phase; re-raise after cleanup.
        interruption = error

    survivors = tuple(process for process in active if not process._is_stopped())
    try:
        for process in survivors:
            try:
                process._signal_group(signal.SIGKILL)
            except OSError as error:
                signal_errors.append(f"{process.name} SIGKILL failed: {error}")

        kill_deadline = time.monotonic() + kill_timeout
        while any(not process._is_stopped() for process in survivors):
            remaining = kill_deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(_STOP_POLL_INTERVAL, remaining))
    except BaseException as error:
        if interruption is None:
            interruption = error

    still_running = [process.name for process in active if not process._finalize_if_stopped()]
    failures = [*signal_errors]
    if still_running:
        failures.append(
            "process groups still alive after SIGKILL deadline: " + ", ".join(still_running)
        )
    if interruption is not None:
        if failures:
            interruption.add_note("process cleanup errors: " + "; ".join(failures))
        raise interruption
    if failures:
        raise ProcessStopError("; ".join(failures))


def kill_managed_processes(
    processes: Sequence[ManagedProcess],
    *,
    kill_timeout: float = 2.0,
) -> None:
    """SIGKILL process groups concurrently within one shared deadline."""

    if not math.isfinite(kill_timeout) or kill_timeout < 0:
        raise ValueError("kill_timeout must be a finite non-negative value")
    started = tuple(process for process in processes if process._process is not None)
    active = tuple(process for process in started if not process._finalize_if_stopped())
    if not active:
        return

    signal_errors: list[str] = []
    interruption: BaseException | None = None
    for process in active:
        try:
            process._signal_group(signal.SIGKILL)
        except OSError as error:
            signal_errors.append(f"{process.name} SIGKILL failed: {error}")

    deadline = time.monotonic() + kill_timeout
    try:
        while any(not process._is_stopped() for process in active):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(_STOP_POLL_INTERVAL, remaining))
    except BaseException as error:
        interruption = error

    still_running = [process.name for process in active if not process._finalize_if_stopped()]
    failures = [*signal_errors]
    if still_running:
        failures.append(
            "process groups still alive after SIGKILL deadline: " + ", ".join(still_running)
        )
    if interruption is not None:
        if failures:
            interruption.add_note("process cleanup errors: " + "; ".join(failures))
        raise interruption
    if failures:
        raise ProcessStopError("; ".join(failures))
