from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

from lmyzmail_blackbox.errors import ProcessStartError
from lmyzmail_blackbox.processes import ManagedProcess, kill_managed_processes
from lmyzmail_blackbox.runtime import JavaOracleRuntime


def _wait_for_path(path: Path, *, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.01)
    raise AssertionError(f"timed out waiting for {path}")


def _pid_exists(pid: int) -> bool:
    try:
        Path(f"/proc/{pid}").stat()
    except FileNotFoundError:
        return False
    return True


def test_managed_process_can_run_without_ambient_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LMYZMAIL_AMBIENT_SECRET", "must-not-leak")
    log = tmp_path / "environment.log"
    process = ManagedProcess(
        "environment-probe",
        [
            sys.executable,
            "-c",
            (
                "import os; "
                "print(os.environ.get('LMYZMAIL_AMBIENT_SECRET', '<absent>')); "
                "print(os.environ['LMYZMAIL_EXPLICIT'])"
            ),
        ],
        log,
        env={"LMYZMAIL_EXPLICIT": "present"},
        inherit_env=False,
    )

    process.start()
    assert process.wait(timeout=5.0) == 0
    process.stop()

    assert log.read_text(encoding="utf-8").splitlines() == ["<absent>", "present"]


def test_postgres_readiness_waits_until_connections_are_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_run_checked(
        argv: list[str],
        *,
        env: dict[str, str],
        log_path: Path,
        timeout: float = 30.0,
    ) -> None:
        del env, log_path, timeout
        calls.append(tuple(argv))
        if len(calls) == 1:
            raise ProcessStartError("database system is starting up")

    monkeypatch.setattr(JavaOracleRuntime, "_run_checked", staticmethod(fake_run_checked))
    runtime = JavaOracleRuntime()

    runtime._wait_for_postgres_ready(
        tmp_path / "postgres-bin",
        15432,
        env={},
        log_path=tmp_path / "postgres.log",
        timeout=1.0,
    )

    assert len(calls) == 2
    assert calls[0][0].endswith("/pg_isready")
    assert "--dbname=postgres" in calls[0]
    assert "--timeout=1" in calls[0]


@pytest.mark.skipif(sys.platform != "linux", reason="process-group contract is Linux-only")
def test_stop_kills_and_reaps_descendants_after_group_leader_exits(tmp_path: Path) -> None:
    child_pid_path = tmp_path / "child.pid"
    child_ready_path = tmp_path / "child.ready"
    child_code = (
        "import pathlib, signal, time; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        f"pathlib.Path({str(child_ready_path)!r}).write_text('ready'); "
        "time.sleep(60)"
    )
    process = ManagedProcess(
        "descendant-probe",
        [
            sys.executable,
            "-c",
            (
                "import pathlib, subprocess, sys, time; "
                f"child = subprocess.Popen([sys.executable, '-c', {child_code!r}]); "
                f"pathlib.Path({str(child_pid_path)!r}).write_text(str(child.pid)); "
                "time.sleep(60)"
            ),
        ],
        tmp_path / "descendant.log",
    )
    process.start()
    try:
        _wait_for_path(child_pid_path)
        _wait_for_path(child_ready_path)
        leader_pid = process.pid
        child_pid = int(child_pid_path.read_text(encoding="utf-8"))

        started = time.monotonic()
        process.stop(timeout=0.2, kill_timeout=2.0)
        elapsed = time.monotonic() - started

        assert elapsed < 2.5
        assert not _pid_exists(leader_pid)
        assert not _pid_exists(child_pid)
    finally:
        process.stop(timeout=0.0, kill_timeout=2.0)


@pytest.mark.skipif(sys.platform != "linux", reason="process-group contract is Linux-only")
def test_force_kill_uses_one_shared_deadline_and_reaps_descendants(tmp_path: Path) -> None:
    processes: list[ManagedProcess] = []
    child_pids: list[int] = []
    try:
        for index in range(3):
            child_pid_path = tmp_path / f"force-child-{index}.pid"
            child_code = "import time; time.sleep(60)"
            process = ManagedProcess(
                f"force-{index}",
                [
                    sys.executable,
                    "-c",
                    (
                        "import pathlib, subprocess, sys, time; "
                        f"child = subprocess.Popen([sys.executable, '-c', {child_code!r}]); "
                        f"pathlib.Path({str(child_pid_path)!r}).write_text(str(child.pid)); "
                        "time.sleep(60)"
                    ),
                ],
                tmp_path / f"force-{index}.log",
            )
            process.start()
            _wait_for_path(child_pid_path)
            child_pids.append(int(child_pid_path.read_text(encoding="utf-8")))
            processes.append(process)

        leader_pids = [process.pid for process in processes]
        started = time.monotonic()
        kill_managed_processes(processes, kill_timeout=2.0)
        elapsed = time.monotonic() - started

        assert elapsed < 2.5
        assert all(not _pid_exists(pid) for pid in [*leader_pids, *child_pids])
    finally:
        for process in processes:
            process.kill(timeout=2.0)


@pytest.mark.skipif(sys.platform != "linux", reason="process-group contract is Linux-only")
def test_stop_force_kills_before_propagating_cancellation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ready = tmp_path / "cancellation.ready"
    process = ManagedProcess(
        "cancellation-probe",
        [
            sys.executable,
            "-c",
            (
                "import pathlib, signal, time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                f"pathlib.Path({str(ready)!r}).write_text('ready'); "
                "time.sleep(60)"
            ),
        ],
        tmp_path / "cancellation.log",
    )
    process.start()
    _wait_for_path(ready)
    pid = process.pid

    class SimulatedCancellation(BaseException):
        pass

    real_sleep = time.sleep
    interrupted = False

    def interrupt_once(duration: float) -> None:
        nonlocal interrupted
        if not interrupted:
            interrupted = True
            raise SimulatedCancellation
        real_sleep(duration)

    monkeypatch.setattr("lmyzmail_blackbox.processes.time.sleep", interrupt_once)
    try:
        with pytest.raises(SimulatedCancellation):
            process.stop(timeout=5.0, kill_timeout=2.0)
        assert not _pid_exists(pid)
    finally:
        process.stop(timeout=0.0, kill_timeout=2.0)


@pytest.mark.skipif(sys.platform != "linux", reason="process-group contract is Linux-only")
def test_runtime_shutdown_signals_all_services_before_shared_grace_wait(
    tmp_path: Path,
) -> None:
    processes: list[ManagedProcess] = []
    term_markers: list[Path] = []
    for name in ("application", "redis", "postgres"):
        ready = tmp_path / f"{name}.ready"
        term_marker = tmp_path / f"{name}.term"
        process = ManagedProcess(
            name,
            [
                sys.executable,
                "-c",
                (
                    "import pathlib, signal, time; "
                    f"ready = pathlib.Path({str(ready)!r}); "
                    f"term = pathlib.Path({str(term_marker)!r}); "
                    "signal.signal(signal.SIGTERM, "
                    "lambda *_: term.write_text(str(time.monotonic()))); "
                    "ready.write_text('ready'); "
                    "time.sleep(60)"
                ),
            ],
            tmp_path / f"{name}.log",
        )
        process.start()
        _wait_for_path(ready)
        processes.append(process)
        term_markers.append(term_marker)

    runtime = JavaOracleRuntime(shutdown_timeout=0.3, shutdown_kill_timeout=2.0)
    runtime._application, runtime._redis, runtime._postgres = processes
    pids = [process.pid for process in processes]
    try:
        started = time.monotonic()
        runtime.stop()
        elapsed = time.monotonic() - started

        term_times = [float(path.read_text(encoding="utf-8")) for path in term_markers]
        assert elapsed < 2.5
        assert max(term_times) - min(term_times) < 0.2
        assert all(not _pid_exists(pid) for pid in pids)
    finally:
        for process in processes:
            process.stop(timeout=0.0, kill_timeout=2.0)
