from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("fsync-mode-syscall-evidence-v1.py")
SPEC = importlib.util.spec_from_file_location(
    "lmyzmail_fsync_mode_syscall_evidence_v1", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
probe = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = probe
SPEC.loader.exec_module(probe)


def _runtime(mode: str) -> dict:
    return {
        "schema_version": 1,
        "mode": mode,
        "candidate": {"path": "target/lmyzmail", "sha256": "a" * 64},
        "smtp_scenario_count": 3,
        "runtime_cleanup_completed": True,
        "postgres_before": {
            "settings": {
                "fsync": "on",
                "synchronous_commit": "on",
                "full_page_writes": "on",
            }
        },
        "postgres_after": {
            "settings": {
                "fsync": "on",
                "synchronous_commit": "on",
                "full_page_writes": "on",
            }
        },
        "postgres_wal_delta": {"wal_records": 3, "wal_bytes": 100},
        "redis_before": {
            "configuration": {
                "appendonly": "yes",
                "appendfsync": "always",
                "save": "",
            }
        },
        "redis_after": {
            "configuration": {
                "appendonly": "yes",
                "appendfsync": "always",
                "save": "",
            },
            "aof_enabled": 1,
            "aof_pending_bio_fsync": 0,
            "aof_current_size": 100,
            "aof_last_write_status": "ok",
        },
    }


def _trace(application_syncs: int) -> dict:
    return {
        "unfinished_sync_calls": 0,
        "application_owned_sync": {
            "invocations": application_syncs,
            "successful": application_syncs,
            "failed": 0,
        },
        "postgres_wal_sync": {"invocations": 2, "successful": 2, "failed": 0},
        "redis_aof_sync": {"invocations": 1, "successful": 1, "failed": 0},
        "application_maildir_atomic_publication": {
            "invocations": 3,
            "successful": 3,
            "failed": 0,
        },
    }


def test_trace_summary_reassembles_sync_and_classifies_paths(tmp_path: Path) -> None:
    workspace = "/tmp/lmyzmail-probe"
    trace = tmp_path / "trace.txt"
    trace.write_text(
        "10  1.000 fsync(7</tmp/lmyzmail-probe/maildir/inbox/file.eml> "
        "<unfinished ...>\n"
        "11  1.001 fdatasync(8</tmp/lmyzmail-probe/postgres-data/pg_wal/x>) = 0\n"
        "10  1.002 <... fsync resumed>) = 0\n"
        "12  1.003 fdatasync(9</tmp/lmyzmail-probe/redis-data/appendonlydir/a.aof>) = 0\n"
        "10  1.004 linkat(1</tmp/lmyzmail-probe/maildir/a>, \"x\", "
        "2</tmp/lmyzmail-probe/maildir/b>, \"y\", 0) = 0\n",
        encoding="utf-8",
    )

    summary = probe._trace_summary(trace, workspace)

    assert summary["application_owned_sync"] == {
        "invocations": 1,
        "successful": 1,
        "failed": 0,
    }
    assert summary["postgres_wal_sync"]["successful"] == 1
    assert summary["redis_aof_sync"]["successful"] == 1
    assert summary["application_maildir_atomic_publication"]["successful"] == 1


def test_trace_summary_ignores_syscall_names_inside_write_payload(tmp_path: Path) -> None:
    trace = tmp_path / "trace.txt"
    trace.write_text(
        '10  1.000 write(2</tmp/log>, "reported fsync(9<fake>) <unfinished ...>", 45) = 45\n'
        "10  1.001 fsync(7</tmp/work/maildir/file>) = 0\n",
        encoding="utf-8",
    )

    summary = probe._trace_summary(trace, "/tmp/work")

    assert summary["all_sync"]["invocations"] == 1
    assert summary["application_owned_sync"]["successful"] == 1


def test_qualification_requires_off_zero_and_on_present() -> None:
    off = {"probe": _runtime("off"), "trace": _trace(0)}
    on = {"probe": _runtime("on"), "trace": _trace(4)}

    qualified, checks = probe._qualified(off, on)

    assert qualified is True
    assert all(checks.values())


def test_qualification_rejects_application_sync_in_off_mode() -> None:
    off = {"probe": _runtime("off"), "trace": _trace(1)}
    on = {"probe": _runtime("on"), "trace": _trace(4)}

    qualified, checks = probe._qualified(off, on)

    assert qualified is False
    assert checks["off_application_sync_zero"] is False


def test_qualification_rejects_changed_service_durability() -> None:
    off = {"probe": _runtime("off"), "trace": _trace(0)}
    on_runtime = _runtime("on")
    on_runtime["postgres_after"]["settings"]["synchronous_commit"] = "off"
    on = {"probe": on_runtime, "trace": _trace(4)}

    qualified, checks = probe._qualified(off, on)

    assert qualified is False
    assert checks["postgres_configuration_durable_and_equal"] is False
