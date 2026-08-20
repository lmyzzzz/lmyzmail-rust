from __future__ import annotations

import importlib.util
import contextlib
import io
import os
import sys
import tempfile
import types
import unittest
from unittest import mock
from pathlib import Path


SOURCE = Path(__file__).with_name("profile-next-benchmark-phases-v1.py")
SPEC = importlib.util.spec_from_file_location("profile_next_benchmark_phases_v1", SOURCE)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load profiler module: {SOURCE}")
profiler = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = profiler
SPEC.loader.exec_module(profiler)


class ProgressAlignedProfilerTests(unittest.TestCase):
    def test_windows_use_disjoint_progress_ranges(self) -> None:
        self.assertEqual(
            [window.thresholds(10_000) for window in profiler.WINDOWS],
            [(500, 2_500), (7_500, 9_500)],
        )
        with self.assertRaisesRegex(ValueError, "empty"):
            profiler.ProgressWindow("tiny", 0.01, 0.02).thresholds(1)

    def test_perf_script_fold_reverses_leaf_first_callchains(self) -> None:
        folded = profiler._fold(
            [
                "lmyzmail 1 [023] 1.0: cpu-clock:\n",
                "        abc child (/tmp/lmyzmail)\n",
                "        def parent (/tmp/lmyzmail)\n",
                "\n",
                "lmyzmail 1 [023] 1.1: cpu-clock:\n",
                "        abc child (/tmp/lmyzmail)\n",
                "        def parent (/tmp/lmyzmail)\n",
                "\n",
            ]
        )
        self.assertEqual(folded, {"parent;child": 2})

    def test_pressure_parser_preserves_totals_and_averages(self) -> None:
        parsed = profiler._pressure(
            "some avg10=1.25 avg60=0.50 avg300=0.10 total=123\n"
            "full avg10=0.00 avg60=0.00 avg300=0.00 total=7\n"
        )
        self.assertEqual(parsed["some"]["avg10"], 1.25)
        self.assertEqual(parsed["some"]["total"], 123)
        self.assertEqual(parsed["full"]["total"], 7)

    def test_network_namespace_join_is_identity_checked_and_recorded(self) -> None:
        identity = profiler.ProcessIdentity(10, 20, 30, 40)
        with (
            mock.patch.object(profiler, "_alive", side_effect=[True, True]),
            mock.patch.object(
                profiler,
                "_namespace_identity",
                side_effect=[(1, 2), (3, 4), (3, 4)],
            ),
            mock.patch.object(profiler.os, "open", return_value=9) as opened,
            mock.patch.object(profiler.os, "setns") as setns,
            mock.patch.object(profiler.os, "close") as closed,
        ):
            result = profiler._join_candidate_network_namespace(identity)
        self.assertEqual(
            result,
            {
                "previous_device": 1,
                "previous_inode": 2,
                "target_device": 3,
                "target_inode": 4,
                "actual_device": 3,
                "actual_inode": 4,
                "joined": True,
            },
        )
        opened.assert_called_once_with(
            Path("/proc/10/ns/net"), os.O_RDONLY | os.O_CLOEXEC
        )
        setns.assert_called_once_with(9, os.CLONE_NEWNET)
        closed.assert_called_once_with(9)

    def test_tree_reports_directory_pressure_without_following_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            crowded = root / "crowded"
            crowded.mkdir()
            (crowded / "a").write_bytes(b"a")
            (crowded / "b").write_bytes(b"bb")
            os.symlink(crowded, root / "alias")
            snapshot = profiler._tree(root)
        self.assertEqual(snapshot["files"], 2)
        self.assertEqual(snapshot["symlinks"], 1)
        self.assertEqual(snapshot["vanished_entries"], 0)
        self.assertEqual(snapshot["maximum_direct_entries"], 2)
        self.assertEqual(snapshot["maximum_direct_entries_path"], ".")

    def test_argument_bounds_reject_unbounded_sampling(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                profiler._parse_args(
                    ["--output-dir", "out", "--sample-interval-seconds", "0.001"]
                )
            with self.assertRaises(SystemExit):
                profiler._parse_args(
                    ["--output-dir", "out", "--perf-frequency", "1000"]
                )

    def test_capture_rejects_an_already_passed_window(self) -> None:
        identity = profiler.ProcessIdentity(1, 2, 3, 4)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(
                profiler,
                "_wait_threshold",
                return_value={
                    "expected": 10_000,
                    "verified": 3_000,
                    "duration_ns": 1,
                    "observer_failures": 0,
                },
            ):
                with self.assertRaisesRegex(RuntimeError, "already passed"):
                    profiler._capture(
                        identity,
                        root / "control",
                        root,
                        root / "perf",
                        root,
                        profiler.WINDOWS[0],
                        10_000,
                        0.25,
                        1.0,
                        1.0,
                        99,
                    )

    def test_postgres_master_discovery_excludes_backend_titles(self) -> None:
        table = {
            10: {
                "command": "/opt/postgres -D /run/example/postgres-data -p 5432",
                "ppid": 1,
                "rss_kib": 1,
            },
            11: {
                "command": "postgres: lmyzmail_test lmyzmail 127.0.0.1 idle",
                "ppid": 10,
                "rss_kib": 1,
            },
            12: {"command": "unrelated", "ppid": 1, "rss_kib": 1},
        }
        self.assertEqual(profiler._postgres_masters(table), [10])

    def test_postgres_sql_snapshot_fails_closed_without_one_master(self) -> None:
        with mock.patch.object(profiler, "_postgres_process_table", return_value={}):
            with self.assertRaisesRegex(RuntimeError, "expected one master"):
                profiler._postgres_sql_snapshot()

    def test_postgres_sql_snapshot_fails_closed_on_connection_error(self) -> None:
        table = {
            10: {
                "command": "/opt/postgres -D /run/example/postgres-data -p 5432",
                "ppid": 1,
                "rss_kib": 1,
            }
        }
        driver = types.SimpleNamespace(
            connect=mock.Mock(side_effect=OSError("connection refused"))
        )
        with (
            mock.patch.object(
                profiler, "_postgres_process_table", return_value=table
            ),
            mock.patch.dict(sys.modules, {"psycopg": driver}),
        ):
            with self.assertRaisesRegex(
                RuntimeError, "PostgreSQL SQL snapshot unavailable.*connection refused"
            ):
                profiler._postgres_sql_snapshot()
        driver.connect.assert_called_once_with(
            host="127.0.0.1",
            port=5432,
            user="lmyzmail_test",
            dbname="lmyzmail",
            connect_timeout=2,
            options="-c default_transaction_read_only=on -c statement_timeout=1000",
        )


if __name__ == "__main__":
    unittest.main()
