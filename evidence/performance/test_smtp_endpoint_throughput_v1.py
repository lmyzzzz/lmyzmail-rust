from __future__ import annotations

import argparse
import hashlib
import importlib.util
import inspect
import json
import os
import socket
import stat
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest import mock


def _install_missing_database_client_stubs() -> None:
    for name in ("psycopg", "redis"):
        if importlib.util.find_spec(name) is not None:
            continue
        module = ModuleType(name)
        if name == "psycopg":
            module.Error = Exception  # type: ignore[attr-defined]
        else:
            module.Redis = object  # type: ignore[attr-defined]
            module.RedisError = Exception  # type: ignore[attr-defined]
        sys.modules[name] = module


_install_missing_database_client_stubs()


RUNNER_PATH = Path(__file__).with_name("smtp-endpoint-throughput-v1.py")
RUNNER_SPEC = importlib.util.spec_from_file_location(
    "smtp_endpoint_throughput_v1_test_target", RUNNER_PATH
)
if RUNNER_SPEC is None or RUNNER_SPEC.loader is None:
    raise RuntimeError(f"cannot load benchmark runner: {RUNNER_PATH}")
runner = importlib.util.module_from_spec(RUNNER_SPEC)
sys.modules[RUNNER_SPEC.name] = runner
RUNNER_SPEC.loader.exec_module(runner)
LAUNCHER_RUN_ID = "12345678-1234-4234-9234-123456789abc"


class _FakeMaildirObserver:
    def __init__(self, _runtime: object, *, expected_messages: int):
        self.expected_messages = expected_messages

    def wait_for_publications(
        self, _timeout_seconds: float, _abort_check: object = None
    ) -> None:
        pass

    def wait_for_removals(self, _timeout_seconds: float) -> None:
        pass

    def _evidence(self, *, cleanup: bool) -> dict[str, Any]:
        receiver_scope = f"{runner.ENDPOINT_RECEIVER}/inbox"
        sender_scope = f"{runner.ENDPOINT_SENDER}/sent"
        return {
            "profile": "lmyzmail-maildir-inotify-publication-v8",
            "expected_messages": self.expected_messages,
            "expected_publication_events": self.expected_messages * 2,
            "publication_events": self.expected_messages * 2,
            "publication_counts_by_mailbox_folder": {
                receiver_scope: self.expected_messages,
                sender_scope: self.expected_messages,
            },
            "removal_counts_by_mailbox_folder": {
                receiver_scope: self.expected_messages if cleanup else 0,
                sender_scope: self.expected_messages if cleanup else 0,
            },
            "receiver_inbox_publications": self.expected_messages,
            "sender_sent_publications": self.expected_messages,
            "publication_clock_id": "CLOCK_MONOTONIC",
            "last_publication_monotonic_ns": runner.time.monotonic_ns(),
            "atomic_rename_publications": self.expected_messages * 2,
            "atomic_rename_publications_by_mailbox_folder": {
                receiver_scope: self.expected_messages,
                sender_scope: self.expected_messages,
            },
            "direct_close_write_publications": 0,
            "directory_reconciled_publications": 0,
            "publication_mechanism_counts": {
                "atomic_rename": self.expected_messages,
                "visible_create": self.expected_messages,
                "direct_close_write": 0,
                "directory_reconciliation": 0,
            },
            "visible_create_publications": self.expected_messages,
            "atomic_only_publication_observed": True,
            "removal_events": self.expected_messages * 2 if cleanup else 0,
            "total_published_bytes": self.expected_messages,
            "content_sha256_samples": [
                {"ordinal": index, "bytes": 1, "sha256": "a" * 64}
                for index in range(min(self.expected_messages, runner.SAMPLE_MESSAGES))
            ],
            "observer_write_syscalls": 0,
            "observer_writes_prohibited": True,
            "endpoint_internal_cleanup_observed": cleanup,
            "publication_passed": True,
            "passed": True,
        }

    def snapshot(self) -> dict[str, Any]:
        return self._evidence(cleanup=False)

    def stop(self) -> dict[str, Any]:
        return self._evidence(cleanup=True)


def _fake_postgres_gate_snapshot(expected_delta: int) -> type:
    class FakePostgresGateSnapshot:
        def __init__(
            self,
            _runtime: object,
            *,
            before_rows: int,
            expected_messages: int,
        ):
            self.before_rows = before_rows
            self.expected_messages = expected_messages

        def capture(self) -> dict[str, Any]:
            started = runner.time.monotonic_ns()
            completed = runner.time.monotonic_ns()
            return {
                "clock_id": "CLOCK_MONOTONIC",
                "snapshot_started_monotonic_ns": started,
                "snapshot_completed_monotonic_ns": completed,
                "postgres_query_duration_ns": 0,
                "transaction_isolation": "repeatable_read",
                "transaction_read_only": True,
                "postgres_before_rows": self.before_rows,
                "postgres_rows": self.before_rows + expected_delta,
                "postgres_expected_rows": self.before_rows + self.expected_messages,
                "postgres_row_delta": expected_delta,
                "expected_messages": self.expected_messages,
                "qualified": expected_delta == self.expected_messages,
            }

        def close(self) -> None:
            pass

    return FakePostgresGateSnapshot


def _configure_proxy_gate(
    proxy: mock.Mock,
    *,
    count: int,
    round_number: int = 1,
    duration_ns: int = 60_000_000_000,
    gate_hold_ns: int = 100,
) -> None:
    state: dict[str, Any] = {}
    proxy.process.pid = os.getpid()
    proxy.wait_for_persistence_gate.return_value = {
        "gate_id": 1,
        "triggered_at_proxy_monotonic_ns": 100,
        "expected_messages": count,
    }

    def release(gate_id: int, snapshot: dict[str, Any]) -> dict[str, Any]:
        state["snapshot"] = snapshot
        return {
            "required": True,
            "proxy_clock_domain": "observer_origin_elapsed",
            "status": "released",
            "gate_id": gate_id,
            "qualified": False,
        }

    def finish(*_args: object) -> dict[str, Any]:
        snapshot = state["snapshot"]
        released = 100 + gate_hold_ns
        forwarding_started = released + 1
        forwarding_completed = forwarding_started + 1
        return {
            "round": round_number,
            "duration_ns": duration_ns,
            "within_arm_throughput_stability": {"passed": True},
            "final_250_boundary": {"completed_at_monotonic_ns": forwarding_completed},
            "persistence_gate": {
                "required": True,
                "proxy_clock_domain": "observer_origin_elapsed",
                "status": "forwarded",
                "gate_id": 1,
                "triggered_at_proxy_monotonic_ns": 100,
                "release_received_at_proxy_monotonic_ns": released,
                "forwarding_started_at_proxy_monotonic_ns": forwarding_started,
                "forwarding_completed_at_proxy_monotonic_ns": forwarding_completed,
                "gate_hold_ns": gate_hold_ns,
                "snapshot": snapshot,
                "qualified": True,
            },
        }

    proxy.release_persistence_gate.side_effect = release
    proxy.finish.side_effect = finish
    proxy.abort_persistence_gate.return_value = None


def _row(target: str, tier: str, median: float) -> dict[str, Any]:
    runs = [median * 0.99, median * 1.01]
    measurements = [_round_record(measured=True), _round_record(measured=True)]
    arms = [
        {
            "target": target,
            "tier": {"label": tier},
            "arm_ordinal": ordinal,
            "endpoint_start_invocations": 1,
            "endpoint_invocations": 1,
            "harness_batches": 0,
            "endpoint_requested_messages": 1,
            "observer_verified_messages": 1,
            "requested_equals_observer_verified": True,
            "throughput_messages_per_second": value,
            "measurement": measurements[ordinal],
        }
        for ordinal, value in enumerate(runs)
    ]
    return {
        "target": target,
        "tier": {"label": tier},
        "arm_count": 2,
        "arms": arms,
        "endpoint_start_invocations": 2,
        "endpoint_invocations": 2,
        "harness_batches": 0,
        "requested_equals_observer_verified": True,
        "throughput": {
            "runs": runs,
            "median_messages_per_second": median,
            "variation": runner._throughput_stability(runs),
        },
        "warmups": [],
        "measurements": measurements,
    }


def _round_record(*, measured: bool) -> dict[str, Any]:
    record: dict[str, Any] = {
        "measured": measured,
        "persistence_barrier": {"passed": True},
        "maildir_observer": {
            "passed": True,
            "observer_write_syscalls": 0,
            "endpoint_internal_cleanup_observed": True,
        },
        "endpoint_outcome": {
            "passed": True,
            "queue_scheduler_observed": True if measured else None,
            "queue_scheduler_evidence_required": measured,
            "retry_count": 0,
            "queue_counter_contract_passed": True,
            "received_counter_contract_passed": True,
            "log_parse_complete": True,
            "residual_clean": True,
            "application_persistence_io_observed": True if measured else None,
            "services_persistence_io_observed": True if measured else None,
            "database_persistence_observed": True,
            "cleanup_database_delta": {
                "passed": True,
                "persistence_audit_observed": True,
            },
        },
    }
    if measured:
        record["smtp"] = {"within_arm_throughput_stability": {"passed": True}}
        record["resource"] = {
            "continuous_membership": True,
            "io_accounting_calibration": {"passed": True},
            "application_persistence_io_observed": True,
            "services_persistence_io_observed": True,
            "candidate_cpu_usage_seconds": 1.0,
            "services_cpu_usage_seconds": 1.0,
            "temperature": {"within_limit": True, "available": False},
        }
    return record


def _wire_digest(index: int) -> str:
    return hashlib.sha256(f"wire-{index}".encode("ascii")).hexdigest()


def _fake_process_io(pids: Any) -> dict[int, dict[str, int]]:
    return {
        pid: {
            "start_time_ticks": pid,
            "wchar": 0,
            "syscw": 0,
            "read_bytes": 0,
            "write_bytes": 0,
        }
        for pid in pids
    }


def _clean_state() -> dict[str, Any]:
    tables = {
        name: {
            "present": name in runner._REQUIRED_STRESS_TABLES,
            "rows": 0,
            "groups": {},
        }
        for name in (
            *runner._REQUIRED_STRESS_TABLES,
            *runner._OPTIONAL_STRESS_TABLES,
        )
    }
    empty_tree = {
        "exists": False,
        "files": 0,
        "directories": 0,
        "allocated_bytes": 0,
    }
    return {
        "phase": "test",
        "captured_at": "2026-08-15T00:00:00+00:00",
        "state_sha256": "0" * 64,
        "database": {
            "tables": tables,
            "email_index_mutations": {
                "profile": "postgresql-cumulative-email-index-mutations-v1",
                "relation_oid": 1234,
                "n_tup_ins": 0,
                "n_tup_del": 0,
                "n_tup_upd": 0,
                "database_xact_rollback": 0,
                "database_stats_reset": None,
            },
            "completed_audit_rows": 0,
            "transient_residual_rows": 0,
        },
        "redis": {
            "key_count": 0,
            "database": 0,
            "dbsize_before": 0,
            "dbsize_after": 0,
            "scan_complete_and_stable": True,
            "scan_keyset_sha256": hashlib.sha256(b"").hexdigest(),
            "ttl_contract_passed": True,
            "keys": [],
            "snapshot_sha256": hashlib.sha256(b"[]\n").hexdigest(),
        },
        "maildir": {
            name: dict(empty_tree)
            for name in (
                "sender",
                "receiver",
                "outbound_spool",
                "stress_temp",
                "wire_capture",
            )
        },
    }


class FixedHistogramTests(unittest.TestCase):
    def test_records_clamped_values_overflow_and_percentiles(self) -> None:
        histogram = runner.FixedHistogram(width_us=10, maximum_us=25)
        for value in (-4, 0, 9, 10, 25, 26):
            histogram.record(value)

        self.assertEqual(histogram.bins.tolist(), [3, 1, 2])
        self.assertEqual(histogram.percentile_us(0.50), 10)
        self.assertEqual(histogram.percentile_us(0.95), 25)
        self.assertEqual(
            histogram.summary(),
            {
                "count": 6,
                "bin_width_us": 10,
                "maximum_tracked_us": 25,
                "overflow": 1,
                "maximum_observed_us": 26,
                "p50_us_upper_bound": 10,
                "p95_us_upper_bound": 25,
                "p99_us_upper_bound": 25,
            },
        )

    def test_empty_and_invalid_histograms(self) -> None:
        histogram = runner.FixedHistogram(width_us=10, maximum_us=25)
        self.assertEqual(histogram.percentile_us(0.99), 0)
        for width_us, maximum_us in ((0, 25), (-1, 25), (10, 9)):
            with self.subTest(width_us=width_us, maximum_us=maximum_us):
                with self.assertRaises(ValueError):
                    runner.FixedHistogram(width_us=width_us, maximum_us=maximum_us)


class JavaStressRuntimeConfigurationTests(unittest.TestCase):
    def test_benchmark_apps_initialize_for_one_logical_cpu(self) -> None:
        java = runner.JavaStressRuntime(benchmark_cpu=23)
        rust = runner.RustStressRuntime(benchmark_cpu=23)
        with (
            mock.patch.object(
                runner.JavaOracleRuntime,
                "_application_environment",
                return_value={"PATH": "/usr/bin:/bin"},
            ),
            mock.patch.object(
                runner.v2.StressCandidateRuntimeV2,
                "_application_environment",
                return_value={"PATH": "/usr/bin:/bin"},
            ),
        ):
            java_environment = java._application_environment()
            rust_environment = rust._application_environment()

        self.assertEqual(
            java_environment["JAVA_TOOL_OPTIONS"], "-XX:ActiveProcessorCount=1"
        )
        self.assertEqual(rust_environment["TOKIO_WORKER_THREADS"], "1")

    def test_runtime_uses_exact_frozen_production_stress_path(self) -> None:
        runtime = runner.JavaStressRuntime(
            production_count=200_000,
            warmup_count=0,
            warmup_rounds=0,
            email_size_kb=10,
        )
        inherited = [
            "--botmail.queue.batch-size=1",
            "--botmail.queue.max-concurrent-sends=2",
            "--botmail.queue.poll-interval-ms=3",
            "--botmail.outbound.pool-enabled=false",
            "--botmail.rate-limit.max-inbound-bytes-per-window=104857600",
        ]
        with tempfile.TemporaryDirectory() as temporary:
            runtime.workspace = Path(temporary)
            with mock.patch.object(
                runner.JavaOracleRuntime,
                "_application_arguments",
                return_value=inherited,
            ):
                arguments = runtime._application_arguments()
            dkim_key_path = runtime.benchmark_dkim_key_path
            self.assertIsNotNone(dkim_key_path)
            assert dkim_key_path is not None
            self.assertEqual(
                arguments.count(
                    f"--botmail.domains.main.dkimSelector={runner.BENCHMARK_DKIM_SELECTOR}"
                ),
                1,
            )
            self.assertEqual(
                arguments.count(
                    f"--botmail.domains.main.dkimPrivateKeyPath={dkim_key_path}"
                ),
                1,
            )
            fixture = runtime._benchmark_dkim_fixture_attestation()
            self.assertTrue(fixture["passed"])
            self.assertEqual(fixture["file_mode"], "0600")
            self.assertEqual(fixture["directory_mode"], "0700")
            self.assertEqual(fixture["key_bits"], runner.BENCHMARK_DKIM_KEY_BITS)
            self.assertEqual(fixture["hard_link_count"], 1)
            self.assertRegex(fixture["private_key_sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(fixture["public_key_spki_sha256"], r"^[0-9a-f]{64}$")

        for name, value in runner.JAVA_FROZEN_STRESS_CONFIGURATION:
            expected = f"--{name}={value}"
            self.assertEqual(arguments.count(expected), 1, expected)
            self.assertEqual(
                sum(
                    argument.partition("=")[0] == f"--{name}" for argument in arguments
                ),
                1,
                name,
            )
        for stale in inherited:
            self.assertNotIn(stale, arguments)
        self.assertIn("--botmail.stress-test-count=200000", arguments)
        self.assertIn("--botmail.stress-test-warmup-count=0", arguments)
        self.assertIn("--botmail.stress-test-warmup-rounds=0", arguments)
        self.assertIn("--botmail.stress-test-email-size-kb=10", arguments)
        self.assertEqual(
            arguments.count("--botmail.smtp-security.connection-limits-enabled=true"),
            1,
        )
        self.assertEqual(
            arguments.count("--botmail.smtp-security.max-connections-per-ip=2048"),
            1,
        )
        self.assertEqual(
            arguments.count(
                "--botmail.smtp-security.max-new-connections-per-minute-per-ip=1000000"
            ),
            1,
        )
        self.assertEqual(
            arguments.count("--botmail.rate-limit.inbound-enabled=true"),
            1,
        )
        self.assertEqual(
            arguments.count(
                "--botmail.rate-limit.max-inbound-bytes-per-window=8589934592"
            ),
            1,
        )
        self.assertEqual(
            arguments.count("--botmail.rate-limit.inbound-rate-window-hours=1"),
            1,
        )
        self.assertFalse(
            any(argument.startswith("--logging.level.") for argument in arguments)
        )

    def test_smoke_runtime_enables_bounded_dkim_diagnostics(self) -> None:
        runtime = runner.JavaStressRuntime(production_count=8)
        with tempfile.TemporaryDirectory() as temporary:
            runtime.workspace = Path(temporary)
            with mock.patch.object(
                runner.JavaOracleRuntime,
                "_application_arguments",
                return_value=[],
            ):
                arguments = runtime._application_arguments()

        self.assertIn(
            "--logging.level.net.lmyz.lmyzmail.outbound.DkimSigner=DEBUG",
            arguments,
        )
        self.assertIn(
            "--logging.level.net.lmyz.lmyzmail.inbound.SpamVerifierService=DEBUG",
            arguments,
        )
        self.assertIn("--logging.level.org.xbill.DNS=DEBUG", arguments)

    def test_profile_values_and_hash_match_frozen_redacted_configuration(self) -> None:
        frozen = {}
        for line in runner.JAVA_FROZEN_CONFIG.read_text(encoding="utf-8").splitlines():
            if not line or line.startswith("#"):
                continue
            name, separator, value = line.partition("=")
            self.assertTrue(separator, line)
            frozen[name] = value

        expected = dict(runner.JAVA_FROZEN_STRESS_CONFIGURATION)
        self.assertEqual({name: frozen[name] for name in expected}, expected)
        profile = runner._java_frozen_stress_profile()
        self.assertEqual(profile["properties"], expected)
        self.assertEqual(
            profile["source_sha256"],
            hashlib.sha256(runner.JAVA_FROZEN_CONFIG.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            profile["readiness_log_markers"],
            list(runner.JAVA_STRESS_READINESS_MARKERS),
        )
        self.assertEqual(
            profile["dkim_signing_fixture"],
            {
                "provisioning": "fresh-per-isolated-arm",
                "algorithm": "rsa-sha256",
                "key_bits": runner.BENCHMARK_DKIM_KEY_BITS,
                "private_key_format": "pkcs8-pem",
                "selector": runner.BENCHMARK_DKIM_SELECTOR,
                "relative_path": "benchmark-fixtures/dkim-private.pem",
                "directory_mode": "0700",
                "file_mode": "0600",
                "production_secret_used": False,
            },
        )
        self.assertEqual(
            profile["isolated_self_smtp_transport"],
            {
                "untrusted_ingress": False,
                "connection_limits_enabled": True,
                "max_connections_per_ip": 2_048,
                "max_new_connections_per_minute_per_ip": 1_000_000,
                "inbound_byte_limit_enabled": True,
                "max_inbound_bytes_per_window": 8 * 1024**3,
                "inbound_rate_window_hours": 1,
            },
        )
        self.assertEqual(
            profile["forbidden_measurement_log_prefixes"],
            [runner.MISSING_DKIM_LOG_PREFIX, runner.ASYNC_DROP_LOG_PREFIX],
        )

    def test_dns_publishes_the_public_key_matching_the_workspace_fixture(self) -> None:
        material = runner._generate_benchmark_dkim_material()
        runtime = runner.JavaStressRuntime(
            benchmark_dkim_private_key_bytes=material.private_key_bytes
        )
        with tempfile.TemporaryDirectory() as temporary:
            runtime.workspace = Path(temporary)
            runtime._ensure_benchmark_dkim_fixture()
            fixture = runtime._benchmark_dkim_fixture_attestation()
        self.assertEqual(fixture["private_key_sha256"], material.private_key_sha256)
        self.assertEqual(
            fixture["public_key_spki_sha256"], material.public_key_spki_sha256
        )

        server = runner.BenchmarkDnsServer.__new__(runner.BenchmarkDnsServer)
        server._dkim_material = material
        server._query_lock = runner.threading.Lock()
        server._query_counts = {
            "dkim_txt": 0,
            "dmarc_txt": 0,
            "spf_txt": 0,
            "mx": 0,
            "a": 0,
        }

        def txt_payload(name: str) -> bytes:
            qname = runner.base.StressDnsServer._encode_name(name)
            question = qname + b"\x00\x10\x00\x01"
            query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + question
            response = server._answer(query)
            self.assertIsNotNone(response)
            assert response is not None
            answer_start = 12 + len(question)
            rdata_length = int.from_bytes(
                response[answer_start + 10 : answer_start + 12], "big"
            )
            rdata = response[answer_start + 12 : answer_start + 12 + rdata_length]
            decoded = bytearray()
            offset = 0
            while offset < len(rdata):
                chunk_length = rdata[offset]
                offset += 1
                decoded.extend(rdata[offset : offset + chunk_length])
                offset += chunk_length
            return bytes(decoded)

        self.assertEqual(
            txt_payload("mail._domainkey.lmyz.net"), material.public_dns_record
        )
        self.assertEqual(txt_payload("_dmarc.lmyz.net"), runner.BENCHMARK_DMARC_RECORD)
        self.assertGreater(len(material.public_dns_record), 255)
        self.assertEqual(server.attestation()["dkim_txt_query_count"], 1)
        self.assertEqual(server.attestation()["dmarc_txt_query_count"], 1)

    def test_dkim_fixture_rejects_permission_changes(self) -> None:
        runtime = runner.JavaStressRuntime()
        with tempfile.TemporaryDirectory() as temporary:
            runtime.workspace = Path(temporary)
            path = runtime._ensure_benchmark_dkim_fixture()
            path.chmod(0o644)
            with self.assertRaisesRegex(
                runner.HarnessError, "private key identity or permissions changed"
            ):
                runtime._benchmark_dkim_fixture_attestation()

    def test_rust_runtime_uses_the_same_attested_dkim_fixture(self) -> None:
        runtime = runner.RustStressRuntime(filesystem_fsync_mode="off")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime.workspace = root
            config_path = root / "candidate-runtime.json"
            config_path.write_text(
                json.dumps({"stress": {}, "limits": {}, "domains": [{}]}),
                encoding="utf-8",
            )
            with mock.patch.object(
                runner.v2.StressCandidateRuntimeV2,
                "_candidate_configuration",
                return_value=config_path,
            ):
                returned = runtime._candidate_configuration()
            value = json.loads(returned.read_text(encoding="utf-8"))
            fixture = runtime._benchmark_dkim_fixture_attestation()
            self.assertEqual(
                value["domains"][0]["dkim_selector"],
                runner.BENCHMARK_DKIM_SELECTOR,
            )
            self.assertEqual(
                value["domains"][0]["dkim_private_key_path"],
                str(root / "benchmark-fixtures/dkim-private.pem"),
            )
            self.assertEqual(
                value["limits"]["postgres_pool"],
                runner.RUST_BENCHMARK_POSTGRES_POOL,
            )
            self.assertEqual(
                value["limits"]["redis_pool"],
                runner.RUST_BENCHMARK_REDIS_POOL,
            )
            self.assertEqual(
                value["limits"]["outbound_max_concurrent_sends"],
                runner.RUST_BENCHMARK_OUTBOUND_MAX_CONCURRENT_SENDS,
            )
            self.assertTrue(value["limits"]["outbound_pool_enabled"])
            self.assertEqual(
                value["limits"]["outbound_max_connections_per_host"],
                runner.RUST_BENCHMARK_OUTBOUND_MAX_CONNECTIONS_PER_HOST,
            )
            self.assertEqual(
                value["limits"]["outbound_max_messages_per_connection"],
                runner.RUST_BENCHMARK_OUTBOUND_MAX_MESSAGES_PER_CONNECTION,
            )
            self.assertEqual(
                value["limits"]["outbound_max_idle_time_ms"],
                runner.RUST_BENCHMARK_OUTBOUND_MAX_IDLE_TIME_MS,
            )
            self.assertEqual(
                value["limits"]["outbound_connection_life_time_ms"],
                runner.RUST_BENCHMARK_OUTBOUND_CONNECTION_LIFE_TIME_MS,
            )
            self.assertEqual(
                value["limits"]["outbound_pool_cleanup_interval_ms"],
                runner.RUST_BENCHMARK_OUTBOUND_POOL_CLEANUP_INTERVAL_MS,
            )
            self.assertEqual(value["storage"], {"fsync_enabled": False})
            self.assertTrue(fixture["passed"])

    def test_rust_profiling_runtime_enables_coordinator_observer_explicitly(
        self,
    ) -> None:
        runtime = runner.RustStressRuntime(coordinator_observer=True)
        with mock.patch.object(
            runner.v2.StressCandidateRuntimeV2,
            "_application_environment",
            return_value={"PATH": "/usr/bin:/bin"},
        ):
            environment = runtime._application_environment()
        self.assertEqual(environment["LMYZMAIL_COORDINATOR_OBSERVER"], "1")
        self.assertEqual(environment["LMYZMAIL_STRESS_ENQUEUE_OBSERVER"], "1")

        runtime.coordinator_observer = False
        with mock.patch.object(
            runner.v2.StressCandidateRuntimeV2,
            "_application_environment",
            return_value={"PATH": "/usr/bin:/bin"},
        ):
            environment = runtime._application_environment()
        self.assertNotIn("LMYZMAIL_COORDINATOR_OBSERVER", environment)
        self.assertNotIn("LMYZMAIL_STRESS_ENQUEUE_OBSERVER", environment)

    def test_readiness_waits_for_all_frozen_java_stress_services(self) -> None:
        runtime = runner.JavaStressRuntime(startup_timeout=1.0)
        process = SimpleNamespace(poll=mock.Mock(return_value=None))
        incomplete = "\n".join(runner.JAVA_STRESS_READINESS_MARKERS[:-1])
        complete = "\n".join(runner.JAVA_STRESS_READINESS_MARKERS)
        runtime._application = SimpleNamespace(
            _process=process,
            log_tail=mock.Mock(side_effect=[incomplete, complete]),
        )

        runtime._wait_for_stress_services(0.5)

        self.assertEqual(runtime._application.log_tail.call_count, 2)
        self.assertEqual(process.poll.call_count, 2)

    def test_readiness_fails_when_shared_startup_deadline_is_exhausted(self) -> None:
        runtime = runner.JavaStressRuntime(startup_timeout=1.0)
        with self.assertRaisesRegex(
            runner.ProcessStartError, "shared startup deadline"
        ):
            runtime._wait_for_stress_services(0.0)


class RoundCaptureTests(unittest.TestCase):
    def test_summary_tracks_digest_bytes_latency_and_samples(self) -> None:
        capture = runner.RoundCapture(
            expected=3,
            message_bytes=100,
            started_monotonic=100.0,
            started_at="2026-08-14T00:00:00+00:00",
        )
        digests = [_wire_digest(index) for index in range(3)]
        for index, digest in enumerate(digests):
            capture.record_final_reply(250)
            capture.add(
                round_number=7,
                index=index,
                message_id=f"message-{index}",
                wire_sha256=digest,
                wire_bytes=10 + index,
                transaction_started=100.5 + index,
                completed_monotonic=101.0 + index * 1.5,
            )

        digest_values = [int(digest, 16) for digest in digests]
        expected_xor = digest_values[0] ^ digest_values[1] ^ digest_values[2]
        expected_sum = sum(digest_values) % (1 << 256)
        summary = capture.summary()
        self.assertEqual(summary["expected"], 3)
        self.assertEqual(summary["verified"], 3)
        self.assertEqual(summary["missing"], 0)
        self.assertEqual(summary["round"], 7)
        self.assertEqual(summary["duration_seconds"], 4.0)
        self.assertEqual(summary["throughput_messages_per_second"], 0.75)
        self.assertEqual(summary["total_wire_bytes"], 33)
        self.assertEqual(summary["wire_digest_xor"], f"{expected_xor:064x}")
        self.assertEqual(summary["wire_digest_sum_mod_2_256"], f"{expected_sum:064x}")
        self.assertEqual(summary["smtp_final_replies"]["success"], 3)
        self.assertEqual(summary["retry_responses"], 0)
        self.assertEqual(
            [sample["index"] for sample in summary["first_samples"]], [0, 1, 2]
        )
        self.assertEqual(
            [sample["index"] for sample in summary["last_samples"]], [0, 1, 2]
        )
        self.assertEqual(summary["completion_latency"]["count"], 3)
        self.assertEqual(summary["smtp_transaction_latency"]["count"], 3)

    def test_sample_windows_keep_first_and_last_eight(self) -> None:
        capture = runner.RoundCapture(
            expected=10,
            message_bytes=100,
            started_monotonic=0.0,
            started_at="start",
        )
        for index in range(10):
            capture.record_final_reply(250)
            capture.add(
                round_number=1,
                index=index,
                message_id=f"message-{index}",
                wire_sha256=_wire_digest(index),
                wire_bytes=100,
                transaction_started=float(index),
                completed_monotonic=float(index + 1),
            )

        summary = capture.summary()
        self.assertEqual(
            [sample["index"] for sample in summary["first_samples"]],
            list(range(runner.SAMPLE_MESSAGES)),
        )
        self.assertEqual(
            [sample["index"] for sample in summary["last_samples"]],
            list(range(2, 10)),
        )

    def test_rejects_invalid_indices_duplicates_and_round_changes(self) -> None:
        capture = runner.RoundCapture(
            expected=2,
            message_bytes=100,
            started_monotonic=0.0,
            started_at="start",
        )
        add = {
            "round_number": 1,
            "message_id": "message",
            "wire_sha256": _wire_digest(0),
            "wire_bytes": 100,
            "transaction_started": 0.0,
            "completed_monotonic": 1.0,
        }
        for index in (-1, 2):
            with self.subTest(index=index):
                with self.assertRaisesRegex(RuntimeError, "outside expected range"):
                    capture.add(index=index, **add)

        capture.add(index=0, **add)
        with self.assertRaisesRegex(RuntimeError, "more than once"):
            capture.add(index=0, **add)
        with self.assertRaisesRegex(RuntimeError, "more than one stress round"):
            capture.add(
                index=1,
                **{**add, "round_number": 2, "wire_sha256": _wire_digest(1)},
            )


class ProxySelectionTests(unittest.TestCase):
    def test_execution_path_uses_only_the_rust_proxy(self) -> None:
        names = set(runner._run_target_tier.__code__.co_names)
        self.assertIn("RustSmtpProxy", names)
        self.assertNotIn("AggregateSmtpProxy", names)
        source = RUNNER_PATH.read_text(encoding="utf-8")
        target_tier = source[
            source.index("def _run_target_tier(") : source.index(
                "\ndef _aggregate_arm_rows("
            )
        ]
        self.assertEqual(target_tier.count("RustSmtpProxy("), 1)
        self.assertEqual(target_tier.count("_run_attested_round("), 1)
        self.assertNotIn("AggregateSmtpProxy", target_tier)
        self.assertNotIn('mode="WARMUP"', target_tier)
        self.assertNotIn("range(", target_tier)
        self.assertIn("persistence_gate_required=False", target_tier)
        dkim_event = target_tier[
            target_tier.index('"event": "dkim_fixture_attested"') : target_tier.index(
                '"dkim_fixture": dkim_fixture'
            )
        ]
        self.assertIn('"rust_filesystem_fsync"', dkim_event)

    def test_proxy_is_closed_before_runtime_workspace_is_removed(self) -> None:
        source = RUNNER_PATH.read_text(encoding="utf-8")
        target_tier = source[
            source.index("def _run_target_tier(") : source.index(
                "\ndef _aggregate_arm_rows("
            )
        ]
        cleanup = target_tier[target_tier.index("    finally:") :]
        self.assertLess(cleanup.index("proxy.close()"), cleanup.index("runtime.stop()"))

    def test_cli_has_no_warmup_or_repetition_controls(self) -> None:
        source = RUNNER_PATH.read_text(encoding="utf-8")
        parse_args = source[
            source.index("def _parse_args(") : source.index(
                "\ndef _enter_isolated_namespace("
            )
        ]
        self.assertNotIn("--repetitions", parse_args)
        self.assertNotIn("--warmup", parse_args)

    def test_java_small_cli_is_java_only_and_rejects_tier_overrides(self) -> None:
        base = [
            "smtp-endpoint-throughput-v1.py",
            "--output",
            "evidence/performance/java-small.json",
            "--launcher-run-id",
            LAUNCHER_RUN_ID,
            "--output-fd",
            "8",
            "--checkpoint-fd",
            "9",
            "--profile",
            "java-small",
        ]
        with mock.patch.object(sys, "argv", [*base, "--target", "java"]):
            args = runner._parse_args()
        self.assertEqual(args.profile, "java-small")
        self.assertEqual(args.target, "java")
        self.assertEqual(args.tier, "all")

        invalid_suffixes = (
            (),
            ("--target", "rust"),
            ("--target", "both"),
            ("--target", "java", "--tier", "10mb"),
            ("--target", "java", "--smoke"),
            ("--target", "java", "--disk-budget-gib", "19"),
            ("--target", "java", "--rust-filesystem-fsync", "off"),
        )
        for suffix in invalid_suffixes:
            with self.subTest(suffix=suffix):
                with mock.patch.object(sys, "argv", [*base, *suffix]):
                    with self.assertRaises(SystemExit):
                        runner._parse_args()

    def test_candidate_stability_cli_is_rust_only_and_binds_fsync(self) -> None:
        base = [
            "smtp-endpoint-throughput-v1.py",
            "--output",
            "evidence/performance/candidate-stability.json",
            "--launcher-run-id",
            LAUNCHER_RUN_ID,
            "--output-fd",
            "8",
            "--checkpoint-fd",
            "9",
            "--profile",
            "candidate-stability",
            "--target",
            "rust",
            "--tier",
            "10kb",
        ]
        with mock.patch.object(sys, "argv", base):
            with self.assertRaises(SystemExit):
                runner._parse_args()
        with mock.patch.object(sys, "argv", [*base, "--rust-filesystem-fsync", "off"]):
            args = runner._parse_args()
        self.assertEqual(args.profile, "candidate-stability")
        self.assertEqual(args.target, "rust")
        self.assertEqual(args.rust_filesystem_fsync, "off")
        with mock.patch.object(sys, "argv", [*base, "--smoke"]):
            smoke = runner._parse_args()
        self.assertEqual(smoke.rust_filesystem_fsync, "on")
        for target in ("both", "java"):
            with self.subTest(target=target):
                arguments = [target if value == "rust" else value for value in base]
                with mock.patch.object(sys, "argv", arguments):
                    with self.assertRaises(SystemExit):
                        runner._parse_args()

    def test_rust_cli_requires_one_explicit_fsync_mode_per_formal_run(self) -> None:
        base = [
            "smtp-endpoint-throughput-v1.py",
            "--output",
            "evidence/performance/rust.json",
            "--launcher-run-id",
            LAUNCHER_RUN_ID,
            "--output-fd",
            "8",
            "--checkpoint-fd",
            "9",
            "--target",
            "rust",
            "--tier",
            "10kb",
        ]
        with mock.patch.object(sys, "argv", base):
            with self.assertRaises(SystemExit):
                runner._parse_args()

        with mock.patch.object(sys, "argv", [*base, "--rust-filesystem-fsync", "off"]):
            args = runner._parse_args()
        self.assertEqual(args.rust_filesystem_fsync, "off")

        with mock.patch.object(sys, "argv", [*base, "--smoke"]):
            smoke = runner._parse_args()
        self.assertEqual(smoke.rust_filesystem_fsync, "on")

        with mock.patch.object(
            sys,
            "argv",
            [
                *base,
                "--target",
                "java",
                "--rust-filesystem-fsync",
                "on",
            ],
        ):
            with self.assertRaises(SystemExit):
                runner._parse_args()

    def test_profiler_message_bound_is_private_to_rust_profiler_selection(self) -> None:
        base = [
            "smtp-endpoint-throughput-v1.py",
            "--output",
            "evidence/performance/rust-profiler.json",
            "--launcher-run-id",
            LAUNCHER_RUN_ID,
            "--output-fd",
            "8",
            "--checkpoint-fd",
            "9",
            "--profile",
            "abba",
            "--target",
            "rust",
            "--tier",
            "10kb",
            "--profiler-candidate",
            "--rust-filesystem-fsync",
            "off",
        ]
        with mock.patch.object(
            sys, "argv", [*base, "--profiler-messages", "8192"]
        ):
            args = runner._parse_args()
        self.assertEqual(args.profiler_messages, 8192)

        invalid_suffixes = (
            ("--profiler-messages", "63"),
            ("--profiler-messages", "500001"),
        )
        for suffix in invalid_suffixes:
            with self.subTest(suffix=suffix):
                with mock.patch.object(sys, "argv", [*base, *suffix]):
                    with self.assertRaises(SystemExit):
                        runner._parse_args()

        with mock.patch.object(
            sys,
            "argv",
            [
                value
                for value in base
                if value != "--profiler-candidate"
            ]
            + ["--profiler-messages", "8192"],
        ):
            with self.assertRaises(SystemExit):
                runner._parse_args()

    def test_cli_prohibits_java_10mb_execution(self) -> None:
        arguments = [
            "smtp-endpoint-throughput-v1.py",
            "--output",
            "evidence/performance/java-10mb-prohibited.json",
            "--launcher-run-id",
            LAUNCHER_RUN_ID,
            "--output-fd",
            "8",
            "--checkpoint-fd",
            "9",
            "--target",
            "java",
            "--tier",
            "10mb",
        ]
        with mock.patch.object(sys, "argv", arguments):
            with self.assertRaises(SystemExit):
                runner._parse_args()


class RustProxyLifecycleTests(unittest.TestCase):
    def test_begin_forwards_persistence_gate_mode_to_rust_control(self) -> None:
        proxy = runner.RustSmtpProxy.__new__(runner.RustSmtpProxy)
        proxy.closed = False
        proxy.expected_messages = None
        proxy.run_id = "gate-calibration-off"
        proxy._command = mock.Mock(return_value={"begin": {"run_id": proxy.run_id}})
        progress_thread = mock.Mock()

        with mock.patch.object(
            runner.threading, "Thread", return_value=progress_thread
        ):
            proxy.begin(
                expected=12_000,
                message_bytes=1_024,
                started_monotonic=1.0,
                started_at="2026-08-15T00:00:00Z",
                persistence_gate_required=False,
            )

        command = proxy._command.call_args.args[0]
        self.assertFalse(command["persistence_gate_required"])
        self.assertEqual(command["expected_messages"], 12_000)
        progress_thread.start.assert_called_once_with()

    def test_finish_stops_progress_monitor_when_abort_check_fails(self) -> None:
        proxy = runner.RustSmtpProxy.__new__(runner.RustSmtpProxy)
        proxy.progress_complete = runner.threading.Event()
        proxy.progress_condition = runner.threading.Condition()
        proxy.progress_samples = []
        proxy._stop_progress_monitor = mock.Mock()

        def abort() -> None:
            raise RuntimeError("resource monitor failed")

        with self.assertRaisesRegex(RuntimeError, "resource monitor failed"):
            proxy.finish(10.0, abort)
        proxy._stop_progress_monitor.assert_called_once_with()

    def test_finish_keeps_control_process_alive_for_cleanup_membership_audit(
        self,
    ) -> None:
        proxy = runner.RustSmtpProxy.__new__(runner.RustSmtpProxy)
        proxy.progress_complete = runner.threading.Event()
        proxy.progress_complete.set()
        proxy.progress_condition = runner.threading.Condition()
        proxy.progress_samples = [{"verified": 1, "duration_ns": 1}]
        proxy.progress_error = None
        proxy.started_at = "2026-08-15T00:00:00Z"
        proxy.binary_sha256 = "a" * 64
        proxy._stop_progress_monitor = mock.Mock()
        proxy._reap_process = mock.Mock()
        proxy._command = mock.Mock(
            return_value={
                "round": {
                    "duration_ns": 1,
                    "total_wire_bytes": 1,
                    "expected": 1,
                },
                "proxy": {},
            }
        )

        with mock.patch.object(
            runner, "_proxy_shutdown_evidence_is_valid", return_value=True
        ):
            proxy.finish(1.0)

        proxy._command.assert_called_once_with({"command": "finish"}, timeout=305.0)
        proxy._reap_process.assert_not_called()

    def test_progress_monitor_requires_elapsed_duration_for_verified_messages(self) -> None:
        proxy = runner.RustSmtpProxy.__new__(runner.RustSmtpProxy)
        proxy.expected_messages = 4
        proxy.progress_samples = []
        proxy.progress_condition = runner.threading.Condition()

        with self.assertRaisesRegex(RuntimeError, "positive elapsed duration"):
            proxy._record_progress({"verified": 1, "progress_duration_ns": 0})

        proxy._record_progress({"verified": 1, "progress_duration_ns": 10})
        self.assertEqual(
            proxy.progress_samples,
            [{"verified": 1, "duration_ns": 10}],
        )

    def test_reap_process_terminates_and_closes_after_finish_timeout(self) -> None:
        class Process:
            def __init__(self) -> None:
                self.wait_calls = 0
                self.terminated = False
                self.killed = False

            def wait(self, timeout: float) -> int:
                self.wait_calls += 1
                if self.wait_calls == 1:
                    raise runner.subprocess.TimeoutExpired("proxy", timeout)
                return 0

            def terminate(self) -> None:
                self.terminated = True

            def kill(self) -> None:
                self.killed = True

        proxy = runner.RustSmtpProxy.__new__(runner.RustSmtpProxy)
        proxy.process = Process()
        proxy.log = mock.Mock()
        proxy.closed = False

        with self.assertRaisesRegex(RuntimeError, "did not exit after finish"):
            proxy._reap_process(require_graceful_exit=True)

        self.assertTrue(proxy.process.terminated)
        self.assertFalse(proxy.process.killed)
        self.assertTrue(proxy.closed)
        proxy.log.close.assert_called_once_with()

    def test_shutdown_evidence_requires_closed_consistent_residuals(self) -> None:
        clean = {
            "active_connections": 0,
            "shutdown_grace_ns": 30_000_000_000,
            "shutdown_wait_ns": 100_000,
            "shutdown_grace_exceeded": False,
            "shutdown_forced_connections": 0,
        }
        forced_idle = {
            **clean,
            "shutdown_wait_ns": 30_000_000_123,
            "shutdown_grace_exceeded": True,
            "shutdown_forced_connections": 2,
        }
        self.assertTrue(runner._proxy_shutdown_evidence_is_valid(clean))
        self.assertTrue(runner._proxy_shutdown_evidence_is_valid(forced_idle))
        for invalid in (
            {**clean, "active_connections": 1},
            {**clean, "shutdown_grace_exceeded": True},
            {**clean, "shutdown_forced_connections": 1},
            {**forced_idle, "shutdown_wait_ns": 29_999_999_999},
            {**forced_idle, "shutdown_forced_connections": 0},
            {**clean, "shutdown_grace_ns": True},
        ):
            with self.subTest(invalid=invalid):
                self.assertFalse(runner._proxy_shutdown_evidence_is_valid(invalid))

    def test_progress_poll_timeout_is_below_monitor_join_timeout(self) -> None:
        self.assertLess(
            runner.PROXY_PROGRESS_COMMAND_TIMEOUT_SECONDS,
            runner.PROXY_MONITOR_JOIN_TIMEOUT_SECONDS,
        )

    def test_close_rejoins_monitor_after_proxy_process_exit(self) -> None:
        class Thread:
            def __init__(self) -> None:
                self.join_calls = 0

            def join(self, timeout: float) -> None:
                self.join_calls += 1

            def is_alive(self) -> bool:
                return self.join_calls < 2

        proxy = runner.RustSmtpProxy.__new__(runner.RustSmtpProxy)
        proxy.closed = False
        proxy.binary_sha256 = "0" * 64
        proxy.progress_stop = runner.threading.Event()
        proxy.progress_thread = Thread()
        proxy._command = mock.Mock()
        proxy._reap_process = mock.Mock()

        with self.assertRaisesRegex(RuntimeError, "progress monitor did not stop"):
            proxy.close()

        proxy._command.assert_called_once_with({"command": "shutdown"}, timeout=305.0)
        proxy._reap_process.assert_called_once_with(require_graceful_exit=False)
        self.assertIsNone(proxy.progress_thread)


class PlanAndComparisonTests(unittest.TestCase):
    def test_profiler_stage_selection_targets_result_checkpoint_transaction(
        self,
    ) -> None:
        expected = (
            "result_checkpoint_legacy_lock",
            "result_checkpoint_attempt_lock",
            "result_checkpoint_attempt_row_lock",
            "result_checkpoint_roster_verify",
            "result_checkpoint_barrier_verify",
            "result_checkpoint_recipient_update",
            "result_checkpoint_attempt_update",
            "result_checkpoint_commit",
        )
        selected = runner.COORDINATOR_SELECTED_DIAGNOSTIC_STAGES
        self.assertEqual(selected[-len(expected) :], expected)
        self.assertEqual(
            len(selected),
            runner.MAXIMUM_COORDINATOR_SELECTED_DIAGNOSTIC_STAGES,
        )
        self.assertEqual(len(set(selected)), len(selected))

    def test_profiler_stage_selection_override_is_bounded_and_default_is_stable(
        self,
    ) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(runner.COORDINATOR_DIAGNOSTIC_STAGES_ENV, None)
            self.assertEqual(
                runner._coordinator_selected_diagnostic_stages(),
                runner.COORDINATOR_SELECTED_DIAGNOSTIC_STAGES,
            )
        with mock.patch.dict(
            os.environ,
            {
                runner.COORDINATOR_DIAGNOSTIC_STAGES_ENV:
                "inbound_prepare_file,inbound_index_commit"
            },
            clear=False,
        ):
            self.assertEqual(
                runner._coordinator_selected_diagnostic_stages(),
                ("inbound_prepare_file", "inbound_index_commit"),
            )
        too_many = ",".join(
            f"stage_{index}"
            for index in range(runner.MAXIMUM_COORDINATOR_SELECTED_DIAGNOSTIC_STAGES + 1)
        )
        with mock.patch.dict(
            os.environ,
            {runner.COORDINATOR_DIAGNOSTIC_STAGES_ENV: too_many},
            clear=False,
        ):
            with self.assertRaisesRegex(RuntimeError, "bounded stage limit"):
                runner._coordinator_selected_diagnostic_stages()

    def test_cli_replacements_remove_prior_values_without_duplicates(self) -> None:
        arguments = [
            "java",
            "--feature.enabled=true",
            "--domain=example.test",
            "--unrelated=kept",
        ]
        replaced = runner._replace_cli_arguments(
            arguments,
            ("--feature.enabled=false", "--domain=lmyz.net"),
        )
        self.assertEqual(
            replaced,
            [
                "java",
                "--unrelated=kept",
                "--feature.enabled=false",
                "--domain=lmyz.net",
            ],
        )
        self.assertEqual(
            [value.partition("=")[0] for value in replaced].count("--feature.enabled"),
            1,
        )
        with self.assertRaisesRegex(ValueError, "duplicate CLI replacement"):
            runner._replace_cli_arguments(
                arguments,
                ("--domain=one", "--domain=two"),
            )

    def test_proxy_control_path_is_short_bounded_and_create_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / ("w" * 80)
            workspace.mkdir()
            path = runner._proxy_control_path(workspace, root)
            self.assertEqual(path, root / "p.sock")
            self.assertLessEqual(len(os.fsencode(path)), 100)
            existing = root / "p.sock"
            existing.write_bytes(b"occupied")
            with self.assertRaises(FileExistsError):
                runner._proxy_control_path(workspace, root)
            long_root = root / ("r" * 90)
            long_root.mkdir()
            with self.assertRaisesRegex(RuntimeError, "AF_UNIX"):
                runner._proxy_control_path(workspace, long_root)

    def test_bounded_file_tail_reads_only_the_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "proxy.log"
            path.write_bytes(b"prefix-tail")
            self.assertEqual(runner._bounded_file_tail(path, 4), "tail")

    def test_benchmark_postgres_uses_tcp_without_a_length_bounded_unix_socket(
        self,
    ) -> None:
        source = inspect.getsource(runner.DurablePostgresRuntimeMixin._start_postgres)
        self.assertNotIn("postgres-socket", source)
        self.assertIn('"-k",\n                "",', source)
        self.assertIn('"fsync=on"', source)
        self.assertIn('"synchronous_commit=on"', source)
        self.assertIn('"full_page_writes=on"', source)
        self.assertIn('"postgres-schema.sql"', source)
        self.assertIn('metadata.get("schema_sha256")', source)
        self.assertIn('"--single-transaction"', source)
        self.assertIn('"--set=ON_ERROR_STOP=1"', source)
        schema_metadata = json.loads(
            (
                runner.REPOSITORY / "blackbox/fixtures/legacy/postgres-schema.json"
            ).read_text(encoding="utf-8")
        )
        last_error = next(
            column
            for column in schema_metadata["columns"]
            if column["table"] == "outbound_mail_queue"
            and column["column"] == "last_error"
        )
        self.assertEqual(last_error["data_type"], "text")

    def test_plans_cover_smoke_non_smoke_and_tier_filters(self) -> None:
        smoke = runner._plans(smoke=True, disk_budget_bytes=0, tier="all")
        self.assertEqual([plan.label for plan in smoke], ["1KB", "10KB", "10MB"])
        self.assertEqual(
            [plan.message_bytes for plan in smoke],
            [1024, 10 * 1024, 10 * 1024 * 1024],
        )
        self.assertEqual([plan.total_messages for plan in smoke], [8, 8, 2])
        self.assertEqual(
            [
                plan.label
                for plan in runner._plans(smoke=True, disk_budget_bytes=0, tier="10kb")
            ],
            ["10KB"],
        )

        for budget, expected_large_count in (
            (0, 50),
            (20 * 1024**3, 500),
            (100 * 1024**3, 1_000),
        ):
            with self.subTest(budget=budget):
                plans = runner._plans(smoke=False, disk_budget_bytes=budget, tier="all")
                self.assertEqual(plans[-1].total_messages, expected_large_count)
                self.assertGreaterEqual(plans[-1].total_messages, 50)
                self.assertLessEqual(plans[-1].total_messages, 1_000)
                self.assertEqual(plans[-1].total_messages % 50, 0)

        self.assertEqual(runner._expected_stress_concurrency(1), 1_500)
        self.assertEqual(runner._expected_stress_concurrency(10), 1_000)
        self.assertEqual(runner._expected_stress_concurrency(10_000), 80)

        profiler = runner._plans(
            smoke=False,
            disk_budget_bytes=20 * 1024**3,
            tier="10kb",
            profiler_messages=8192,
        )
        self.assertEqual(
            [
                (plan.label, plan.message_bytes, plan.total_messages)
                for plan in profiler
            ],
            [("10KB", 10 * 1024, 8192)],
        )
        self.assertEqual(len(profiler), 1)
        with self.assertRaisesRegex(ValueError, "non-smoke 10KB"):
            runner._plans(
                smoke=True,
                disk_budget_bytes=20 * 1024**3,
                tier="10kb",
                profiler_messages=8192,
            )

    def test_comparison_applies_tier_gates_and_rejects_unpaired_rows(self) -> None:
        rows = [
            _row("java-oracle", "1KB", 100.0),
            _row("rust-candidate", "1KB", 123.0),
            _row("java-oracle", "10KB", 100.0),
            _row("rust-candidate", "10KB", 119.0),
            _row("java-oracle", "10MB", 100.0),
            _row("rust-candidate", "10MB", 94.0),
            _row("java-oracle", "unpaired", 10.0),
        ]
        comparison = runner._comparison(rows, smoke=False)
        by_tier = {entry["tier"]: entry for entry in comparison["comparisons"]}
        self.assertIn("unpaired", by_tier)
        self.assertFalse(by_tier["unpaired"]["pair_complete"])
        self.assertTrue(by_tier["1KB"]["passed"])
        self.assertEqual(len(by_tier["1KB"]["paired_ratios"]), 2)
        self.assertTrue(all(pair["passed"] for pair in by_tier["1KB"]["paired_ratios"]))
        self.assertTrue(by_tier["1KB"]["conservative_ratio_passed"])
        self.assertEqual(
            by_tier["1KB"]["required_ratio"], runner.MINIMUM_CLEAR_IMPROVEMENT
        )
        self.assertFalse(by_tier["10KB"]["passed"])
        self.assertFalse(by_tier["10MB"]["passed"])
        self.assertFalse(by_tier["10MB"]["candidate_only_complete"])
        self.assertTrue(by_tier["10MB"]["java_present"])
        self.assertTrue(by_tier["10MB"]["java_comparison_intentionally_excluded"])
        self.assertFalse(comparison["all_passed"])

        smoke_comparison = runner._comparison(rows, smoke=True)
        self.assertFalse(smoke_comparison["all_passed"])
        self.assertFalse(smoke_comparison["pair_completeness_passed"])

        rust_large_only = runner._comparison(
            [_row("rust-candidate", "10MB", 94.0)],
            smoke=True,
        )
        large_gate = rust_large_only["comparisons"][0]
        self.assertTrue(large_gate["candidate_only_complete"])
        self.assertFalse(large_gate["java_present"])
        self.assertEqual(set(large_gate["rust_arm_messages_per_second"]), {0, 1})
        self.assertTrue(rust_large_only["all_passed"])

    def test_execution_matrix_pairs_small_tiers_and_excludes_java_10mb(self) -> None:
        plans = runner._plans(smoke=False, disk_budget_bytes=20 * 1024**3, tier="all")
        matrix = runner._execution_matrix(runner._targets("both"), plans)
        self.assertEqual(
            [(target, plan.label, ordinal) for target, plan, ordinal in matrix],
            [
                (target, tier, ordinal)
                for tier in ("1KB", "10KB")
                for target, ordinal in (
                    ("java-oracle", 0),
                    ("rust-candidate", 0),
                    ("rust-candidate", 1),
                    ("java-oracle", 1),
                )
            ]
            + [
                ("rust-candidate", "10MB", 0),
                ("rust-candidate", "10MB", 1),
            ],
        )
        self.assertNotIn(
            "java-oracle",
            {
                target
                for target, plan, _ordinal in matrix
                if plan.label == "10MB"
            },
        )

    def test_java_small_baseline_is_exactly_two_single_java_arms(self) -> None:
        plans = runner._java_small_baseline_plans()
        self.assertEqual(
            [(plan.label, plan.message_bytes, plan.total_messages) for plan in plans],
            [
                ("1KB", 1_024, 200_000),
                ("10KB", 10 * 1_024, 200_000),
            ],
        )
        matrix = runner._java_small_baseline_execution_matrix(plans)
        self.assertEqual(
            [(target, plan.label, ordinal) for target, plan, ordinal in matrix],
            [("java-oracle", "1KB", 0), ("java-oracle", "10KB", 0)],
        )
        with self.assertRaisesRegex(ValueError, "plan contract changed"):
            runner._java_small_baseline_execution_matrix(
                [runner.BenchmarkPlan("10MB", 10 * 1_024 * 1_024, 1)]
            )

    def test_java_small_baseline_accepts_only_exact_single_call_evidence(self) -> None:
        plans = runner._java_small_baseline_plans()
        arms = []
        for plan, throughput in zip(plans, (1_000.0, 1_500.0), strict=True):
            measurement = _round_record(measured=True)
            measurement["endpoint_outcome"]["failure_count"] = 0
            arms.append(
                {
                    "target": "java-oracle",
                    "tier": {
                        "label": plan.label,
                        "message_bytes": plan.message_bytes,
                        "total_messages": plan.total_messages,
                    },
                    "arm_ordinal": 0,
                    "measurement": measurement,
                    "endpoint_start_invocations": 1,
                    "endpoint_invocations": 1,
                    "harness_batches": 0,
                    "endpoint_requested_messages": plan.total_messages,
                    "observer_verified_messages": plan.total_messages,
                    "requested_equals_observer_verified": True,
                    "throughput_messages_per_second": throughput,
                }
            )
        rows = runner._aggregate_arm_rows(arms, plans, expected_ordinals=(0,))
        comparison = runner._java_small_baseline_comparison(rows, plans)
        self.assertTrue(comparison["all_passed"])
        self.assertTrue(comparison["java_only_passed"])
        self.assertTrue(comparison["ten_megabyte_excluded"])
        self.assertEqual(
            [entry["requested_messages"] for entry in comparison["comparisons"]],
            [200_000, 200_000],
        )

        rows[1]["arms"][0]["endpoint_start_invocations"] = 2
        self.assertFalse(
            runner._java_small_baseline_comparison(rows, plans)["all_passed"]
        )

    def test_candidate_stability_is_one_rust_arm_with_operational_gates(self) -> None:
        plan = runner.BenchmarkPlan("10KB", 10 * 1024, 500_000)
        matrix = runner._candidate_stability_execution_matrix([plan])
        self.assertEqual(
            [(target, value.label, ordinal) for target, value, ordinal in matrix],
            [("rust-candidate", "10KB", 0)],
        )
        measurement = _round_record(measured=True)
        measurement["endpoint_outcome"]["failure_count"] = 0
        arm = {
            "target": "rust-candidate",
            "tier": {
                "label": plan.label,
                "message_bytes": plan.message_bytes,
                "total_messages": plan.total_messages,
            },
            "arm_ordinal": 0,
            "measurement": measurement,
            "endpoint_start_invocations": 1,
            "endpoint_invocations": 1,
            "harness_batches": 0,
            "endpoint_requested_messages": plan.total_messages,
            "observer_verified_messages": plan.total_messages,
            "requested_equals_observer_verified": True,
            "throughput_messages_per_second": 120.0,
        }
        rows = runner._aggregate_arm_rows([arm], [plan], expected_ordinals=(0,))
        comparison = runner._candidate_stability_comparison(
            rows,
            [plan],
            smoke=False,
            proxy_headroom={
                "tiers": {"10KB": {"sustained_messages_per_second": 300.0}}
            },
        )
        self.assertTrue(comparison["all_passed"])
        self.assertTrue(comparison["candidate_only_passed"])
        self.assertTrue(comparison["single_arm_per_tier_passed"])
        self.assertTrue(comparison["proxy_headroom_passed"])

        rows[0]["arms"][0]["measurement"]["endpoint_outcome"]["retry_count"] = 1
        failed = runner._candidate_stability_comparison(
            rows,
            [plan],
            smoke=True,
        )
        self.assertFalse(failed["zero_retry_gate_passed"])
        self.assertFalse(failed["all_passed"])

    def test_arm_aggregation_preserves_four_raw_values_and_equal_weights(self) -> None:
        plan = runner.BenchmarkPlan("10KB", 10 * 1024, 500_000)
        arms = []
        for target, values in (
            ("java-oracle", (100.0, 110.0)),
            ("rust-candidate", (130.0, 140.0)),
        ):
            for ordinal, throughput in enumerate(values):
                arms.append(
                    {
                        "target": target,
                        "tier": {
                            "label": plan.label,
                            "message_bytes": plan.message_bytes,
                            "total_messages": plan.total_messages,
                        },
                        "arm_ordinal": ordinal,
                        "measurement": _round_record(measured=True),
                        "endpoint_start_invocations": 1,
                        "endpoint_invocations": 1,
                        "harness_batches": 0,
                        "endpoint_requested_messages": plan.total_messages,
                        "observer_verified_messages": plan.total_messages,
                        "requested_equals_observer_verified": True,
                        "throughput_messages_per_second": throughput,
                    }
                )
        rows = runner._aggregate_arm_rows(arms, [plan])
        self.assertEqual(len(rows), 2)
        by_target = {row["target"]: row for row in rows}
        self.assertEqual(by_target["java-oracle"]["throughput"]["runs"], [100.0, 110.0])
        self.assertEqual(
            by_target["rust-candidate"]["throughput"]["runs"], [130.0, 140.0]
        )
        self.assertEqual(
            by_target["java-oracle"]["throughput"]["median_messages_per_second"],
            105.0,
        )
        self.assertTrue(by_target["java-oracle"]["throughput"]["equally_weighted_arms"])

    def test_stability_statistics_preserve_all_three_runs(self) -> None:
        stability = runner._throughput_stability([100.0, 110.0, 120.0])
        self.assertEqual(stability["runs"], 3)
        self.assertEqual(
            stability["all_runs_messages_per_second"], [100.0, 110.0, 120.0]
        )
        self.assertEqual(stability["mean_messages_per_second"], 110.0)
        self.assertEqual(stability["median_absolute_deviation"], 10.0)
        self.assertGreater(stability["coefficient_of_variation"], 0.0)

    def test_within_arm_progress_stability_is_bounded_and_fail_closed(self) -> None:
        stable = runner._within_arm_throughput_stability(
            [
                {"verified": 25, "duration_ns": 1_000_000_000},
                {"verified": 50, "duration_ns": 2_000_000_000},
                {"verified": 75, "duration_ns": 3_000_000_000},
                {"verified": 100, "duration_ns": 4_000_000_000},
            ],
            100,
        )
        self.assertTrue(stable["qualification_required"])
        self.assertTrue(stable["passed"])
        self.assertEqual(len(stable["segments"]), 4)
        self.assertEqual(stable["relative_range"], 0.0)

        bursty = runner._within_arm_throughput_stability(
            [
                {"verified": 25, "duration_ns": 1_000_000_000},
                {"verified": 50, "duration_ns": 1_100_000_000},
                {"verified": 75, "duration_ns": 3_000_000_000},
                {"verified": 100, "duration_ns": 4_000_000_000},
            ],
            100,
        )
        self.assertFalse(bursty["passed"])

    def test_coordinator_quartile_diagnostics_compute_cumulative_deltas(self) -> None:
        def record(
            completed: int,
            completed_total_ns: int,
            database_total_ns: int,
            index_total_ns: int,
        ) -> dict[str, Any]:
            return {
                "completed_tasks": completed,
                "completed_total_ns": completed_total_ns,
                "inbound_index_batches": {
                    "batches": completed // 4,
                    "rows": completed,
                    "max_rows": 4,
                    "size_buckets": {
                        "1": 0,
                        "2_4": completed // 4,
                        "5_8": 0,
                        "9_16": 0,
                        "17_32": 0,
                        "33_64": 0,
                    },
                },
                "stages": {
                    "database_claim": {
                        "count": completed,
                        "total_ns": database_total_ns,
                        "max_ns": 90,
                    },
                    "inbound_index_commit": {
                        "count": completed,
                        "total_ns": index_total_ns,
                        "max_ns": 120,
                    },
                },
            }

        diagnostic = runner._coordinator_quartile_diagnostics(
            [
                record(2_048, 20_000, 8_000, 10_000),
                record(4_096, 45_000, 17_000, 23_000),
                record(6_144, 75_000, 27_000, 39_000),
                record(8_192, 110_000, 38_000, 58_000),
            ],
            8_192,
            selected_stage_names=("database_claim",),
        )

        self.assertTrue(diagnostic["complete"])
        self.assertEqual(diagnostic["thresholds"], [2_048, 4_096, 6_144, 8_192])
        self.assertEqual(
            [segment["delta_completed_total_ns"] for segment in diagnostic["segments"]],
            [20_000, 25_000, 30_000, 35_000],
        )
        second = diagnostic["segments"][1]
        self.assertEqual(second["delta_completed_tasks"], 2_048)
        self.assertEqual(second["all_stage_delta_total_ns"], 22_000)
        self.assertEqual(second["top_stages"][0]["stage"], "inbound_index_commit")
        self.assertEqual(second["top_stages"][0]["delta_count"], 2_048)
        self.assertEqual(second["top_stages"][0]["delta_total_ns"], 13_000)
        self.assertEqual(second["selected_stages"][0]["stage"], "database_claim")
        self.assertEqual(second["selected_stages"][0]["delta_total_ns"], 9_000)
        self.assertEqual(second["inbound_index_batches"]["delta_batches"], 512)
        self.assertEqual(second["inbound_index_batches"]["delta_rows"], 2_048)
        self.assertEqual(
            second["inbound_index_batches"]["average_rows_per_batch"], 4.0
        )
        self.assertEqual(
            second["inbound_index_batches"]["delta_size_buckets"]["2_4"],
            512,
        )

    def test_coordinator_quartile_diagnostics_are_bounded_and_partial(self) -> None:
        stages = {
            f"stage_{index:02d}": {
                "count": 2_048,
                "total_ns": index + 1,
                "max_ns": index + 1,
            }
            for index in range(12)
        }
        diagnostic = runner._coordinator_quartile_diagnostics(
            [
                {
                    "completed_tasks": 2_048,
                    "completed_total_ns": 100,
                    "stages": stages,
                }
            ],
            8_192,
            maximum_stages=3,
        )

        self.assertFalse(diagnostic["complete"])
        self.assertEqual(diagnostic["reason"], "missing_threshold")
        self.assertEqual(diagnostic["missing_threshold"], 4_096)
        self.assertEqual(len(diagnostic["segments"]), 1)
        self.assertEqual(
            [stage["stage"] for stage in diagnostic["segments"][0]["top_stages"]],
            ["stage_11", "stage_10", "stage_09"],
        )
        self.assertNotIn("records", diagnostic)

    def test_coordinator_quartile_diagnostics_reject_invalid_batch_buckets(self) -> None:
        records = []
        for completed in range(1, 5):
            records.append(
                {
                    "completed_tasks": completed,
                    "completed_total_ns": completed * 100,
                    "stages": {
                        "inbound_index_commit": {
                            "count": completed,
                            "total_ns": completed * 10,
                            "max_ns": 10,
                        }
                    },
                    "inbound_index_batches": {
                        "batches": completed,
                        "rows": completed,
                        "max_rows": 1,
                        "size_buckets": {
                            "1": completed,
                            "2_4": 0,
                            "5_8": 0,
                            "9_16": 0,
                            "17_32": 0,
                            "33_64": 0,
                        },
                    },
                }
            )
        records[2]["inbound_index_batches"]["size_buckets"]["1"] = 2

        diagnostic = runner._coordinator_quartile_diagnostics(records, 4)

        self.assertFalse(diagnostic["complete"])
        self.assertEqual(
            diagnostic["reason"],
            "non_monotonic_or_invalid_inbound_index_batch_metrics",
        )

    def test_two_arm_relative_range_is_a_fail_closed_stability_gate(self) -> None:
        java = _row("java-oracle", "10KB", 100.0)
        rust = _row("rust-candidate", "10KB", 120.0)
        java["arms"][0]["throughput_messages_per_second"] = 20.0
        java["arms"][1]["throughput_messages_per_second"] = 180.0
        java["throughput"]["runs"] = [20.0, 180.0]
        java["throughput"]["variation"] = runner._throughput_stability([20.0, 180.0])
        comparison = runner._comparison([java, rust], smoke=False)
        self.assertFalse(comparison["abba_stability_passed"])
        self.assertFalse(comparison["all_passed"])

    def test_nonfinite_throughput_and_ratios_are_rejected(self) -> None:
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value):
                with self.assertRaisesRegex(RuntimeError, "finite"):
                    runner._throughput_stability([100.0, value, 101.0])

        java = _row("java-oracle", "10KB", 100.0)
        rust = _row("rust-candidate", "10KB", 120.0)
        rust["throughput"]["median_messages_per_second"] = float("nan")
        with self.assertRaisesRegex(RuntimeError, "finite"):
            runner._comparison([java, rust], smoke=False)
        with self.assertRaisesRegex(RuntimeError, "finite"):
            runner._reject_nonfinite_metrics(
                {"tiers": {"10KB": {"sustained_headroom_ratio": float("inf")}}}
            )
        runner._reject_nonfinite_metrics(
            {
                "isolation_policy": {
                    "root_only_cgroup_migration": True,
                    "passed": True,
                }
            }
        )
        for key in ("throughput", "headroom", "ratio"):
            with self.subTest(key=key):
                with self.assertRaisesRegex(RuntimeError, "must not be boolean"):
                    runner._reject_nonfinite_metrics({key: True})

    def test_formal_comparison_requires_queue_scheduler_evidence(self) -> None:
        java = _row("java-oracle", "10KB", 100.0)
        rust = _row("rust-candidate", "10KB", 120.0)
        rust["measurements"][0]["endpoint_outcome"]["queue_scheduler_observed"] = False
        comparison = runner._comparison([java, rust], smoke=False)
        self.assertFalse(comparison["operational_evidence_passed"])
        self.assertFalse(comparison["all_passed"])

    def test_round_contract_rejects_zero_application_or_service_io(self) -> None:
        for role in ("application", "services"):
            with self.subTest(role=role):
                record = _round_record(measured=True)
                key = f"{role}_persistence_io_observed"
                record["resource"][key] = False
                record["endpoint_outcome"][key] = False
                self.assertFalse(runner._round_contract_passed(record))

    def test_formal_comparison_rejects_any_retry(self) -> None:
        java = _row("java-oracle", "10KB", 100.0)
        rust = _row("rust-candidate", "10KB", 120.0)
        rust["measurements"][0]["endpoint_outcome"]["retry_count"] = 1
        comparison = runner._comparison([java, rust], smoke=False)
        self.assertFalse(comparison["zero_retry_gate_passed"])
        self.assertFalse(comparison["all_passed"])

    def test_proxy_headroom_uses_maximum_observed_arm_not_asserted_ratio(self) -> None:
        java = _row("java-oracle", "10KB", 100.0)
        rust = _row("rust-candidate", "10KB", 120.0)
        rust["arms"][1]["throughput_messages_per_second"] = 150.0
        rust["throughput"]["runs"] = [118.8, 150.0]
        rust["throughput"]["variation"] = runner._throughput_stability(
            rust["throughput"]["runs"]
        )
        proxy = {
            "tiers": {
                "10KB": {
                    "sustained_messages_per_second": 299.0,
                    "sustained_headroom_ratio": 100.0,
                }
            }
        }
        failed = runner._comparison([java, rust], smoke=False, proxy_headroom=proxy)
        gate = failed["proxy_headroom_gates"][0]
        self.assertEqual(gate["maximum_observed_arm_messages_per_second"], 150.0)
        self.assertFalse(gate["passed"])
        proxy["tiers"]["10KB"]["sustained_messages_per_second"] = 300.0
        passed = runner._comparison([java, rust], smoke=False, proxy_headroom=proxy)
        self.assertTrue(passed["proxy_headroom_passed"])

    def test_arm_completeness_is_fail_closed_without_warmups(self) -> None:
        java = _row("java-oracle", "10KB", 100.0)
        rust = _row("rust-candidate", "10KB", 120.0)
        rust["arms"][0]["endpoint_start_invocations"] = 2
        comparison = runner._comparison([java, rust], smoke=False)
        self.assertFalse(comparison["arm_completeness_passed"])
        self.assertFalse(comparison["all_passed"])
        self.assertEqual(java["warmups"], [])
        self.assertEqual(rust["warmups"], [])

    def test_formal_qualification_requires_external_attestation(self) -> None:
        layout = SimpleNamespace(
            io_bytes_per_second=500_000_000,
            host_reserve_bytes=10 * 1024**3,
            max_memory_bytes=8 * 1024**3,
            max_pids=8_192,
            nofile_limit=8_192,
        )
        arguments = {
            "smoke": False,
            "target": "both",
            "tier": "all",
            "disk_budget_bytes": 20 * 1024**3,
            "layout": layout,
            "isolation_policy_passed": True,
        }
        self.assertFalse(
            runner._qualified(**arguments, external_prerequisites_passed=False)
        )
        self.assertTrue(
            runner._qualified(**arguments, external_prerequisites_passed=True)
        )
        prerequisites = runner._external_prerequisites(
            path=None,
            expected_sha256=None,
            plans=[],
            disk_budget_bytes=20 * 1024**3,
            layout=layout,
            started_attestation={},
        )
        self.assertFalse(prerequisites["provided"])
        self.assertFalse(prerequisites["passed"])

    def test_proxy_calibration_is_bound_to_binary_source_and_absolute_capacity(
        self,
    ) -> None:
        source = RUNNER_PATH.read_text(encoding="utf-8")
        external = source[
            source.index("def _external_prerequisites(") : source.index(
                "\ndef _qualified("
            )
        ]
        self.assertIn('proxy.get("binary_sha256")', external)
        self.assertIn('proxy.get("source_tree_sha256")', external)
        self.assertIn('tier.get("sustained_messages_per_second")', external)
        self.assertNotIn("ratio < MINIMUM_PROXY_HEADROOM_RATIO", external)

    def test_proxy_raw_headroom_rejects_cross_host_cgroup_stale_and_tamper(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "formal"
            harness = parent / "harness"
            harness.mkdir(parents=True)
            io_payload = (
                "7:0 rbps=500000000 wbps=500000000 riops=max wiops=max\n"
                "7:1 rbps=500000000 wbps=500000000 riops=max wiops=max\n"
            ).encode("ascii")
            (parent / "io.max").write_bytes(io_payload)
            (harness / "cpuset.cpus.effective").write_text("0-2\n", encoding="ascii")
            layout = SimpleNamespace(
                parent=parent,
                harness=harness,
                cpu=3,
                device="7:1",
                backing_device="7:0",
                io_bytes_per_second=500_000_000,
                max_memory_bytes=8 * 1024**3,
                max_pids=8_192,
                nofile_limit=8_192,
            )
            now = 2_000_000_000
            started_attestation = {
                "captured_at_unix_seconds": now,
                "host_boot_id": "12345678-1234-4234-9234-123456789abc",
            }
            environment = {
                "host_boot_id": started_attestation["host_boot_id"],
                "benchmark_cpu": 3,
                "calibration_cpus": "0-2",
                "cgroup_parent": str(parent.resolve()),
                "process_cgroup": str(harness.resolve()),
                "cpuset_cpus_effective": "0-2",
                "io_bytes_per_second_per_device": 500_000_000,
                "io_device": "7:1",
                "backing_device": "7:0",
                "io_max_lines": io_payload.decode("ascii").splitlines(),
                "io_max_sha256": hashlib.sha256(io_payload).hexdigest(),
                "memory_max_bytes": 8 * 1024**3,
                "memory_swap_max_bytes": 0,
                "pids_max": 8_192,
                "nofile_soft_and_hard": 8_192,
                "nofile_required": 6_512,
                "nofile_reserve": 512,
            }
            tiers: dict[str, Any] = {}
            hashes: dict[str, str] = {}
            runner_sha256 = "1" * 64
            binary_sha256 = "2" * 64
            source_tree_sha256 = "3" * 64
            for label, message_bytes, messages, concurrency in (
                ("1KB", 1024, 250_000, 1_500),
                ("10KB", 10 * 1024, 250_000, 1_000),
                ("10MB", 10 * 1024 * 1024, 2_000, 80),
            ):
                direct_rounds = [
                    {
                        "messages": messages,
                        "message_bytes": message_bytes,
                        "messages_per_second": 2_000.0,
                    }
                    for _ in range(4)
                ]
                proxied_rounds = [
                    {
                        "messages": messages,
                        "message_bytes": message_bytes,
                        "messages_per_second": 1_800.0,
                    }
                    for _ in range(4)
                ]
                accounted_connection_bytes = 512 * 1024
                observer_round_reserve_bytes = 128 * 1024 * 1024
                control_runtime_reserve_bytes = 8 * 1024 * 1024
                memory_budget_bytes = 2 * 1024 * 1024 * 1024
                required_memory_budget_bytes = (
                    accounted_connection_bytes * concurrency
                    + observer_round_reserve_bytes
                    + control_runtime_reserve_bytes
                )
                raw = {
                    "schema_version": 4,
                    "control_topology": "bounded-unobserved-proxy",
                    "observed_topology": "bounded-observing-proxy",
                    "equal_tcp_hop_topology": True,
                    "mode": "data",
                    "messages": messages,
                    "message_bytes": message_bytes,
                    "concurrency": concurrency,
                    "rounds_per_arm": 4,
                    "sequence": ["direct", "proxied", "proxied", "direct"] * 2,
                    "direct_rounds": direct_rounds,
                    "proxied_rounds": proxied_rounds,
                    "direct": {"messages_per_second": 2_000.0},
                    "proxied": {"messages_per_second": 1_800.0},
                    "proxy_to_direct_ratio": 0.9,
                    "direct_round_spread": 0.0,
                    "proxied_round_spread": 0.0,
                    "maximum_round_spread": 0.2,
                    "minimum_proxy_to_direct_ratio": 0.9,
                    "estimated_observer_cpu_ns_per_message": 100.0,
                    "observer": {
                        "qualification": True,
                        "expected": messages * 4,
                        "verified": messages * 4,
                        "missing": 0,
                        "duplicates": 0,
                    },
                    "proxy": {
                        "accepted_connections": concurrency * 4,
                        "completed_connections": concurrency * 4,
                        "failed_connections": 0,
                        "active_connections": 0,
                        "peak_connections": concurrency,
                        "pump_buffer_bytes": 64 * 1024,
                        "configured_max_connections": concurrency,
                        "backend_reply_block_limit_bytes": 128 * 1024,
                        "accounted_backend_reply_buffer_bytes": 128 * 1024,
                        "memory_permit_quantum_bytes": 64 * 1024,
                        "memory_budget_bytes": memory_budget_bytes,
                        "usable_memory_budget_bytes": memory_budget_bytes,
                        "required_memory_budget_bytes": required_memory_budget_bytes,
                        "memory_budget_headroom_bytes": (
                            memory_budget_bytes - required_memory_budget_bytes
                        ),
                        "accounted_connection_bytes": accounted_connection_bytes,
                        "observer_round_reserve_bytes": observer_round_reserve_bytes,
                        "control_runtime_reserve_bytes": control_runtime_reserve_bytes,
                    },
                    "qualification": True,
                }
                raw["control_proxy"] = json.loads(json.dumps(raw["proxy"]))
                raw_sha = runner._canonical_json_sha256(raw)
                gate_messages, gate_concurrency = {
                    "1KB": (24_000, 1_500),
                    "10KB": (8_000, 1_000),
                    "10MB": (100, 20),
                }[label]
                gate_proxy = json.loads(json.dumps(raw["proxy"]))
                gate_proxy["configured_max_connections"] = gate_concurrency
                gate_proxy["required_memory_budget_bytes"] = (
                    accounted_connection_bytes * gate_concurrency
                    + observer_round_reserve_bytes
                    + control_runtime_reserve_bytes
                )
                gate_proxy["memory_budget_headroom_bytes"] = (
                    gate_proxy["usable_memory_budget_bytes"]
                    - gate_proxy["required_memory_budget_bytes"]
                )
                gate_duration_ns = gate_messages * 1_000_000

                def gate_round(
                    mode: str, ordinal: int, sequence_index: int
                ) -> dict[str, Any]:
                    persistence: dict[str, Any] = {
                        "required": mode == "on",
                        "proxy_clock_domain": "observer_origin_elapsed",
                        "status": "disabled",
                        "gate_id": None,
                        "triggered_at_proxy_monotonic_ns": None,
                        "release_received_at_proxy_monotonic_ns": None,
                        "forwarding_started_at_proxy_monotonic_ns": None,
                        "forwarding_completed_at_proxy_monotonic_ns": None,
                        "gate_hold_ns": None,
                        "snapshot": None,
                        "qualified": True,
                    }
                    if mode == "on":
                        persistence.update(
                            {
                                "status": "forwarded",
                                "gate_id": ordinal + 1,
                                "triggered_at_proxy_monotonic_ns": 1_000,
                                "release_received_at_proxy_monotonic_ns": 2_000,
                                "forwarding_started_at_proxy_monotonic_ns": 2_100,
                                "forwarding_completed_at_proxy_monotonic_ns": 2_200,
                                "gate_hold_ns": 1_000,
                                "snapshot": {
                                    "clock_id": "CLOCK_MONOTONIC",
                                    "snapshot_started_monotonic_ns": 1,
                                    "snapshot_completed_monotonic_ns": 2,
                                    "postgres_query_duration_ns": 0,
                                    "maildir_snapshot_duration_ns": 0,
                                    "transaction_isolation": "repeatable_read",
                                    "transaction_read_only": True,
                                    "postgres_before_rows": 0,
                                    "postgres_rows": gate_messages,
                                    "postgres_expected_rows": gate_messages,
                                    "postgres_row_delta": gate_messages,
                                    "expected_messages": gate_messages,
                                    "maildir_atomic_rename_publications": gate_messages,
                                    "qualified": True,
                                },
                            }
                        )
                    return {
                        "mode": mode,
                        "mode_ordinal": ordinal,
                        "sequence_index": sequence_index,
                        "measurement": {
                            "messages": gate_messages,
                            "message_bytes": message_bytes,
                            "duration_ns": gate_duration_ns,
                            "messages_per_second": 1_000.0,
                            "process_scheduled_cpu_ns": gate_duration_ns // 2,
                        },
                        "observer": {
                            "qualification": True,
                            "expected": gate_messages,
                            "verified": gate_messages,
                            "missing": 0,
                            "duplicates": 0,
                            "persistence_gate": persistence,
                        },
                        "proxy": json.loads(json.dumps(gate_proxy)),
                    }

                sequence = ["off", "on", "on", "off", "on", "off", "off", "on"]
                off_rounds = [
                    gate_round("off", ordinal, sequence_index)
                    for ordinal, sequence_index in enumerate(
                        index for index, mode in enumerate(sequence) if mode == "off"
                    )
                ]
                on_rounds = [
                    gate_round("on", ordinal, sequence_index)
                    for ordinal, sequence_index in enumerate(
                        index for index, mode in enumerate(sequence) if mode == "on"
                    )
                ]
                median_measurement = {
                    "messages": gate_messages,
                    "message_bytes": message_bytes,
                    "duration_ns": gate_duration_ns,
                    "messages_per_second": 1_000.0,
                    "process_scheduled_cpu_ns": gate_duration_ns // 2,
                }
                gate = {
                    "schema_version": 2,
                    "profile": "lmyzmail-persistence-gate-overhead-calibration-v2",
                    "qualification_basis": "direct-gate-timing",
                    "synthetic_no_postgres_or_maildir": True,
                    "messages": gate_messages,
                    "message_bytes": message_bytes,
                    "concurrency": gate_concurrency,
                    "rounds_per_mode": 4,
                    "sequence": sequence,
                    "off_rounds": off_rounds,
                    "on_rounds": on_rounds,
                    "off_median": median_measurement,
                    "on_median": median_measurement,
                    "off_round_spread": 0.0,
                    "on_round_spread": 0.0,
                    "median_on_to_off_ratio": 1.0,
                    "paired_on_to_off_ratios": [1.0] * 4,
                    "maximum_round_spread": 0.01,
                    "minimum_median_on_to_off_ratio": 0.995,
                    "minimum_paired_on_to_off_ratio": 0.99,
                    "observed_maximum_gate_hold_fraction": 1_000 / gate_duration_ns,
                    "maximum_gate_hold_fraction": 0.01,
                    "observed_maximum_release_to_forwarding_ns": 100,
                    "maximum_release_to_forwarding_ns": 5_000_000,
                    "observed_maximum_forwarding_ns": 100,
                    "maximum_forwarding_ns": 1_000_000,
                    "binding": {
                        "common": {
                            "runner_sha256": runner_sha256,
                            "binary_sha256": binary_sha256,
                            "source_tree_sha256": source_tree_sha256,
                            "host_boot_id": environment["host_boot_id"],
                            "benchmark_cpu": environment["benchmark_cpu"],
                            "calibration_cpus": environment["calibration_cpus"],
                            "cgroup_parent": environment["cgroup_parent"],
                            "process_cgroup": environment["process_cgroup"],
                            "io_max_sha256": environment["io_max_sha256"],
                            "nofile_soft_and_hard": environment["nofile_soft_and_hard"],
                        },
                        "tier": label,
                        "message_bytes": message_bytes,
                        "messages": gate_messages,
                        "concurrency": gate_concurrency,
                    },
                    "qualification": True,
                }
                gate_sha = runner._canonical_json_sha256(gate)
                hashes[label] = runner._canonical_json_sha256(
                    {
                        "raw_calibration_sha256": raw_sha,
                        "gate_overhead_calibration_sha256": gate_sha,
                    }
                )
                tiers[label] = {
                    "message_bytes": message_bytes,
                    "messages_per_round": messages,
                    "concurrency": concurrency,
                    "rounds_per_arm": 4,
                    "sustained_messages_per_second": 1_800.0,
                    "raw_calibration_schema_version": 4,
                    "raw_calibration_sha256": raw_sha,
                    "raw_calibration": raw,
                    "gate_overhead_calibration_schema_version": 2,
                    "gate_overhead_calibration_sha256": gate_sha,
                    "gate_overhead_calibration": gate,
                    "passed": True,
                }
            proxy = {
                "attestation_started_at_unix_seconds": now - 2,
                "attestation_completed_at_unix_seconds": now - 1,
                "environment": environment,
                "tiers": tiers,
                "calibration_bundle_sha256": runner._canonical_json_sha256(hashes),
                "max_active_connections": 1_500,
                "runner_sha256": runner_sha256,
                "binary_sha256": binary_sha256,
                "source_tree_sha256": source_tree_sha256,
                "minimum_product_headroom_ratio": 2.0,
                "semantic_transparency_passed": True,
                "passed": True,
            }
            self.assertEqual(
                proxy["environment"]["nofile_required"],
                4 * proxy["max_active_connections"] + 512,
            )
            runner._validate_proxy_headroom_raw(
                proxy, layout=layout, started_attestation=started_attestation
            )

            mutations = {
                "cross host": lambda value: value["environment"].__setitem__(
                    "host_boot_id", "ffffffff-ffff-4fff-8fff-ffffffffffff"
                ),
                "cross cgroup": lambda value: value["environment"].__setitem__(
                    "process_cgroup", str(parent.resolve())
                ),
                "stale": lambda value: value.__setitem__(
                    "attestation_completed_at_unix_seconds", now - 901
                ),
                "low rlimit": lambda value: value["environment"].__setitem__(
                    "nofile_soft_and_hard", 6_511
                ),
                "active below 1500": lambda value: value.__setitem__(
                    "max_active_connections", 1_499
                ),
                "tampered raw": lambda value: value["tiers"]["10KB"]["raw_calibration"][
                    "proxied_rounds"
                ][0].__setitem__("messages_per_second", 9_999.0),
                "control connection count": lambda value: value["tiers"]["10KB"][
                    "raw_calibration"
                ]["control_proxy"].__setitem__("completed_connections", 3_999),
                "control active connection": lambda value: value["tiers"]["10KB"][
                    "raw_calibration"
                ]["control_proxy"].__setitem__("active_connections", 1),
                "control memory accounting": lambda value: value["tiers"]["10KB"][
                    "raw_calibration"
                ]["control_proxy"].__setitem__("required_memory_budget_bytes", 1),
                "reply block limit": lambda value: value["tiers"]["10KB"][
                    "raw_calibration"
                ]["proxy"].__setitem__("backend_reply_block_limit_bytes", 64 * 1024),
                "reply buffer accounting": lambda value: value["tiers"]["10KB"][
                    "raw_calibration"
                ]["proxy"].__setitem__(
                    "accounted_backend_reply_buffer_bytes", 64 * 1024
                ),
                "required proxy memory": lambda value: value["tiers"]["10KB"][
                    "raw_calibration"
                ]["proxy"].__setitem__("required_memory_budget_bytes", 1),
            }
            for label, mutate in mutations.items():
                with self.subTest(label=label):
                    changed = json.loads(json.dumps(proxy))
                    mutate(changed)
                    with self.assertRaises(RuntimeError):
                        runner._validate_proxy_headroom_raw(
                            changed,
                            layout=layout,
                            started_attestation=started_attestation,
                        )

    def test_io_max_parser_accepts_only_exact_bandwidth_and_unlimited_iops(
        self,
    ) -> None:
        devices = {"7:0", "7:1"}
        self.assertTrue(
            runner._io_max_lines_match_fixed_limits(
                [
                    "7:0 rbps=500000000 wbps=500000000",
                    "7:1 rbps=500000000 wbps=500000000",
                ],
                devices=devices,
                bytes_per_second=500_000_000,
            )
        )
        self.assertTrue(
            runner._io_max_lines_match_fixed_limits(
                [
                    "7:0 rbps=500000000 wbps=500000000 riops=max wiops=max",
                    "7:1 wbps=500000000 wiops=max rbps=500000000 riops=max",
                ],
                devices=devices,
                bytes_per_second=500_000_000,
            )
        )
        for lines in (
            [
                "7:0 rbps=500000000 wbps=500000000 riops=1 wiops=max",
                "7:1 rbps=500000000 wbps=500000000",
            ],
            [
                "7:0 rbps=500000000 wbps=500000000 extra=max",
                "7:1 rbps=500000000 wbps=500000000",
            ],
            [
                "7:0 rbps=500000000 wbps=500000000",
                "7:0 rbps=500000000 wbps=500000000",
            ],
            [
                "7:0 rbps=500000000 wbps=499999999",
                "7:1 rbps=500000000 wbps=500000000",
            ],
        ):
            self.assertFalse(
                runner._io_max_lines_match_fixed_limits(
                    lines,
                    devices=devices,
                    bytes_per_second=500_000_000,
                )
            )

    def test_rust_proxy_rejects_binary_hash_change_before_spawn(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "proxy"
            binary.write_bytes(b"proxy")
            runtime = SimpleNamespace(
                workspace=root,
                ports=SimpleNamespace(smtp=2525),
            )
            with self.assertRaisesRegex(RuntimeError, "binary changed"):
                runner.RustSmtpProxy(
                    runtime,
                    binary=binary,
                    expected_sha256="0" * 64,
                    run_id="identity-test",
                )

    def test_user_namespace_attestation_rejects_mapped_user_owner(self) -> None:
        metadata = SimpleNamespace(
            st_uid=0,
            st_gid=0,
            st_mode=stat.S_IFREG | 0o444,
            st_nlink=1,
        )
        with self.assertRaisesRegex(RuntimeError, "host-root-owned"):
            runner._validate_external_metadata(
                metadata,
                expected_uid=65_534,
                expected_gid=65_534,
                kind="file",
            )

        metadata.st_uid = 65_534
        metadata.st_gid = 65_534
        runner._validate_external_metadata(
            metadata,
            expected_uid=65_534,
            expected_gid=65_534,
            kind="file",
        )
        self.assertFalse(runner._host_id_is_mapped("0 1000 1\n", 0))
        self.assertTrue(runner._host_id_is_mapped("0 0 1\n", 0))

    def test_external_attestation_rejects_lexical_parent_escape(self) -> None:
        digest = "a" * 64
        path = Path("/run/lmyzmail-benchmark-attestations/../") / f"{digest}.json"
        with self.assertRaisesRegex(RuntimeError, "direct content-addressed child"):
            runner._external_prerequisites(
                path=path,
                expected_sha256=digest,
                plans=[],
                disk_budget_bytes=20 * 1024**3,
                layout=SimpleNamespace(),
                started_attestation={},
            )


class LogEvidenceTests(unittest.TestCase):
    def test_extracts_valid_coordinator_observer_snapshots(self) -> None:
        record = {
            "schema": "lmyzmail.coordinator-stage-observation.v1",
            "sequence": 1,
            "pid": 123,
            "completed_tasks": 256,
            "completed_total_ns": 10_000,
            "completed_max_ns": 100,
            "stages": {
                "database_claim": {"count": 256, "total_ns": 2_000, "max_ns": 20}
            },
        }
        payload = (
            runner.COORDINATOR_OBSERVER_PREFIX
            + json.dumps(record, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "application.log"
            path.write_bytes(payload)
            metadata = path.stat()
            evidence = runner._log_evidence(
                runner.LogCursor(path, 0, metadata.st_dev, metadata.st_ino)
            )
        self.assertTrue(evidence["parse_complete"])
        self.assertEqual(evidence["coordinator_observer_record_count"], 1)
        self.assertEqual(evidence["coordinator_observer_parse_failure_count"], 0)
        self.assertEqual(evidence["coordinator_observer_last"], record)

    def test_malformed_coordinator_observer_snapshot_fails_closed(self) -> None:
        payload = (runner.COORDINATOR_OBSERVER_PREFIX + "{}\n").encode()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "application.log"
            path.write_bytes(payload)
            metadata = path.stat()
            evidence = runner._log_evidence(
                runner.LogCursor(path, 0, metadata.st_dev, metadata.st_ino)
            )
        self.assertFalse(evidence["parse_complete"])
        self.assertEqual(evidence["coordinator_observer_record_count"], 0)
        self.assertEqual(evidence["coordinator_observer_parse_failure_count"], 1)

    def test_streams_the_complete_log_and_extracts_structured_endpoint_counters(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "application.log"
            path.write_bytes(b"")
            metadata = path.stat()
            cursor = runner.LogCursor(path, 0, metadata.st_dev, metadata.st_ino)
            counter = (
                b"[RESULT] Actually Queued: 7 (success=7, failed=0, "
                b"exceptions=0, oom=0, rateLimited=0)\n"
                b"[RESULT] Received: 7\n"
            )
            payload = b"ordinary log line\n" * 150_000 + counter
            path.write_bytes(payload)

            evidence = runner._log_evidence(cursor)

        self.assertGreater(len(payload), 2 * 1024 * 1024)
        self.assertEqual(evidence["bytes"], len(payload))
        self.assertEqual(evidence["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertTrue(evidence["parse_complete"])
        self.assertFalse(evidence["truncated"])
        self.assertEqual(evidence["queue_counter_match_count"], 1)
        self.assertEqual(evidence["queue_counter_records"][0]["queued"], 7)
        self.assertEqual(evidence["received_counter_match_count"], 1)
        self.assertEqual(evidence["received_counter_records"], [7])
        self.assertTrue(
            any("Actually Queued: 7" in line for line in evidence["result_lines"])
        )

    def test_forbidden_delivery_warnings_are_counted_without_truncation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "application.log"
            warning = (
                b"WARN No DKIM configuration for domain: lmyz.net. "
                b"Returning unsigned message.\n"
            )
            async_drop = (
                b"WARN Async drop: email rejected after verification: "
                b"unauthenticated use of local RFC5322.From domain lmyz.net.\n"
            )
            path.write_bytes(warning + async_drop)
            metadata = path.stat()
            evidence = runner._log_evidence(
                runner.LogCursor(path, 0, metadata.st_dev, metadata.st_ino)
            )
        self.assertTrue(evidence["parse_complete"])
        self.assertEqual(evidence["missing_dkim_configuration_line_count"], 1)
        self.assertEqual(
            evidence["missing_dkim_configuration_lines"], [warning.decode().strip()]
        )
        self.assertEqual(evidence["async_drop_line_count"], 1)
        self.assertEqual(evidence["async_drop_lines"], [async_drop.decode().strip()])

    def test_oversized_or_rotated_log_is_not_qualification_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "application.log"
            path.write_bytes(b"")
            metadata = path.stat()
            cursor = runner.LogCursor(path, 0, metadata.st_dev, metadata.st_ino)
            path.write_bytes(b"x" * (64 * 1024 + 1) + b"\n")
            evidence = runner._log_evidence(cursor)
        self.assertFalse(evidence["parse_complete"])
        self.assertTrue(evidence["truncated"])
        self.assertEqual(evidence["line_overflow_count"], 1)

    def test_endpoint_outcome_requires_counters_complete_log_and_zero_retries(
        self,
    ) -> None:
        capture = {
            "expected": 7,
            "verified": 7,
            "missing": 0,
            "failures": [],
            "retry_responses": 0,
            "smtp_final_replies": {"success": 7},
            "qualification": True,
        }
        cleanup = {
            "final": _clean_state(),
            "stable_polls": runner.STATE_STABLE_POLLS,
            "semantic_sha256": "a" * 64,
            "database_delta": {
                "passed": True,
                "persistence_audit_observed": True,
            },
        }
        log = {
            "queue_counter_records": [
                {
                    "queued": 7,
                    "success": 7,
                    "failed": 0,
                    "exceptions": 0,
                    "oom": 0,
                    "rate_limited": 0,
                }
            ],
            "queue_counter_match_count": 1,
            "received_counter_records": [7],
            "received_counter_match_count": 1,
            "failure_lines": [],
            "failure_line_count": 0,
            "parse_complete": True,
            "truncated": False,
        }
        resource = {
            "queue_peak": 1,
            "application_persistence_io_observed": True,
            "services_persistence_io_observed": True,
        }
        passed = runner._endpoint_outcome(capture, resource, cleanup, log)
        self.assertTrue(passed["passed"])
        self.assertTrue(passed["queue_counter_contract_passed"])

        fsync_off_resource = {
            **resource,
            "application_persistence_io_observed": False,
            "application_persistence_io_sources": {
                "cgroup_observed": False,
                "process_observed": True,
                "observed": True,
            },
        }
        fsync_off = runner._endpoint_outcome(
            capture,
            fsync_off_resource,
            cleanup,
            log,
            application_io_requirement="process-write-with-fsync-disabled",
        )
        self.assertTrue(fsync_off["passed"])
        self.assertEqual(
            fsync_off["application_persistence_io_requirement"],
            "process-write-with-fsync-disabled",
        )

        for mutation in (
            "retry",
            "missing_counters",
            "truncated",
            "missing_dkim",
            "async_drop",
            "missing_received",
        ):
            changed_capture = dict(capture)
            changed_log = dict(log)
            if mutation == "retry":
                changed_capture["retry_responses"] = 1
            elif mutation == "missing_counters":
                changed_log["queue_counter_records"] = []
                changed_log["queue_counter_match_count"] = 0
            elif mutation == "truncated":
                changed_log["parse_complete"] = False
                changed_log["truncated"] = True
            elif mutation == "missing_dkim":
                changed_log["missing_dkim_configuration_line_count"] = 1
            elif mutation == "missing_received":
                changed_log["received_counter_records"] = []
                changed_log["received_counter_match_count"] = 0
            else:
                changed_log["async_drop_line_count"] = 1
            outcome = runner._endpoint_outcome(
                changed_capture,
                resource,
                cleanup,
                changed_log,
            )
            self.assertFalse(outcome["passed"], mutation)


class ArtifactCapabilityTests(unittest.TestCase):
    def test_launcher_uuid_is_strict_canonical_uuid4(self) -> None:
        self.assertEqual(runner._canonical_uuid4(LAUNCHER_RUN_ID), LAUNCHER_RUN_ID)
        for invalid in (
            LAUNCHER_RUN_ID.upper(),
            "12345678-1234-1234-9234-123456789abc",
            "not-a-uuid",
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(argparse.ArgumentTypeError):
                    runner._canonical_uuid4(invalid)

    def test_json_and_checkpoint_are_written_only_through_descriptors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output_path = root / "root-private-output"
            checkpoint_path = root / "root-private-checkpoint"
            binary = getattr(os, "O_BINARY", 0)
            output_fd = os.open(
                output_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | binary
            )
            checkpoint_fd = os.open(
                checkpoint_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | binary
            )
            try:
                value = {"status": "passed", "launcher_run_id": LAUNCHER_RUN_ID}
                runner._write_json_fd(output_fd, value)
                self.assertEqual(
                    runner._sha256_fd(output_fd),
                    hashlib.sha256(output_path.read_bytes()).hexdigest(),
                )

                logical_path = root / "inaccessible" / "logical.running.jsonl"
                checkpoint = runner.Checkpoint(logical_path, descriptor=checkpoint_fd)
                checkpoint.append(
                    {
                        "event": "started",
                        "run_id": "runner-id",
                        "launcher_run_id": LAUNCHER_RUN_ID,
                    }
                )
                checkpoint.append(
                    {
                        "event": "completed",
                        "run_id": "runner-id",
                        "launcher_run_id": LAUNCHER_RUN_ID,
                    }
                )
                checkpoint.close()
                checkpoint_fd = -1
                records = [
                    json.loads(line)
                    for line in checkpoint_path.read_text(encoding="utf-8").splitlines()
                ]
                self.assertFalse(logical_path.exists())
                self.assertEqual(records[-1]["event"], "completed")
                self.assertEqual(records[-1]["launcher_run_id"], LAUNCHER_RUN_ID)
                self.assertEqual(
                    records[-1]["_previous_record_sha256"],
                    records[0]["_record_sha256"],
                )
            finally:
                os.close(output_fd)
                if checkpoint_fd >= 0:
                    os.close(checkpoint_fd)

    def test_capabilities_become_cloexec_after_namespace_reexec(self) -> None:
        metadata = [
            SimpleNamespace(
                st_mode=stat.S_IFREG | 0o600, st_nlink=1, st_dev=1, st_ino=10
            ),
            SimpleNamespace(
                st_mode=stat.S_IFREG | 0o600, st_nlink=1, st_dev=1, st_ino=11
            ),
        ]
        fake_fcntl = ModuleType("fcntl")
        fake_fcntl.F_GETFL = 3  # type: ignore[attr-defined]
        fake_fcntl.fcntl = mock.Mock(return_value=os.O_RDWR)  # type: ignore[attr-defined]
        with (
            mock.patch.dict(sys.modules, {"fcntl": fake_fcntl}),
            mock.patch.object(runner.os, "fstat", side_effect=metadata),
            mock.patch.object(runner.os, "O_ACCMODE", 3, create=True),
            mock.patch.object(runner.os, "set_inheritable") as set_inheritable,
            mock.patch.object(runner.os, "get_inheritable", return_value=False),
        ):
            runner._seal_artifact_capabilities(8, 9)
        self.assertEqual(
            set_inheritable.call_args_list,
            [mock.call(8, False), mock.call(9, False)],
        )
        with self.assertRaisesRegex(RuntimeError, "must be distinct"):
            runner._seal_artifact_capabilities(8, 8)

        alias = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600, st_nlink=1, st_dev=1, st_ino=10
        )
        with (
            mock.patch.dict(sys.modules, {"fcntl": fake_fcntl}),
            mock.patch.object(runner.os, "fstat", side_effect=[alias, alias]),
            mock.patch.object(runner.os, "O_ACCMODE", 3, create=True),
            mock.patch.object(runner.os, "set_inheritable"),
            mock.patch.object(runner.os, "get_inheritable", return_value=False),
        ):
            with self.assertRaisesRegex(RuntimeError, "alias one inode"):
                runner._seal_artifact_capabilities(8, 9)

        source = RUNNER_PATH.read_text(encoding="utf-8")
        main = source[source.index("def main() -> int:") :]
        self.assertLess(
            main.index("_enter_isolated_namespace()"),
            main.index("_seal_artifact_capabilities"),
        )
        self.assertLess(
            main.index("_seal_artifact_capabilities"),
            main.index("CgroupLayout.from_environment()"),
        )

    def test_success_path_finishes_checkpoint_with_both_run_ids(self) -> None:
        class Dns:
            port = 5353

            def __init__(self, material: runner.BenchmarkDkimMaterial):
                self.material = material

            def close(self) -> None:
                return None

            def attestation(self) -> dict[str, Any]:
                return {
                    "passed": True,
                    "dkim": {
                        "public_key_spki_sha256": self.material.public_key_spki_sha256
                    },
                    "dkim_txt_query_count": 4,
                    "dmarc_txt_query_count": 4,
                }

        comparison = {
            "all_passed": True,
            "zero_retry_gate_passed": True,
            "pair_completeness_passed": True,
            "arm_completeness_passed": True,
            "proxy_headroom_passed": True,
            "comparisons": [],
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output_path = root / "output-capability"
            checkpoint_path = root / "checkpoint-capability"
            logical_output = root / "logical-output.json"
            binary = getattr(os, "O_BINARY", 0)
            output_fd = os.open(
                output_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | binary
            )
            checkpoint_fd = os.open(
                checkpoint_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | binary
            )
            args = SimpleNamespace(
                disk_budget_gib=5.0,
                smoke=True,
                tier="all",
                target="both",
                output=logical_output,
                output_fd=output_fd,
                checkpoint_fd=checkpoint_fd,
                launcher_run_id=LAUNCHER_RUN_ID,
                external_prerequisites=None,
                external_prerequisites_sha256=None,
            )
            layout = SimpleNamespace(
                snapshot=lambda: {"passed": True}, io_bytes_per_second=500_000_000
            )
            try:
                with (
                    mock.patch.object(runner, "_plans", return_value=[]),
                    mock.patch.object(runner, "REPOSITORY", root),
                    mock.patch.object(
                        runner,
                        "_targets",
                        return_value=("java-oracle", "rust-candidate"),
                    ),
                    mock.patch.object(
                        runner, "_resolve_output", return_value=logical_output
                    ),
                    mock.patch.object(
                        runner,
                        "_attestation",
                        return_value={"isolation_policy": {"passed": True}},
                    ),
                    mock.patch.object(
                        runner,
                        "_external_prerequisites",
                        return_value={
                            "passed": True,
                            "quota_mount_root": str(root),
                            "proxy_headroom": {},
                        },
                    ),
                    mock.patch.object(runner.tempfile, "gettempdir", return_value=root),
                    mock.patch.object(runner, "_qualified", return_value=True),
                    mock.patch.object(runner, "_execution_matrix", return_value=[]),
                    mock.patch.object(runner, "BenchmarkDnsServer", Dns),
                    mock.patch.object(
                        runner, "_verify_definition_attestation", return_value={}
                    ),
                    mock.patch.object(runner, "_comparison", return_value=comparison),
                    mock.patch.object(runner, "_hardware_evidence", return_value={}),
                ):
                    result = runner._run_benchmark(args, layout)
                checkpoint_fd = -1
                records = [
                    json.loads(line)
                    for line in checkpoint_path.read_text(encoding="utf-8").splitlines()
                ]
                self.assertEqual(result["status"], "passed")
                self.assertEqual(records[0]["event"], "started")
                self.assertEqual(records[-1]["event"], "completed")
                self.assertEqual(records[0]["run_id"], records[-1]["run_id"])
                self.assertEqual(records[0]["launcher_run_id"], LAUNCHER_RUN_ID)
                self.assertEqual(records[-1]["launcher_run_id"], LAUNCHER_RUN_ID)
                self.assertEqual(
                    records[-1]["output_sha256"],
                    hashlib.sha256(output_path.read_bytes()).hexdigest(),
                )
            finally:
                os.close(output_fd)
                if checkpoint_fd >= 0:
                    try:
                        os.close(checkpoint_fd)
                    except OSError:
                        pass

    def test_java_small_success_path_writes_two_single_call_tiers(self) -> None:
        class Dns:
            port = 5353

            def __init__(self, material: runner.BenchmarkDkimMaterial):
                self.material = material

            def close(self) -> None:
                return None

            def attestation(self) -> dict[str, Any]:
                return {
                    "passed": True,
                    "dkim": {
                        "public_key_spki_sha256": self.material.public_key_spki_sha256
                    },
                    "dkim_txt_query_count": 4,
                    "dmarc_txt_query_count": 4,
                }

        def run_target(
            target: str,
            plan: runner.BenchmarkPlan,
            _layout: object,
            *,
            arm_ordinal: int,
            **kwargs: object,
        ) -> dict[str, Any]:
            self.assertEqual(kwargs["quota_mount_root"], root)
            measurement = _round_record(measured=True)
            measurement["endpoint_start_invocation_count"] = 1
            measurement["endpoint_start_automatic_retries"] = 0
            measurement["endpoint_outcome"]["failure_count"] = 0
            return {
                "target": target,
                "tier": {
                    "label": plan.label,
                    "message_bytes": plan.message_bytes,
                    "total_messages": plan.total_messages,
                },
                "arm_ordinal": arm_ordinal,
                "measurement": measurement,
                "endpoint_start_invocations": 1,
                "endpoint_invocations": 1,
                "harness_batches": 0,
                "endpoint_requested_messages": plan.total_messages,
                "observer_verified_messages": plan.total_messages,
                "requested_equals_observer_verified": True,
                "throughput_messages_per_second": (
                    1_000.0 if plan.label == "1KB" else 1_500.0
                ),
            }

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output_path = root / "output-capability"
            checkpoint_path = root / "checkpoint-capability"
            logical_output = root / "logical-output.json"
            binary = getattr(os, "O_BINARY", 0)
            output_fd = os.open(
                output_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | binary
            )
            checkpoint_fd = os.open(
                checkpoint_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | binary
            )
            args = SimpleNamespace(
                profile="java-small",
                disk_budget_gib=20.0,
                smoke=False,
                tier="all",
                target="java",
                output=logical_output,
                output_fd=output_fd,
                checkpoint_fd=checkpoint_fd,
                launcher_run_id=LAUNCHER_RUN_ID,
                external_prerequisites=None,
                external_prerequisites_sha256=None,
            )
            layout = SimpleNamespace(
                snapshot=lambda: {"passed": True}, io_bytes_per_second=500_000_000
            )
            try:
                with (
                    mock.patch.object(runner, "REPOSITORY", root),
                    mock.patch.object(
                        runner, "_resolve_output", return_value=logical_output
                    ),
                    mock.patch.object(
                        runner,
                        "_attestation",
                        return_value={"isolation_policy": {"passed": True}},
                    ),
                    mock.patch.object(
                        runner,
                        "_external_prerequisites",
                        return_value={"provided": False, "passed": False},
                    ),
                    mock.patch.object(runner.tempfile, "gettempdir", return_value=root),
                    mock.patch.object(runner, "BenchmarkDnsServer", Dns),
                    mock.patch.object(
                        runner, "_run_target_tier", side_effect=run_target
                    ),
                    mock.patch.object(
                        runner, "_verify_definition_attestation", return_value={}
                    ),
                    mock.patch.object(runner, "_hardware_evidence", return_value={}),
                ):
                    result = runner._run_benchmark(args, layout)
                checkpoint_fd = -1
                records = [
                    json.loads(line)
                    for line in checkpoint_path.read_text(encoding="utf-8").splitlines()
                ]
                self.assertEqual(result["status"], "passed")
                self.assertFalse(result["qualified"])
                self.assertEqual(result["profile"], runner.JAVA_SMALL_BASELINE_PROFILE)
                self.assertEqual(
                    result["endpoint_requested_messages"], [200_000, 200_000]
                )
                self.assertEqual(
                    result["observer_verified_messages"], [200_000, 200_000]
                )
                self.assertEqual(
                    [entry["tier"] for entry in result["execution_order"]],
                    ["1KB", "10KB"],
                )
                self.assertTrue(result["acceptance"]["java_small_baseline"])
                self.assertTrue(result["acceptance"]["ten_megabyte_excluded"])
                self.assertEqual(
                    records[0]["benchmark_profile"],
                    runner.JAVA_SMALL_BASELINE_PROFILE,
                )
                self.assertEqual(
                    records[0]["java_stress_runtime_profile"],
                    runner._java_frozen_stress_profile(),
                )
                self.assertEqual(
                    result["methodology"]["java_stress_runtime_profile"],
                    runner._java_frozen_stress_profile(),
                )
                self.assertEqual(records[-1]["event"], "completed")
            finally:
                os.close(output_fd)
                if checkpoint_fd >= 0:
                    try:
                        os.close(checkpoint_fd)
                    except OSError:
                        pass


class CheckpointTests(unittest.TestCase):
    def test_records_form_a_sha256_hash_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "checkpoint.jsonl"
            checkpoint = runner.Checkpoint(path)
            checkpoint.append({"event": "started", "payload": {"n": 1}})
            checkpoint.append({"event": "finished", "ok": True})
            checkpoint.close()

            records = [
                json.loads(line)
                for line in path.read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual([record["_sequence"] for record in records], [0, 1])
        self.assertIsNone(records[0]["_previous_record_sha256"])
        self.assertEqual(
            records[1]["_previous_record_sha256"], records[0]["_record_sha256"]
        )
        for record in records:
            unsigned = {
                key: value for key, value in record.items() if key != "_record_sha256"
            }
            canonical = json.dumps(
                unsigned, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            self.assertEqual(
                record["_record_sha256"], hashlib.sha256(canonical).hexdigest()
            )

    def test_finalization_failure_is_recorded_without_replacing_primary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "checkpoint.jsonl"
            checkpoint = runner.Checkpoint(path)
            checkpoint.append({"event": "started"})

            def fail() -> None:
                raise ValueError("primary finalization failure")

            with self.assertRaisesRegex(ValueError, "primary finalization failure"):
                runner._checkpointed_finalization(
                    checkpoint,
                    "run-id",
                    "test_phase",
                    fail,
                )
            self.assertEqual(checkpoint.descriptor, -1)
            records = [
                json.loads(line)
                for line in path.read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(records[-1]["event"], "finalization_failed")
        self.assertEqual(records[-1]["phase"], "test_phase")
        self.assertEqual(records[-1]["error"]["type"], "ValueError")

    def test_complete_checkpoint_is_create_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "evidence.running.jsonl"
            destination = root / "evidence.complete.jsonl"
            source.write_bytes(b"new")
            destination.write_bytes(b"existing")
            with self.assertRaises(FileExistsError):
                runner._complete_checkpoint_noreplace(source, destination)
            self.assertEqual(source.read_bytes(), b"new")
            self.assertEqual(destination.read_bytes(), b"existing")

            destination.unlink()
            runner._complete_checkpoint_noreplace(source, destination)
            self.assertFalse(source.exists())
            self.assertEqual(destination.read_bytes(), b"new")
            self.assertEqual(destination.stat().st_nlink, 1)

    def test_complete_checkpoint_rejects_inode_change_after_hardlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "evidence.running.jsonl"
            destination = root / "evidence.complete.jsonl"
            source.write_bytes(b"new")
            real_lstat = Path.lstat
            source_calls = 0

            def changed_lstat(path: Path) -> Any:
                nonlocal source_calls
                metadata = real_lstat(path)
                if path == source:
                    source_calls += 1
                    if source_calls == 2:
                        return SimpleNamespace(
                            st_dev=metadata.st_dev,
                            st_ino=metadata.st_ino + 1,
                            st_nlink=metadata.st_nlink,
                        )
                return metadata

            with mock.patch.object(Path, "lstat", changed_lstat):
                with self.assertRaisesRegex(RuntimeError, "identity changed"):
                    runner._complete_checkpoint_noreplace(source, destination)
            self.assertTrue(source.exists())
            self.assertTrue(destination.exists())

    def test_complete_checkpoint_rejects_source_replacement_before_link(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "evidence.running.jsonl"
            destination = root / "evidence.complete.jsonl"
            displaced = root / "evidence.displaced.jsonl"
            source.write_bytes(b"original")
            real_link = os.link

            def replace_then_link(
                link_source: str | os.PathLike[str],
                link_destination: str | os.PathLike[str],
                *,
                src_dir_fd: int | None = None,
                dst_dir_fd: int | None = None,
                follow_symlinks: bool = True,
            ) -> None:
                source.replace(displaced)
                source.write_bytes(b"replacement")
                real_link(
                    link_source,
                    link_destination,
                    src_dir_fd=src_dir_fd,
                    dst_dir_fd=dst_dir_fd,
                    follow_symlinks=follow_symlinks,
                )

            with mock.patch.object(os, "link", replace_then_link):
                with self.assertRaisesRegex(RuntimeError, "identity changed"):
                    runner._complete_checkpoint_noreplace(source, destination)
            self.assertEqual(displaced.read_bytes(), b"original")
            self.assertEqual(source.read_bytes(), b"replacement")
            self.assertEqual(destination.read_bytes(), b"replacement")

    def test_definition_attestation_binds_v2_v1_and_loaded_blackbox_helpers(
        self,
    ) -> None:
        attestation = runner._definition_attestation()
        paths = {entry["path"] for entry in attestation["source_files"]}
        self.assertIn("evidence/compatibility/smtp-self-stress-v2.py", paths)
        self.assertIn("evidence/compatibility/smtp-self-stress-v1.py", paths)
        self.assertIn("evidence/performance/smtp-endpoint-throughput-v1.py", paths)
        self.assertIn("evidence/performance/run-smtp-endpoint-throughput-v1.sh", paths)
        self.assertIn("blackbox/src/lmyzmail_blackbox/runtime.py", paths)
        self.assertIn("blackbox/src/lmyzmail_blackbox/ports.py", paths)
        self.assertIn("blackbox/fixtures/legacy/postgres-schema.sql", paths)
        self.assertIn("blackbox/fixtures/legacy/redis-seed.json", paths)
        self.assertIn("config/lmyzmail.properties.example", paths)
        self.assertIn(
            "evidence/freeze/java-oracle/application.properties.redacted", paths
        )
        self.assertIn("crates/lmyzmail-benchmark-proxy/Cargo.toml", paths)
        self.assertIn("crates/lmyzmail-benchmark-proxy/src/proxy.rs", paths)
        self.assertFalse(
            any("__pycache__" in path or path.endswith(".pyc") for path in paths)
        )
        self.assertEqual(len(attestation["sha256"]), 64)
        proxy_source = attestation["benchmark_proxy_source_tree"]
        self.assertGreater(proxy_source["source_file_count"], 0)
        self.assertEqual(len(proxy_source["sha256"]), 64)

    def test_target_artifact_rejects_after_run_sha_change(self) -> None:
        expected = "a" * 64
        attestation = {
            "candidate_release_sha256": expected,
            "java_oracle_sha256": "b" * 64,
        }
        with mock.patch.object(runner, "_sha256_file", return_value=expected):
            before = runner._verify_target_artifact(
                "rust-candidate", attestation, "before"
            )
        self.assertTrue(before["unchanged"])

        with mock.patch.object(runner, "_sha256_file", return_value="c" * 64):
            with self.assertRaisesRegex(RuntimeError, "changed after"):
                runner._verify_target_artifact("rust-candidate", attestation, "after")

    def test_target_artifact_uses_only_fixed_attested_candidate_paths(self) -> None:
        expected = "a" * 64
        profiling_relative = runner.CANDIDATE_PROFILING_RELEASE.relative_to(
            runner.REPOSITORY
        ).as_posix()
        attestation = {
            "candidate_release_path": profiling_relative,
            "candidate_release_sha256": expected,
        }
        with mock.patch.object(runner, "_sha256_file", return_value=expected) as digest:
            verified = runner._verify_target_artifact(
                "rust-candidate", attestation, "before"
            )
        digest.assert_called_once_with(runner.CANDIDATE_PROFILING_RELEASE)
        self.assertEqual(verified["path"], profiling_relative)

        attestation["candidate_release_path"] = "target/attacker/lmyzmail"
        with self.assertRaisesRegex(RuntimeError, "not an allowed fixed artifact"):
            runner._verify_target_artifact("rust-candidate", attestation, "before")


class RoundContractTests(unittest.TestCase):
    def test_gate_off_round_uses_same_endpoint_without_snapshot_transaction(
        self,
    ) -> None:
        proxy = mock.Mock()
        proxy.finish.return_value = {
            "round": 1,
            "duration_ns": 6_000_000_000,
            "duration_seconds": 6.0,
            "throughput_messages_per_second": 2.0,
            "data_throughput_mib_per_second": 1.0,
            "within_arm_throughput_stability": {"passed": True},
            "final_250_boundary": {"completed_at_monotonic_ns": 100},
            "persistence_gate": {
                "required": False,
                "proxy_clock_domain": "observer_origin_elapsed",
                "status": "disabled",
                "gate_id": None,
                "triggered_at_proxy_monotonic_ns": None,
                "release_received_at_proxy_monotonic_ns": None,
                "forwarding_started_at_proxy_monotonic_ns": None,
                "forwarding_completed_at_proxy_monotonic_ns": None,
                "gate_hold_ns": None,
                "snapshot": None,
                "qualified": True,
            },
        }
        cleanup = {
            "final": _clean_state(),
            "stable_polls": 3,
            "semantic_sha256": "a" * 64,
            "database_delta": {"passed": True},
        }
        postgres = mock.Mock()
        with (
            mock.patch.object(
                runner, "MaildirPersistenceObserver", _FakeMaildirObserver
            ),
            mock.patch.object(runner, "PostgresPersistenceGateSnapshot", postgres),
            mock.patch.object(runner, "_cleanup_state", return_value=_clean_state()),
            mock.patch.object(
                runner,
                "_wait_for_delivery_database_visibility",
                return_value={"passed": True},
            ),
            mock.patch.object(runner, "_log_cursor", return_value=(Path("log"), 0)),
            mock.patch.object(
                runner, "_start_round", return_value={"body": {"round": 1}}
            ),
            mock.patch.object(
                runner, "_establish_persistence_barrier", return_value={"passed": True}
            ),
            mock.patch.object(runner, "_apply_persistence_completion_timing"),
            mock.patch.object(
                runner, "_wait_for_automatic_cleanup", return_value=cleanup
            ),
            mock.patch.object(runner, "_log_evidence", return_value={}),
            mock.patch.object(
                runner,
                "_endpoint_outcome",
                return_value=_round_record(measured=False)["endpoint_outcome"],
            ),
        ):
            result = runner._run_round(
                object(),
                proxy,
                object(),
                mode="PRODUCTION",
                count=2,
                message_bytes=1024,
                disk_budget_bytes=1024**3,
                measured=False,
                persistence_gate_required=False,
            )
        postgres.assert_not_called()
        proxy.wait_for_persistence_gate.assert_not_called()
        proxy.release_persistence_gate.assert_not_called()
        self.assertFalse(proxy.begin.call_args.kwargs["persistence_gate_required"])
        self.assertEqual(result["persistence_gate_mode"], "off")
        self.assertFalse(
            result["persistence_barrier"]["pre_final_persistence_snapshot_performed"]
        )

    def test_maildir_publication_observer_performs_no_writes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receiver = root / runner.ENDPOINT_RECEIVER / "inbox"
            receiver.mkdir(parents=True)
            message = receiver / "published.eml"
            message.write_bytes(b"Subject: passive\r\n\r\nbody\r\n")
            observer = runner.MaildirPersistenceObserver.__new__(
                runner.MaildirPersistenceObserver
            )
            observer.expected_messages = 1
            observer.root = root
            observer.receiver_root = receiver
            observer.published = 0
            observer.removed = 0
            observer.close_write_events = 0
            observer.peak_live_files = 0
            observer.publication_mechanisms = {}
            observer.removed_paths = set()
            observer.event_digest = hashlib.sha256()
            message.unlink()
            with (
                mock.patch.object(
                    runner.os,
                    "open",
                    side_effect=AssertionError("observer opened a message"),
                ) as open_message,
                mock.patch.object(
                    runner.os, "fsync", side_effect=AssertionError("observer wrote")
                ) as fsync,
                mock.patch.object(
                    runner,
                    "_fsync_directory",
                    side_effect=AssertionError("observer wrote a directory"),
                ) as fsync_directory,
            ):
                observer._observe_publication(message)
            evidence = observer._evidence(require_cleanup=False)
        open_message.assert_not_called()
        fsync.assert_not_called()
        fsync_directory.assert_not_called()
        self.assertEqual(evidence["observer_write_syscalls"], 0)
        self.assertTrue(evidence["observer_writes_prohibited"])
        self.assertTrue(evidence["passed"])

    def test_v2_mailbox_path_matches_rust_address_contract(self) -> None:
        expected = "v2/c-7374726573732D7265636569766572406C6D797A2E6E6574/z-00000018"
        self.assertEqual(
            runner._v2_mailbox_relative_path(runner.ENDPOINT_RECEIVER).as_posix(),
            expected,
        )
        self.assertEqual(
            runner.v2._v2_mailbox_relative_path(runner.ENDPOINT_RECEIVER).as_posix(),
            expected,
        )

    def test_maildir_observer_initialization_is_passive_and_layout_specific(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            maildir = workspace / "maildir"
            maildir.mkdir()
            initial_entries = tuple(maildir.rglob("*"))
            layouts = {
                "java-raw": (
                    maildir / runner.ENDPOINT_RECEIVER / "inbox",
                    maildir / runner.ENDPOINT_SENDER / "sent",
                ),
                "lmyzmail-v2": (
                    maildir
                    / runner._v2_mailbox_relative_path(runner.ENDPOINT_RECEIVER)
                    / "inbox",
                    maildir
                    / runner._v2_mailbox_relative_path(runner.ENDPOINT_SENDER)
                    / "sent",
                ),
            }
            for layout, (expected_receiver, expected_sender) in layouts.items():
                runtime = SimpleNamespace(
                    workspace=workspace,
                    benchmark_maildir_address_layout=layout,
                )
                observer = runner.MaildirPersistenceObserver(
                    runtime, expected_messages=1
                )
                try:
                    self.assertEqual(observer.receiver_root, expected_receiver)
                    self.assertEqual(observer.sender_root, expected_sender)
                    self.assertEqual(
                        observer._scope_for_path(expected_sender / "1" / "message.eml"),
                        f"{runner.ENDPOINT_SENDER}/sent",
                    )
                    self.assertIsNone(
                        observer._scope_for_path(
                            expected_sender
                            / "1"
                            / ".lmyzmail-quarantine"
                            / ".lmyzmail-stage-test.tmp"
                        )
                    )
                    self.assertEqual(tuple(maildir.rglob("*")), initial_entries)
                finally:
                    observer.stop()

    def test_maildir_observer_tracks_real_v2_atomic_publish_and_cleanup(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            maildir = workspace / "maildir"
            staging = maildir / ".lmyzmail-inbound"
            receiver = (
                maildir
                / runner._v2_mailbox_relative_path(runner.ENDPOINT_RECEIVER)
                / "inbox"
            )
            sender = (
                maildir
                / runner._v2_mailbox_relative_path(runner.ENDPOINT_SENDER)
                / "sent"
            )
            staging.mkdir(parents=True)
            receiver.mkdir(parents=True)
            sender.mkdir(parents=True)
            runtime = SimpleNamespace(
                workspace=workspace,
                benchmark_maildir_address_layout="lmyzmail-v2",
            )
            observer = runner.MaildirPersistenceObserver(runtime, expected_messages=1)
            evidence: dict[str, Any] | None = None
            try:
                staged = staging / ".lmyzmail-inbound-test.tmp"
                published = receiver / "published.eml"
                sent_staged = staging / ".lmyzmail-sent-test.tmp"
                sent_published = sender / "sent.eml"
                staged.write_bytes(b"Subject: atomic\r\n\r\nbody\r\n")
                sent_staged.write_bytes(b"Subject: sent\r\n\r\nbody\r\n")
                staged.rename(published)
                sent_staged.rename(sent_published)
                observer.wait_for_publications(5.0)
                published.unlink()
                sent_published.unlink()
                observer.wait_for_removals(5.0)
            finally:
                evidence = observer.stop()
            self.assertIsNotNone(evidence)
            assert evidence is not None
            self.assertEqual(
                evidence["profile"], "lmyzmail-maildir-inotify-publication-v8"
            )
            self.assertEqual(evidence["atomic_rename_publications"], 2)
            self.assertEqual(evidence["receiver_inbox_publications"], 1)
            self.assertEqual(evidence["sender_sent_publications"], 1)
            self.assertEqual(evidence["direct_close_write_publications"], 0)
            self.assertEqual(evidence["directory_reconciled_publications"], 0)
            self.assertEqual(
                evidence["watch_scope_profile"],
                "target-mailbox-folders-only-v1",
            )
            self.assertTrue(evidence["unrelated_maildir_trees_excluded"])
            self.assertTrue(evidence["passed"])

    def test_maildir_observer_excludes_unrelated_high_churn_trees(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            maildir = workspace / "maildir"
            receiver = (
                maildir
                / runner._v2_mailbox_relative_path(runner.ENDPOINT_RECEIVER)
                / "inbox"
            )
            sender = (
                maildir
                / runner._v2_mailbox_relative_path(runner.ENDPOINT_SENDER)
                / "sent"
            )
            unrelated = (
                maildir / ".lmyzmail-outbound" / ".lmyzmail-quarantine" / "noise"
            )
            receiver.mkdir(parents=True)
            sender.mkdir(parents=True)
            unrelated.mkdir(parents=True)
            runtime = SimpleNamespace(
                workspace=workspace,
                benchmark_maildir_address_layout="lmyzmail-v2",
            )
            observer = runner.MaildirPersistenceObserver(runtime, expected_messages=1)
            try:
                watched = set(observer.watches.values())
                self.assertIn(maildir.resolve(), watched)
                self.assertIn(receiver.resolve(), watched)
                self.assertIn(sender.resolve(), watched)
                self.assertTrue(all(not path.is_relative_to(unrelated) for path in watched))
                self.assertFalse(observer._directory_is_relevant(unrelated))
                self.assertTrue(observer._directory_is_relevant(receiver / "1"))
            finally:
                observer.stop()

    def test_maildir_observer_tracks_profiler_scale_publish_delete_burst(self) -> None:
        message_count = 8192
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            maildir = workspace / "maildir"
            staging = maildir / ".lmyzmail-inbound"
            receiver = (
                maildir
                / runner._v2_mailbox_relative_path(runner.ENDPOINT_RECEIVER)
                / "inbox"
            )
            sender = (
                maildir
                / runner._v2_mailbox_relative_path(runner.ENDPOINT_SENDER)
                / "sent"
            )
            staging.mkdir(parents=True)
            receiver.mkdir(parents=True)
            sender.mkdir(parents=True)
            receiver_staged = [
                staging / f"receiver-{index}.eml" for index in range(message_count)
            ]
            sender_staged = [
                staging / f"sender-{index}.eml" for index in range(message_count)
            ]
            for path in (*receiver_staged, *sender_staged):
                path.touch()
            runtime = SimpleNamespace(
                workspace=workspace,
                benchmark_maildir_address_layout="lmyzmail-v2",
            )
            observer = runner.MaildirPersistenceObserver(
                runtime, expected_messages=message_count
            )
            evidence: dict[str, Any] | None = None
            try:
                published: list[Path] = []
                for index, (receiver_source, sender_source) in enumerate(
                    zip(receiver_staged, sender_staged, strict=True)
                ):
                    receiver_target = receiver / f"receiver-{index}.eml"
                    sender_target = sender / f"sender-{index}.eml"
                    receiver_source.rename(receiver_target)
                    sender_source.rename(sender_target)
                    published.extend((receiver_target, sender_target))
                observer.wait_for_publications(30.0)
                for path in published:
                    path.unlink()
                observer.wait_for_removals(30.0)
            finally:
                evidence = observer.stop()
            self.assertIsNotNone(evidence)
            assert evidence is not None
            self.assertEqual(evidence["publication_events"], message_count * 2)
            self.assertEqual(evidence["removal_events"], message_count * 2)
            self.assertEqual(evidence["inotify_overflow_events"], 0)
            self.assertTrue(evidence["passed"])

    def test_maildir_tree_installs_watch_before_directory_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            observer = runner.MaildirPersistenceObserver.__new__(
                runner.MaildirPersistenceObserver
            )
            observer.root = root
            events: list[tuple[str, Path]] = []
            original_scandir = runner.os.scandir

            def add_watch(path: Path) -> None:
                events.append(("watch", path.resolve(strict=True)))

            def scandir(path: Path) -> Any:
                events.append(("scan", Path(path).resolve(strict=True)))
                return original_scandir(path)

            with (
                mock.patch.object(observer, "_add_watch", side_effect=add_watch),
                mock.patch.object(runner.os, "scandir", side_effect=scandir),
            ):
                observer._add_tree(root)

        self.assertEqual(events, [("watch", root), ("scan", root)])

    def test_maildir_observer_handles_rapid_move_delete_and_cleanup_overflow(
        self,
    ) -> None:
        root = Path("/maildir")
        receiver = root / runner.ENDPOINT_RECEIVER / "inbox"
        observer = runner.MaildirPersistenceObserver.__new__(
            runner.MaildirPersistenceObserver
        )
        observer.expected_messages = 1
        observer.root = root
        observer.receiver_root = receiver
        observer.published = 0
        observer.removed = 0
        observer.close_write_events = 0
        observer.peak_live_files = 0
        observer.publication_mechanisms = {}
        observer.removed_paths = set()
        observer.event_digest = hashlib.sha256()
        observer.watches = {7: receiver}

        def event(mask: int, name: bytes = b"message.eml") -> bytes:
            padded = name + b"\0"
            padded += b"\0" * ((4 - len(padded) % 4) % 4)
            return observer._EVENT.pack(7, mask, 0, len(padded)) + padded

        with mock.patch.object(
            runner.os,
            "open",
            side_effect=AssertionError("event observer opened a file"),
        ) as open_message:
            observer._consume(event(observer._IN_MOVED_TO) + event(observer._IN_DELETE))
        open_message.assert_not_called()
        self.assertEqual(observer.published, 1)
        self.assertEqual(observer.removed, 1)
        self.assertTrue(observer._evidence(require_cleanup=True)["passed"])
        observer._consume(event(observer._IN_Q_OVERFLOW, b""))
        evidence = observer._evidence(require_cleanup=True)
        self.assertEqual(evidence["inotify_overflow_events"], 1)
        self.assertEqual(evidence["overflow_reconciliations"], 1)
        self.assertEqual(evidence["overflow_reconciled_removals"], 0)
        self.assertTrue(evidence["cleanup_overflow_recovery_read_only"])

    def test_maildir_observer_publication_overflow_still_fails_closed(self) -> None:
        root = Path("/maildir")
        receiver = root / runner.ENDPOINT_RECEIVER / "inbox"
        observer = runner.MaildirPersistenceObserver.__new__(
            runner.MaildirPersistenceObserver
        )
        observer.expected_messages = 1
        observer.root = root
        observer.receiver_root = receiver
        observer.published = 0
        observer.removed = 0
        observer.close_write_events = 0
        observer.peak_live_files = 0
        observer.publication_mechanisms = {}
        observer.publications_by_parent = {}
        observer.removed_paths = set()
        observer.event_digest = hashlib.sha256()
        observer.watches = {7: receiver}
        payload = observer._EVENT.pack(
            -1, observer._IN_Q_OVERFLOW, 0, 0
        )
        with self.assertRaisesRegex(RuntimeError, "before all publications"):
            observer._consume(payload)

    def test_maildir_observer_reconciles_missing_names_after_cleanup_overflow(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            receiver = root / runner.ENDPOINT_RECEIVER / "inbox"
            receiver.mkdir(parents=True)
            message = receiver / "message.eml"
            message.write_bytes(b"message")
            observer = runner.MaildirPersistenceObserver.__new__(
                runner.MaildirPersistenceObserver
            )
            observer.expected_messages = 1
            observer.root = root
            observer.receiver_root = receiver
            observer.published = 1
            observer.removed = 0
            observer.last_publication_monotonic_ns = runner.time.monotonic_ns()
            observer.close_write_events = 0
            observer.peak_live_files = 1
            relative = message.relative_to(root).as_posix()
            parent = message.parent.relative_to(root).as_posix()
            observer.publication_mechanisms = {relative: "atomic_rename"}
            observer.publications_by_parent = {parent: {relative}}
            observer.removed_paths = set()
            observer.event_digest = hashlib.sha256()
            observer.watches = {7: receiver}
            message.unlink()

            payload = observer._EVENT.pack(-1, observer._IN_Q_OVERFLOW, 0, 0)
            observer._consume(payload)
            evidence = observer._evidence(require_cleanup=True)

        self.assertEqual(evidence["removal_events"], 1)
        self.assertEqual(evidence["overflow_reconciled_removals"], 1)
        self.assertEqual(evidence["overflow_directory_scans"], 1)
        self.assertEqual(evidence["message_file_open_calls"], 0)
        self.assertEqual(evidence["message_file_stat_calls"], 0)
        self.assertTrue(evidence["passed"])

    def test_maildir_observer_handles_directory_self_removal_without_isdir(
        self,
    ) -> None:
        root = Path("/maildir")
        receiver = root / runner.ENDPOINT_RECEIVER / "inbox"
        shard = receiver / "1"
        message = shard / "message.eml"
        observer = runner.MaildirPersistenceObserver.__new__(
            runner.MaildirPersistenceObserver
        )
        observer.expected_messages = 1
        observer.root = root
        observer.receiver_root = receiver
        observer.published = 1
        observer.removed = 0
        observer.last_publication_monotonic_ns = runner.time.monotonic_ns()
        observer.close_write_events = 0
        observer.peak_live_files = 1
        relative = message.relative_to(root).as_posix()
        observer.publication_mechanisms = {relative: "atomic_rename"}
        observer.publications_by_parent = {
            shard.relative_to(root).as_posix(): {relative}
        }
        observer.removed_paths = set()
        observer.event_digest = hashlib.sha256()
        observer.watches = {7: shard}
        event = observer._EVENT.pack(
            7,
            observer._IN_DELETE_SELF | observer._IN_IGNORED,
            0,
            0,
        )

        observer._consume(event)

        self.assertEqual(observer.removed, 1)
        self.assertNotIn(7, observer.watches)
        self.assertTrue(observer._evidence(require_cleanup=True)["passed"])

    def test_maildir_tree_removal_does_not_scan_unrelated_publications(self) -> None:
        class NoIterationDict(dict[str, str]):
            def __iter__(self) -> Any:
                raise AssertionError("tree removal scanned every publication")

        root = Path("/maildir")
        receiver = root / runner.ENDPOINT_RECEIVER / "inbox"
        first = receiver / "1" / "first.eml"
        second = receiver / "2" / "second.eml"
        observer = runner.MaildirPersistenceObserver.__new__(
            runner.MaildirPersistenceObserver
        )
        observer.root = root
        observer.receiver_root = receiver
        observer.publication_mechanisms = NoIterationDict(
            {
                first.relative_to(root).as_posix(): "atomic_rename",
                second.relative_to(root).as_posix(): "atomic_rename",
            }
        )
        observer.publications_by_parent = {
            first.parent.relative_to(root).as_posix(): {
                first.relative_to(root).as_posix()
            },
            second.parent.relative_to(root).as_posix(): {
                second.relative_to(root).as_posix()
            },
        }
        observer.removed_paths = set()
        observer.removed = 0
        observer.event_digest = hashlib.sha256()

        observer._observe_tree_removal(first.parent)

        self.assertEqual(observer.removed_paths, {first.relative_to(root).as_posix()})
        self.assertIn(
            second.parent.relative_to(root).as_posix(),
            observer.publications_by_parent,
        )

    def test_maildir_observer_distinguishes_direct_and_reconciled_publication(
        self,
    ) -> None:
        root = Path("/maildir")
        receiver = root / runner.ENDPOINT_RECEIVER / "inbox"
        observer = runner.MaildirPersistenceObserver.__new__(
            runner.MaildirPersistenceObserver
        )
        observer.expected_messages = 3
        observer.root = root
        observer.receiver_root = receiver
        observer.published = 0
        observer.removed = 0
        observer.close_write_events = 0
        observer.peak_live_files = 0
        observer.publication_mechanisms = {}
        observer.removed_paths = set()
        observer.event_digest = hashlib.sha256()
        observer.watches = {7: receiver}

        def event(mask: int, name: bytes) -> bytes:
            padded = name + b"\0"
            padded += b"\0" * ((4 - len(padded) % 4) % 4)
            return observer._EVENT.pack(7, mask, 0, len(padded)) + padded

        observer._consume(event(observer._IN_CREATE, b"hard-linked.eml"))
        observer._consume(
            event(observer._IN_CREATE, b"direct.eml")
            + event(observer._IN_CLOSE_WRITE, b"direct.eml")
        )
        observer._observe_publication(
            receiver / "reconciled.eml",
            mechanism="directory_reconciliation",
        )
        evidence = observer._evidence(require_cleanup=False)
        self.assertEqual(evidence["publication_events"], 3)
        self.assertEqual(evidence["atomic_rename_publications"], 0)
        self.assertEqual(evidence["visible_create_publications"], 1)
        self.assertEqual(evidence["direct_close_write_publications"], 1)
        self.assertEqual(evidence["directory_reconciled_publications"], 1)
        self.assertFalse(evidence["atomic_only_publication_observed"])
        self.assertTrue(evidence["passed"])

    def test_timed_persistence_barrier_requires_exact_passive_maildir_count(
        self,
    ) -> None:
        before = _clean_state()
        database = json.loads(json.dumps(before["database"]))
        database["tables"]["email_index"].update(
            {
                "rows": 4,
                "groups": {
                    f"{runner.ENDPOINT_RECEIVER}/inbox": 2,
                    f"{runner.ENDPOINT_SENDER}/sent": 2,
                },
            }
        )
        database["tables"]["outbound_mail_queue"].update(
            {"rows": 2, "groups": {"SENT": 2}}
        )
        database["email_index_mutations"].update({"n_tup_ins": 4})
        cleanup_state = _clean_state()
        cleanup_state["database"]["tables"]["outbound_mail_queue"].update(
            {"rows": 2, "groups": {"SENT": 2}}
        )
        cleanup_state["database"]["email_index_mutations"].update(
            {"n_tup_ins": 4, "n_tup_del": 4}
        )
        cleanup = {
            "database_delta": runner._automatic_cleanup_delta(before, cleanup_state, 2),
            "final": cleanup_state,
        }
        log = {
            "received_counter_records": [2],
            "received_counter_match_count": 1,
        }
        capture = {
            "qualification": True,
            "expected": 2,
            "verified": 2,
            "smtp_final_replies": {"success": 2},
        }
        maildir = {
            "passed": True,
            "publication_events": 4,
            "atomic_rename_publications": 4,
            "publication_counts_by_mailbox_folder": {
                f"{runner.ENDPOINT_RECEIVER}/inbox": 2,
                f"{runner.ENDPOINT_SENDER}/sent": 2,
            },
            "observer_write_syscalls": 0,
            "observer_writes_prohibited": True,
        }
        with (
            mock.patch.object(
                runner, "_database_snapshot", return_value=database
            ) as database_snapshot,
            mock.patch.object(
                runner, "_postgres_persistence_barrier", return_value={"passed": True}
            ),
            mock.patch.object(
                runner, "_redis_persistence_barrier", return_value={"passed": True}
            ),
        ):
            evidence = runner._establish_persistence_barrier(
                object(),
                before=before,
                capture=capture,
                maildir=maildir,
                cleanup=cleanup,
                log=log,
                expected_messages=2,
            )
            self.assertTrue(evidence["passed"])
            self.assertTrue(evidence["automatic_cleanup_excluded_from_timing"])
            self.assertEqual(
                evidence["exact_counts"][
                    "postgres_receiver_inbox_rows_at_transient_snapshot"
                ],
                2,
            )
            self.assertEqual(
                evidence["exact_counts"][
                    "postgres_sender_sent_rows_at_transient_snapshot"
                ],
                2,
            )
            self.assertEqual(
                evidence["exact_counts"][
                    "postgres_total_index_rows_at_transient_snapshot"
                ],
                4,
            )
            self.assertEqual(
                evidence["email_index_evidence_mode"], "transient_exact_snapshot"
            )
            self.assertEqual(evidence["database_visibility_polls"], 1)

            lagged_database = json.loads(json.dumps(database))
            lagged_database["tables"]["email_index"].update({"rows": 0, "groups": {}})
            database_snapshot.side_effect = [lagged_database, database]
            delayed = runner._establish_persistence_barrier(
                object(),
                before=before,
                capture=capture,
                maildir=maildir,
                cleanup=cleanup,
                log=log,
                expected_messages=2,
                timeout_seconds=1.0,
            )
            self.assertTrue(delayed["passed"])
            self.assertEqual(delayed["database_visibility_polls"], 2)
            self.assertGreaterEqual(delayed["database_visibility_wait_millis"], 0)
            database_snapshot.side_effect = None
            database_snapshot.return_value = database

            with self.assertRaisesRegex(RuntimeError, "did not prove exact"):
                runner._establish_persistence_barrier(
                    object(),
                    before=before,
                    capture=capture,
                    maildir={**maildir, "publication_events": 1},
                    cleanup=cleanup,
                    log=log,
                    expected_messages=2,
                )
            with self.assertRaisesRegex(RuntimeError, "did not prove exact"):
                runner._establish_persistence_barrier(
                    object(),
                    before=before,
                    capture=capture,
                    maildir={**maildir, "observer_write_syscalls": 1},
                    cleanup=cleanup,
                    log=log,
                    expected_messages=2,
                )
            wrong_folder = json.loads(json.dumps(database))
            wrong_folder["tables"]["email_index"]["groups"] = {
                f"{runner.ENDPOINT_RECEIVER}/inbox": 2,
                f"{runner.ENDPOINT_SENDER}/drafts": 2,
            }
            database_snapshot.return_value = wrong_folder
            lifecycle = runner._establish_persistence_barrier(
                object(),
                before=before,
                capture=capture,
                maildir=maildir,
                cleanup=cleanup,
                log=log,
                expected_messages=2,
                timeout_seconds=0,
            )
            self.assertEqual(
                lifecycle["email_index_evidence_mode"],
                "committed_lifecycle_counters",
            )
            broken_cleanup = json.loads(json.dumps(cleanup))
            broken_cleanup["database_delta"]["email_index_mutation_evidence"][
                "passed"
            ] = False
            with self.assertRaisesRegex(RuntimeError, "did not prove exact"):
                runner._establish_persistence_barrier(
                    object(),
                    before=before,
                    capture=capture,
                    maildir=maildir,
                    cleanup=broken_cleanup,
                    log=log,
                    expected_messages=2,
                    timeout_seconds=0,
                )

    def test_postgresql_barrier_waits_for_wal_flush_without_checkpoint(self) -> None:
        connection = mock.Mock()

        def execute(statement: str, _parameters: object = None) -> mock.Mock:
            cursor = mock.Mock()
            if statement.startswith("SHOW "):
                cursor.fetchone.return_value = ("on",)
            elif "pg_current_wal_insert_lsn" in statement:
                cursor.fetchone.return_value = ("0/20",)
            elif "pg_current_wal_flush_lsn" in statement:
                cursor.fetchone.return_value = ("0/20", True)
            return cursor

        connection.execute.side_effect = execute
        context = mock.MagicMock()
        context.__enter__.return_value = connection
        with mock.patch.object(
            runner.base.psycopg, "connect", return_value=context, create=True
        ):
            evidence = runner._postgres_persistence_barrier(
                SimpleNamespace(ports=SimpleNamespace(postgres=15432))
            )
        statements = [str(call.args[0]) for call in connection.execute.call_args_list]
        self.assertTrue(evidence["flush_reached_arm_end"])
        self.assertFalse(evidence["forced_checkpoint"])
        self.assertFalse(any("CHECKPOINT" in statement for statement in statements))

        connection.execute.side_effect = lambda statement, _parameters=None: (
            mock.Mock(fetchone=mock.Mock(return_value=("off",)))
            if statement == "SHOW fsync"
            else execute(statement, _parameters)
        )
        with mock.patch.object(
            runner.base.psycopg, "connect", return_value=context, create=True
        ):
            with self.assertRaisesRegex(RuntimeError, "WAL flush"):
                runner._postgres_persistence_barrier(
                    SimpleNamespace(ports=SimpleNamespace(postgres=15432))
                )

    def test_redis_barrier_uses_waitaof_and_rejects_pending_fsync(self) -> None:
        client = mock.Mock()
        persistence = {
            "aof_enabled": 1,
            "aof_pending_bio_fsync": 0,
            "aof_rewrite_in_progress": 0,
            "rdb_bgsave_in_progress": 0,
            "rdb_last_bgsave_status": "ok",
        }
        client.info.return_value = persistence
        client.execute_command.return_value = [1, 0]
        with mock.patch.object(runner.base.redis, "Redis", return_value=client):
            evidence = runner._redis_persistence_barrier(
                SimpleNamespace(ports=SimpleNamespace(redis=16379))
            )
        client.execute_command.assert_called_once_with("WAITAOF", 1, 0, 30_000)
        self.assertTrue(evidence["passed"])
        self.assertFalse(evidence["forced_save"])

        client.info.return_value = {
            **persistence,
            "aof_pending_bio_fsync": 1,
        }
        with mock.patch.object(runner.base.redis, "Redis", return_value=client):
            with self.assertRaisesRegex(RuntimeError, "pending disk work"):
                runner._redis_persistence_barrier(
                    SimpleNamespace(ports=SimpleNamespace(redis=16379))
                )

    def test_postgres_gate_uses_one_repeatable_read_snapshot_and_never_repolls(
        self,
    ) -> None:
        connection = mock.Mock()
        cursor = mock.Mock()
        cursor.fetchone.return_value = (1,)
        connection.execute.side_effect = [mock.Mock(), cursor]
        runtime = SimpleNamespace(ports=SimpleNamespace(postgres=15432))
        with mock.patch.object(
            runner.base.psycopg, "connect", return_value=connection, create=True
        ):
            snapshot = runner.PostgresPersistenceGateSnapshot(
                runtime,
                before_rows=0,
                expected_messages=2,
            )
            evidence = snapshot.capture()
            cursor.fetchone.return_value = (2,)
            snapshot.close()
        self.assertFalse(evidence["qualified"])
        self.assertEqual(evidence["postgres_rows"], 1)
        self.assertEqual(connection.execute.call_count, 2)
        self.assertEqual(
            connection.execute.call_args_list[0].args[0],
            "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY",
        )
        self.assertEqual(
            connection.execute.call_args_list[1].args[0],
            "SELECT count(*) FROM outbound_mail_queue",
        )
        connection.commit.assert_called_once_with()
        connection.rollback.assert_not_called()
        connection.close.assert_called_once_with()

    def test_persistence_audit_does_not_change_throughput_denominator(self) -> None:
        capture = {
            "duration_ns": 2_000_000_000,
            "duration_seconds": 2.0,
            "throughput_messages_per_second": 5.0,
            "data_throughput_mib_per_second": 3.0,
        }
        runner._apply_persistence_completion_timing(
            capture,
            started_monotonic=10.0,
            final_250_completed_monotonic=12.0,
            persistence_completed_monotonic=19.0,
            persistence_barrier={"passed": True},
        )
        self.assertEqual(capture["duration_seconds"], 2.0)
        self.assertEqual(capture["duration_ns"], 2_000_000_000)
        self.assertEqual(capture["throughput_messages_per_second"], 5.0)
        self.assertEqual(capture["data_throughput_mib_per_second"], 3.0)
        self.assertEqual(capture["persistence_audit_duration_seconds"], 7.0)
        self.assertEqual(
            capture["measurement_completion_boundary"], "final_250_forwarded"
        )
        self.assertTrue(
            capture["persistence_audit_excluded_from_throughput_denominator"]
        )

    def test_early_final_250_cannot_be_repaired_by_post_final_persistence(
        self,
    ) -> None:
        class EarlyObserver(_FakeMaildirObserver):
            def __init__(self, *args: object, expected_messages: int):
                super().__init__(*args, expected_messages=expected_messages)
                self.complete = False

            def snapshot(self) -> dict[str, Any]:
                evidence = super().snapshot()
                if not self.complete:
                    evidence["atomic_rename_publications"] = 1
                    evidence["publication_passed"] = False
                    evidence["passed"] = False
                return evidence

            def wait_for_publications(self, *_args: object) -> None:
                self.complete = True

        proxy = mock.Mock()
        _configure_proxy_gate(proxy, count=2)
        cleanup = {
            "final": _clean_state(),
            "stable_polls": 3,
            "semantic_sha256": "a" * 64,
            "database_delta": {"passed": True},
        }
        barrier = mock.Mock(return_value={"passed": True})
        with (
            mock.patch.object(runner, "MaildirPersistenceObserver", EarlyObserver),
            mock.patch.object(
                runner,
                "PostgresPersistenceGateSnapshot",
                _fake_postgres_gate_snapshot(2),
            ),
            mock.patch.object(runner, "_cleanup_state", return_value=_clean_state()),
            mock.patch.object(
                runner,
                "_wait_for_delivery_database_visibility",
                return_value={"passed": True},
            ),
            mock.patch.object(runner, "_log_cursor", return_value=(Path("log"), 0)),
            mock.patch.object(
                runner, "_start_round", return_value={"body": {"round": 1}}
            ),
            mock.patch.object(runner, "_establish_persistence_barrier", barrier),
            mock.patch.object(
                runner, "_wait_for_automatic_cleanup", return_value=cleanup
            ),
            mock.patch.object(runner, "_log_evidence", return_value={}),
        ):
            with self.assertRaisesRegex(RuntimeError, "persistence gate lacked exact"):
                runner._run_round(
                    object(),
                    proxy,
                    object(),
                    mode="PRODUCTION",
                    count=2,
                    message_bytes=1024,
                    disk_budget_bytes=1024**3,
                    measured=False,
                )
        barrier.assert_not_called()

    def test_late_postgres_commit_during_monitor_stop_cannot_qualify(self) -> None:
        events: list[str] = []

        class Monitor:
            def __init__(self, *_args: object, **_kwargs: object):
                pass

            def raise_if_failed(self) -> None:
                pass

            def stop(self) -> dict[str, Any]:
                events.append("late-postgres-commit")
                return _round_record(measured=True)["resource"]

        proxy = mock.Mock()
        _configure_proxy_gate(proxy, count=2)
        cleanup = {
            "final": _clean_state(),
            "stable_polls": 3,
            "semantic_sha256": "a" * 64,
            "database_delta": {"passed": True},
        }
        barrier = mock.Mock(return_value={"passed": True})
        with (
            mock.patch.object(
                runner, "MaildirPersistenceObserver", _FakeMaildirObserver
            ),
            mock.patch.object(
                runner,
                "PostgresPersistenceGateSnapshot",
                _fake_postgres_gate_snapshot(1),
            ),
            mock.patch.object(runner, "ResourceMonitor", Monitor),
            mock.patch.object(runner, "_cleanup_state", return_value=_clean_state()),
            mock.patch.object(
                runner,
                "_wait_for_delivery_database_visibility",
                return_value={"passed": True},
            ),
            mock.patch.object(runner, "_log_cursor", return_value=(Path("log"), 0)),
            mock.patch.object(
                runner, "_start_round", return_value={"body": {"round": 1}}
            ),
            mock.patch.object(runner, "_establish_persistence_barrier", barrier),
            mock.patch.object(
                runner, "_wait_for_automatic_cleanup", return_value=cleanup
            ),
            mock.patch.object(runner, "_log_evidence", return_value={}),
        ):
            with self.assertRaisesRegex(RuntimeError, "persistence gate lacked exact"):
                runner._run_round(
                    object(),
                    proxy,
                    object(),
                    mode="PRODUCTION",
                    count=2,
                    message_bytes=1024,
                    disk_budget_bytes=1024**3,
                    measured=True,
                )
        self.assertEqual(events, ["late-postgres-commit"])
        barrier.assert_not_called()

    def test_gate_hold_over_250ms_fails_even_when_exact_counts_match(self) -> None:
        proxy = mock.Mock()
        _configure_proxy_gate(
            proxy,
            count=50,
            gate_hold_ns=runner.MAXIMUM_PERSISTENCE_GATE_HOLD_NS + 1,
        )
        cleanup = {
            "final": _clean_state(),
            "stable_polls": 3,
            "semantic_sha256": "a" * 64,
            "database_delta": {"passed": True},
        }
        with (
            mock.patch.object(
                runner, "MaildirPersistenceObserver", _FakeMaildirObserver
            ),
            mock.patch.object(
                runner,
                "PostgresPersistenceGateSnapshot",
                _fake_postgres_gate_snapshot(50),
            ),
            mock.patch.object(runner, "_cleanup_state", return_value=_clean_state()),
            mock.patch.object(
                runner,
                "_wait_for_delivery_database_visibility",
                return_value={"passed": True},
            ),
            mock.patch.object(runner, "_log_cursor", return_value=(Path("log"), 0)),
            mock.patch.object(
                runner, "_start_round", return_value={"body": {"round": 1}}
            ),
            mock.patch.object(
                runner, "_wait_for_automatic_cleanup", return_value=cleanup
            ),
            mock.patch.object(runner, "_log_evidence", return_value={}),
        ):
            with self.assertRaisesRegex(RuntimeError, "causal qualification"):
                runner._run_round(
                    object(),
                    proxy,
                    object(),
                    mode="PRODUCTION",
                    count=50,
                    message_bytes=1024,
                    disk_budget_bytes=1024**3,
                    measured=False,
                )

    def test_cleanup_log_and_observer_shutdown_are_after_post_final_audit(self) -> None:
        events: list[str] = []

        class OrderedObserver(_FakeMaildirObserver):
            def wait_for_publications(self, *_args: object) -> None:
                events.append("maildir-visible")

            def snapshot(self) -> dict[str, Any]:
                events.append("maildir-snapshot")
                return super().snapshot()

            def wait_for_removals(self, *_args: object) -> None:
                events.append("maildir-cleanup-visible")

            def stop(self) -> dict[str, Any]:
                events.append("observer-stop")
                return super().stop()

        class OrderedMonitor:
            def __init__(self, *_args: object, **_kwargs: object):
                pass

            def raise_if_failed(self) -> None:
                pass

            def stop(self) -> dict[str, Any]:
                events.append("monitor-stop")
                return _round_record(measured=True)["resource"]

        proxy = mock.Mock()
        _configure_proxy_gate(proxy, count=2)
        finish = proxy.finish.side_effect
        proxy.finish.side_effect = lambda *_args: (
            events.append("final-250") or finish(*_args)
        )
        cleanup = {
            "final": _clean_state(),
            "stable_polls": 3,
            "semantic_sha256": "a" * 64,
            "database_delta": {"passed": True},
        }
        with (
            mock.patch.object(runner, "MaildirPersistenceObserver", OrderedObserver),
            mock.patch.object(
                runner,
                "PostgresPersistenceGateSnapshot",
                _fake_postgres_gate_snapshot(2),
            ),
            mock.patch.object(runner, "ResourceMonitor", OrderedMonitor),
            mock.patch.object(runner, "_cleanup_state", return_value=_clean_state()),
            mock.patch.object(
                runner,
                "_wait_for_delivery_database_visibility",
                return_value={"passed": True},
            ),
            mock.patch.object(runner, "_log_cursor", return_value=(Path("log"), 0)),
            mock.patch.object(
                runner, "_start_round", return_value={"body": {"round": 1}}
            ),
            mock.patch.object(
                runner,
                "_establish_persistence_barrier",
                side_effect=lambda *_args, **_kwargs: (
                    events.append("timed-barrier") or {"passed": True}
                ),
            ),
            mock.patch.object(
                runner,
                "_apply_persistence_completion_timing",
                side_effect=lambda *_args, **_kwargs: events.append("timing-applied"),
            ),
            mock.patch.object(
                runner,
                "_wait_for_automatic_cleanup",
                side_effect=lambda *_args, **_kwargs: (
                    events.append("cleanup") or cleanup
                ),
            ),
            mock.patch.object(
                runner,
                "_log_evidence",
                side_effect=lambda *_args: events.append("log") or {},
            ),
            mock.patch.object(
                runner,
                "_endpoint_outcome",
                return_value=_round_record(measured=True)["endpoint_outcome"],
            ),
        ):
            runner._run_round(
                object(),
                proxy,
                object(),
                mode="PRODUCTION",
                count=2,
                message_bytes=1024,
                disk_budget_bytes=1024**3,
                measured=True,
            )
        self.assertLess(events.index("final-250"), events.index("timed-barrier"))
        self.assertLess(events.index("final-250"), events.index("monitor-stop"))
        self.assertLess(events.index("monitor-stop"), events.index("maildir-visible"))
        self.assertLess(events.index("cleanup"), events.index("observer-stop"))
        self.assertLess(events.index("observer-stop"), events.index("timed-barrier"))
        self.assertLess(events.index("timed-barrier"), events.index("timing-applied"))

    def test_each_round_rehashes_definition_before_and_after(self) -> None:
        record = _round_record(measured=False)
        events: list[dict[str, Any]] = []

        def run_round(*_args: object, **kwargs: Any) -> dict[str, Any]:
            kwargs["invocation_event"]({"method": "POST", "path": "/api/stress/start"})
            return record

        with (
            mock.patch.object(
                runner,
                "_verify_definition_attestation",
                side_effect=[
                    {"sha256": "a" * 64, "unchanged": True},
                    {"sha256": "a" * 64, "unchanged": True},
                ],
            ) as verify,
            mock.patch.object(runner, "_run_round", side_effect=run_round),
        ):
            result = runner._run_attested_round(
                object(),
                object(),
                object(),
                target="rust-candidate",
                tier="10KB",
                phase="warmup",
                ordinal=0,
                mode="WARMUP",
                count=2,
                message_bytes=10 * 1024,
                disk_budget_bytes=20 * 1024**3,
                measured=False,
                started_attestation={},
                checkpoint_event=events.append,
                rust_filesystem_fsync="off",
            )
        self.assertEqual(verify.call_count, 2)
        self.assertEqual(
            [
                event["boundary"]
                for event in events
                if event["event"] == "round_definition_attestation"
            ],
            ["before", "after"],
        )
        self.assertEqual(events[1]["event"], "endpoint_start_attempt")
        self.assertTrue(
            all(event["rust_filesystem_fsync"] == "off" for event in events)
        )
        self.assertEqual(result["definition_attestation"]["before"]["sha256"], "a" * 64)

    def test_each_round_invokes_original_start_endpoint_exactly_once(self) -> None:
        events: list[str] = []
        proxy = mock.Mock()
        _configure_proxy_gate(proxy, count=500_000, round_number=7)
        release = proxy.release_persistence_gate.side_effect
        proxy.release_persistence_gate.side_effect = lambda *args, **kwargs: (
            events.append("gate-release") or release(*args, **kwargs)
        )
        start_response = {"body": {"round": 7}}
        cleanup = {
            "final": _clean_state(),
            "stable_polls": 3,
            "semantic_sha256": "a" * 64,
            "database_delta": {"passed": True},
        }
        with (
            mock.patch.object(
                runner, "MaildirPersistenceObserver", _FakeMaildirObserver
            ),
            mock.patch.object(
                runner,
                "PostgresPersistenceGateSnapshot",
                _fake_postgres_gate_snapshot(500_000),
            ),
            mock.patch.object(runner, "_cleanup_state", return_value=_clean_state()),
            mock.patch.object(
                runner,
                "_wait_for_delivery_database_visibility",
                return_value={"passed": True},
            ),
            mock.patch.object(runner, "_log_cursor", return_value=(Path("log"), 0)),
            mock.patch.object(
                runner,
                "_start_round",
                side_effect=lambda *_args, **_kwargs: (
                    events.append("post-sent") or start_response
                ),
            ) as start,
            mock.patch.object(
                runner,
                "_finish_start_round",
                side_effect=lambda pending: (events.append("response-read") or pending),
            ) as finish_start,
            mock.patch.object(
                runner, "_wait_for_automatic_cleanup", return_value=cleanup
            ),
            mock.patch.object(
                runner, "_log_evidence", return_value={"result_lines": []}
            ),
            mock.patch.object(
                runner,
                "_endpoint_outcome",
                return_value=_round_record(measured=False)["endpoint_outcome"],
            ),
            mock.patch.object(
                runner, "_establish_persistence_barrier", return_value={"passed": True}
            ),
            mock.patch.object(runner, "_apply_persistence_completion_timing"),
        ):
            result = runner._run_round(
                object(),
                proxy,
                object(),
                mode="PRODUCTION",
                count=500_000,
                message_bytes=10 * 1024,
                disk_budget_bytes=20 * 1024**3,
                measured=False,
            )
        start.assert_called_once()
        self.assertTrue(start.call_args.kwargs["defer_response"])
        finish_start.assert_called_once_with(start_response)
        self.assertLess(events.index("gate-release"), events.index("response-read"))
        proxy.begin.assert_called_once()
        proxy.finish.assert_called_once()
        self.assertTrue(result["single_start_invocation"])

    def test_measurement_clock_is_armed_after_monitor_ready_and_before_post(
        self,
    ) -> None:
        events: list[str] = []

        class FakeMonitor:
            def __init__(self, *_args: object, **_kwargs: object):
                events.append("monitor-ready")

            def raise_if_failed(self) -> None:
                pass

            def stop(self) -> dict[str, int]:
                return {
                    "queue_peak": 1,
                    "continuous_membership": True,
                    "io_accounting_calibration": {"passed": True},
                    "application_persistence_io_observed": True,
                    "services_persistence_io_observed": True,
                    "candidate_cpu_usage_seconds": 1.0,
                    "services_cpu_usage_seconds": 1.0,
                    "temperature": {"within_limit": True, "available": False},
                }

        proxy = mock.Mock()
        _configure_proxy_gate(proxy, count=8, round_number=7)
        proxy.begin.side_effect = lambda **_kwargs: events.append("proxy-armed")
        cleanup = {
            "final": _clean_state(),
            "stable_polls": 3,
            "semantic_sha256": "a" * 64,
            "database_delta": {"passed": True},
        }

        def start(*_args: object, **_kwargs: object) -> dict[str, Any]:
            events.append("post")
            return {"body": {"round": 7}}

        with (
            mock.patch.object(
                runner, "MaildirPersistenceObserver", _FakeMaildirObserver
            ),
            mock.patch.object(
                runner,
                "PostgresPersistenceGateSnapshot",
                _fake_postgres_gate_snapshot(8),
            ),
            mock.patch.object(runner, "ResourceMonitor", FakeMonitor),
            mock.patch.object(runner, "_cleanup_state", return_value=_clean_state()),
            mock.patch.object(
                runner,
                "_wait_for_delivery_database_visibility",
                return_value={"passed": True},
            ),
            mock.patch.object(runner, "_log_cursor", return_value=(Path("log"), 0)),
            mock.patch.object(runner, "_start_round", side_effect=start),
            mock.patch.object(
                runner, "_wait_for_automatic_cleanup", return_value=cleanup
            ),
            mock.patch.object(runner, "_log_evidence", return_value={}),
            mock.patch.object(
                runner,
                "_endpoint_outcome",
                return_value=_round_record(measured=True)["endpoint_outcome"],
            ),
            mock.patch.object(
                runner, "_establish_persistence_barrier", return_value={"passed": True}
            ),
            mock.patch.object(runner, "_apply_persistence_completion_timing"),
        ):
            runner._run_round(
                object(),
                proxy,
                object(),
                mode="PRODUCTION",
                count=8,
                message_bytes=10 * 1024,
                disk_budget_bytes=20 * 1024**3,
                measured=True,
            )
        self.assertEqual(events[:3], ["monitor-ready", "proxy-armed", "post"])

    def test_start_response_must_preserve_original_concurrency_and_mode(self) -> None:
        runtime = SimpleNamespace(ports=SimpleNamespace(http=8080))

        def response(max_concurrency: int, in_memory: bool) -> SimpleNamespace:
            return SimpleNamespace(
                status_code=200,
                body=json.dumps(
                    {
                        "round": 1,
                        "mode": "PRODUCTION",
                        "emailCount": 500_000,
                        "emailSizeKB": 10,
                        "maxConcurrency": max_concurrency,
                        "inMemoryMode": in_memory,
                    }
                ).encode("utf-8"),
            )

        with mock.patch.object(
            runner.base, "http_exchange", return_value=response(1_000, True)
        ):
            record = runner._start_round(
                runtime,
                expected_mode="PRODUCTION",
                expected_count=500_000,
                expected_size_kib=10,
            )
        self.assertEqual(record["body"]["maxConcurrency"], 1_000)
        self.assertEqual(record["invocation"]["maximum_attempts"], 1)
        self.assertEqual(record["invocation"]["automatic_retries"], 0)

        with mock.patch.object(
            runner.base, "http_exchange", return_value=response(999, True)
        ):
            with self.assertRaisesRegex(RuntimeError, "response contract changed"):
                runner._start_round(
                    runtime,
                    expected_mode="PRODUCTION",
                    expected_count=500_000,
                    expected_size_kib=10,
                )

    def test_deferred_start_sends_once_journals_once_and_closes_without_thread(
        self,
    ) -> None:
        runtime = SimpleNamespace(ports=SimpleNamespace(http=8080))
        stream = SimpleNamespace(sendall=mock.Mock(), sock=mock.Mock())
        invocations: list[dict[str, Any]] = []
        threads_before = {thread.ident for thread in threading.enumerate()}
        with mock.patch.object(
            runner.blackbox_protocols,
            "connect_bounded",
            return_value=stream,
        ) as connect:
            pending = runner._start_round(
                runtime,
                expected_mode="PRODUCTION",
                expected_count=500_000,
                expected_size_kib=10,
                invocation_event=invocations.append,
                defer_response=True,
            )
        self.assertIsInstance(pending, runner.PendingStartRound)
        connect.assert_called_once_with(
            "127.0.0.1",
            8080,
            timeout=runner.MEASUREMENT_TIMEOUT_SECONDS,
            max_received=8 * 1024 * 1024,
        )
        stream.sendall.assert_called_once()
        request = stream.sendall.call_args.args[0]
        self.assertEqual(request.count(b"POST /api/stress/start HTTP/1.1"), 1)
        self.assertIn(b"X-API-Key: blackbox-admin-key\r\n", request)
        self.assertEqual(invocations, [pending.invocation])
        self.assertEqual(pending.invocation["attempt"], 1)
        self.assertEqual(pending.invocation["automatic_retries"], 0)
        self.assertEqual(
            {thread.ident for thread in threading.enumerate()}, threads_before
        )
        pending.close()
        pending.close()
        stream.sock.shutdown.assert_called_once_with(socket.SHUT_RDWR)
        stream.sock.close.assert_called_once()
        self.assertTrue(pending.completed)

    def test_uncertain_start_result_is_attempted_once_and_fails_closed(self) -> None:
        runtime = SimpleNamespace(ports=SimpleNamespace(http=8080))
        exchange = mock.Mock(side_effect=TimeoutError("response was uncertain"))
        events: list[dict[str, Any]] = []
        with mock.patch.object(runner.base, "http_exchange", exchange):
            with self.assertRaisesRegex(TimeoutError, "uncertain"):
                runner._start_round(
                    runtime,
                    expected_mode="PRODUCTION",
                    expected_count=500_000,
                    expected_size_kib=10,
                    invocation_event=events.append,
                )
        exchange.assert_called_once()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["attempt"], 1)
        self.assertEqual(events[0]["maximum_attempts"], 1)
        self.assertEqual(events[0]["automatic_retries"], 0)
        self.assertEqual(
            events[0]["uncertain_outcome_policy"],
            "fail_closed_and_restart_as_a_new_benchmark_run",
        )


class RealGateCalibrationTests(unittest.TestCase):
    @staticmethod
    def round_record(mode: str, rate: float) -> dict[str, Any]:
        messages, message_bytes, concurrency = runner.REAL_GATE_CALIBRATION_SHAPES[
            "10KB"
        ]
        accounted = 512 * 1024
        observer_reserve = 128 * 1024 * 1024
        control_reserve = 8 * 1024 * 1024
        budget = 2 * 1024 * 1024 * 1024
        required = accounted * concurrency + observer_reserve + control_reserve
        snapshot = (
            {
                "transaction_isolation": "repeatable_read",
                "transaction_read_only": True,
                "postgres_row_delta": messages,
                "maildir_atomic_rename_publications": messages,
                "qualified": True,
            }
            if mode == "on"
            else None
        )
        return {
            "persistence_gate_mode": mode,
            "measured": False,
            "count": messages,
            "message_bytes": message_bytes,
            "single_start_invocation": True,
            "endpoint_start_invocation_count": 1,
            "endpoint_start_automatic_retries": 0,
            "start_response": {
                "endpoint": "/api/stress/start",
                "status_code": 200,
                "body": {
                    "emailCount": messages,
                    "emailSizeKB": message_bytes // 1024,
                    "maxConcurrency": concurrency,
                },
            },
            "smtp": {
                "duration_seconds": 6.0,
                "throughput_messages_per_second": rate,
                "qualification": True,
                "expected": messages,
                "verified": messages,
                "missing": 0,
                "duplicates": 0,
                "retry_responses": 0,
                "persistence_gate": {
                    "required": mode == "on",
                    "qualified": True,
                    "status": "forwarded" if mode == "on" else "disabled",
                    "snapshot": snapshot,
                    "gate_id": 1 if mode == "on" else None,
                    "gate_hold_ns": 100 if mode == "on" else None,
                },
                "proxy": {
                    "pump_buffer_bytes": 64 * 1024,
                    "configured_max_connections": concurrency,
                    "backend_reply_block_limit_bytes": 128 * 1024,
                    "accounted_backend_reply_buffer_bytes": 128 * 1024,
                    "memory_permit_quantum_bytes": 64 * 1024,
                    "memory_budget_bytes": budget,
                    "usable_memory_budget_bytes": budget,
                    "required_memory_budget_bytes": required,
                    "memory_budget_headroom_bytes": budget - required,
                    "accounted_connection_bytes": accounted,
                    "observer_round_reserve_bytes": observer_reserve,
                    "control_runtime_reserve_bytes": control_reserve,
                },
            },
            "persistence_barrier": {
                "passed": True,
                "pre_final_persistence_snapshot_performed": mode == "on",
            },
            "endpoint_outcome": {"passed": True},
            "definition_attestation": {"before": {}, "after": {}},
        }

    def test_report_requires_actual_snapshot_duration_and_abba(self) -> None:
        rounds = [
            self.round_record(mode, 1_001.0 if mode == "on" else 1_000.0)
            for mode in runner.REAL_GATE_CALIBRATION_SEQUENCE
        ]
        report = runner._real_gate_calibration_report(
            "10KB", rounds, binding={"synthetic_backend": False}
        )
        self.assertTrue(report["qualification"])
        self.assertFalse(report["synthetic_no_postgres_or_maildir"])
        self.assertEqual(
            report["sequence"], list(runner.REAL_GATE_CALIBRATION_SEQUENCE)
        )
        self.assertEqual(len(report["paired_on_to_off_ratios"]), 4)

        too_short = json.loads(json.dumps(rounds))
        too_short[0]["smtp"]["duration_seconds"] = 4.999
        self.assertFalse(
            runner._real_gate_calibration_report(
                "10KB", too_short, binding={"synthetic_backend": False}
            )["qualification"]
        )
        missing_snapshot = json.loads(json.dumps(rounds))
        missing_snapshot[1]["smtp"]["persistence_gate"]["snapshot"] = None
        self.assertFalse(
            runner._real_gate_calibration_report(
                "10KB", missing_snapshot, binding={"synthetic_backend": False}
            )["qualification"]
        )

    def test_formal_runner_wires_real_calibration_before_measurement_arms(self) -> None:
        source = RUNNER_PATH.read_text(encoding="utf-8")
        calibration = source.index(
            "_run_real_gate_calibration_tier(", source.index("def _run_benchmark")
        )
        measurement = source.index(
            "_run_target_tier(", source.index("def _run_benchmark")
        )
        self.assertLess(calibration, measurement)
        self.assertIn('and real_gate_calibration["passed"]', source)

    def test_post_calibration_artifact_failure_does_not_mask_round_failure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            layout = SimpleNamespace(device="1:2", cpu=23)
            runtime = SimpleNamespace(
                workspace=workspace,
                start=mock.Mock(),
                stop=mock.Mock(),
            )
            proxy = mock.Mock()
            verify = mock.Mock(
                side_effect=[
                    {"sha256": "a" * 64},
                    RuntimeError("artifact after failed"),
                ]
            )
            with (
                mock.patch.object(runner, "_runtime_for", return_value=runtime),
                mock.patch.object(runner.os, "major", return_value=1, create=True),
                mock.patch.object(runner.os, "minor", return_value=2, create=True),
                mock.patch.object(
                    runner, "_cleanup_state", return_value=_clean_state()
                ),
                mock.patch.object(runner, "_state_is_clean", return_value=True),
                mock.patch.object(runner, "_move_runtime_to_workload", return_value={}),
                mock.patch.object(runner, "RustSmtpProxy", return_value=proxy),
                mock.patch.object(
                    runner,
                    "_run_attested_round",
                    side_effect=ValueError("round failed"),
                ),
                mock.patch.object(runner, "_assert_workload_empty"),
                mock.patch.object(runner, "_verify_target_artifact", verify),
            ):
                with self.assertRaisesRegex(ValueError, "round failed") as caught:
                    runner._run_real_gate_calibration_tier(
                        "1KB",
                        layout,
                        dns_port=53,
                        dkim_private_key_bytes=b"fixture",
                        disk_budget_bytes=1024**3,
                        started_attestation={
                            "benchmark_proxy_release_sha256": "b" * 64
                        },
                        quota_mount_root=root,
                        checkpoint_event=lambda _event: None,
                    )

        self.assertEqual(verify.call_count, 2)
        runtime.stop.assert_called_once_with()
        proxy.close.assert_called_once_with()
        self.assertTrue(
            any(
                "artifact after failed" in note
                for note in getattr(caught.exception, "__notes__", [])
            )
        )


class RoundFailureTests(unittest.TestCase):
    def test_gate_failure_aborts_before_closing_pending_start_socket(self) -> None:
        events: list[str] = []

        class FailedSnapshot:
            def __init__(self, *_args: object, **_kwargs: object):
                pass

            def capture(self) -> dict[str, Any]:
                raise RuntimeError("snapshot failed")

            def close(self) -> None:
                pass

        class TrackingSocket:
            def shutdown(self, _how: int) -> None:
                events.append("socket-shutdown")

            def close(self) -> None:
                events.append("socket-close")

        pending = runner.PendingStartRound(
            stream=SimpleNamespace(sock=TrackingSocket()),
            requested_at="2026-08-15T00:00:00Z",
            started_monotonic=1.0,
            invocation=runner._start_invocation_record("2026-08-15T00:00:00Z"),
            expected_mode="PRODUCTION",
            expected_count=1,
            expected_size_kib=1,
        )
        proxy = mock.Mock()
        _configure_proxy_gate(proxy, count=1)
        proxy.abort_persistence_gate.side_effect = lambda *_args: events.append(
            "gate-abort"
        )
        clean_state = _clean_state()
        cleanup = {
            "final": clean_state,
            "stable_polls": 3,
            "semantic_sha256": "a" * 64,
            "database_delta": {"passed": True},
        }
        with (
            mock.patch.object(
                runner, "MaildirPersistenceObserver", _FakeMaildirObserver
            ),
            mock.patch.object(
                runner, "PostgresPersistenceGateSnapshot", FailedSnapshot
            ),
            mock.patch.object(runner, "_cleanup_state", return_value=clean_state),
            mock.patch.object(runner, "_log_cursor", return_value=(Path("log"), 0)),
            mock.patch.object(runner, "_start_round", return_value=pending),
            mock.patch.object(
                runner, "_wait_for_automatic_cleanup", return_value=cleanup
            ),
            mock.patch.object(runner, "_log_evidence", return_value={}),
        ):
            with self.assertRaisesRegex(RuntimeError, "snapshot failed"):
                runner._run_round(
                    object(),
                    proxy,
                    object(),
                    mode="PRODUCTION",
                    count=1,
                    message_bytes=1024,
                    disk_budget_bytes=1024**3,
                    measured=False,
                )

        proxy.release_persistence_gate.assert_not_called()
        self.assertLess(events.index("gate-abort"), events.index("socket-shutdown"))
        self.assertLess(events.index("socket-shutdown"), events.index("socket-close"))
        self.assertTrue(pending.completed)

    def test_pre_invocation_monitor_failure_checks_zero_message_cleanup(self) -> None:
        class FailedMonitor:
            def __init__(self, *_args: object, **_kwargs: object):
                raise RuntimeError("initial resource sample failed")

        proxy = mock.Mock()
        _configure_proxy_gate(proxy, count=1)
        clean_state = _clean_state()
        cleanup = mock.Mock(
            return_value={
                "final": clean_state,
                "stable_polls": 3,
                "semantic_sha256": "a" * 64,
                "database_delta": {"passed": True},
            }
        )
        with (
            mock.patch.object(
                runner, "MaildirPersistenceObserver", _FakeMaildirObserver
            ),
            mock.patch.object(
                runner,
                "PostgresPersistenceGateSnapshot",
                _fake_postgres_gate_snapshot(0),
            ),
            mock.patch.object(runner, "_cleanup_state", return_value=clean_state),
            mock.patch.object(runner, "_log_cursor", return_value=(Path("log"), 0)),
            mock.patch.object(runner, "ResourceMonitor", FailedMonitor),
            mock.patch.object(runner, "_wait_for_automatic_cleanup", cleanup),
            mock.patch.object(runner, "_log_evidence", return_value={}),
        ):
            with self.assertRaisesRegex(RuntimeError, "initial resource sample"):
                runner._run_round(
                    object(),
                    proxy,
                    object(),
                    mode="PRODUCTION",
                    count=1,
                    message_bytes=1024,
                    disk_budget_bytes=1024**3,
                    measured=True,
                )

        proxy.begin.assert_not_called()
        self.assertEqual(cleanup.call_args.kwargs["expected_messages"], 0)

    def test_monitor_and_cleanup_failures_are_notes_on_capture_primary(self) -> None:
        class FakeMonitor:
            def __init__(self, *_args: object, **_kwargs: object):
                pass

            def raise_if_failed(self) -> None:
                pass

            def stop(self) -> dict[str, object]:
                raise RuntimeError("monitor stop failed")

        proxy = mock.Mock()
        _configure_proxy_gate(proxy, count=1)
        proxy.finish.side_effect = ValueError("capture failed")
        clean_state = _clean_state()
        with (
            mock.patch.object(
                runner, "MaildirPersistenceObserver", _FakeMaildirObserver
            ),
            mock.patch.object(
                runner,
                "PostgresPersistenceGateSnapshot",
                _fake_postgres_gate_snapshot(1),
            ),
            mock.patch.object(runner, "_cleanup_state", return_value=clean_state),
            mock.patch.object(runner, "_log_cursor", return_value=(Path("log"), 0)),
            mock.patch.object(
                runner,
                "_start_round",
                return_value={"body": {"round": 1}},
            ),
            mock.patch.object(runner, "ResourceMonitor", FakeMonitor),
            mock.patch.object(
                runner,
                "_wait_for_automatic_cleanup",
                side_effect=TimeoutError("cleanup failed"),
            ) as cleanup,
        ):
            with self.assertRaisesRegex(ValueError, "capture failed") as caught:
                runner._run_round(
                    object(),
                    proxy,
                    object(),
                    mode="PRODUCTION",
                    count=1,
                    message_bytes=1024,
                    disk_budget_bytes=1024**3,
                    measured=True,
                )

        self.assertEqual(cleanup.call_count, 1)
        notes = getattr(caught.exception, "__notes__", [])
        self.assertTrue(any("monitor stop failed" in note for note in notes))
        self.assertTrue(any("cleanup failed" in note for note in notes))


class CleanupStateTests(unittest.TestCase):
    def test_redis_snapshot_pipelines_full_values_in_fixed_key_batches(self) -> None:
        class FakePipeline:
            def __init__(self, client: Any):
                self.client = client
                self.commands: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []

            def __getattr__(self, name: str) -> Any:
                def queue(*args: Any, **kwargs: Any) -> Any:
                    self.commands.append((name, args, kwargs))
                    return self

                return queue

            def execute(self) -> list[Any]:
                self.client.pipeline_command_counts.append(len(self.commands))
                return [
                    self.client.dispatch(name, args, kwargs)
                    for name, args, kwargs in self.commands
                ]

        class FakeClient:
            def __init__(self, values: dict[bytes, tuple[str, int, Any]]):
                self.values = values
                self.pipeline_command_counts: list[int] = []
                self.pipeline_transaction_flags: list[bool] = []

            def pipeline(self, *, transaction: bool) -> FakePipeline:
                self.pipeline_transaction_flags.append(transaction)
                return FakePipeline(self)

            def dispatch(
                self, name: str, args: tuple[Any, ...], kwargs: dict[str, Any]
            ) -> Any:
                key = args[0]
                kind, pttl, value = self.values[key]
                if name == "type":
                    return kind.encode("ascii")
                if name == "pttl":
                    return pttl
                if name == "get":
                    return value
                if name in ("lrange", "smembers", "hgetall", "xrange"):
                    return value
                if name == "zrange":
                    self.assert_withscores(kwargs)
                    return value
                raise AssertionError(f"unexpected Redis command: {name}")

            @staticmethod
            def assert_withscores(kwargs: dict[str, Any]) -> None:
                if kwargs != {"withscores": True}:
                    raise AssertionError("zrange lost withscores=True")

        values: dict[bytes, tuple[str, int, Any]] = {
            b"string": ("string", 1000, b"abc"),
            b"list": ("list", -1, [b"a", b"b"]),
            b"set": ("set", -1, {b"b", b"a"}),
            b"zset": ("zset", -1, [(b"member", 1.5)]),
            b"hash": ("hash", -1, {b"b": b"2", b"a": b"1"}),
            b"stream": ("stream", -1, [(b"1-0", {b"field": b"value"})]),
            b"none": ("none", -2, None),
        }
        for index in range(506):
            key = f"string-{index:04d}".encode("ascii")
            values[key] = ("string", -1, f"value-{index}".encode("ascii"))
        keys = tuple(values)
        client = FakeClient(values)

        records = runner.v2._redis_snapshot_records(client, keys)
        by_key = {record["key"]: record for record in records}

        self.assertEqual(len(records), 513)
        self.assertEqual(client.pipeline_command_counts, [1024, 511, 2, 1])
        self.assertTrue(all(flag is False for flag in client.pipeline_transaction_flags))
        self.assertEqual(by_key["string"]["value_bytes"], 3)
        self.assertEqual(by_key["list"]["cardinality"], 2)
        self.assertEqual(
            by_key["list"]["value_stream_sha256"],
            runner.v2._hash_redis_values([b"a", b"b"]),
        )
        self.assertEqual(by_key["set"]["value_bytes"], 2)
        self.assertEqual(by_key["zset"]["cardinality"], 1)
        self.assertEqual(by_key["hash"]["cardinality"], 2)
        self.assertEqual(by_key["stream"]["cardinality"], 1)
        self.assertEqual(by_key["none"]["cardinality"], 0)

    def test_outbound_staging_lease_is_validated_and_not_counted_as_workload(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root) / "outbound"
            quarantine = root / ".lmyzmail-quarantine"
            quarantine.mkdir(parents=True)
            lease = quarantine / ".lmyzmail-staging.lease"
            lease.touch(mode=0o600)
            lease.chmod(0o600)

            snapshot = runner.v2._outbound_spool_snapshot(root)

            self.assertEqual(snapshot["files"], 0)
            self.assertEqual(snapshot["control_files"], 1)
            self.assertEqual(
                snapshot["staging_lease"],
                {
                    "present": True,
                    "validated": True,
                    "relative_path": ".lmyzmail-quarantine/.lmyzmail-staging.lease",
                    "mode": "0600",
                    "size_bytes": 0,
                    "hard_links": 1,
                },
            )

    def test_outbound_staging_lease_contract_rejects_mutable_content(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root) / "outbound"
            quarantine = root / ".lmyzmail-quarantine"
            quarantine.mkdir(parents=True)
            lease = quarantine / ".lmyzmail-staging.lease"
            lease.write_bytes(b"unexpected")
            lease.chmod(0o600)

            with self.assertRaisesRegex(RuntimeError, "bounded control-file contract"):
                runner.v2._outbound_spool_snapshot(root)

    def test_clean_state_allows_only_bounded_authentication_dns_caches(self) -> None:
        clean = _clean_state()
        records = [
            {
                "key": key,
                "type": "string",
                "pttl_ms": runner._AUTHENTICATION_DNS_CACHE_MAX_TTL_MS,
                "cardinality": 1,
                "value_stream_sha256": hashlib.sha256(key.encode()).hexdigest(),
                "value_bytes": len(key),
            }
            for key in sorted(runner._AUTHENTICATION_DNS_CACHE_KEYS)
        ]
        clean["redis"]["keys"] = records
        clean["redis"]["key_count"] = len(records)
        clean["redis"]["dbsize_before"] = len(records)
        clean["redis"]["dbsize_after"] = len(records)
        self.assertTrue(runner._state_is_clean(clean))

        for field, invalid in (
            ("pttl_ms", runner._AUTHENTICATION_DNS_CACHE_MAX_TTL_MS + 1),
            ("type", "hash"),
            ("cardinality", 2),
            ("value_bytes", 0),
        ):
            with self.subTest(field=field):
                malformed = json.loads(json.dumps(clean))
                malformed["redis"]["keys"][0][field] = invalid
                self.assertFalse(runner._state_is_clean(malformed))

        unexpected = json.loads(json.dumps(clean))
        unexpected["redis"]["keys"][0]["key"] = "dns:txt:unexpected.lmyz.net"
        self.assertFalse(runner._state_is_clean(unexpected))

    def test_clean_state_rejects_non_pending_queue_and_spool_residuals(self) -> None:
        clean = _clean_state()
        self.assertTrue(runner._state_is_clean(clean))

        queue_residual = json.loads(json.dumps(clean))
        queue_residual["redis"]["keys"] = [
            {
                "key": "botmail:mail:queue:processing",
                "type": "list",
                "pttl_ms": -1,
                "cardinality": 1,
                "value_stream_sha256": hashlib.sha256(b"task").hexdigest(),
                "value_bytes": 4,
            }
        ]
        queue_residual["redis"]["key_count"] = 1
        queue_residual["redis"]["dbsize_before"] = 1
        queue_residual["redis"]["dbsize_after"] = 1
        self.assertFalse(runner._state_is_clean(queue_residual))

        spool_residual = json.loads(json.dumps(clean))
        spool_residual["maildir"]["outbound_spool"]["files"] = 1
        spool_residual["maildir"]["outbound_spool"]["allocated_bytes"] = 4096
        self.assertFalse(runner._state_is_clean(spool_residual))

        database_residual = json.loads(json.dumps(clean))
        database_residual["database"]["tables"]["lmyzmail_outbound_delivery_attempt"][
            "rows"
        ] = 1
        database_residual["database"]["transient_residual_rows"] = 1
        self.assertFalse(runner._state_is_clean(database_residual))

    def test_clean_state_accepts_completed_audit_rows_and_checks_round_delta(
        self,
    ) -> None:
        before = _clean_state()
        for name in runner._OPTIONAL_STRESS_TABLES:
            before["database"]["tables"][name]["present"] = True
        after = json.loads(json.dumps(before))
        after["database"]["tables"]["outbound_mail_queue"].update(
            {"rows": 2, "groups": {"SENT": 2}}
        )
        after["database"]["tables"]["lmyzmail_outbound_delivery_recipient"].update(
            {"rows": 2, "groups": {"DELIVERED": 2}}
        )
        after["database"]["tables"]["lmyzmail_outbound_delivery_attempt"].update(
            {"rows": 2, "groups": {"PROJECTED": 2}}
        )
        after["database"]["email_index_mutations"].update(
            {"n_tup_ins": 4, "n_tup_del": 4}
        )
        after["database"]["completed_audit_rows"] = 6
        self.assertTrue(runner._state_is_clean(after))
        exact = runner._automatic_cleanup_delta(before, after, 2)
        self.assertTrue(exact["passed"])
        self.assertEqual(
            exact["email_index_mutation_evidence"]["counter_deltas"],
            {
                "n_tup_ins": 4,
                "n_tup_del": 4,
                "n_tup_upd": 0,
                "database_xact_rollback": 0,
            },
        )
        self.assertFalse(runner._automatic_cleanup_delta(before, after, 3)["passed"])
        for counter in ("n_tup_ins", "n_tup_del", "database_xact_rollback"):
            with self.subTest(counter=counter):
                malformed = json.loads(json.dumps(after))
                malformed["database"]["email_index_mutations"][counter] += 1
                evidence = runner._automatic_cleanup_delta(before, malformed, 2)
                self.assertFalse(evidence["passed"])
                self.assertFalse(evidence["email_index_mutation_evidence"]["passed"])

    def test_automatic_cleanup_requires_three_identical_semantic_snapshots(
        self,
    ) -> None:
        states = [_clean_state(), _clean_state(), _clean_state()]
        states[0]["captured_at"] = "first"
        states[1]["captured_at"] = "second"
        states[2]["captured_at"] = "third"
        with (
            mock.patch.object(
                runner,
                "_automatic_cleanup_readiness",
                return_value={"ready": True},
            ) as readiness,
            mock.patch.object(runner, "_cleanup_state", side_effect=states) as capture,
            mock.patch.object(runner.time, "sleep"),
        ):
            result = runner._wait_for_automatic_cleanup(
                object(),
                before=_clean_state(),
                expected_messages=0,
                timeout_seconds=1.0,
            )
        self.assertEqual(capture.call_count, runner.STATE_STABLE_POLLS)
        self.assertEqual(readiness.call_count, runner.STATE_STABLE_POLLS)
        self.assertEqual(result["stable_polls"], runner.STATE_STABLE_POLLS)
        self.assertEqual(len(result["samples"]), runner.STATE_STABLE_POLLS)
        self.assertEqual(result["full_value_snapshots"], runner.STATE_STABLE_POLLS)

    def test_automatic_cleanup_fails_immediately_on_monotonic_rollback_delta(
        self,
    ) -> None:
        before = _clean_state()
        after = _clean_state()
        after["database"]["email_index_mutations"]["database_xact_rollback"] = 1
        with (
            mock.patch.object(
                runner,
                "_automatic_cleanup_readiness",
                return_value={"ready": True},
            ),
            mock.patch.object(runner, "_cleanup_state", return_value=after) as capture,
            mock.patch.object(runner.time, "sleep") as sleep,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "database_xact_rollback delta=1",
            ):
                runner._wait_for_automatic_cleanup(
                    object(),
                    before=before,
                    expected_messages=0,
                    timeout_seconds=1.0,
                )
        self.assertEqual(capture.call_count, 1)
        sleep.assert_not_called()

    def test_redis_cleanup_readiness_uses_bounded_endpoint_key_allowance(
        self,
    ) -> None:
        client = mock.Mock()
        client.dbsize.side_effect = [25, 24]
        runtime = SimpleNamespace(ports=SimpleNamespace(redis=16379))
        before = _clean_state()
        before["redis"]["dbsize_after"] = 0
        with mock.patch.object(runner.base.redis, "Redis", return_value=client):
            not_ready = runner._redis_cleanup_readiness(runtime, before, 8)
            ready = runner._redis_cleanup_readiness(runtime, before, 8)

        self.assertFalse(not_ready["ready"])
        self.assertTrue(ready["ready"])
        self.assertFalse(ready["full_values_read"])
        self.assertEqual(ready["profile"], "redis-cleanup-readiness-v2")
        self.assertEqual(ready["expected_message_key_allowance"], 16)
        self.assertEqual(ready["fixed_key_allowance"], 8)
        self.assertEqual(ready["maximum_ready_key_count"], 24)
        self.assertEqual(client.dbsize.call_count, 2)
        self.assertEqual(client.close.call_count, 2)
        self.assertEqual(
            [call[0] for call in client.method_calls],
            ["dbsize", "close", "dbsize", "close"],
        )

    def test_automatic_cleanup_does_not_read_full_values_before_readiness(
        self,
    ) -> None:
        readiness = [
            {"ready": False, "redis": {"full_values_read": False}},
            {"ready": True, "redis": {"full_values_read": False}},
            {"ready": True, "redis": {"full_values_read": False}},
            {"ready": True, "redis": {"full_values_read": False}},
        ]
        states = [_clean_state(), _clean_state(), _clean_state()]
        with (
            mock.patch.object(
                runner, "_automatic_cleanup_readiness", side_effect=readiness
            ) as probe,
            mock.patch.object(runner, "_cleanup_state", side_effect=states) as capture,
            mock.patch.object(runner.time, "sleep"),
        ):
            result = runner._wait_for_automatic_cleanup(
                object(),
                before=_clean_state(),
                expected_messages=0,
                timeout_seconds=1.0,
            )

        self.assertEqual(probe.call_count, 4)
        self.assertEqual(capture.call_count, runner.STATE_STABLE_POLLS)
        self.assertEqual(len(result["readiness_samples"]), 4)
        self.assertFalse(
            result["readiness_samples"][0]["probe"]["redis"]["full_values_read"]
        )


class CgroupLayoutTests(unittest.TestCase):
    def test_runner_is_non_dumpable_and_drops_ptrace_from_bounding_set(self) -> None:
        class FakePrctl:
            def __init__(self) -> None:
                self.calls: list[tuple[int, ...]] = []
                self.argtypes: Any = None
                self.restype: Any = None

            def __call__(self, *arguments: int) -> int:
                self.calls.append(arguments)
                return 0

        prctl = FakePrctl()
        library = SimpleNamespace(prctl=prctl)
        bounded = f"CapBnd:\t{1 << runner.CAP_SYS_PTRACE:016x}\n"
        dropped = "CapBnd:\t0000000000000000\n"
        with (
            mock.patch.object(runner.ctypes, "CDLL", return_value=library),
            mock.patch.object(Path, "read_text", side_effect=[bounded, dropped]),
        ):
            evidence = runner._runner_process_hardening(apply=True)
        self.assertTrue(evidence["passed"])
        self.assertIn(
            (runner.PR_SET_DUMPABLE, 0, 0, 0, 0),
            prctl.calls,
        )
        self.assertIn(
            (runner.PR_CAPBSET_DROP, runner.CAP_SYS_PTRACE, 0, 0, 0),
            prctl.calls,
        )

    def test_namespace_reexec_targets_this_runner_not_v1_or_v2(self) -> None:
        with (
            mock.patch.dict(runner.os.environ, {}, clear=True),
            mock.patch.object(
                runner.base, "_required_command", return_value="/usr/bin/unshare"
            ),
            mock.patch.object(runner.os, "getuid", return_value=1000, create=True),
            mock.patch.object(runner.os, "getgid", return_value=1000, create=True),
            mock.patch.object(
                runner.os, "execve", side_effect=RuntimeError("exec")
            ) as execute,
            mock.patch.object(runner.sys, "argv", [str(RUNNER_PATH), "--smoke"]),
            self.assertRaisesRegex(RuntimeError, "exec"),
        ):
            runner._enter_isolated_namespace()
        arguments = execute.call_args.args[1]
        self.assertEqual(Path(arguments[-2]), RUNNER_PATH.resolve())
        self.assertEqual(arguments[-1], "--smoke")

    def test_nofile_limit_requires_exact_soft_and_hard_values(self) -> None:
        self.assertIn(
            "actual_affinity != layout.housekeeping_cpus",
            RUNNER_PATH.read_text(encoding="utf-8"),
        )
        fake = SimpleNamespace(RLIMIT_NOFILE=7, getrlimit=lambda _kind: (1024, 1024))
        with mock.patch.object(runner.importlib, "import_module", return_value=fake):
            evidence = runner._nofile_evidence(SimpleNamespace(nofile_limit=1024))
        self.assertEqual(evidence, {"soft": 1024, "hard": 1024, "passed": True})

        fake.getrlimit = lambda _kind: (1024, 2048)
        with (
            mock.patch.object(runner.importlib, "import_module", return_value=fake),
            self.assertRaisesRegex(RuntimeError, "NOFILE"),
        ):
            runner._nofile_evidence(SimpleNamespace(nofile_limit=1024))

    def test_io_max_parser_accepts_kernel_shape_and_rejects_conflicts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "io.max"
            path.write_text(
                "7:0 wiops=max rbps=10 riops=max wbps=10\n"
                "8:0 rbps=10 wbps=10 riops=max wiops=max\n",
                encoding="ascii",
            )
            parsed = runner._parse_io_max(path)
            self.assertEqual(parsed["7:0"]["rbps"], "10")
            self.assertEqual(parsed["7:0"]["wiops"], "max")

            for invalid in (
                "7:0 rbps=10 wbps=10\n7:0 rbps=10 wbps=10\n",
                "7:0 rbps=10 wbps=10 wiops=1\n",
                "7:0 rbps=10 rbps=10 wbps=10\n",
            ):
                path.write_text(invalid, encoding="ascii")
                if "wiops=1" in invalid:
                    parsed = runner._parse_io_max(path)
                    self.assertEqual(parsed["7:0"]["wiops"], "1")
                else:
                    with self.assertRaises(RuntimeError):
                        runner._parse_io_max(path)

    def test_verify_accepts_contract_and_rejects_mismatched_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "parent"
            harness = parent / "harness"
            workload = parent / "workload"
            services = parent / "services"
            supervisor_socket = Path(temporary) / "supervisor.sock"
            harness.mkdir(parents=True)
            workload.mkdir()
            services.mkdir()
            io_bytes_per_second = 123_456
            (parent / "io.max").write_text(
                f"7:0 wiops=max wbps={io_bytes_per_second} rbps={io_bytes_per_second} riops=max\n"
                f"8:0 rbps={io_bytes_per_second} riops=max wbps={io_bytes_per_second} wiops=max\n",
                encoding="ascii",
            )
            (workload / "cpuset.cpus.effective").write_text("3\n", encoding="ascii")
            (harness / "cpuset.cpus.effective").write_text("0-2\n", encoding="ascii")
            (services / "cpuset.cpus.effective").write_text("0-2\n", encoding="ascii")
            (workload / "cpu.max").write_text("100000 100000\n", encoding="ascii")
            (parent / "pids.max").write_text("64\n", encoding="ascii")
            (parent / "memory.max").write_text("1048576\n", encoding="ascii")
            (parent / "memory.swap.max").write_text("0\n", encoding="ascii")
            if sys.platform == "linux":
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as endpoint:
                    endpoint.bind(str(supervisor_socket))
                for control in (
                    parent / "cgroup.procs",
                    parent / "io.max",
                    parent / "memory.max",
                    parent / "memory.swap.max",
                    parent / "pids.max",
                    harness / "cgroup.procs",
                    services / "cgroup.procs",
                    workload / "cgroup.procs",
                    workload / "cpu.max",
                ):
                    control.touch(exist_ok=True)
                    control.chmod(0o444)
            layout = runner.CgroupLayout(
                parent=parent,
                harness=harness,
                workload=workload,
                services=services,
                cpu=3,
                housekeeping_cpus=(0, 1, 2),
                device="7:0",
                backing_device="8:0",
                io_bytes_per_second=io_bytes_per_second,
                max_pids=64,
                max_memory_bytes=1_048_576,
                nofile_limit=1_024,
                host_reserve_bytes=10 * 1024**3,
                supervisor_socket=supervisor_socket,
            )

            current_identity = (
                getattr(os, "getuid", lambda: 0)(),
                getattr(os, "getgid", lambda: 0)(),
            )
            with mock.patch.object(
                runner, "_unmapped_host_root_identity", return_value=current_identity
            ):
                layout.verify()
                snapshot = layout.snapshot()
                self.assertEqual(snapshot["cpuset_cpus_effective"], "3")
                self.assertEqual(snapshot["cpu_max"], "100000 100000")
                self.assertIn("rbps=123456", snapshot["io_max"])
                self.assertIn("wbps=123456", snapshot["io_max"])

                (parent / "io.max").chmod(0o644)
                (parent / "io.max").write_text(
                    f"7:0 rbps={io_bytes_per_second} wbps={io_bytes_per_second} wiops=1\n"
                    f"8:0 rbps={io_bytes_per_second} wbps={io_bytes_per_second}\n",
                    encoding="ascii",
                )
                (parent / "io.max").chmod(0o444)
                with self.assertRaisesRegex(RuntimeError, "I/O limit"):
                    layout.verify()

                (parent / "io.max").chmod(0o644)
                (parent / "io.max").write_text(
                    f"7:0 rbps={io_bytes_per_second} wbps={io_bytes_per_second}\n",
                    encoding="ascii",
                )
                (parent / "io.max").chmod(0o444)
                with self.assertRaisesRegex(RuntimeError, "I/O limit"):
                    layout.verify()
                (parent / "io.max").chmod(0o644)
                (parent / "io.max").write_text(
                    f"7:0 rbps={io_bytes_per_second} wbps={io_bytes_per_second}\n"
                    f"8:0 rbps={io_bytes_per_second} wbps={io_bytes_per_second}\n",
                    encoding="ascii",
                )
                (parent / "io.max").chmod(0o444)
                (workload / "cpu.max").chmod(0o644)
                (workload / "cpu.max").write_text("50000 100000\n", encoding="ascii")
                (workload / "cpu.max").chmod(0o444)
                with self.assertRaisesRegex(RuntimeError, "CPU quota"):
                    layout.verify()

    def test_verify_rejects_cgroup_outside_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent = root / "parent"
            harness = root / "outside-harness"
            workload = parent / "workload"
            services = parent / "services"
            parent.mkdir()
            harness.mkdir()
            workload.mkdir()
            services.mkdir()
            layout = runner.CgroupLayout(
                parent=parent,
                harness=harness,
                workload=workload,
                services=services,
                cpu=0,
                housekeeping_cpus=(1,),
                device="8:0",
                backing_device="9:0",
                io_bytes_per_second=1,
                max_pids=1,
                max_memory_bytes=1,
                nofile_limit=1,
                host_reserve_bytes=1,
                supervisor_socket=root / "supervisor.sock",
            )

            with self.assertRaisesRegex(
                RuntimeError, "invalid benchmark cgroup layout"
            ):
                layout.verify()


class CgroupMigrationTests(unittest.TestCase):
    def test_runtime_roles_use_supervisor_and_services_are_separate(self) -> None:
        layout = SimpleNamespace(
            workload=Path("/sys/fs/cgroup/bench/workload"),
            services=Path("/sys/fs/cgroup/bench/services"),
            cpu=3,
            housekeeping_cpus=(0, 1, 2),
        )
        roots = {"application": 101, "postgres": 202, "redis": 303}
        cgroups = {
            101: "/bench/workload",
            202: "/bench/services",
            303: "/bench/services",
        }

        def request(_layout: Any, *, role: str, root_pid: int) -> dict[str, Any]:
            return {
                "passed": True,
                "role": role,
                "root_pid": root_pid,
                "migrated_pids": [root_pid],
            }

        with (
            mock.patch.object(runner, "_runtime_root_roles", return_value=roots),
            mock.patch.object(
                runner, "_request_cgroup_migration", side_effect=request
            ) as migrate,
            mock.patch.object(
                runner, "_process_tree", side_effect=lambda values: set(values)
            ),
            mock.patch.object(
                runner, "_unified_cgroup", side_effect=cgroups.__getitem__
            ),
            mock.patch.object(
                runner.os,
                "sched_getaffinity",
                side_effect=lambda pid: {3} if pid == 101 else {0, 1, 2},
                create=True,
            ),
        ):
            placement = runner._move_runtime_to_workload(object(), layout)

        self.assertEqual(migrate.call_count, 3)
        self.assertEqual(placement["application_cpuset"], [3])
        self.assertEqual(placement["services_cpuset"], [0, 1, 2])
        self.assertTrue(placement["root_only_migration"])
        self.assertTrue(placement["all_observed_pids_migrated"])


class IoAccountingTests(unittest.TestCase):
    def test_accounting_device_uses_one_layer_and_requires_each_phase(self) -> None:
        phases = [
            {
                "delta": {
                    "7:0": {"wbytes": 10},
                    "8:0": {"wbytes": 100},
                }
            },
            {
                "delta": {
                    "7:0": {"wbytes": 20},
                    "8:0": {"wbytes": 110},
                }
            },
        ]
        self.assertEqual(
            runner._select_io_accounting_device(
                phases, devices=("7:0", "8:0"), logical_bytes=100
            ),
            "8:0",
        )
        phases[0]["delta"] = {
            "7:0": {"wbytes": 100},
            "8:0": {"wbytes": 100},
        }
        phases[1]["delta"] = {
            "7:0": {"wbytes": 100},
            "8:0": {"wbytes": 10},
        }
        self.assertEqual(
            runner._select_io_accounting_device(
                phases, devices=("7:0", "8:0"), logical_bytes=100
            ),
            "7:0",
        )
        phases[1]["delta"]["7:0"]["wbytes"] = 10
        with self.assertRaisesRegex(RuntimeError, "95 percent"):
            runner._select_io_accounting_device(
                phases, devices=("7:0", "8:0"), logical_bytes=100
            )

    def test_io_stat_preserves_missing_and_both_device_rows_without_summing(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "io.stat"
            path.write_text("8:0 rbytes=3 wbytes=200 rios=1 wios=2\n", encoding="ascii")
            values = runner._io_stats_by_device(path, ("7:0", "8:0"))
            self.assertEqual(values["7:0"], {})
            self.assertEqual(values["8:0"]["wbytes"], 200)

            path.write_text(
                "7:0 rbytes=1 wbytes=100 rios=1 wios=1\n"
                "8:0 rbytes=3 wbytes=200 rios=1 wios=2\n",
                encoding="ascii",
            )
            values = runner._io_stats_by_device(path, ("7:0", "8:0"))
            self.assertEqual(values["7:0"]["wbytes"], 100)
            self.assertEqual(values["8:0"]["wbytes"], 200)


class ProcessIoEvidenceTests(unittest.TestCase):
    @staticmethod
    def _stat(pid: int, start_time: int) -> str:
        fields = ["S", *("0" for _ in range(18)), str(start_time)]
        return f"{pid} (worker thread) {' '.join(fields)}\n"

    @staticmethod
    def _sample(
        values: dict[int, tuple[str, int, int, int, int, int]],
    ) -> dict[str, Any]:
        return {
            "process_role_by_pid": {
                str(pid): role for pid, (role, *_rest) in values.items()
            },
            "process_io_by_pid": {
                str(pid): {
                    "start_time_ticks": start_time,
                    "wchar": wchar,
                    "syscw": syscw,
                    "read_bytes": read_bytes,
                    "write_bytes": write_bytes,
                }
                for pid, (
                    _role,
                    start_time,
                    wchar,
                    syscw,
                    read_bytes,
                    write_bytes,
                ) in values.items()
            },
        }

    def test_process_io_parser_preserves_required_kernel_counters_and_identity(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            process = Path(temporary) / "101"
            process.mkdir()
            (process / "stat").write_text(self._stat(101, 777), encoding="ascii")
            (process / "io").write_text(
                "rchar: 1\n"
                "wchar: 200\n"
                "syscr: 3\n"
                "syscw: 4\n"
                "read_bytes: 500\n"
                "write_bytes: 600\n"
                "cancelled_write_bytes: 0\n",
                encoding="ascii",
            )
            observed = runner._process_io_status([101], proc_root=Path(temporary))

        self.assertEqual(
            observed[101],
            {
                "start_time_ticks": 777,
                "wchar": 200,
                "syscw": 4,
                "read_bytes": 500,
                "write_bytes": 600,
            },
        )

    def test_process_io_parser_rejects_missing_or_malformed_required_counter(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            process = Path(temporary) / "101"
            process.mkdir()
            (process / "stat").write_text(self._stat(101, 777), encoding="ascii")
            (process / "io").write_text(
                "wchar: 1\nsyscw: nope\nread_bytes: 2\nwrite_bytes: 3\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(RuntimeError, "malformed syscw"):
                runner._process_io_status([101], proc_root=Path(temporary))

            (process / "io").write_text(
                "wchar: 1\nsyscw: 2\nread_bytes: 3\n", encoding="ascii"
            )
            with self.assertRaisesRegex(RuntimeError, "omitted process I/O"):
                runner._process_io_status([101], proc_root=Path(temporary))

    def test_lifecycle_delta_counts_new_children_and_tolerates_pid_reuse(self) -> None:
        samples = [
            self._sample({2: ("services", 20, 100, 10, 0, 1_000)}),
            self._sample(
                {
                    2: ("services", 20, 500, 20, 0, 1_400),
                    9: ("services", 90, 50, 2, 0, 60),
                }
            ),
            self._sample({2: ("services", 21, 10, 1, 0, 20)}),
        ]
        observed = runner._process_io_lifecycle_delta(samples)

        self.assertEqual(observed["lifecycle_count"], 3)
        self.assertEqual(observed["by_role"]["services"]["write_bytes"], 480)
        self.assertEqual(observed["by_role"]["services"]["syscw"], 13)
        self.assertEqual(observed["by_role"]["total"], observed["by_role"]["services"])
        self.assertTrue(observed["role_immutability_verified"])
        self.assertTrue(observed["counter_monotonicity_verified"])

    def test_lifecycle_delta_rejects_role_mutation_and_decreasing_counters(
        self,
    ) -> None:
        first = self._sample({2: ("services", 20, 100, 10, 0, 1_000)})
        role_changed = self._sample({2: ("application", 20, 101, 11, 0, 1_001)})
        with self.assertRaisesRegex(RuntimeError, "changed role"):
            runner._process_io_lifecycle_delta([first, role_changed])

        decreased = self._sample({2: ("services", 20, 99, 11, 0, 1_001)})
        with self.assertRaisesRegex(RuntimeError, "counter decreased"):
            runner._process_io_lifecycle_delta([first, decreased])

    def test_service_persistence_accepts_proc_io_when_cgroup_writeback_moves(
        self,
    ) -> None:
        observed = runner._persistence_io_sources(
            {"wbytes": 0, "wios": 89},
            {"write_bytes": 557_056, "syscw": 72},
        )
        self.assertFalse(observed["cgroup_observed"])
        self.assertTrue(observed["process_observed"])
        self.assertTrue(observed["observed"])


class ResourceMonitorTests(unittest.TestCase):
    def test_temperature_snapshot_reports_absence_and_over_limit_reading(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            missing = runner._temperature_snapshot(root / "missing", root / "none")
            self.assertFalse(missing["available"])
            self.assertTrue(missing["unavailable_is_reported_not_fabricated"])
            self.assertTrue(missing["within_limit"])

            zone = root / "thermal" / "thermal_zone0"
            zone.mkdir(parents=True)
            (zone / "type").write_text("cpu\n", encoding="ascii")
            (zone / "temp").write_text("96000\n", encoding="ascii")
            observed = runner._temperature_snapshot(
                root / "thermal", root / "missing-hwmon"
            )
            self.assertTrue(observed["available"])
            self.assertEqual(observed["maximum_millicelsius"], 96_000)
            self.assertFalse(observed["within_limit"])

    def test_rss_and_hwm_are_aggregated_by_role_and_total(self) -> None:
        role_pids = {"application": {1}, "services": {2, 3}, "harness": {4}}
        process_memory = {
            pid: {"rss_bytes": pid * 10, "hwm_bytes": pid * 20} for pid in range(1, 5)
        }
        aggregated = runner._role_process_memory(role_pids, process_memory)
        self.assertEqual(aggregated["application"]["rss_bytes"], 10)
        self.assertEqual(aggregated["services"]["rss_bytes"], 50)
        self.assertEqual(aggregated["services"]["hwm_bytes"], 100)
        self.assertEqual(aggregated["total"]["rss_bytes"], 100)
        self.assertEqual(aggregated["total"]["hwm_bytes"], 200)

    def _monitor(self, root: Path) -> Any:
        parent = root / "parent"
        workload = parent / "workload"
        services = parent / "services"
        harness = parent / "harness"
        for path in (workload, services, harness):
            path.mkdir(parents=True, exist_ok=True)
        (workload / "cgroup.procs").write_text("101\n", encoding="ascii")
        (services / "cgroup.procs").write_text("202\n", encoding="ascii")
        (harness / "cgroup.procs").write_text("303\n", encoding="ascii")
        (parent / "pids.current").write_text("3\n", encoding="ascii")
        (parent / "memory.current").write_text("1024\n", encoding="ascii")
        (parent / "memory.swap.current").write_text("0\n", encoding="ascii")
        (parent / "memory.events").write_text(
            "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n", encoding="ascii"
        )
        (parent / "pids.events").write_text("max 0\n", encoding="ascii")
        for path in (parent, workload, services):
            (path / "cpu.stat").write_text("usage_usec 10\n", encoding="ascii")
        for index, path in enumerate((workload, services, harness), start=1):
            (path / "memory.current").write_text(f"{index * 100}\n", encoding="ascii")
            (path / "memory.stat").write_text(
                f"anon {index * 50}\nfile {index * 25}\n", encoding="ascii"
            )
            (path / "io.stat").write_text(
                f"7:0 rbytes=0 wbytes={index * 10} rios=0 wios={index}\n"
                f"8:0 rbytes=0 wbytes={index * 20} rios=0 wios={index}\n",
                encoding="ascii",
            )
        (parent / "memory.stat").write_text("anon 600\nfile 300\n", encoding="ascii")
        (parent / "io.stat").write_text(
            "7:0 rbytes=1 wbytes=100 rios=1 wios=1\n"
            "8:0 rbytes=2 wbytes=200 rios=2 wios=2\n",
            encoding="ascii",
        )
        monitor = object.__new__(runner.ResourceMonitor)
        monitor.layout = SimpleNamespace(
            parent=parent,
            workload=workload,
            services=services,
            harness=harness,
            device="7:0",
            backing_device="8:0",
            max_pids=4,
            max_memory_bytes=2_048,
            nofile_limit=8,
        )
        monitor.runtime = object()
        monitor.workspace = root
        monitor.filesystem_baseline = 0
        monitor.started_monotonic = 0.0
        monitor.accounting_device = "8:0"
        monitor.memory_events_baseline = {
            "low": 0,
            "high": 0,
            "max": 0,
            "oom": 0,
            "oom_kill": 0,
        }
        monitor.pids_events_baseline = {"max": 0}
        monitor.harness_auxiliary_roots = {}
        monitor.redis = SimpleNamespace(llen=lambda _key: 0)
        monitor.expected_messages = 10
        monitor.disk_budget_bytes = 1_000_000
        return monitor

    def test_membership_includes_attested_proxy_identity(self) -> None:
        layout = SimpleNamespace(
            parent=Path("/sys/fs/cgroup/test-run"),
            workload=Path("/sys/fs/cgroup/test-run/workload"),
            services=Path("/sys/fs/cgroup/test-run/services"),
            harness=Path("/sys/fs/cgroup/test-run/harness"),
        )
        role_pids = {
            "application": {101},
            "services": {202, 203},
            "harness": {303, 404},
        }
        cgroups = {
            101: "/test-run/workload",
            202: "/test-run/services",
            203: "/test-run/services",
            303: "/test-run/harness",
            404: "/test-run/harness",
        }

        def process_tree(roots: tuple[int, ...]) -> set[int]:
            return {101: {101}, 202: {202, 203}, 204: set(), 404: {404}}[roots[0]]

        with (
            mock.patch.object(Path, "read_text", return_value=""),
            mock.patch.object(
                runner,
                "_runtime_root_roles",
                return_value={"application": 101, "postgres": 202, "redis": 204},
            ),
            mock.patch.object(runner, "_process_tree", side_effect=process_tree),
            mock.patch.object(runner, "_process_start_time", return_value=999),
            mock.patch.object(
                runner, "_unified_cgroup", side_effect=lambda pid: cgroups[pid]
            ),
            mock.patch.object(runner.os, "getpid", return_value=303),
        ):
            evidence = runner._membership_audit(
                object(),
                layout,
                role_pids,
                {404: 999},
                require_harness_auxiliaries=True,
            )

        self.assertEqual(evidence["roles"]["harness"], [303, 404])
        self.assertEqual(evidence["harness_auxiliary_roots"], {"404": 999})
        self.assertEqual(evidence["missing_harness_auxiliaries"], [])

    def test_membership_rejects_missing_required_proxy_identity(self) -> None:
        layout = SimpleNamespace(
            parent=Path("/sys/fs/cgroup/test-run"),
            workload=Path("/sys/fs/cgroup/test-run/workload"),
            services=Path("/sys/fs/cgroup/test-run/services"),
            harness=Path("/sys/fs/cgroup/test-run/harness"),
        )
        role_pids = {
            "application": {101, 105},
            "services": {202, 203},
            "harness": {303, 404},
        }
        with (
            mock.patch.object(Path, "read_text", return_value=""),
            mock.patch.object(
                runner,
                "_runtime_root_roles",
                return_value={"application": 101, "postgres": 202, "redis": 204},
            ),
            mock.patch.object(runner, "_process_tree", return_value=set()),
            mock.patch.object(
                runner, "_process_start_time", side_effect=FileNotFoundError
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "disappeared or changed"):
                runner._membership_audit(
                    object(),
                    layout,
                    {"application": set(), "services": set(), "harness": set()},
                    {404: 999},
                    require_harness_auxiliaries=True,
                )

    def test_membership_allows_transient_child_exit_during_verification(self) -> None:
        layout = SimpleNamespace(
            parent=Path("/sys/fs/cgroup/test-run"),
            workload=Path("/sys/fs/cgroup/test-run/workload"),
            services=Path("/sys/fs/cgroup/test-run/services"),
            harness=Path("/sys/fs/cgroup/test-run/harness"),
        )
        role_pids = {
            "application": {101, 105},
            "services": {202, 203},
            "harness": {303, 404},
        }
        cgroups = {
            101: "/test-run/workload",
            202: "/test-run/services",
            203: "/test-run/services",
            303: "/test-run/harness",
            404: "/test-run/harness",
        }

        def process_tree(roots: tuple[int, ...]) -> set[int]:
            return {
                101: {101, 105},
                202: {202, 203},
                204: set(),
                404: {404},
            }[roots[0]]

        def cgroup(pid: int) -> str:
            if pid == 105:
                raise FileNotFoundError
            return cgroups[pid]

        with (
            mock.patch.object(Path, "read_text", return_value=""),
            mock.patch.object(
                runner,
                "_runtime_root_roles",
                return_value={"application": 101, "postgres": 202, "redis": 204},
            ),
            mock.patch.object(runner, "_process_tree", side_effect=process_tree),
            mock.patch.object(runner, "_process_start_time", return_value=999),
            mock.patch.object(runner, "_unified_cgroup", side_effect=cgroup),
            mock.patch.object(runner.os, "getpid", return_value=303),
        ):
            evidence = runner._membership_audit(
                object(),
                layout,
                role_pids,
                {404: 999},
                require_harness_auxiliaries=True,
            )

        self.assertEqual(
            evidence["vanished_during_cgroup_verification"],
            {"application": [105], "services": [], "harness": []},
        )

    def test_membership_reconciles_child_zombie_between_cgroup_and_tree_reads(
        self,
    ) -> None:
        layout = SimpleNamespace(
            parent=Path("/sys/fs/cgroup/test-run"),
            workload=Path("/sys/fs/cgroup/test-run/workload"),
            services=Path("/sys/fs/cgroup/test-run/services"),
            harness=Path("/sys/fs/cgroup/test-run/harness"),
        )
        role_pids = {
            "application": {101, 105},
            "services": {202, 203},
            "harness": {303, 404},
        }
        with (
            mock.patch.object(Path, "read_text", return_value=""),
            mock.patch.object(Path, "exists", return_value=True),
            mock.patch.object(
                runner,
                "_runtime_root_roles",
                return_value={"application": 101, "postgres": 202, "redis": 204},
            ),
            mock.patch.object(
                runner,
                "_process_tree",
                side_effect=lambda roots: {
                    101: {101},
                    202: {202, 203},
                    204: set(),
                    404: {404},
                }[roots[0]],
            ),
            mock.patch.object(runner, "_process_start_time", return_value=999),
            mock.patch.object(
                runner, "_process_state", return_value="Z"
            ) as process_state,
            mock.patch.object(
                runner,
                "_unified_cgroup",
                side_effect=lambda pid: {
                    101: "/test-run/workload",
                    202: "/test-run/services",
                    203: "/test-run/services",
                    303: "/test-run/harness",
                    404: "/test-run/harness",
                }[pid],
            ),
            mock.patch.object(runner.os, "getpid", return_value=303),
        ):
            evidence = runner._membership_audit(
                object(),
                layout,
                role_pids,
                {404: 999},
                require_harness_auxiliaries=True,
            )
            process_state.return_value = "R"
            with self.assertRaisesRegex(
                RuntimeError, "continuous cgroup membership changed"
            ):
                runner._membership_audit(
                    object(),
                    layout,
                    role_pids,
                    {404: 999},
                    require_harness_auxiliaries=True,
                )

        self.assertEqual(evidence["roles"]["application"], [101])
        self.assertEqual(
            evidence["vanished_during_membership_reconciliation"],
            {"application": [105], "services": [], "harness": []},
        )

    def test_membership_includes_child_forked_after_cgroup_snapshot(self) -> None:
        layout = SimpleNamespace(
            parent=Path("/sys/fs/cgroup/test-run"),
            workload=Path("/sys/fs/cgroup/test-run/workload"),
            services=Path("/sys/fs/cgroup/test-run/services"),
            harness=Path("/sys/fs/cgroup/test-run/harness"),
        )
        role_pids = {
            "application": {101},
            "services": {202, 204},
            "harness": {303, 404},
        }
        cgroups = {
            101: "/test-run/workload",
            202: "/test-run/services",
            204: "/test-run/services",
            205: "/test-run/services",
            206: "/test-run/services",
            303: "/test-run/harness",
            404: "/test-run/harness",
        }

        with (
            mock.patch.object(Path, "read_text", return_value=""),
            mock.patch.object(
                runner,
                "_runtime_root_roles",
                return_value={"application": 101, "postgres": 202, "redis": 204},
            ),
            mock.patch.object(
                runner,
                "_process_tree",
                side_effect=lambda roots: {
                    101: {101},
                    202: {202, 205, 206},
                    204: {204},
                    404: {404},
                }[roots[0]],
            ),
            mock.patch.object(runner, "_process_start_time", return_value=999),
            mock.patch.object(runner, "_process_state", return_value="S"),
            mock.patch.object(
                runner, "_unified_cgroup", side_effect=lambda pid: cgroups[pid]
            ),
            mock.patch.object(runner.os, "getpid", return_value=303),
        ):
            evidence = runner._membership_audit(
                object(),
                layout,
                role_pids,
                {404: 999},
                require_harness_auxiliaries=True,
            )

        self.assertEqual(evidence["roles"]["services"], [202, 204, 205, 206])
        self.assertEqual(
            evidence["appeared_during_membership_reconciliation"],
            {"application": [], "services": [205, 206], "harness": []},
        )

    def test_membership_rejects_root_exit_during_verification(self) -> None:
        layout = SimpleNamespace(
            parent=Path("/sys/fs/cgroup/test-run"),
            workload=Path("/sys/fs/cgroup/test-run/workload"),
            services=Path("/sys/fs/cgroup/test-run/services"),
            harness=Path("/sys/fs/cgroup/test-run/harness"),
        )
        with (
            mock.patch.object(Path, "read_text", return_value=""),
            mock.patch.object(
                runner,
                "_runtime_root_roles",
                return_value={"application": 101, "postgres": 202, "redis": 204},
            ),
            mock.patch.object(
                runner,
                "_process_tree",
                side_effect=lambda roots: {roots[0]},
            ),
            mock.patch.object(runner, "_process_start_time", return_value=999),
            mock.patch.object(
                runner,
                "_unified_cgroup",
                side_effect=lambda pid: (
                    (_ for _ in ()).throw(FileNotFoundError())
                    if pid == 101
                    else {
                        202: "/test-run/services",
                        204: "/test-run/services",
                        303: "/test-run/harness",
                        404: "/test-run/harness",
                    }[pid]
                ),
            ),
            mock.patch.object(runner.os, "getpid", return_value=303),
        ):
            with self.assertRaisesRegex(
                RuntimeError, "required application PID 101 disappeared"
            ):
                runner._membership_audit(
                    object(),
                    layout,
                    {
                        "application": {101},
                        "services": {202, 204},
                        "harness": {303, 404},
                    },
                    {404: 999},
                    require_harness_auxiliaries=True,
                )

    def test_process_evidence_filters_only_exited_non_root_children(self) -> None:
        role_pids = {
            "application": {101, 105},
            "services": {202, 203},
            "harness": {303, 404},
        }
        with (
            mock.patch.object(
                runner,
                "_runtime_root_roles",
                return_value={"application": 101, "postgres": 202, "redis": 203},
            ),
            mock.patch.object(runner.os, "getpid", return_value=303),
            mock.patch.object(Path, "exists", return_value=False),
        ):
            stable, vanished = runner._stable_process_evidence(
                role_pids,
                required_identity_pids={101, 202, 203, 303, 404},
                fd_counts={101: 1, 202: 1, 203: 1, 303: 1, 404: 1},
                process_memory={
                    pid: {"rss_bytes": 1, "hwm_bytes": 1}
                    for pid in (101, 202, 203, 303, 404)
                },
                process_io=_fake_process_io((101, 202, 203, 303, 404)),
            )

        self.assertEqual(vanished, [105])
        self.assertEqual(stable["application"], {101})

    def test_process_evidence_rejects_missing_required_root(self) -> None:
        with (
            mock.patch.object(
                runner,
                "_runtime_root_roles",
                return_value={"application": 101, "postgres": 202, "redis": 203},
            ),
            mock.patch.object(runner.os, "getpid", return_value=303),
        ):
            with self.assertRaisesRegex(
                RuntimeError, "required benchmark process omitted"
            ):
                runner._stable_process_evidence(
                    {
                        "application": {101},
                        "services": {202, 203},
                        "harness": {303, 404},
                    },
                    required_identity_pids={101, 202, 203, 303, 404},
                    fd_counts={101: 1, 202: 1, 203: 1, 303: 1, 404: 1},
                    process_memory={
                        pid: {"rss_bytes": 1, "hwm_bytes": 1}
                        for pid in (101, 202, 203, 303, 404)
                    },
                    process_io=_fake_process_io((202, 203, 303, 404)),
                )

    def test_parent_totals_include_service_fds_and_backing_io_without_double_count(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            monitor = self._monitor(Path(temporary))
            with (
                mock.patch.object(runner, "_filesystem_used", return_value=0),
                mock.patch.object(
                    runner, "_filesystem_free", return_value=10 * 1024**3
                ),
                mock.patch.object(
                    runner,
                    "_membership_audit",
                    return_value={"passed": True, "continuous_membership": True},
                ),
                mock.patch.object(
                    runner, "_fd_counts", return_value={101: 2, 202: 7, 303: 1}
                ),
                mock.patch.object(
                    runner,
                    "_process_memory_status",
                    side_effect=lambda pids: {
                        pid: {"rss_bytes": pid, "hwm_bytes": pid * 2} for pid in pids
                    },
                ),
                mock.patch.object(
                    runner, "_process_io_status", side_effect=_fake_process_io
                ),
                mock.patch.object(runner.time, "monotonic", return_value=1.0),
            ):
                sample = monitor._sample()
            self.assertEqual(sample["fd_count"], 10)
            self.assertEqual(sample["io_write_bytes"], 200)
            self.assertEqual(sample["io_by_device"]["7:0"]["wbytes"], 100)
            self.assertEqual(sample["io_by_device"]["8:0"]["wbytes"], 200)
            self.assertEqual(
                sample["process_memory_by_role"]["application"]["rss_bytes"], 101
            )
            self.assertEqual(
                sample["process_memory_by_role"]["services"]["hwm_bytes"], 404
            )
            self.assertEqual(
                sample["process_memory_by_role"]["total"]["rss_bytes"], 606
            )
            self.assertEqual(
                sample["cgroup_memory_by_role"]["services"]["anon_bytes"], 100
            )

    def test_service_only_resource_growth_trips_parent_limits(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            monitor = self._monitor(Path(temporary))
            with (
                mock.patch.object(runner, "_filesystem_used", return_value=0),
                mock.patch.object(
                    runner, "_filesystem_free", return_value=10 * 1024**3
                ),
                mock.patch.object(
                    runner,
                    "_membership_audit",
                    return_value={"passed": True, "continuous_membership": True},
                ),
                mock.patch.object(runner, "_fd_counts", return_value={202: 9}),
                mock.patch.object(
                    runner,
                    "_process_memory_status",
                    side_effect=lambda pids: {
                        pid: {"rss_bytes": pid, "hwm_bytes": pid * 2} for pid in pids
                    },
                ),
                mock.patch.object(
                    runner, "_process_io_status", side_effect=_fake_process_io
                ),
            ):
                with self.assertRaisesRegex(RuntimeError, "NOFILE"):
                    monitor._sample()

            (monitor.layout.parent / "memory.current").write_text(
                "2049\n", encoding="ascii"
            )
            with (
                mock.patch.object(runner, "_filesystem_used", return_value=0),
                mock.patch.object(
                    runner, "_filesystem_free", return_value=10 * 1024**3
                ),
                mock.patch.object(
                    runner,
                    "_membership_audit",
                    return_value={"passed": True, "continuous_membership": True},
                ),
                mock.patch.object(runner, "_fd_counts", return_value={202: 1}),
                mock.patch.object(
                    runner,
                    "_process_memory_status",
                    side_effect=lambda pids: {
                        pid: {"rss_bytes": pid, "hwm_bytes": pid * 2} for pid in pids
                    },
                ),
                mock.patch.object(
                    runner, "_process_io_status", side_effect=_fake_process_io
                ),
            ):
                with self.assertRaisesRegex(RuntimeError, "memory"):
                    monitor._sample()

            (monitor.layout.parent / "memory.current").write_text(
                "1024\n", encoding="ascii"
            )
            (monitor.layout.parent / "pids.current").write_text("5\n", encoding="ascii")
            with (
                mock.patch.object(runner, "_filesystem_used", return_value=0),
                mock.patch.object(
                    runner, "_filesystem_free", return_value=10 * 1024**3
                ),
                mock.patch.object(
                    runner,
                    "_membership_audit",
                    return_value={"passed": True, "continuous_membership": True},
                ),
                mock.patch.object(runner, "_fd_counts", return_value={202: 1}),
                mock.patch.object(
                    runner,
                    "_process_memory_status",
                    side_effect=lambda pids: {
                        pid: {"rss_bytes": pid, "hwm_bytes": pid * 2} for pid in pids
                    },
                ),
                mock.patch.object(
                    runner, "_process_io_status", side_effect=_fake_process_io
                ),
            ):
                with self.assertRaisesRegex(RuntimeError, "PID"):
                    monitor._sample()


if __name__ == "__main__":
    unittest.main()
