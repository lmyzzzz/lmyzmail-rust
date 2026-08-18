from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path

LAUNCHER = Path(__file__).with_name("run-smtp-endpoint-throughput-v1.sh")
DEFAULT_BASH = (
    r"C:\Program Files\Git\bin\bash.exe" if os.name == "nt" else "/usr/bin/bash"
)
GIT_BASH = Path(os.environ.get("GIT_BASH", DEFAULT_BASH))
RUN_ID = "12345678-1234-4234-9234-123456789abc"


class LauncherIsolationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = LAUNCHER.read_text(encoding="utf-8")

    @classmethod
    def bash_function(cls, name: str) -> str:
        start = cls.source.index(f"{name}() {{")
        end = cls.source.index("\n}\n", start) + 2
        return cls.source[start:end]

    @classmethod
    def embedded_python(cls, name: str) -> str:
        function = cls.bash_function(name)
        start = function.index("<<'PY'\n") + len("<<'PY'\n")
        end = function.rindex("\nPY")
        return function[start:end]

    @classmethod
    def bash_function_before(cls, name: str, next_name: str) -> str:
        start = cls.source.index(f"{name}() {{")
        next_start = cls.source.index(f"\n{next_name}() {{", start)
        end = cls.source.rindex("\n}\n", start, next_start) + 2
        return cls.source[start:end]

    def test_promotion_validator_separates_abba_and_java_small_profiles(self) -> None:
        source = self.source
        self.assertIn(
            '"mixed-single-invocation-smtp-endpoint-throughput-v2",',
            source,
        )
        self.assertIn(
            '"java-small-single-invocation-smtp-endpoint-baseline-v1",',
            source,
        )
        for contract in (
            '"arm_completeness_passed"',
            '"required_topology_passed"',
            '"proxy_headroom_passed"',
            'acceptance.get("small_message_tiers_abba") is True',
            'acceptance.get("ten_megabyte_java_prohibited") is True',
            'acceptance.get("ten_megabyte_rust_only") is True',
            'proxy.get("binary_sha256") == proxy_binary_sha',
            'proxy.get("source_tree_sha256") == proxy_source_sha',
            'value.get("execution_order") == expected_order',
        ):
            self.assertIn(contract, source)

    def test_java_small_launcher_profile_is_exact_and_rejects_10mb(self) -> None:
        parse = self.bash_function("parse_runner_arguments")
        result = self.run_bash_probe(
            f"""
set -euo pipefail
{parse}
repository=/tmp/lmyzmail-java-small-launcher-test
mkdir -p "$repository/evidence/performance"
run_id={RUN_ID}
formal_run=1
java_small_baseline_run=0
disk_budget_gib=20
image_bytes=0
declare -a runner_arguments=()
parse_runner_arguments \
    --profile java-small \
    --target java \
    --output evidence/performance/java-small.json
[[ $java_small_baseline_run == 1 ]]
[[ $formal_run == 0 ]]
[[ $disk_budget_gib == 20 ]]
[[ $image_bytes == 21474836480 ]]
[[ ${{runner_arguments[*]}} == *'--profile java-small --target java'* ]]
(
    declare -a runner_arguments=()
    ! parse_runner_arguments --profile java-small --target java \
        --tier 10mb --output evidence/performance/reject-10mb.json
)
(
    declare -a runner_arguments=()
    ! parse_runner_arguments --profile java-small --target rust \
        --output evidence/performance/reject-rust.json
)
(
    declare -a runner_arguments=()
    ! parse_runner_arguments --profile java-small --target java --smoke \
        --output evidence/performance/reject-smoke.json
)
printf 'java-small-launcher-profile: PASS\n'
"""
        )
        self.assertIn("java-small-launcher-profile: PASS", result.stdout)

    def test_launcher_binds_one_explicit_rust_filesystem_fsync_mode(self) -> None:
        parse = self.bash_function("parse_runner_arguments")
        result = self.run_bash_probe(
            f"""
set -euo pipefail
{parse}
repository=/tmp/lmyzmail-rust-fsync-launcher-test
mkdir -p "$repository/evidence/performance"
run_id={RUN_ID}
formal_run=1
java_small_baseline_run=0
profiler_run=0
rust_filesystem_fsync=not-applicable
disk_budget_gib=20
image_bytes=0
declare -a runner_arguments=()
parse_runner_arguments \
    --profile abba --target both --tier 10kb \
    --rust-filesystem-fsync off \
    --output evidence/performance/formal-off.json
[[ $formal_run == 1 ]]
[[ $rust_filesystem_fsync == off ]]
[[ ${{runner_arguments[*]}} == *'--rust-filesystem-fsync off'* ]]
(
    declare -a runner_arguments=()
    ! parse_runner_arguments --profile abba --target both --tier 10kb \
        --output evidence/performance/reject-missing.json
)
(
    declare -a runner_arguments=()
    ! parse_runner_arguments --profile abba --target rust --tier 10kb \
        --rust-filesystem-fsync=on --rust-filesystem-fsync off \
        --output evidence/performance/reject-duplicate.json
)
(
    declare -a runner_arguments=()
    ! parse_runner_arguments --profile java-small --target java \
        --rust-filesystem-fsync off \
        --output evidence/performance/reject-java-small.json
)
(
    declare -a runner_arguments=()
    parse_runner_arguments --smoke --target rust --tier 10kb \
        --output evidence/performance/smoke-default-on.json
    [[ $rust_filesystem_fsync == on ]]
    [[ ${{runner_arguments[*]}} == *'--rust-filesystem-fsync on'* ]]
)
printf 'rust-filesystem-fsync-launcher: PASS\n'
"""
        )
        self.assertIn("rust-filesystem-fsync-launcher: PASS", result.stdout)

    def test_promotion_validator_uses_process_io_only_for_rust_fsync_off(
        self,
    ) -> None:
        source = self.embedded_python("inspect_runner_artifacts")
        self.assertIn("import math", source)
        tree = ast.parse(source)
        selected = [
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "valid_application_persistence_io"
        ]
        namespace: dict[str, object] = {"expected_rust_fsync_value": "off"}
        exec(
            compile(
                ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[])),
                "<application-io-validator>",
                "exec",
            ),
            namespace,
        )
        validate = namespace["valid_application_persistence_io"]
        assert callable(validate)
        process_only = {
            "application_persistence_io_observed": False,
            "application_persistence_io_sources": {
                "process_observed": True,
                "observed": True,
            },
        }
        self.assertTrue(validate({"target": "rust-candidate"}, process_only))
        self.assertFalse(validate({"target": "java-oracle"}, process_only))
        namespace["expected_rust_fsync_value"] = "on"
        self.assertFalse(validate({"target": "rust-candidate"}, process_only))
        self.assertTrue(
            validate(
                {"target": "rust-candidate"},
                {"application_persistence_io_observed": True},
            )
        )

    def test_rust_profiler_launcher_keeps_full_isolation_without_qualification(
        self,
    ) -> None:
        parse = self.bash_function("parse_runner_arguments")
        result = self.run_bash_probe(
            f"""
set -euo pipefail
{parse}
repository=/tmp/lmyzmail-rust-profiler-launcher-test
mkdir -p "$repository/evidence/performance"
run_id={RUN_ID}
formal_run=1
java_small_baseline_run=0
profiler_run=0
disk_budget_gib=20
image_bytes=0
declare -a runner_arguments=()
parse_runner_arguments \
    --profile rust-profiler \
    --target rust \
    --tier 10kb \
    --profiler-messages 8192 \
    --output evidence/performance/rust-profiler.json
[[ $profiler_run == 1 ]]
[[ $java_small_baseline_run == 0 ]]
[[ $formal_run == 0 ]]
[[ $disk_budget_gib == 20 ]]
[[ $image_bytes == 21474836480 ]]
[[ ${{runner_arguments[*]}} == *'--profile abba --target rust --tier 10kb'* ]]
[[ ${{runner_arguments[*]}} == *'--profiler-candidate'* ]]
[[ ${{runner_arguments[*]}} == *'--profiler-messages 8192'* ]]
(
    declare -a runner_arguments=()
    ! parse_runner_arguments --profile rust-profiler --target java \
        --tier 10kb --output evidence/performance/reject-java.json
)
(
    declare -a runner_arguments=()
    ! parse_runner_arguments --profile rust-profiler --target rust \
        --tier 1kb --output evidence/performance/reject-1kb.json
)
(
    declare -a runner_arguments=()
    ! parse_runner_arguments --profile rust-profiler --target rust \
        --tier 10kb --smoke --output evidence/performance/reject-smoke.json
)
(
    declare -a runner_arguments=()
    ! parse_runner_arguments --profile abba --target rust --tier 10kb \
        --profiler-candidate --output evidence/performance/reject-injected-candidate.json
)
(
    declare -a runner_arguments=()
    ! parse_runner_arguments --profile rust-profiler --target rust --tier 10kb \
        --profiler-messages 63 --output evidence/performance/reject-profiler-63.json
)
(
    declare -a runner_arguments=()
    ! parse_runner_arguments --profile rust-profiler --target rust --tier 10kb \
        --profiler-messages=500001 \
        --output evidence/performance/reject-profiler-500001.json
)
(
    declare -a runner_arguments=()
    ! parse_runner_arguments --profile abba --target rust --tier 10kb \
        --rust-filesystem-fsync off --profiler-messages 8192 \
        --output evidence/performance/reject-formal-profiler-messages.json
)
(
    declare -a runner_arguments=()
    ! parse_runner_arguments --profile java-small --target java --tier 10kb \
        --profiler-messages 8192 \
        --output evidence/performance/reject-java-profiler-messages.json
)
(
    declare -a runner_arguments=()
    ! parse_runner_arguments --smoke --target rust --tier 10kb \
        --profiler-messages 8192 \
        --output evidence/performance/reject-smoke-profiler-messages.json
)
printf 'rust-profiler-launcher-profile: PASS\n'
"""
        )
        self.assertIn("rust-profiler-launcher-profile: PASS", result.stdout)

    def test_java_small_artifact_validator_rejects_tampered_evidence(self) -> None:
        source = self.embedded_python("inspect_runner_artifacts")
        tree = ast.parse(source)
        selected = [
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name
            in {
                "canonical_uuid4",
                "valid_sha256",
                "valid_dkim_fixture",
                "validate_checkpoint",
                "validate_output",
            }
        ]
        namespace = {
            "expected_rust_fsync_value": None,
            "formal": False,
            "hashlib": hashlib,
            "json": json,
            "launcher_run_id": RUN_ID,
            "logical_relative": "evidence/performance/java-small.json",
            "uuid": uuid,
        }
        exec(
            compile(
                ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[])),
                "<artifact-validator>",
                "exec",
            ),
            namespace,
        )
        validate_output = namespace["validate_output"]
        validate_checkpoint = namespace["validate_checkpoint"]
        plans = [
            {"label": "1KB", "message_bytes": 1024, "total_messages": 200_000},
            {"label": "10KB", "message_bytes": 10 * 1024, "total_messages": 200_000},
        ]

        def measurement() -> dict[str, object]:
            return {
                "endpoint_start_invocation_count": 1,
                "endpoint_start_automatic_retries": 0,
                "endpoint_outcome": {
                    "failure_count": 0,
                    "retry_count": 0,
                    "queue_scheduler_observed": True,
                },
                "application_log": {
                    "missing_dkim_configuration_line_count": 0,
                    "missing_dkim_configuration_lines": [],
                    "async_drop_line_count": 0,
                    "async_drop_lines": [],
                },
                "smtp": {"within_arm_throughput_stability": {"passed": True}},
                "resource": {
                    "candidate_cpu_usage_seconds": 1.0,
                    "services_cpu_usage_seconds": 1.0,
                    "application_persistence_io_observed": True,
                    "services_persistence_io_observed": True,
                    "temperature": {"within_limit": True},
                },
            }

        rows = []
        comparisons = []
        for plan, throughput in zip(plans, (1_000.0, 1_500.0), strict=True):
            observed = measurement()
            arm = {
                "target": "java-oracle",
                "rust_filesystem_fsync": None,
                "tier": plan,
                "arm_ordinal": 0,
                "endpoint_start_invocations": 1,
                "endpoint_invocations": 1,
                "harness_batches": 0,
                "endpoint_requested_messages": 200_000,
                "observer_verified_messages": 200_000,
                "requested_equals_observer_verified": True,
                "throughput_messages_per_second": throughput,
                "dkim_fixture": {
                    "profile": "lmyzmail-ephemeral-dkim-signing-fixture-v1",
                    "relative_path": "benchmark-fixtures/dkim-private.pem",
                    "selector": "mail",
                    "algorithm": "rsa-sha256",
                    "key_bits": 2048,
                    "private_key_format": "pkcs8-pem",
                    "private_key_bytes": 1704,
                    "private_key_sha256": "d" * 64,
                    "public_key_spki_sha256": "e" * 64,
                    "directory_mode": "0700",
                    "file_mode": "0600",
                    "owner_uid": 1000,
                    "owner_gid": 1000,
                    "hard_link_count": 1,
                    "inside_quota_workspace": True,
                    "production_secret_used": False,
                    "passed": True,
                },
                "measurement": observed,
            }
            rows.append(
                {
                    "target": "java-oracle",
                    "tier": plan,
                    "arm_count": 1,
                    "arms": [arm],
                    "warmups": [],
                    "measurements": [observed],
                    "endpoint_start_invocations": 1,
                    "endpoint_invocations": 1,
                    "harness_batches": 0,
                    "requested_equals_observer_verified": True,
                }
            )
            comparisons.append(
                {
                    "tier": plan["label"],
                    "target": "java-oracle",
                    "requested_messages": 200_000,
                    "observer_verified_messages": 200_000,
                    "throughput_messages_per_second": throughput,
                    "single_endpoint_invocation": True,
                    "queue_scheduler_observed": True,
                    "passed": True,
                }
            )
        payload = {
            "schema_version": 1,
            "profile": "java-small-single-invocation-smtp-endpoint-baseline-v1",
            "launcher_run_id": RUN_ID,
            "run_id": "87654321-4321-4321-8321-abcdefabcdef",
            "status": "passed",
            "qualified": False,
            "rust_filesystem_fsync": None,
            "qualification_prerequisites_passed": False,
            "endpoint_invocations": 1,
            "endpoint_invocation_scope": "per_arm",
            "harness_batches": 0,
            "total_endpoint_invocations": 2,
            "endpoint_requested_messages": [200_000, 200_000],
            "observer_verified_messages": [200_000, 200_000],
            "endpoint_requested_messages_match_observer_verified": True,
            "plans": plans,
            "execution_order": [
                {"target": "java-oracle", "tier": plan["label"], "arm_ordinal": 0}
                for plan in plans
            ],
            "comparison": {
                "comparisons": comparisons,
                "all_passed": True,
                "baseline_complete_passed": True,
                "plan_order_passed": True,
                "operational_evidence_passed": True,
                "zero_retry_gate_passed": True,
                "java_only_passed": True,
                "single_arm_per_tier_passed": True,
                "ten_megabyte_excluded": True,
            },
            "acceptance": {
                "passed": True,
                "qualified": False,
                "no_batching": True,
                "java_small_baseline": True,
                "java_only": True,
                "one_arm_per_tier": True,
                "one_endpoint_invocation_per_tier": True,
                "one_kib_then_ten_kib": True,
                "two_hundred_thousand_messages_per_tier": True,
                "ten_megabyte_excluded": True,
                "not_qualification_evidence": True,
                "no_warmup_endpoint_calls": True,
                "no_repetition_loop": True,
                "no_stress_start_retries": True,
            },
            "methodology": {
                "rust_filesystem_fsync": None,
                "one_rust_filesystem_fsync_mode_per_evidence_file": True,
                "per_tier_order": "1KB then 10KB",
                "per_tier_arms": ["java-oracle"],
                "one_large_start_invocation_per_arm": True,
                "harness_batching": False,
                "automatic_endpoint_cleanup_only": True,
                "warmup_endpoint_invocations": 0,
                "repetition_loop": False,
                "single_logical_cpu_for_application": True,
                "io_limit_bytes_per_second_read_and_write": 500_000_000,
                "hard_disk_budget_bytes": 20 * 1024**3,
                "performance_gate_uses_both_ordinal_pairs": False,
                "performance_gate_uses_min_rust_over_max_java": False,
                "java_small_baseline_is_not_qualification_evidence": True,
                "java_stress_runtime_profile": {
                    "profile": "java-oracle-frozen-production-stress-path-v1",
                    "source_path": (
                        "evidence/freeze/java-oracle/application.properties.redacted"
                    ),
                    "source_sha256": (
                        "350effbab18151cf78d5e850ee22d8d22569b30e2f38b18b281b7a8b50be3394"
                    ),
                    "dkim_signing_fixture": {
                        "provisioning": "fresh-per-isolated-arm",
                        "algorithm": "rsa-sha256",
                        "key_bits": 2048,
                        "private_key_format": "pkcs8-pem",
                        "selector": "mail",
                        "relative_path": "benchmark-fixtures/dkim-private.pem",
                        "directory_mode": "0700",
                        "file_mode": "0600",
                        "production_secret_used": False,
                    },
                    "forbidden_measurement_log_prefixes": [
                        "No DKIM configuration for domain:",
                        "Async drop: email rejected after verification:",
                    ],
                },
            },
            "rows": rows,
            "dns_fixture": {
                "profile": "lmyzmail-smtp-benchmark-dns-v1",
                "spf_record": "v=spf1 +all",
                "dmarc_record": "v=DMARC1; p=none; adkim=s; aspf=s",
                "dkim": {
                    "profile": "lmyzmail-shared-ephemeral-dkim-material-v1",
                    "selector": "mail",
                    "domain": "lmyz.net",
                    "dns_name": "mail._domainkey.lmyz.net",
                    "algorithm": "rsa-sha256",
                    "key_bits": 2048,
                    "private_key_format": "pkcs8-pem",
                    "private_key_sha256": "d" * 64,
                    "public_key_spki_sha256": "e" * 64,
                    "public_dns_record_sha256": "f" * 64,
                    "production_secret_used": False,
                    "passed": True,
                },
                "query_counts": {
                    "dkim_txt": 2,
                    "dmarc_txt": 2,
                    "spf_txt": 2,
                    "mx": 2,
                    "a": 2,
                },
                "dkim_txt_query_count": 2,
                "dmarc_txt_query_count": 2,
                "passed": True,
            },
            "attestation": {
                "rust_filesystem_fsync": None,
                "runner_sha256": "a" * 64,
                "launcher_sha256": "b" * 64,
                "benchmark_definition": {"sha256": "c" * 64},
            },
            "external_prerequisites": {"provided": False, "passed": False},
            "real_gate_calibration": {
                "required_for_qualification": False,
                "performed": False,
            },
        }
        result = validate_output(json.dumps(payload).encode("utf-8"))
        self.assertEqual(result[0], payload)
        self.assertEqual(result[2], payload["profile"])

        mutations = []
        with_10mb = json.loads(json.dumps(payload))
        with_10mb["plans"].append(
            {"label": "10MB", "message_bytes": 10 * 1024 * 1024, "total_messages": 1}
        )
        mutations.append(with_10mb)
        wrong_count = json.loads(json.dumps(payload))
        wrong_count["endpoint_requested_messages"][1] = 200_001
        mutations.append(wrong_count)
        missing_queue_proof = json.loads(json.dumps(payload))
        missing_queue_proof["rows"][0]["arms"][0]["measurement"]["endpoint_outcome"][
            "queue_scheduler_observed"
        ] = False
        mutations.append(missing_queue_proof)
        missing_dkim_fixture = json.loads(json.dumps(payload))
        del missing_dkim_fixture["rows"][0]["arms"][0]["dkim_fixture"]
        mutations.append(missing_dkim_fixture)
        unsigned_warning = json.loads(json.dumps(payload))
        unsigned_warning["rows"][0]["arms"][0]["measurement"]["application_log"][
            "missing_dkim_configuration_line_count"
        ] = 1
        mutations.append(unsigned_warning)
        async_drop = json.loads(json.dumps(payload))
        async_drop["rows"][0]["arms"][0]["measurement"]["application_log"][
            "async_drop_line_count"
        ] = 1
        mutations.append(async_drop)
        missing_dns = json.loads(json.dumps(payload))
        del missing_dns["dns_fixture"]
        mutations.append(missing_dns)
        mixed_fsync = json.loads(json.dumps(payload))
        mixed_fsync["rows"][0]["arms"][0]["rust_filesystem_fsync"] = "off"
        mutations.append(mixed_fsync)
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaises(SystemExit):
                    validate_output(json.dumps(mutation).encode("utf-8"))

        output_sha256 = "d" * 64

        def checkpoint_payload(started_profile: str) -> bytes:
            values = [
                {
                    "event": "started",
                    "run_id": payload["run_id"],
                    "launcher_run_id": RUN_ID,
                    "benchmark_profile": started_profile,
                    "rust_filesystem_fsync": None,
                },
                {
                    "event": "completed",
                    "run_id": payload["run_id"],
                    "launcher_run_id": RUN_ID,
                    "status": "passed",
                    "qualified": False,
                    "rust_filesystem_fsync": None,
                    "output": "evidence/performance/java-small.json",
                    "output_sha256": output_sha256,
                    "comparison": payload["comparison"],
                },
            ]
            records = []
            previous = None
            for sequence, value in enumerate(values):
                record = {
                    **value,
                    "_sequence": sequence,
                    "_previous_record_sha256": previous,
                }
                canonical = json.dumps(
                    record, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
                record["_record_sha256"] = hashlib.sha256(canonical).hexdigest()
                previous = record["_record_sha256"]
                records.append(record)
            return b"\n".join(
                json.dumps(record, sort_keys=True, separators=(",", ":")).encode(
                    "utf-8"
                )
                for record in records
            )

        validate_checkpoint(
            checkpoint_payload(payload["profile"]),
            payload,
            output_sha256,
            payload["run_id"],
            False,
        )
        with self.assertRaises(SystemExit):
            validate_checkpoint(
                checkpoint_payload(
                    "abba-single-invocation-smtp-endpoint-throughput-v1"
                ),
                payload,
                output_sha256,
                payload["run_id"],
                False,
            )

    def test_external_attestation_rehashes_proxy_binary_and_source_tree(self) -> None:
        function = self.bash_function_before(
            "create_external_attestation", "start_cgroup_supervisor"
        )
        self.assertIn('proxy_binary="${repository}/target/', self.source)
        self.assertIn("hashlib.sha256(proxy_binary.read_bytes())", function)
        self.assertIn('repository / "crates/lmyzmail-benchmark-proxy"', function)
        self.assertIn('proxy.get("binary_sha256") != proxy_binary_sha', function)
        self.assertIn('proxy.get("source_tree_sha256") != proxy_source_sha', function)
        self.assertIn('value.get("backend_reply_block_limit_bytes")', function)
        self.assertIn('value.get("accounted_backend_reply_buffer_bytes")', function)
        self.assertIn('value.get("configured_max_connections")', function)
        self.assertIn('value.get("required_memory_budget_bytes")', function)
        self.assertIn("expected_required_budget_bytes", function)
        self.assertIn("proxy_memory_evidence_passed(raw_proxy)", function)

    def run_bash_probe(
        self, script: str, *, timeout: float = 10
    ) -> subprocess.CompletedProcess[str]:
        self.assertTrue(GIT_BASH.is_file(), f"Git Bash is missing: {GIT_BASH}")
        result = subprocess.run(
            [str(GIT_BASH)],
            input=script,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        self.assertEqual(
            result.returncode,
            0,
            f"Git Bash probe failed\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )
        return result

    def test_launcher_has_valid_bash_syntax(self) -> None:
        result = subprocess.run(
            [str(GIT_BASH), "-n", str(LAUNCHER)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_all_embedded_python_heredocs_compile(self) -> None:
        blocks = re.findall(r"<<'PY'\n(.*?)\nPY(?:\n|$)", self.source, re.DOTALL)
        self.assertEqual(len(blocks), self.source.count("<<'PY'"))
        for index, block in enumerate(blocks):
            with self.subTest(index=index):
                compile(block, f"<launcher-heredoc-{index}>", "exec")

    def test_persistent_root_and_controller_enablement_are_monotonic(self) -> None:
        source = self.source
        self.assertIn("persistent_group=${cgroup_root}/lmyzmail-benchmark-root", source)
        self.assertIn("enable_controller_monotonic", source)
        self.assertNotIn("printf -- '-%s", source)
        self.assertNotIn("disable_controller", source)

        function = self.bash_function("enable_controller_monotonic")
        with tempfile.TemporaryDirectory() as temporary:
            group = Path(temporary).as_posix()
            self.run_bash_probe(
                f"""
set -euo pipefail
{function}
printf 'cpuset\n' > {group!r}/cgroup.subtree_control
write_calls=0
write_subtree_control() {{
    ((write_calls += 1))
    printf 'cpuset cpu\n' > "$1"
    return 1
}}
enable_controller_monotonic {group!r} cpu
[[ $write_calls -eq 1 ]]
grep -qw cpu {group!r}/cgroup.subtree_control
printf 'monotonic-controller-enable: PASS\n'
"""
            )

    def test_fixed_uuid_derives_every_resource_path(self) -> None:
        function = self.bash_function("derive_run_paths")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).as_posix()
            result = self.run_bash_probe(
                f"""
set -euo pipefail
{function}
persistent_group={root!r}/cgroup/lmyzmail-benchmark-root
journal_root={root!r}/journal
image_root={root!r}/images
artifact_root={root!r}/artifacts
mounts_root={root!r}/mounts
runtime_root={root!r}
derive_run_paths {RUN_ID!r}
[[ $benchmark_group == "$persistent_group/run-{RUN_ID}" ]]
[[ $harness_group == "$benchmark_group/harness" ]]
[[ $workload_group == "$benchmark_group/workload" ]]
[[ $services_group == "$benchmark_group/services" ]]
[[ $migration_socket == {root!r}/cgroup-supervisor-{RUN_ID}.sock ]]
[[ $runner_gate == {root!r}/runner-gate-{RUN_ID}.fifo ]]
[[ $intent_path == "$journal_root/{RUN_ID}.intent" ]]
[[ $done_path == "$journal_root/{RUN_ID}.done" ]]
[[ $runner_success_path == "$journal_root/{RUN_ID}.runner-success" ]]
[[ $partial_output_publish_path == "$journal_root/{RUN_ID}.partial-publish.output" ]]
[[ $partial_checkpoint_publish_path == "$journal_root/{RUN_ID}.partial-publish.checkpoint" ]]
[[ $image_path == "$image_root/{RUN_ID}.ext4" ]]
[[ $output_artifact == "$artifact_root/{RUN_ID}.output" ]]
[[ $checkpoint_artifact == "$artifact_root/{RUN_ID}.checkpoint" ]]
[[ $quota_mount == "$mounts_root/{RUN_ID}" ]]
printf 'fixed-run-paths: PASS\n'
"""
            )
        self.assertIn("fixed-run-paths: PASS", result.stdout)

    def test_recovery_and_watchdog_readiness_precede_current_run_mutations(
        self,
    ) -> None:
        source = self.source
        recover = source.rindex("\nrecover_incomplete_runs\n")
        new_run = source.rindex("\nrun_id=$(new_run_id)\n")
        coproc = source.rindex("coproc BENCHMARK_WATCHDOG")
        ready_read = source.rindex("watchdog_ready watchdog_reported_pid")
        intent = source.rindex("\nwrite_intent\n")
        controllers = source.rindex("\nenable_persistent_controllers\n")
        allocation = source.rindex("\nallocate_quota_filesystem\n")
        preflight = source.rindex("\npreflight_image_capacity\n")
        self.assertLess(controllers, recover)
        self.assertLess(recover, new_run)
        self.assertLess(new_run, preflight)
        self.assertLess(preflight, coproc)
        self.assertLess(coproc, ready_read)
        self.assertLess(ready_read, intent)
        self.assertLess(intent, allocation)
        self.assertIn("benchmark watchdog did not inherit the benchmark lock", source)

    def test_intent_and_done_journals_are_root_owned_create_only(self) -> None:
        function = self.bash_function("write_journal_once")
        with tempfile.TemporaryDirectory() as temporary:
            target = (Path(temporary) / "run.intent").as_posix()
            self.run_bash_probe(
                f"""
set -euo pipefail
{function}
fsync_file_and_parent() {{ :; }}
fsync_directory() {{ :; }}
chown() {{ :; }}
chmod() {{ :; }}
stat() {{ printf '0:0:400:1:regular file\n'; }}
write_journal_once {target!r} first
[[ $(<{target!r}) == first ]]
if write_journal_once {target!r} second; then
    exit 30
fi
[[ $(<{target!r}) == first ]]
printf 'create-only-journal: PASS\n'
"""
            )

    def test_journal_mutation_failures_propagate_inside_conditionals(self) -> None:
        function = self.bash_function("write_journal_once")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).as_posix()
            result = self.run_bash_probe(
                f"""
set -euo pipefail
{function}
root={root!r}
fail=
directory_sync_calls=0
chmod() {{ [[ $fail != chmod ]]; }}
chown() {{ [[ $fail != chown ]]; }}
fsync_file_and_parent() {{ [[ $fail != file-fsync ]]; }}
fsync_directory() {{
    ((directory_sync_calls += 1))
    [[ $fail != directory-fsync && ! ( $fail == second-directory-fsync && $directory_sync_calls -eq 2 ) ]]
}}
ln() {{ [[ $fail != link ]] && command ln "$@"; }}
stat() {{ printf '0:0:400:1:regular file\n'; }}
for fail in chmod chown file-fsync link directory-fsync; do
    directory_sync_calls=0
    target="$root/$fail.intent"
    if write_journal_once "$target" payload; then
        exit 50
    fi
done
fail=second-directory-fsync
directory_sync_calls=0
target="$root/second-directory-fsync.intent"
if write_journal_once "$target" payload; then
    exit 51
fi
[[ -f $target && $(<"$target") == payload ]]
fail=
directory_sync_calls=0
write_journal_once "$root/success.intent" payload
[[ $(<"$root/success.intent") == payload ]]
printf 'journal-failure-propagation: PASS\n'
"""
            )
        self.assertIn("journal-failure-propagation: PASS", result.stdout)

    def test_journal_writer_is_newline_terminated_and_reader_accepts_legacy_eof(
        self,
    ) -> None:
        writer = self.bash_function("write_journal_once")
        reader = self.bash_function("read_journal_value")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).as_posix()
            result = self.run_bash_probe(
                f"""
set -euo pipefail
{writer}
{reader}
fsync_file_and_parent() {{ :; }}
fsync_directory() {{ :; }}
chown() {{ :; }}
chmod() {{ :; }}
stat() {{ printf '0:0:400:1:regular file\n'; }}
root={root!r}
payload=$(printf 'first=1\nlast=2\n')
write_journal_once "$root/current" "$payload"
[[ $(tail -c 1 "$root/current" | od -An -tuC | tr -d ' ') == 10 ]]
[[ $(read_journal_value "$root/current" last) == 2 ]]
printf '%s' "$payload" >"$root/legacy"
[[ $(read_journal_value "$root/legacy" last) == 2 ]]
printf 'journal-newline-compatibility: PASS\n'
"""
            )
        self.assertIn("journal-newline-compatibility: PASS", result.stdout)

    def test_root_private_artifact_fd_ownership_is_explicit(self) -> None:
        source = self.source
        create = self.bash_function("create_root_artifacts")
        register = self.bash_function("register_managed_artifacts")
        watchdog = self.bash_function("root_cleanup_watchdog")
        self.assertIn(
            '"${artifact_root}"', source[source.index("install -d -m 0700") :]
        )
        self.assertIn(
            'chmod 0600 -- "${output_artifact}" "${checkpoint_artifact}"', create
        )
        self.assertIn('exec 8<>"${output_artifact}"', create)
        self.assertIn('exec 9<>"${checkpoint_artifact}"', create)
        self.assertIn("--output-fd 8 --checkpoint-fd 9", source)
        self.assertIn('exec {managed_output_fd}<"${output_artifact}"', register)
        self.assertIn('exec {managed_checkpoint_fd}<"${checkpoint_artifact}"', register)
        self.assertIn(
            "[[ -f ${output_fd_path} && -f ${checkpoint_fd_path} ]]", register
        )
        self.assertIn("600:1", register)
        self.assertNotIn("%F", register)
        self.assertIn("watchdog_artifacts_match_receipt", watchdog)
        self.assertIn("validate_runner_success", watchdog)

        artifacts = source.rindex("printf 'ARTIFACTS %s %s %s %s")
        runner = source.rindex("unshare --mount --propagation private")
        close_launcher_fds = source.rindex("\nclose_runner_artifact_fds\n")
        self.assertLess(artifacts, runner)
        self.assertLess(runner, close_launcher_fds)
        self.assertLess(close_launcher_fds, source.rindex("runner_start_time=$("))

    def test_unqualified_artifact_cleanup_is_bounded_and_fail_closed(self) -> None:
        cleanup = self.bash_function("remove_unqualified_artifacts")
        self.assertIn("${success_schema} == 2", cleanup)
        self.assertIn("path.parent != root", cleanup)
        self.assertIn("os.O_NOFOLLOW", cleanup)
        self.assertIn("root_metadata.st_uid == 0", cleanup)
        self.assertIn("root_metadata.st_gid == 0", cleanup)
        self.assertIn("metadata.st_nlink == path_metadata.st_nlink == 1", cleanup)
        self.assertIn("{0o600, 0o444}", cleanup)
        self.assertIn("{0o600, 0o400}", cleanup)
        self.assertIn("os.unlink(path.name, dir_fd=directory)", cleanup)
        self.assertIn("os.fsync(directory)", cleanup)
        self.assertGreaterEqual(
            self.source.count('remove_unqualified_artifacts "${identifier}"'), 3
        )
        self.assertIn('remove_unqualified_artifacts "${run_id}"', self.source)

    def test_artifact_validation_rejects_alias_replay_and_checkpoint_tamper(
        self,
    ) -> None:
        inspector = self.bash_function("inspect_runner_artifacts")
        self.assertIn("metadata.st_nlink != 1", inspector)
        self.assertIn("current.st_nlink in allowed_links", inspector)
        self.assertIn("identity differs from the runner receipt", inspector)
        self.assertIn("output_sha != expected_output_sha", inspector)
        self.assertIn("checkpoint_sha != expected_checkpoint_sha", inspector)
        self.assertIn("completed checkpoint hash chain is invalid", inspector)
        self.assertIn('value.get("launcher_run_id") != launcher_run_id', inspector)
        self.assertIn('completed.get("run_id") == runner_run_id', inspector)

    def test_image_is_fully_allocated_and_both_devices_are_throttled(self) -> None:
        allocate = self.bash_function("allocate_quota_filesystem")
        self.assertIn('fallocate -l "${image_bytes}"', allocate)
        self.assertIn("allocated_bytes=$((allocated_blocks * 512))", allocate)
        self.assertIn("allocated_bytes < image_bytes", allocate)
        self.assertIn("benchmark image is sparse", allocate)

        io_writer = self.bash_function("write_io_max_line")
        io_verify = self.bash_function("verify_io_max_limit")
        io_limit = self.bash_function("write_io_max_limit")
        configure = self.bash_function("configure_run_cgroups")
        self.assertIn("printf '+cpuset +cpu +io +memory +pids\\n'", configure)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).as_posix()
            result = self.run_bash_probe(
                f"""
set -euo pipefail
{io_writer}
{io_verify}
{io_limit}
{configure}
benchmark_group={root!r}/run
harness_group="$benchmark_group/harness"
workload_group="$benchmark_group/workload"
services_group="$benchmark_group/services"
root_cpus=0-3
root_mems=0
benchmark_cpu=3
housekeeping_cpus=0-2
loop_device_id=7:0
backing_device_id=8:0
io_bytes_per_second=500000000
max_pids=8192
max_memory_bytes=8589934592
benchmark_uid=1000
benchmark_gid=1000
io_write_log={root!r}/io-writes
write_io_max_line() {{
    local path=$1 line=$2 device temporary
    device=${{line%% *}}
    temporary="${{path}}.next"
    if [[ -f $path ]]; then
        grep -Fv -- "${{device}} " "$path" >"$temporary" || :
    else
        : >"$temporary"
    fi
    printf '%s riops=max wiops=max\n' "$line" >>"$temporary"
    mv -- "$temporary" "$path"
    printf '%s\n' "$line" >>"$io_write_log"
}}
chown() {{ :; }}
stage_checkpoint() {{ [[ $1 == cgroups-configured ]]; }}
configure_run_cgroups
grep -qx '7:0 rbps=500000000 wbps=500000000 riops=max wiops=max' "$benchmark_group/io.max"
grep -qx '8:0 rbps=500000000 wbps=500000000 riops=max wiops=max' "$benchmark_group/io.max"
[[ $(wc -l < "$benchmark_group/io.max") -eq 2 ]]
[[ $(wc -l < "$io_write_log") -eq 2 ]]
[[ $(sed -n '1p' "$io_write_log") == '7:0 rbps=500000000 wbps=500000000' ]]
[[ $(sed -n '2p' "$io_write_log") == '8:0 rbps=500000000 wbps=500000000' ]]
[[ $(<"$benchmark_group/pids.max") == 8192 ]]
[[ $(<"$benchmark_group/memory.max") == 8589934592 ]]
[[ $(<"$benchmark_group/memory.swap.max") == 0 ]]
[[ $(<"$services_group/cpuset.cpus") == 0-2 ]]
[[ $(<"$harness_group/cpuset.cpus") == 0-2 ]]
[[ $(<"$workload_group/cpuset.cpus") == 3 ]]
probe={root!r}/io-max-probe
printf '7:0 wiops=max wbps=500000000 rbps=500000000 riops=max\n' >"$probe"
verify_io_max_limit "$probe" 7:0 500000000
printf '7:0 rbps=500000000 wbps=500000000 riops=1 wiops=max\n' >"$probe"
! verify_io_max_limit "$probe" 7:0 500000000
printf '7:0 rbps=500000000 wbps=500000000 riops=max wiops=max\n7:0 rbps=500000000 wbps=500000000 riops=max wiops=max\n' >"$probe"
! verify_io_max_limit "$probe" 7:0 500000000
printf '7:0 rbps=500000000 wbps=500000000 riops=max wiops=max future=max\n' >"$probe"
! verify_io_max_limit "$probe" 7:0 500000000
printf 'dual-device-io-limit: PASS\n'
"""
            )
        self.assertIn("dual-device-io-limit: PASS", result.stdout)

    def test_headroom_attestation_is_generated_automatically_in_harness_cgroup(
        self,
    ) -> None:
        producer = self.bash_function("generate_proxy_attestation")
        self.assertNotIn("LMYZMAIL_BENCHMARK_PROXY_ATTESTATION=", self.source)
        self.assertNotIn("LMYZMAIL_BENCHMARK_PROXY_ATTESTATION_SHA256", self.source)
        self.assertIn('"${BASHPID}" >"${harness_group}/cgroup.procs"', producer)
        self.assertIn('"${proxy_binary}" headroom-attest', producer)
        self.assertIn('--nofile="${nofile_limit}:${nofile_limit}"', producer)
        self.assertIn(
            "generate_proxy_attestation || ! create_external_attestation",
            self.source,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            harness = root / "cgroup" / "harness"
            harness.mkdir(parents=True)
            proxy = root / "proxy"
            proxy.write_text(
                """#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" >"$ARG_LOG"
output_root=
while (($#)); do
    if [[ $1 == --output-root ]]; then output_root=$2; break; fi
    shift
done
zero=0000000000000000000000000000000000000000000000000000000000000000
mkdir -p -- "$output_root"
target="$output_root/$zero.json"
: >"$target"
printf '%s\n%s\n' "$target" "$zero"
""",
                encoding="utf-8",
                newline="\n",
            )
            proxy.chmod(0o755)
            prlimit = root / "prlimit"
            prlimit.write_text(
                """#!/usr/bin/env bash
set -euo pipefail
while [[ $1 != -- ]]; do shift; done
shift
exec "$@"
""",
                encoding="utf-8",
                newline="\n",
            )
            prlimit.chmod(0o755)
            root_bash = (
                f"/{root.drive[0].lower()}{root.as_posix()[2:]}"
                if os.name == "nt"
                else root.as_posix()
            )
            result = self.run_bash_probe(
                producer
                + f"""
set -euo pipefail
export PATH={root_bash!r}:$PATH
export ARG_LOG={str(root / "args.log").replace(chr(92), "/")!r}
proxy_binary={proxy.as_posix()!r}
proxy_attestation_root={str(root / "attestations").replace(chr(92), "/")!r}
runner=/runner
benchmark_group={str(root / "cgroup").replace(chr(92), "/")!r}
harness_group={harness.as_posix()!r}
benchmark_cpu=3
housekeeping_cpus=0-2
loop_device_id=7:1
backing_device_id=7:0
io_bytes_per_second=500000000
max_memory_bytes=8589934592
max_pids=8192
nofile_limit=8192
benchmark_proxy_source_sha256() {{ printf '%064d\n' 0; }}
sha256sum() {{ printf '%064d  %s\n' 0 "$2"; }}
generate_proxy_attestation
[[ -f $proxy_attestation_path ]]
[[ $proxy_attestation_sha256 == $(printf '%064d' 0) ]]
[[ $(<"$harness_group/cgroup.procs") =~ ^[0-9]+$ ]]
grep -qx headroom-attest "$ARG_LOG"
grep -qx -- --nofile-soft-and-hard "$ARG_LOG"
grep -qx 8192 "$ARG_LOG"
printf 'automatic-headroom-producer: PASS\n'
"""
            )
        self.assertIn("automatic-headroom-producer: PASS", result.stdout)

    def test_every_mutation_stage_has_launcher_sigkill_and_live_stages_have_watchdog_sigkill(
        self,
    ) -> None:
        stages = (
            "intent-durable",
            "artifact-capabilities-durable",
            "controllers-enabled",
            "image-allocated",
            "loop-attached",
            "quota-mounted",
            "cgroups-configured",
            "attestation-durable",
            "runner-registered",
            "runner-success-durable",
            "cleanup-receipt-durable",
            "final-published",
        )
        watchdog_live_stages = stages[:10]
        for stage in stages:
            self.assertIn(f"stage_checkpoint {stage}", self.source)

        function = self.bash_function("stage_checkpoint")
        quoted_stages = " ".join(stages)
        quoted_watchdog_stages = " ".join(watchdog_live_stages)
        self.run_bash_probe(
            f"""
set -euo pipefail
{function}
LMYZMAIL_BENCHMARK_TEST_MODE=1
watchdog_pid=777
watchdog_started=1
kill_log=$(mktemp)
kill() {{ printf '%s\n' "$*" >> "$kill_log"; }}
wait() {{ :; }}
for stage in {quoted_stages}; do
    LMYZMAIL_BENCHMARK_TEST_CRASH_AFTER="launcher:$stage"
    stage_checkpoint "$stage"
done
for stage in {quoted_watchdog_stages}; do
    watchdog_pid=777
    watchdog_started=1
    LMYZMAIL_BENCHMARK_TEST_CRASH_AFTER="watchdog:$stage"
    if stage_checkpoint "$stage"; then
        exit 32
    else
        [[ $? -eq 137 ]]
    fi
    [[ -z $watchdog_pid && $watchdog_started -eq 0 ]]
done
[[ $(grep -c -- "-KILL --" "$kill_log") -eq {len(stages) + len(watchdog_live_stages)} ]]
[[ $(grep -c -- "-KILL -- 777" "$kill_log") -eq {len(watchdog_live_stages)} ]]
printf 'all-sigkill-checkpoints: PASS\n'
"""
        )

    def test_normal_cleanup_has_strict_destructive_order(self) -> None:
        cleanup = self.bash_function("cleanup_run_resources")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).as_posix()
            result = self.run_bash_probe(
                f"""
set -euo pipefail
{cleanup}
log={root!r}/calls
derive_run_paths() {{
    benchmark_group={root!r}/run
    harness_group="$benchmark_group/harness"
    workload_group="$benchmark_group/workload"
    services_group="$benchmark_group/services"
    image_path={root!r}/run.ext4
    quota_mount={root!r}/mount
    migration_socket={root!r}/supervisor.sock
    runner_gate={root!r}/runner-gate.fifo
}}
mkdir -p {root!r}/run/harness {root!r}/run/services {root!r}/run/workload {root!r}/mount
: > {root!r}/run.ext4
: > {root!r}/supervisor.sock
: > {root!r}/runner-gate.fifo
kill_benchmark_cgroup() {{ echo kill >> "$log"; }}
wait_for_cgroup_unpopulated() {{ echo unpopulated >> "$log"; }}
terminate_members() {{ exit 40; }}
mount_is_active() {{ return 0; }}
umount() {{ echo "umount $*" >> "$log"; }}
loop_devices_for_image() {{ echo /dev/loop7; }}
losetup() {{ echo "losetup $*" >> "$log"; }}
rm() {{ echo "rm $*" >> "$log"; command rm "$@"; }}
rmdir() {{ echo "rmdir $*" >> "$log"; command rmdir "$@"; }}
cleanup_run_resources {RUN_ID!r} 0
mapfile -t calls < "$log"
[[ ${{calls[0]}} == kill ]]
[[ ${{calls[1]}} == unpopulated ]]
[[ ${{calls[2]}} == "umount -- {root}/mount" ]]
[[ ${{calls[3]}} == "losetup -d /dev/loop7" ]]
[[ ${{calls[4]}} == "rm -f -- {root}/run.ext4" ]]
[[ ${{calls[5]}} == "rmdir -- {root}/run/workload" ]]
[[ ${{calls[6]}} == "rmdir -- {root}/run/services" ]]
[[ ${{calls[7]}} == "rmdir -- {root}/run/harness" ]]
[[ ${{calls[8]}} == "rmdir -- {root}/run" ]]
[[ ${{calls[9]}} == "rmdir -- {root}/mount" ]]
[[ ${{calls[10]}} == "rm -f -- {root}/supervisor.sock" ]]
[[ ${{calls[11]}} == "rm -f -- {root}/runner-gate.fifo" ]]
printf 'strict-cleanup-order: PASS\n'
"""
            )
        self.assertIn("strict-cleanup-order: PASS", result.stdout)

    def test_lazy_unmount_is_recovery_only_and_disqualifies_receipt(self) -> None:
        cleanup = self.bash_function("cleanup_run_resources")
        receipt = self.bash_function("write_cleanup_receipt")
        self.assertIn("[[ ${allow_lazy} == 1 ]]", cleanup)
        self.assertIn("cleanup_lazy_used=1", cleanup)
        self.assertIn("${success_schema} == 2 && ${lazy} == 0", receipt)
        self.assertIn("qualified_cleanup=${qualified}", receipt)

    def test_historical_schema3_cleanup_is_only_accepted_as_unqualified(self) -> None:
        validator = self.bash_function(
            "validate_historical_unqualified_cleanup_receipt"
        )
        receipt = self.bash_function("write_cleanup_receipt")
        self.assertIn("'0:0:400:1:regular file'", validator)
        self.assertIn("schema_version) == 3", validator)
        self.assertIn("qualified_cleanup) == 0", validator)
        self.assertIn("provisional_sha256) == missing", validator)
        self.assertIn("-z ${checkpoint} || ${checkpoint} == missing", validator)
        self.assertIn("validate_historical_unqualified_cleanup_receipt", receipt)
        self.assertIn("(( qualified == 0 ))", receipt)

        with tempfile.TemporaryDirectory() as temporary:
            receipt_path = Path(temporary, "historical.done")
            receipt_path.touch()
            result = self.run_bash_probe(
                f"""
set -euo pipefail
{validator}
stat() {{ printf '0:0:400:1:regular file\n'; }}
schema=3
qualified=0
provisional=missing
        stub_checkpoint=absent
read_journal_value() {{
    case $2 in
        schema_version) printf '%s\n' "$schema" ;;
        run_id) printf '%s\n' {RUN_ID!r} ;;
        request) printf 'ABORT\n' ;;
        cleanup) printf 'passed\n' ;;
        lazy_unmount|recovered) printf '0\n' ;;
        qualified_cleanup) printf '%s\n' "$qualified" ;;
        provisional_sha256) printf '%s\n' "$provisional" ;;
        checkpoint_sha256)
            [[ $stub_checkpoint != absent ]] || return 1
            printf '%s\n' "$stub_checkpoint"
            ;;
        *) return 1 ;;
    esac
}}
validate_historical_unqualified_cleanup_receipt \
    {receipt_path.as_posix()!r} {RUN_ID!r}
qualified=1
! validate_historical_unqualified_cleanup_receipt \
    {receipt_path.as_posix()!r} {RUN_ID!r}
qualified=0
provisional=$(printf 'a%.0s' {{1..64}})
! validate_historical_unqualified_cleanup_receipt \
    {receipt_path.as_posix()!r} {RUN_ID!r}
provisional=missing
stub_checkpoint=missing
validate_historical_unqualified_cleanup_receipt \
    {receipt_path.as_posix()!r} {RUN_ID!r}
stub_checkpoint=$(printf 'b%.0s' {{1..64}})
! validate_historical_unqualified_cleanup_receipt \
    {receipt_path.as_posix()!r} {RUN_ID!r}
printf 'historical-schema3-unqualified-only: PASS\n'
"""
            )
        self.assertIn("historical-schema3-unqualified-only: PASS", result.stdout)

    def test_recovery_is_idempotent_across_two_entries(self) -> None:
        recover = self.bash_function("recover_incomplete_runs")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).as_posix()
            result = self.run_bash_probe(
                f"""
set -euo pipefail
{recover}
journal_root={root!r}/journal
mkdir -p "$journal_root"
: > "$journal_root/{RUN_ID}.intent"
cleanup_calls=0
receipt_calls=0
artifact_cleanup_calls=0
validate_intent() {{ derive_run_paths "$2"; }}
derive_run_paths() {{
    done_path="$journal_root/$1.done"
    runner_success_path="$journal_root/$1.runner-success"
}}
cleanup_run_resources() {{ ((cleanup_calls += 1)); cleanup_lazy_used=0; }}
write_cleanup_receipt() {{ ((receipt_calls += 1)); : > "$done_path"; }}
read_journal_value() {{
    case "$1:$2" in
        *.intent:schema_version) printf '2\n' ;;
        *) printf '%s\n' {root!r}/final.json ;;
    esac
}}
remove_unqualified_artifacts() {{ ((artifact_cleanup_calls += 1)); }}
publish_provisional() {{ exit 41; }}
        recover_incomplete_runs
        recover_incomplete_runs
        [[ $cleanup_calls -eq 2 ]]
        [[ $receipt_calls -eq 2 ]]
        [[ $artifact_cleanup_calls -eq 2 ]]
        [[ -f "$journal_root/{RUN_ID}.done" ]]
printf 'recovery-reentry: PASS\n'
"""
            )
        self.assertIn("recovery-reentry: PASS", result.stdout)

    def test_recovery_resumes_publish_when_final_exists_but_checkpoint_is_missing(
        self,
    ) -> None:
        recover = self.bash_function("recover_incomplete_runs")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).as_posix()
            result = self.run_bash_probe(
                f"""
set -euo pipefail
{recover}
journal_root={root!r}/journal
mkdir -p "$journal_root"
: > "$journal_root/{RUN_ID}.intent"
: > {root!r}/final.json
: > "$journal_root/{RUN_ID}.done"
: > "$journal_root/{RUN_ID}.runner-success"
publish_calls=0
validate_intent() {{ derive_run_paths "$2"; }}
derive_run_paths() {{
    done_path="$journal_root/$1.done"
    runner_success_path="$journal_root/$1.runner-success"
}}
cleanup_run_resources() {{ cleanup_lazy_used=0; }}
write_cleanup_receipt() {{ :; }}
read_journal_value() {{
    case $2 in
        schema_version) printf '2\n' ;;
        qualified_cleanup) printf '1\n' ;;
        final_output) printf '%s\n' {root!r}/final.json ;;
        *) exit 43 ;;
    esac
}}
publish_provisional() {{ ((publish_calls += 1)); }}
remove_unqualified_artifacts() {{ exit 42; }}
recover_incomplete_runs
[[ $publish_calls -eq 1 ]]
printf 'resume-existing-final: PASS\n'
"""
            )
        self.assertIn("resume-existing-final: PASS", result.stdout)

    def test_publish_existing_final_completes_hidden_provisional_checkpoint(
        self,
    ) -> None:
        publish = self.bash_function("publish_provisional")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).as_posix()
            result = self.run_bash_probe(
                f"""
set -euo pipefail
{publish}
run={RUN_ID!r}
intent={root!r}/$run.intent
intent_path="$intent"
done_path={root!r}/$run.done
runner_success_path={root!r}/$run.runner-success
expected_provisional={root!r}/.result.json.$run.provisional.json
expected_final={root!r}/result.json
final="$expected_final"
output_artifact={root!r}/$run.output
checkpoint_artifact={root!r}/$run.checkpoint
checkpoint_source="$checkpoint_artifact"
printf final > "$expected_final"
printf checkpoint > "$checkpoint_source"
: > "$done_path"
: > "$runner_success_path"
: > "$intent"
derive_run_paths() {{
    output_artifact={root!r}/$1.output
    checkpoint_artifact={root!r}/$1.checkpoint
    partial_output_publish_path={root!r}/$1.partial-publish.output
    partial_checkpoint_publish_path={root!r}/$1.partial-publish.checkpoint
}}
read_journal_value() {{
    case "$1:$2" in
        "$intent:final_output") printf '%s\n' "$expected_final" ;;
        "$intent:provisional_output") printf '%s\n' "$expected_provisional" ;;
        "$intent:formal_run") printf '1\n' ;;
        "$done_path:qualified_cleanup") printf '1\n' ;;
        "$done_path:lazy_unmount") printf '0\n' ;;
        "$runner_success_path:schema_version") printf '2\n' ;;
        "$runner_success_path:provisional_path") printf '%s\n' "$expected_provisional" ;;
        "$runner_success_path:output_artifact") printf '%s\n' "$output_artifact" ;;
        "$runner_success_path:checkpoint_artifact") printf '%s\n' "$checkpoint_artifact" ;;
        "$runner_success_path:output_sha256") printf '%064d\n' 0 ;;
        "$runner_success_path:output_device") printf '1\n' ;;
        "$runner_success_path:output_inode") printf '2\n' ;;
        "$runner_success_path:checkpoint_sha256") printf '%064d\n' 0 ;;
        "$runner_success_path:checkpoint_device") printf '1\n' ;;
        "$runner_success_path:checkpoint_inode") printf '3\n' ;;
        *) exit 44 ;;
    esac
}}
validation_calls=0
validate_runner_success() {{
    [[ $1 == "$run" ]]
    ((validation_calls += 1))
}}
chown() {{ :; }}
chmod() {{ :; }}
fsync_file_and_parent() {{ :; }}
stat() {{ printf '1:3\n'; }}
publish_hardlink_once() {{
    local source=$1 destination=$2 remove_source=$3
    if [[ ! -e $destination ]]; then
        command ln -- "$source" "$destination"
    fi
    if [[ $remove_source == 1 ]]; then
        command rm -f -- "$source"
    fi
}}
publish_provisional "$run"
[[ $validation_calls -eq 3 ]]
[[ -f "$expected_final.runner.complete.jsonl" ]]
[[ ! -e "$checkpoint_source" ]]
[[ -f "$expected_final.root-cleanup" ]]
printf 'hidden-checkpoint-recovered: PASS\n'
"""
            )
        self.assertIn("hidden-checkpoint-recovered: PASS", result.stdout)

    def test_runner_drop_cgroup_and_pdeath_contracts_are_explicit(self) -> None:
        source = self.source
        self.assertIn('printf \'%s\\n\' "$$" >"${harness_group}/cgroup.procs"', source)
        self.assertIn('printf \'%s\\n\' "$$" >"${cgroup_root}/cgroup.procs"', source)
        self.assertIn('--reuid "+${benchmark_uid}"', source)
        self.assertIn('--regid "+${benchmark_gid}"', source)
        self.assertIn("--init-groups", source)
        self.assertIn("--pdeathsig SIGINT", source)
        self.assertIn('prlimit --nofile="${nofile_limit}:${nofile_limit}"', source)
        self.assertIn("unshare --mount --propagation private", source)
        self.assertIn('mount -o remount,bind,ro "${cgroup_root}"', source)
        self.assertIn("env -i", source)
        self.assertEqual(source.count("os.getppid() != expected_parent"), 2)
        self.assertIn("os.setsid()", source)
        self.assertIn('TMPDIR="${quota_mount}"', source)
        self.assertIn(
            'LMYZMAIL_BENCHMARK_BACKING_DEVICE="${backing_device_id}"', source
        )
        self.assertIn(
            'LMYZMAIL_BENCHMARK_CGROUP_SUPERVISOR_SOCKET="${migration_socket}"',
            source,
        )
        configure = self.bash_function("configure_run_cgroups")
        self.assertNotIn("chown", configure)
        self.assertIn("socket.SO_PEERCRED", source)
        self.assertIn("peer_pid != registered[0]", source)
        self.assertIn("root_only_cgroup_migration", source)
        self.assertIn(
            "except (FileNotFoundError, ProcessLookupError):",
            source,
        )
        self.assertGreaterEqual(
            source.count('raise RuntimeError("migration root identity changed")'),
            2,
        )
        self.assertIn(
            "_move_runtime_to_workload",
            Path(__file__)
            .with_name("smtp-endpoint-throughput-v1.py")
            .read_text(encoding="utf-8"),
        )

    def test_disk_preflight_and_formal_policy_fail_closed(self) -> None:
        preflight = self.bash_function("preflight_image_capacity")
        policy = self.bash_function("verify_launcher_isolation_policy")
        result = self.run_bash_probe(
            f"""
set -euo pipefail
{preflight}
{policy}
filesystem_available_bytes() {{ printf '%s\n' "$mock_available"; }}
image_root=/unused
image_bytes=21474836480
host_reserve_bytes=10737418240
mock_available=32212254719
! preflight_image_capacity
mock_available=32212254720
preflight_image_capacity
formal_run=1
java_small_baseline_run=0
io_bytes_per_second=500000000
max_memory_bytes=8589934592
max_pids=8192
nofile_limit=8192
verify_launcher_isolation_policy
nofile_limit=2048
! verify_launcher_isolation_policy
formal_run=0
verify_launcher_isolation_policy
java_small_baseline_run=1
nofile_limit=2048
! verify_launcher_isolation_policy
nofile_limit=8192
verify_launcher_isolation_policy
printf 'capacity-and-policy: PASS\n'
"""
        )
        self.assertIn("capacity-and-policy: PASS", result.stdout)
        allocation = self.bash_function("allocate_quota_filesystem")
        self.assertLess(
            allocation.index("preflight_image_capacity"),
            allocation.index(': >"${image_path}"'),
        )
        self.assertIn("available_after < host_reserve_bytes", allocation)
        self.assertIn(
            "backing_device_id=${backing_device_id//[[:space:]]/}", allocation
        )
        self.assertIn("mount_device=${mount_device//[[:space:]]/}", allocation)
        self.assertIn("loop_device_id=${loop_device_id//[[:space:]]/}", allocation)

    def test_watchdog_supervisor_is_ready_before_runner_and_uses_a_gate(self) -> None:
        source = self.source
        persistent = source.rindex("\nenable_persistent_controllers\n")
        recover = source.rindex("\nrecover_incomplete_runs\n")
        coproc = source.rindex("coproc BENCHMARK_WATCHDOG")
        self.assertLess(persistent, recover)
        self.assertLess(recover, coproc)
        self.assertIn(
            'printf \'%s\\n\' "${BASHPID}" >"${housekeeping_group}/cgroup.procs"',
            source,
        )
        self.assertIn("start_cgroup_supervisor", source)
        self.assertIn("REGISTERED %s %s", source)
        self.assertIn("[[ ${gate_value} == GO ]]", source)
        self.assertIn("release_registered_runner_gate", source)
        self.assertNotIn("printf 'GO\\n' >\"${runner_gate}\"", source)

    def test_runner_gate_fails_when_runner_exits_before_rendezvous(self) -> None:
        release = self.bash_function("release_registered_runner_gate")
        attempt = self.bash_function("try_write_runner_gate")
        self.assertIn("os.O_NONBLOCK", attempt)
        self.assertIn("os.O_NOFOLLOW", attempt)
        self.assertEqual(attempt.count("runner_start_time_matches()"), 3)
        result = self.run_bash_probe(
            f"""
set -euo pipefail
{release}
runner_gate_timeout_seconds=5
identity_checks=0
registered_runner_matches() {{
    identity_checks=$((identity_checks + 1))
    (( identity_checks == 1 ))
}}
try_write_runner_gate() {{ return 75; }}
sleep() {{ :; }}
if release_registered_runner_gate 4242 123456; then
    exit 45
fi
[[ $identity_checks -eq 2 ]]
printf 'dead-runner-gate: PASS\n'
"""
        )
        self.assertIn("dead-runner-gate: PASS", result.stdout)

    def test_runner_gate_persistent_enxio_times_out(self) -> None:
        release = self.bash_function("release_registered_runner_gate")
        result = self.run_bash_probe(
            f"""
set -euo pipefail
{release}
# Two SECONDS ticks avoid a one-iteration probe when the shell starts just
# before the integer clock rolls over.
runner_gate_timeout_seconds=2
attempts=0
registered_runner_matches() {{ :; }}
try_write_runner_gate() {{ ((attempts += 1)); return 75; }}
if release_registered_runner_gate 4242 123456; then
    exit 52
fi
[[ $attempts -gt 1 ]]
printf 'persistent-enxio-timeout: PASS\n'
""",
            timeout=5,
        )
        self.assertIn("persistent-enxio-timeout: PASS", result.stdout)

    def test_runner_identity_rejects_starttime_reuse_and_cgroup_mismatch(self) -> None:
        identity = self.bash_function("registered_runner_matches")
        result = self.run_bash_probe(
            f"""
set -euo pipefail
{identity}
actual_start=123456
inside=1
process_start_time() {{ printf '%s\n' "$actual_start"; }}
pid_in_benchmark_cgroup() {{ [[ $inside == 1 ]]; }}
registered_runner_matches 4242 123456
actual_start=123457
! registered_runner_matches 4242 123456
actual_start=123456
inside=0
! registered_runner_matches 4242 123456
printf 'runner-identity-fail-closed: PASS\n'
"""
        )
        self.assertIn("runner-identity-fail-closed: PASS", result.stdout)

    def test_schema1_recovery_is_historical_and_never_publishes(self) -> None:
        recover = self.bash_function("recover_incomplete_runs")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).as_posix()
            result = self.run_bash_probe(
                f"""
set -euo pipefail
{recover}
journal_root={root!r}/journal
mkdir -p "$journal_root"
: > "$journal_root/{RUN_ID}.intent"
legacy_receipts=0
artifact_cleanups=0
validate_intent() {{ derive_run_paths "$2"; }}
derive_run_paths() {{
    intent_path="$journal_root/$1.intent"
    runner_success_path="$journal_root/$1.runner-success"
}}
read_journal_value() {{
    [[ $1 == "$intent_path" && $2 == schema_version ]]
    printf '1\n'
}}
cleanup_run_resources() {{ cleanup_lazy_used=0; }}
write_legacy_unqualified_receipt() {{ ((legacy_receipts += 1)); }}
remove_unqualified_artifacts() {{ ((artifact_cleanups += 1)); }}
write_cleanup_receipt() {{ exit 45; }}
publish_provisional() {{ exit 46; }}
recover_incomplete_runs
[[ $legacy_receipts -eq 1 && $artifact_cleanups -eq 1 ]]
printf 'schema1-unqualified: PASS\n'
"""
            )
        self.assertIn("schema1-unqualified: PASS", result.stdout)

    def test_runner_success_validation_binds_identity_path_and_hash(self) -> None:
        validator = self.bash_function("validate_runner_success")
        inspector = self.bash_function("inspect_runner_artifacts")
        self.assertIn("schema_version) == 2", validator)
        self.assertIn("runner_pid", validator)
        self.assertIn("runner_start_time", validator)
        self.assertIn("output_artifact", validator)
        self.assertIn("checkpoint_artifact", validator)
        self.assertIn("inspect_runner_artifacts validate", validator)
        self.assertIn("expected_output_inode", inspector)
        self.assertIn("expected_checkpoint_inode", inspector)
        self.assertIn("completed checkpoint hash chain is invalid", inspector)
        self.assertIn('completed.get("launcher_run_id") == launcher_run_id', inspector)
        self.assertIn("root-owned artifact hash differs", inspector)

    def test_final_evidence_requires_root_receipt_and_idempotent_hardlinks(
        self,
    ) -> None:
        publish = self.bash_function("publish_provisional")
        helper = self.bash_function("publish_hardlink_once")
        self.assertIn("qualified_cleanup) == 1", publish)
        self.assertIn("lazy_unmount) == 0", publish)
        self.assertIn(
            'publish_hardlink_once "${done_path}" "${receipt_target}" 0', publish
        )
        self.assertIn('"${output_artifact}" "${final}" 1', publish)
        self.assertIn('"${checkpoint_source}" "${final_checkpoint}" 1', publish)
        self.assertIn("${final}.runner.complete.jsonl", publish)
        self.assertIn("/proc/self/fd/{descriptor}", helper)
        self.assertIn("create-only hardlink destination differs", helper)
        self.assertIn("st_nlink", helper)
        self.assertIn("durable_record_partial_publish(stage)", helper)
        self.assertIn("source-restore-durability-unverified", helper)
        self.assertIn("clear_partial_publish()", helper)
        self.assertIn('"${partial_output_publish_path}" output', publish)
        self.assertIn('"${partial_checkpoint_publish_path}"', publish)

    def test_hardlink_rollback_cutpoints_never_delete_the_only_valid_link(
        self,
    ) -> None:
        module = ast.parse(self.embedded_python("publish_hardlink_once"))
        rollback_node = next(
            node
            for node in module.body
            if isinstance(node, ast.FunctionDef) and node.name == "rollback"
        )
        rollback_module = ast.fix_missing_locations(
            ast.Module(body=[rollback_node], type_ignores=[])
        )

        class FakePath:
            def __init__(self, value: str, parent: object) -> None:
                self.value = value
                self.name = value.rsplit("/", 1)[-1]
                self.parent = parent

        identity = (23, 4242)
        alien_identity = (23, 9999)

        for cutpoint, expected_stage in (
            ("restore-link", "source-restore-failed"),
            ("source-parent-fsync", "source-restore-durability-unverified"),
            ("identity-recheck", "source-identity-conflict"),
            ("partial-marker-durability", "source-restore-failed"),
        ):
            with self.subTest(cutpoint=cutpoint):
                source_parent = object()
                source = FakePath("/artifacts/run.output", source_parent)
                destination = FakePath("/evidence/result.json", object())
                states = {source: None, destination: identity}
                source_reads = 0
                recorded: list[str] = []

                def path_identity(path: FakePath) -> tuple[int, int] | None:
                    nonlocal source_reads
                    if path is source:
                        source_reads += 1
                        if cutpoint == "identity-recheck" and source_reads >= 2:
                            return alien_identity
                    return states[path]

                class FakeOs:
                    def __init__(self) -> None:
                        self.destination_unlinked = False

                    def link(self, old: str, new: FakePath, **_: object) -> None:
                        self_outer.assertEqual(old, "/proc/self/fd/99")
                        self_outer.assertIs(new, source)
                        if cutpoint in {"restore-link", "partial-marker-durability"}:
                            raise OSError("injected source restore failure")
                        states[source] = identity

                    def unlink(self, name: str, *, dir_fd: int) -> None:
                        self_outer.assertEqual(name, destination.name)
                        self_outer.assertEqual(dir_fd, 77)
                        self.destination_unlinked = True
                        states[destination] = None

                    def fsync(self, descriptor: int) -> None:
                        self_outer.assertEqual(descriptor, 77)

                fake_os = FakeOs()
                self_outer = self

                def fsync_directory(path: object) -> None:
                    self.assertIs(path, source_parent)
                    if cutpoint == "source-parent-fsync":
                        raise OSError("injected source parent fsync failure")

                def durable_record_partial_publish(stage: str) -> None:
                    recorded.append(stage)
                    if cutpoint == "partial-marker-durability":
                        raise OSError("injected partial marker fsync failure")

                namespace: dict[str, object] = {
                    "identity": identity,
                    "removed_source": True,
                    "created_destination": True,
                    "remove_source": True,
                    "source": source,
                    "destination": destination,
                    "descriptor": 99,
                    "destination_directory": 77,
                    "path_identity": path_identity,
                    "fsync_directory": fsync_directory,
                    "durable_record_partial_publish": durable_record_partial_publish,
                    "os": fake_os,
                }
                exec(compile(rollback_module, "<launcher-rollback>", "exec"), namespace)
                namespace["rollback"]()

                self.assertFalse(fake_os.destination_unlinked)
                self.assertEqual(states[destination], identity)
                self.assertEqual(recorded, [expected_stage])

        source_parent = object()
        source = FakePath("/artifacts/run.output", source_parent)
        destination = FakePath("/evidence/result.json", object())
        states = {source: None, destination: identity}
        unlinked: list[str] = []

        class SuccessfulFakeOs:
            def link(self, _old: str, _new: FakePath, **_: object) -> None:
                states[source] = identity

            def unlink(self, name: str, *, dir_fd: int) -> None:
                self_outer.assertEqual(dir_fd, 77)
                unlinked.append(name)
                states[destination] = None

            def fsync(self, descriptor: int) -> None:
                self_outer.assertEqual(descriptor, 77)

        success_namespace: dict[str, object] = {
            "identity": identity,
            "removed_source": True,
            "created_destination": True,
            "remove_source": True,
            "source": source,
            "destination": destination,
            "descriptor": 99,
            "destination_directory": 77,
            "path_identity": lambda path: states[path],
            "fsync_directory": lambda path: self.assertIs(path, source_parent),
            "durable_record_partial_publish": lambda stage: self.fail(stage),
            "os": SuccessfulFakeOs(),
        }
        exec(compile(rollback_module, "<launcher-rollback>", "exec"), success_namespace)
        success_namespace["rollback"]()
        self.assertEqual(unlinked, [destination.name])
        self.assertEqual(states[source], identity)

    def test_external_attestation_failures_propagate_inside_conditional(
        self,
    ) -> None:
        function = self.bash_function_before(
            "create_external_attestation", "start_cgroup_supervisor"
        )
        self.assertIn("]] || return 1", function)
        self.assertIn("0o444", function)
        self.assertNotIn("0o400", function)
        self.assertEqual(function.count("sha256sum --"), 2)
        self.assertEqual(function.count("sed -n"), 2)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wrapper = root / "mock-python.sh"
            wrapper.write_text(
                """#!/usr/bin/env bash
set -u
[[ ${MOCK_FAIL:-} != python ]] || exit 71
output_root=$5
zero=0000000000000000000000000000000000000000000000000000000000000000
one=1111111111111111111111111111111111111111111111111111111111111111
mkdir -p -- "$output_root"
target="$output_root/$zero.json"
: > "$target"
case ${MOCK_FAIL:-} in
    final-path) printf '%s\n%s\n' "$output_root/missing.json" "$zero" ;;
    final-hash) printf '%s\n%s\n' "$target" "$one" ;;
    *) printf '%s\n%s\n' "$target" "$zero" ;;
esac
""",
                encoding="utf-8",
                newline="\n",
            )
            wrapper.chmod(0o755)
            root_posix = root.as_posix()
            wrapper_posix = wrapper.as_posix()
            result = self.run_bash_probe(
                function
                + f"""
set -uo pipefail
launcher=/launcher
runner=/runner
repository={root_posix!r}
proxy_binary=/bin/true
venv_python={wrapper_posix!r}
proxy_attestation_root={root_posix!r}/proxy
attestation_root={root_posix!r}/attestations
benchmark_group={root_posix!r}/cgroup/run
harness_group="$benchmark_group/harness"
quota_mount=/quota
loop_device_id=7:1
backing_device_id=7:0
image_bytes=21474836480
host_reserve_bytes=10737418240
io_bytes_per_second=500000000
max_memory_bytes=8589934592
max_pids=8192
nofile_limit=8192
benchmark_cpu=3
housekeeping_cpus=0-2
sha256sum() {{
    case "${{MOCK_FAIL:-}}:$2" in
        sha-launcher:/launcher|sha-runner:/runner) return 72 ;;
    esac
    printf '%064d  %s\n' 0 "$2"
}}
sed() {{
    case "${{MOCK_FAIL:-}}:$2" in
        sed-first:1p|sed-second:2p) return 73 ;;
    esac
    command sed "$@"
}}
assert_fails() {{
    MOCK_FAIL=$1
    export MOCK_FAIL
    if create_external_attestation; then
        printf 'unexpected attestation success at %s\n' "$MOCK_FAIL" >&2
        exit 80
    fi
}}
unset proxy_attestation_path
unset proxy_attestation_sha256
assert_fails missing-proxy
proxy_attestation_path=/proxy/attestation.json
proxy_attestation_sha256=$(printf '%064d' 0)
for failure in sha-launcher sha-runner python sed-first sed-second final-path final-hash; do
    assert_fails "$failure"
done
MOCK_FAIL=
export MOCK_FAIL
create_external_attestation
[[ -f $external_attestation_path ]]
[[ $external_attestation_sha256 == $(printf '%064d' 0) ]]
printf 'external-attestation-explicit-errors: PASS\n'
"""
            )
        self.assertIn("external-attestation-explicit-errors: PASS", result.stdout)

    def test_watchdog_commands_bind_runner_pid_and_starttime(self) -> None:
        functions = "\n\n".join(
            self.bash_function(name)
            for name in ("register_managed_runner", "runner_completion_matches")
        )
        result = self.run_bash_probe(
            f"""
set -euo pipefail
{functions}
managed_runner_pid=
managed_runner_start_time=
register_managed_runner 4242 123456 ''
runner_completion_matches 4242 123456 ''
! runner_completion_matches 4242 999999 ''
! runner_completion_matches 9999 123456 ''
! register_managed_runner 4242 999999 ''
printf 'runner-starttime-binding: PASS\n'
"""
        )
        self.assertIn("runner-starttime-binding: PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
