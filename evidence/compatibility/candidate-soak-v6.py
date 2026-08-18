from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


REPOSITORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY / "blackbox/src"))

from lmyzmail_blackbox.golden import GoldenAttestation  # noqa: E402


SOURCE = Path(__file__).with_name("candidate-soak-v4.py")
RUNNER = Path(__file__).resolve()
DEFAULT_POLICY = {
    "max_rss_kib": 2 * 1024 * 1024,
    "max_fd_count": 512,
    "max_task_count": 512,
    "max_disk_delta_peak_bytes": 1024 * 1024 * 1024,
    "max_workspace_delta_peak_bytes": 512 * 1024 * 1024,
    "max_steady_rss_growth_kib": 64 * 1024,
    "max_steady_fd_growth": 4,
    "max_steady_task_growth": 4,
    "max_steady_workspace_growth_bytes": 64 * 1024 * 1024,
}


def _sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _git_head() -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPOSITORY,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _write_json(path: Path, value: dict[str, Any], *, exclusive: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        if exclusive:
            os.link(temporary, path)
        else:
            os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _load_source() -> Any:
    spec = importlib.util.spec_from_file_location("candidate_soak_v4", SOURCE)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load soak implementation: {SOURCE}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _steady_deltas(result: dict[str, Any]) -> dict[str, int]:
    samples = result["resource"]["samples_all"]
    steady = [sample for sample in samples if sample["elapsed_millis"] >= 60_000]
    if not steady:
        return {
            "rss_kib": 0,
            "fd_count": 0,
            "task_count": 0,
            "workspace_bytes": 0,
        }
    first = steady[0]
    final = samples[-1]
    return {
        "rss_kib": final["rss_kib"] - first["rss_kib"],
        "fd_count": final["fd_count"] - first["fd_count"],
        "task_count": final["task_count"] - first["task_count"],
        "workspace_bytes": final["workspace_bytes"] - first["workspace_bytes"],
    }


def _policy_checks(
    result: dict[str, Any], *, qualified_half_hour: bool
) -> dict[str, dict[str, int | bool]]:
    resource = result["resource"]
    steady = _steady_deltas(result)
    checks: dict[str, tuple[int, int, bool]] = {
        "rss_absolute": (
            resource["rss_max_kib"],
            DEFAULT_POLICY["max_rss_kib"],
            True,
        ),
        "fd_absolute": (
            resource["fd_max"],
            DEFAULT_POLICY["max_fd_count"],
            True,
        ),
        "task_absolute": (
            resource["task_max"],
            DEFAULT_POLICY["max_task_count"],
            True,
        ),
        "disk_peak": (
            resource["disk_delta_peak_bytes"],
            DEFAULT_POLICY["max_disk_delta_peak_bytes"],
            True,
        ),
        "workspace_peak": (
            resource["workspace_delta_peak_bytes"],
            DEFAULT_POLICY["max_workspace_delta_peak_bytes"],
            True,
        ),
        "steady_rss_growth": (
            steady["rss_kib"],
            DEFAULT_POLICY["max_steady_rss_growth_kib"],
            qualified_half_hour,
        ),
        "steady_fd_growth": (
            steady["fd_count"],
            DEFAULT_POLICY["max_steady_fd_growth"],
            qualified_half_hour,
        ),
        "steady_task_growth": (
            steady["task_count"],
            DEFAULT_POLICY["max_steady_task_growth"],
            qualified_half_hour,
        ),
        "steady_workspace_growth": (
            steady["workspace_bytes"],
            DEFAULT_POLICY["max_steady_workspace_growth_bytes"],
            qualified_half_hour,
        ),
    }
    return {
        name: {
            "observed": observed,
            "limit": limit,
            "enforced": enforced,
            "passed": (not enforced) or observed <= limit,
        }
        for name, (observed, limit, enforced) in checks.items()
    }


def _validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if args.duration <= 0 or not args.duration < float("inf"):
        parser.error("--duration must be finite and positive")
    if args.workers < 5 or args.workers > 256:
        parser.error("--workers must be between 5 and 256 so every module is exercised")
    if args.output is None:
        parser.error("--output is required for auditable soak evidence")
    if args.output.exists():
        parser.error(f"evidence already exists: {args.output}")
    running = args.output.with_name(f"{args.output.name}.running")
    if running.exists():
        parser.error(
            f"running checkpoint already exists: {running}; audit or remove it before retry"
        )
    if not args.smoke and (args.duration < 1800 or args.workers < 16):
        parser.error(
            "qualified soak requires --duration >= 1800 and --workers >= 16; "
            "use --smoke for runner validation"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=float, default=1800.0)
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    _validate_args(args, parser)
    assert args.output is not None
    output = args.output.resolve()
    running = output.with_name(f"{output.name}.running")
    run_id = str(uuid.uuid4())
    started_at = datetime.now(UTC).isoformat()
    attestation = GoldenAttestation.from_repository(
        REPOSITORY,
        profile="candidate-multi-module-half-hour-soak-v6",
        normalizers=(),
    )
    runner_sha256 = _sha256(RUNNER)
    source_sha256 = _sha256(SOURCE)
    definition_tree_sha256 = attestation.harness_definition_sha256
    invocation = {
        "argv": [str(RUNNER.relative_to(REPOSITORY)), *sys.argv[1:]],
        "cwd": str(Path.cwd().resolve()),
        "git_head": _git_head(),
        "pid": os.getpid(),
    }
    checkpoint = {
        "schema_version": 1,
        "profile": "candidate-multi-module-half-hour-soak-v6",
        "run_id": run_id,
        "status": "running",
        "complete": False,
        "started_at": started_at,
        "invocation": invocation,
        "runner_sha256": runner_sha256,
        "source_sha256": source_sha256,
        "definition_tree_sha256": definition_tree_sha256,
    }
    _write_json(running, checkpoint, exclusive=True)
    try:
        result = _load_source().run(args.duration, args.workers)
        qualified = not args.smoke and result["duration_seconds"] >= 1800
        checks = _policy_checks(result, qualified_half_hour=qualified)
        after_attestation = GoldenAttestation.from_repository(
            REPOSITORY,
            profile="candidate-multi-module-half-hour-soak-v6",
            normalizers=(),
        )
        immutable_inputs = {
            "runner_sha256_before": runner_sha256,
            "runner_sha256_after": _sha256(RUNNER),
            "source_sha256_before": source_sha256,
            "source_sha256_after": _sha256(SOURCE),
            "definition_tree_sha256_before": definition_tree_sha256,
            "definition_tree_sha256_after": (
                after_attestation.harness_definition_sha256
            ),
            "git_head_before": invocation["git_head"],
            "git_head_after": _git_head(),
        }
        immutable_inputs["unchanged"] = (
            immutable_inputs["runner_sha256_before"]
            == immutable_inputs["runner_sha256_after"]
            and immutable_inputs["source_sha256_before"]
            == immutable_inputs["source_sha256_after"]
            and immutable_inputs["definition_tree_sha256_before"]
            == immutable_inputs["definition_tree_sha256_after"]
            and immutable_inputs["git_head_before"]
            == immutable_inputs["git_head_after"]
        )
        protocol_activity_verified = all(
            int(result["successes"].get(protocol, 0)) > 0
            for protocol in ("http", "smtp", "htcpcp", "minecraft")
        )
        result.update(
            {
                "schema_version": 2,
                "profile": "candidate-multi-module-half-hour-soak-v6",
                "run_id": run_id,
                "complete": True,
                "started_at": started_at,
                "finished_at": datetime.now(UTC).isoformat(),
                "candidate_release_sha256_before": result["release_sha256"],
                "candidate_release_sha256_after": result[
                    "release_sha256_after"
                ],
                "qualification": {
                    "qualified_half_hour": qualified,
                    "smoke": args.smoke,
                    "minimum_duration_seconds": 1800,
                    "minimum_workers": 16,
                },
                "invocation": invocation,
                "runner_sha256": runner_sha256,
                "source_sha256": source_sha256,
                "definition_tree_sha256": definition_tree_sha256,
                "immutable_inputs": immutable_inputs,
                "protocol_activity_verified": protocol_activity_verified,
                "resource_policy": DEFAULT_POLICY,
                "resource_policy_basis": (
                    "Hard ceilings are at least 4x the v5 measured candidate RSS "
                    "and over 10x its transient filesystem/workspace growth; steady "
                    "growth gates apply only to a qualified >=30 minute run."
                ),
                "resource_policy_checks": checks,
                "recovery_semantics": {
                    "runtime_stop_always_attempted": True,
                    "managed_processes_must_exit": True,
                    "ephemeral_workspace_must_be_removed": True,
                    "release_binary_must_remain_unchanged": True,
                    "running_checkpoint_retained_on_interruption_or_failure": True,
                    "final_evidence_create_once": True,
                    "final_evidence_created_before_checkpoint_removed": True,
                },
            }
        )
        result["status"] = (
            "passed"
            if result["status"] == "passed"
            and all(check["passed"] for check in checks.values())
            and immutable_inputs["unchanged"]
            and protocol_activity_verified
            else "failed"
        )
        # Keep the running checkpoint until the complete evidence file is
        # durably created. An interruption in this window must leave both
        # artifacts available for audit and recovery.
        _write_json(output, result, exclusive=True)
        running.unlink()
        directory = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        print(
            json.dumps(
                {
                    "status": result["status"],
                    "output": str(output),
                    "qualified_half_hour": qualified,
                    "failures": result["failures"],
                    "release_sha256": result["release_sha256"],
                    "resource_policy_checks": checks,
                },
                sort_keys=True,
                indent=2,
            )
        )
        return 0 if result["status"] == "passed" else 1
    except BaseException as error:
        checkpoint["status"] = "failed"
        checkpoint["finished_at"] = datetime.now(UTC).isoformat()
        checkpoint["error"] = {
            "type": type(error).__name__,
            "message": str(error),
        }
        _write_json(running, checkpoint, exclusive=False)
        raise


if __name__ == "__main__":
    raise SystemExit(main())
