from __future__ import annotations

import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import psycopg
import pytest

from lmyzmail_blackbox.differential import DifferentialRunner, RuntimeTarget, Scenario
from lmyzmail_blackbox.persistent_runtime import PersistentJavaOracleRuntime
from lmyzmail_blackbox.ports import PortSet
from lmyzmail_blackbox.runtime import CandidateRuntime

_GOLDEN = "managed-fail2ban-v1"
_PROFILE = "managed-fail2ban"
_LOG_NAME = "auth.log"
_STARTUP_IP = "198.51.100.10"
_IGNORED_IP = "198.51.100.11"
_INVALID_IP = "999.999.999.999"
_THRESHOLD_IP = "198.51.100.21"
_PARTIAL_IP = "198.51.100.40"
_ROTATED_IP = "198.51.100.41"
_SCAN_SECONDS = 0.05
_WAIT_SECONDS = 8.0

_COMMON_OVERRIDES = (
    "fail2ban.enabled=true",
    "fail2ban.scan-interval=50ms",
    "fail2ban.max-retries=2",
    "fail2ban.find-time=10m",
    "fail2ban.report-cooldown=5s",
    "fail2ban.max-tracked-ips=16",
    "fail2ban.cleanup-interval=30s",
)


def _failed_password(ip: str, *, user: str = "root") -> str:
    return f"Aug 10 12:00:00 host sshd[100]: Failed password for {user} from {ip} port 22 ssh2"


def _prepare_log(workspace: Path) -> Path:
    path = workspace / _LOG_NAME
    if not path.exists():
        path.write_text(_failed_password(_STARTUP_IP) + "\n", encoding="utf-8")
    return path


class _Fail2BanJavaRuntime(PersistentJavaOracleRuntime):
    def _application_arguments(self) -> list[str]:
        workspace = cast(Path, self.workspace)
        log_path = _prepare_log(workspace)
        arguments = [
            "--botmail.fail2ban.enabled=true"
            if value == "--botmail.fail2ban.enabled=false"
            else value
            for value in super()._application_arguments()
        ]
        return [
            *arguments,
            *(
                f"--botmail.{value}"
                for value in _COMMON_OVERRIDES
                if value != "fail2ban.enabled=true"
            ),
            f"--botmail.fail2ban.ssh-log-paths={log_path}",
        ]


class _Fail2BanCandidateRuntime(CandidateRuntime):
    def _application_arguments(self) -> list[str]:
        workspace = cast(Path, self.workspace)
        log_path = _prepare_log(workspace)
        return [
            *super()._application_arguments(),
            *(f"--lmyzmail.{value}" for value in _COMMON_OVERRIDES),
            f"--lmyzmail.fail2ban.ssh-log-paths={log_path}",
        ]


@dataclass(frozen=True, slots=True)
class _OracleTarget:
    runtime: PersistentJavaOracleRuntime

    @property
    def target_kind(self) -> str:
        return "java-oracle"

    @property
    def workspace(self) -> Path | None:
        return self.runtime.workspace

    @property
    def ports(self) -> PortSet | None:
        return self.runtime.ports


def _candidate(repository: Path) -> _Fail2BanCandidateRuntime:
    if os.environ.get("LMYZMAIL_CANDIDATE_COMMAND_JSON") is not None:
        return cast(
            _Fail2BanCandidateRuntime,
            _Fail2BanCandidateRuntime.from_environment(),
        )
    return _Fail2BanCandidateRuntime(
        command_template=(
            str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
            "--config",
            "{config}",
        )
    )


def _connect(target: RuntimeTarget) -> psycopg.Connection[Any]:
    if target.ports is None:
        raise AssertionError("Fail2Ban target is not started")
    return psycopg.connect(
        host="127.0.0.1",
        port=target.ports.postgres,
        user="lmyzmail_test",
        dbname="lmyzmail",
        connect_timeout=5,
    )


def _append(target: RuntimeTarget, *lines: str, terminate: bool = True) -> None:
    if target.workspace is None:
        raise AssertionError("Fail2Ban target workspace is unavailable")
    payload = "\n".join(lines)
    if terminate:
        payload += "\n"
    path = target.workspace / _LOG_NAME
    with path.open("a", encoding="utf-8", newline="") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def _activity_count(target: RuntimeTarget, ip: str) -> int:
    with _connect(target) as connection:
        row = connection.execute(
            "SELECT count(*) FROM skibidi_cringe_ip_activity WHERE ip_address=%s",
            (ip,),
        ).fetchone()
    if row is None:
        raise AssertionError(f"missing activity count row for {ip}")
    return cast(int, row[0])


def _wait_for_activity_count(target: RuntimeTarget, ip: str, expected: int) -> None:
    deadline = time.monotonic() + _WAIT_SECONDS
    while time.monotonic() < deadline:
        if _activity_count(target, ip) == expected:
            return
        time.sleep(_SCAN_SECONDS)
    raise AssertionError(
        f"Fail2Ban activity count for {ip} did not reach {expected}: "
        f"{_activity_count(target, ip)}"
    )


def _snapshot(target: RuntimeTarget, ips: tuple[str, ...]) -> dict[str, Any]:
    with _connect(target) as connection:
        ip_rows = connection.execute(
            """
            SELECT ip_address,total_score,current_score,activity_count,
                   self_spoofing_count,open_relay_count,auth_probe_count,
                   illegal_domain_count,spamhaus_count,http_on_smtp_count,
                   ssh_on_smtp_count,http_port_scanning_count,honeypot_hit_count,
                   ssh_bruteforce_count,pps_overlimit_count,syn_flood_count,other_count
            FROM skibidi_cringe_ip
            WHERE ip_address = ANY(%s)
            ORDER BY ip_address
            """,
            (list(ips),),
        ).fetchall()
        activities = connection.execute(
            """
            SELECT ip_address,activity_type,score,mail_from,rcpt_to,helo_name,
                   session_id,response_message,metadata
            FROM skibidi_cringe_ip_activity
            WHERE ip_address = ANY(%s)
            ORDER BY ip_address,id
            """,
            (list(ips),),
        ).fetchall()
    return {
        "ipRows": [list(row) for row in ip_rows],
        "activities": [list(row) for row in activities],
    }


def _capture_threshold_and_cooldown(target: RuntimeTarget) -> dict[str, Any]:
    if _activity_count(target, _STARTUP_IP) != 0:
        raise AssertionError("Fail2Ban replayed content that existed before startup")
    _append(
        target,
        f"Aug 10 12:00:00 host cron[1]: Failed password for root from {_IGNORED_IP} port 22 ssh2",
        _failed_password(_INVALID_IP),
        _failed_password(_THRESHOLD_IP),
    )
    time.sleep(_SCAN_SECONDS * 4)
    before_threshold = _activity_count(target, _THRESHOLD_IP)
    _append(
        target,
        f"Aug 10 12:00:01 host sshd[101]: Invalid user admin from {_THRESHOLD_IP} port 22",
    )
    _wait_for_activity_count(target, _THRESHOLD_IP, 1)

    _append(
        target,
        _failed_password(_THRESHOLD_IP, user="nobody"),
        _failed_password(_THRESHOLD_IP, user="daemon"),
    )
    time.sleep(_SCAN_SECONDS * 4)
    during_cooldown = _activity_count(target, _THRESHOLD_IP)
    time.sleep(5.2)
    _append(target, _failed_password(_THRESHOLD_IP, user="postcooldown"))
    _wait_for_activity_count(target, _THRESHOLD_IP, 2)

    return {
        "startupContentSkipped": _activity_count(target, _STARTUP_IP) == 0,
        "nonSshdIgnored": _activity_count(target, _IGNORED_IP) == 0,
        "invalidIpIgnored": _activity_count(target, _INVALID_IP) == 0,
        "beforeThreshold": before_threshold,
        "duringCooldown": during_cooldown,
        "state": _snapshot(target, (_THRESHOLD_IP,)),
    }


_PATTERNS: tuple[Callable[[str], str], ...] = (
    lambda ip: f"Aug 10 12:01:00 host sshd[200]: Failed publickey for root from {ip} port 22 ssh2",
    lambda ip: f"Aug 10 12:01:01 host sshd[201]: Invalid user oracle from {ip} port 2222",
    lambda ip: (
        "Aug 10 12:01:02 host sshd[202]: pam_unix(sshd:auth): "
        f"authentication failure; logname= uid=0 rhost={ip}"
    ),
    lambda ip: (
        "Aug 10 12:01:03 host sshd[203]: Connection closed by invalid user "
        f"oracle {ip} port 45822 [preauth]"
    ),
    lambda ip: (
        "Aug 10 12:01:04 host sshd[204]: error: maximum authentication attempts "
        f"exceeded for root from {ip} port 22 ssh2"
    ),
    lambda ip: (
        "Aug 10 12:01:05 host sshd[205]: Bad protocol version identification "
        f"'GET / HTTP/1.1' from {ip} port 22"
    ),
    lambda ip: (
        "Aug 10 12:01:06 host sshd[206]: Did not receive identification string "
        f"from {ip} port 22"
    ),
    lambda ip: f"Aug 10 12:01:07 host sshd[207]: refused connect from {ip}",
)


def _capture_pattern_matrix(target: RuntimeTarget) -> dict[str, Any]:
    ips = tuple(f"198.51.100.{30 + index}" for index in range(len(_PATTERNS)))
    lines: list[str] = []
    for ip, pattern in zip(ips, _PATTERNS, strict=True):
        lines.extend((_failed_password(ip), pattern(ip)))
    _append(target, *lines)
    for ip in ips:
        _wait_for_activity_count(target, ip, 1)
    return _snapshot(target, ips)


def _capture_partial_line_and_rotation(target: RuntimeTarget) -> dict[str, Any]:
    _append(target, _failed_password(_PARTIAL_IP))
    _append(target, _failed_password(_PARTIAL_IP), terminate=False)
    time.sleep(_SCAN_SECONDS * 4)
    partial_count = _activity_count(target, _PARTIAL_IP)
    _append(target, "")
    _wait_for_activity_count(target, _PARTIAL_IP, 1)

    if target.workspace is None:
        raise AssertionError("Fail2Ban target workspace is unavailable")
    path = target.workspace / _LOG_NAME
    rotated = target.workspace / f"{_LOG_NAME}.1"
    path.replace(rotated)
    with path.open("w", encoding="utf-8", newline="") as stream:
        stream.write(_failed_password(_ROTATED_IP) + "\n")
        stream.write(
            f"Aug 10 12:02:01 host sshd[301]: Invalid user rotated from {_ROTATED_IP} port 22\n"
        )
        stream.flush()
        os.fsync(stream.fileno())
    _wait_for_activity_count(target, _ROTATED_IP, 1)
    return {
        "partialLineActivityCount": partial_count,
        "state": _snapshot(target, (_PARTIAL_IP, _ROTATED_IP)),
    }


SCENARIOS = (
    Scenario(
        "fail2ban/threshold-and-cooldown",
        _capture_threshold_and_cooldown,
        (),
        contract={
            "source": "incremental SSH authentication log",
            "startup_position": "EOF",
            "max_retries": 2,
            "find_time": "PT10M",
            "report_cooldown": "PT5S",
            "activity": {"type": "SSH_BRUTEFORCE", "score": 10},
            "persistence": ["skibidi_cringe_ip", "skibidi_cringe_ip_activity"],
        },
    ),
    Scenario(
        "fail2ban/eight-sshd-patterns",
        _capture_pattern_matrix,
        (),
        contract={
            "patterns": [
                "failed-password-or-publickey",
                "invalid-user",
                "pam-auth-failure",
                "preauth-disconnect",
                "max-auth-attempts",
                "bad-protocol",
                "missing-identification",
                "refused-connect",
            ],
            "cardinality": "one report per two matching lines and IP",
        },
    ),
    Scenario(
        "fail2ban/partial-line-and-rotation",
        _capture_partial_line_and_rotation,
        (),
        contract={
            "partial_line": "retained until newline",
            "rotation": "inode replacement resets offset and reads new file from byte zero",
        },
    ),
)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(240)
def test_frozen_java_fail2ban_golden(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    record = os.environ.get("LMYZMAIL_RECORD_JAVA_GOLDEN") == "1"
    runner = DifferentialRunner(
        repository,
        repository / "blackbox/golden/java" / _GOLDEN,
        _PROFILE,
        record_java=record,
    )
    with _Fail2BanJavaRuntime(tmp_path / "java-fail2ban") as oracle:
        target = _OracleTarget(oracle)
        if record:
            runner.record_from_java(SCENARIOS, target)
        else:
            runner.verify_java(SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(240)
def test_rust_candidate_fail2ban_matches_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        DifferentialRunner(
            repository,
            repository / "blackbox/golden/java" / _GOLDEN,
            _PROFILE,
        ).verify_candidate(SCENARIOS, candidate)
