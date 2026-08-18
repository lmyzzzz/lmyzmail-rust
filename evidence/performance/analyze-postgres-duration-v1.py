#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


RECORD = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} [^ ]+) UTC \[(?P<pid>\d+)\] LOG:\s+"
    r"duration: (?P<duration>[0-9]+(?:\.[0-9]+)?) ms\s+"
    r"(?:(?P<phase>parse|bind|execute) [^:]+|(?P<statement>statement)):\s*"
    r"(?P<sql>.*)$"
)


@dataclass(frozen=True)
class DurationRecord:
    timestamp: str
    pid: int
    duration_ms: float
    phase: str
    sql: str


def normalized_sql(sql: str) -> str:
    return " ".join(sql.lower().split())


def category(sql: str) -> str:
    value = normalized_sql(sql)
    if value == "start transaction":
        return "transaction_begin"
    if value == "commit":
        return "transaction_commit"
    if value == "rollback":
        return "transaction_rollback"
    if "select pg_advisory_xact_lock(value)" in value:
        return "inbound_batch_advisory_lock"
    if "select pg_advisory_xact_lock($1)" in value:
        return "single_advisory_lock"
    if (
        "from lmyzmail_inbound_delivery_intent" in value
        and "intent_id::text = any($1::text[])" in value
        and "for update" in value
    ):
        return "inbound_batch_intent_read"
    if (
        "from mailbox" in value
        and "address::text = any($1::text[])" in value
        and "for key share" in value
    ):
        return "inbound_batch_mailbox_read"
    if "with input as" in value and "join email_index" in value:
        return "inbound_batch_existing_read"
    if "with missing_input as" in value and "advanced_intents as materialized" in value:
        return "inbound_batch_mutation"
    if value.startswith("insert into email_index") and "from unnest(" in value:
        return "inbound_batch_insert"
    if value.startswith("insert into lmyzmail_inbound_mail_count_state"):
        return "inbound_batch_count_state"
    if value.startswith("insert into lmyzmail_inbound_mail_count_projection"):
        return "inbound_batch_projection_state"
    if (
        value.startswith("update lmyzmail_inbound_delivery_intent")
        and "state='indexed'" in value
        and "intent_id::text = any($1::text[])" in value
    ):
        return "inbound_batch_intent_advance"
    if "lmyzmail_inbound_delivery_intent" in value:
        return "other_inbound_intent"
    if "lmyzmail_inbound_mail_count_" in value:
        return "other_inbound_count"
    if "email_index" in value:
        return "other_email_index"
    return "other"


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


def statistics(values: list[float]) -> dict[str, float | int | None]:
    return {
        "count": len(values),
        "total_ms": round(sum(values), 6),
        "mean_ms": round(sum(values) / len(values), 6) if values else None,
        "p50_ms": percentile(values, 0.50),
        "p95_ms": percentile(values, 0.95),
        "p99_ms": percentile(values, 0.99),
        "max_ms": max(values) if values else None,
    }


def parse_records(path: Path) -> tuple[list[DurationRecord], int]:
    records: list[DurationRecord] = []
    failed_duration_lines = 0
    current: re.Match[str] | None = None
    sql_lines: list[str] = []

    def finish() -> None:
        nonlocal current, sql_lines
        if current is None:
            return
        records.append(
            DurationRecord(
                timestamp=current.group("timestamp"),
                pid=int(current.group("pid")),
                duration_ms=float(current.group("duration")),
                phase=current.group("phase") or "statement",
                sql="\n".join(sql_lines),
            )
        )
        current = None
        sql_lines = []

    with path.open("r", encoding="utf-8", errors="strict") as stream:
        for raw_line in stream:
            line = raw_line.rstrip("\n")
            match = RECORD.match(line)
            if match is not None:
                finish()
                current = match
                sql_lines = [match.group("sql")]
                continue
            if current is not None and line.startswith("\t"):
                sql_lines.append(line.lstrip())
                continue
            finish()
            if " duration: " in line:
                failed_duration_lines += 1
    finish()
    return records, failed_duration_lines


def record_time(record: DurationRecord) -> datetime:
    return datetime.strptime(record.timestamp, "%Y-%m-%d %H:%M:%S.%f").replace(
        tzinfo=UTC
    )


def inbound_transaction_summary(records: list[DurationRecord]) -> dict[str, object]:
    active: dict[int, list[DurationRecord]] = {}
    completed: list[list[DurationRecord]] = []
    incomplete_with_inbound = 0
    for record in records:
        label = category(record.sql)
        if label == "transaction_begin":
            previous = active.pop(record.pid, None)
            if previous is not None and any(
                category(item.sql) == "inbound_batch_intent_read" for item in previous
            ):
                incomplete_with_inbound += 1
            active[record.pid] = [record]
            continue
        transaction = active.get(record.pid)
        if transaction is None:
            continue
        transaction.append(record)
        if label in {"transaction_commit", "transaction_rollback"}:
            active.pop(record.pid)
            if any(
                category(item.sql) == "inbound_batch_intent_read"
                for item in transaction
            ):
                completed.append(transaction)
    incomplete_with_inbound += sum(
        1
        for transaction in active.values()
        if any(
            category(item.sql) == "inbound_batch_intent_read" for item in transaction
        )
    )

    by_category_phase: dict[tuple[str, str], list[float]] = defaultdict(list)
    elapsed_ms: list[float] = []
    logged_duration_ms: list[float] = []
    record_counts: list[float] = []
    for transaction in completed:
        elapsed_ms.append(
            (record_time(transaction[-1]) - record_time(transaction[0])).total_seconds()
            * 1000
        )
        logged_duration_ms.append(sum(item.duration_ms for item in transaction))
        record_counts.append(float(len(transaction)))
        for item in transaction:
            label = category(item.sql)
            by_category_phase[(label, item.phase)].append(item.duration_ms)

    categories: dict[str, dict[str, object]] = defaultdict(dict)
    for (label, phase), values in sorted(by_category_phase.items()):
        categories[label][phase] = statistics(values)
    return {
        "count": len(completed),
        "incomplete_count": incomplete_with_inbound,
        "elapsed_ms": statistics(elapsed_ms),
        "logged_duration_ms": statistics(logged_duration_ms),
        "duration_record_count": statistics(record_counts),
        "categories": dict(categories),
    }


def summarize(path: Path) -> dict[str, object]:
    records, failed_duration_lines = parse_records(path)
    by_category_phase: dict[tuple[str, str], list[float]] = defaultdict(list)
    by_pid_category_phase: dict[int, dict[tuple[str, str], list[float]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for record in records:
        label = category(record.sql)
        by_category_phase[(label, record.phase)].append(record.duration_ms)
        by_pid_category_phase[record.pid][(label, record.phase)].append(
            record.duration_ms
        )

    categories: dict[str, dict[str, object]] = defaultdict(dict)
    for (label, phase), values in sorted(by_category_phase.items()):
        categories[label][phase] = statistics(values)

    inbound_pids = []
    for pid, groups in by_pid_category_phase.items():
        if not any(label == "inbound_batch_intent_read" for label, _ in groups):
            continue
        pid_categories: dict[str, dict[str, object]] = defaultdict(dict)
        for (label, phase), values in sorted(groups.items()):
            if label.startswith("inbound_batch_") or label.startswith("transaction_"):
                pid_categories[label][phase] = statistics(values)
        inbound_pids.append(
            {
                "pid": pid,
                "categories": dict(pid_categories),
            }
        )
    inbound_pids.sort(key=lambda value: int(value["pid"]))

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return {
        "schema_version": 1,
        "source": path.name,
        "source_bytes": path.stat().st_size,
        "source_sha256": digest.hexdigest(),
        "first_timestamp_utc": records[0].timestamp if records else None,
        "last_timestamp_utc": records[-1].timestamp if records else None,
        "duration_record_count": len(records),
        "failed_duration_line_count": failed_duration_lines,
        "categories": dict(categories),
        "inbound_backend_pids": inbound_pids,
        "inbound_transactions": inbound_transaction_summary(records),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = summarize(args.input.resolve(strict=True))
    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output is None:
        print(payload, end="")
    else:
        args.output.write_text(payload, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
