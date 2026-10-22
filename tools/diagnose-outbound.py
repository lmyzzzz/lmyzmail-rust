#!/usr/bin/env python3
"""Run an unchanged outbound scenario and retain its logs/DB state on failure."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "blackbox/src"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("4XX", "QUEUE", "TLS_VALIDITY", "STRESS_DELIVERY"), required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--inside", action="store_true")
    args = parser.parse_args()
    if not args.inside:
        command = ["unshare", "--user", "--net", "--map-current-user", "--keep-caps",
                   "--kill-child", "--fork", sys.executable, str(Path(__file__).resolve()),
                   "--inside", "--mode", args.mode, "--output", str(args.output.resolve())]
        raise SystemExit(subprocess.call(command, cwd=ROOT))
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    subprocess.run(["ip", "addr", "add", "93.184.216.34/32", "dev", "lo"], check=True)
    args.output.mkdir(exist_ok=False, parents=True)
    os.environ["LMYZMAIL_OUTBOUND_TARGET"] = "candidate"
    if binary := os.environ.get("LMYZMAIL_DIAGNOSTIC_BINARY"):
        os.environ["LMYZMAIL_CANDIDATE_COMMAND_JSON"] = json.dumps([
            str(Path(binary).resolve(strict=True)), "--config", "{config}",
        ])
    from lmyzmail_blackbox import outbound_oracle_probe as probe
    from lmyzmail_blackbox.runtime import CandidateRuntime
    import psycopg
    from psycopg import sql
    import redis

    original_stop = CandidateRuntime.stop
    runtime_number = 0

    def retain_then_stop(runtime):
        nonlocal runtime_number
        runtime_number += 1
        destination = args.output / f"runtime-{runtime_number}"
        destination.mkdir()
        try:
            if runtime.workspace is not None:
                for log in runtime.workspace.rglob("*.log"):
                    target = destination / log.relative_to(runtime.workspace)
                    target.parent.mkdir(exist_ok=True, parents=True)
                    shutil.copyfile(log, target)
                files = [str(path.relative_to(runtime.workspace))
                         for path in runtime.workspace.rglob("*") if path.is_file()]
                with (destination / "files.json").open("x") as stream:
                    json.dump(sorted(files), stream, indent=2)
            if runtime.ports is not None:
                with psycopg.connect(host="127.0.0.1", port=runtime.ports.postgres,
                                     user="lmyzmail_test", dbname="lmyzmail", connect_timeout=5) as connection:
                    rows = connection.execute(
                        "SELECT id,status,retry_count,last_error,next_retry_at,processor_id,processing_started_at "
                        "FROM outbound_mail_queue ORDER BY id LIMIT 1000"
                    ).fetchall()
                    with (destination / "queue-state.json").open("x") as stream:
                        json.dump(rows, stream, default=str, indent=2)
                    tables = connection.execute(
                        "SELECT tablename FROM pg_tables WHERE schemaname='public' "
                        "AND tablename LIKE 'lmyzmail%' ORDER BY tablename"
                    ).fetchall()
                    for (table,) in tables:
                        values = connection.execute(sql.SQL(
                            "SELECT row_to_json(t) FROM (SELECT * FROM {} LIMIT 1000) t"
                        ).format(sql.Identifier(table))).fetchall()
                        with (destination / f"{table}.json").open("x") as stream:
                            json.dump([value[0] for value in values], stream, default=str, indent=2)
                with redis.Redis(host="127.0.0.1", port=runtime.ports.redis,
                                 decode_responses=True) as client:
                    state = {}
                    for key in sorted(client.scan_iter(match="botmail:mail:queue:*", count=100)):
                        kind = client.type(key)
                        value = {"string": client.get, "list": lambda k: client.lrange(k, 0, -1),
                                 "set": lambda k: sorted(client.smembers(k)), "hash": client.hgetall,
                                 "zset": lambda k: client.zrange(k, 0, -1, withscores=True)}[kind](key)
                        state[key] = {"type": kind, "ttl": client.ttl(key), "value": value}
                    with (destination / "redis-state.json").open("x") as stream:
                        json.dump(state, stream, default=str, indent=2)
        finally:
            original_stop(runtime)

    CandidateRuntime.stop = retain_then_stop
    if args.mode == "STRESS_DELIVERY":
        sys.path.insert(0, str(ROOT / "blackbox/tests"))
        from test_oracle_stress import test_rust_candidate_sigterm_during_stress_delivery_keeps_queue_consistent
        test_rust_candidate_sigterm_during_stress_delivery_keeps_queue_consistent()
        return
    runners = {"4XX": probe.run_4xx_probe, "QUEUE": probe.run_probe,
               "TLS_VALIDITY": probe.run_tls_validity_probe}
    result = runners[args.mode]()
    with (args.output / "observation.json").open("x") as stream:
        json.dump(result, stream, indent=2, default=str)


if __name__ == "__main__":
    main()
