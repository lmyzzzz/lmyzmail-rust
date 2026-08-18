#!/usr/bin/env bash
set -euo pipefail

if (($# != 1)); then
  echo "usage: $0 OUTPUT" >&2
  exit 2
fi

repository="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
output="$1"
if [[ "$output" != /* ]]; then
  output="$repository/$output"
fi
if [[ -e "$output" ]]; then
  echo "trace output already exists: $output" >&2
  exit 2
fi

while :; do
  postgres_pid="$(
    pgrep -n -f '/postgres -D /run/lmyzmail-benchmark-root/mounts/.*/postgres-data' || true
  )"
  if [[ -n "$postgres_pid" && -r "/proc/$postgres_pid/cmdline" ]]; then
    break
  fi
  sleep 0.2
done

command_line="$(tr '\0' ' ' <"/proc/$postgres_pid/cmdline")"
postgres_port="$(
  grep -oE -- '-p [0-9]+' <<<"$command_line" | head -n 1 | cut -d' ' -f2
)"
postgres_data="$(
  grep -oE -- '-D [^ ]+' <<<"$command_line" | head -n 1 | cut -d' ' -f2
)"
postgres_log="$(dirname "$postgres_data")/postgres.log"
postgres_root="$repository/.blackbox/runtime/postgres-root"
psql="$postgres_root/usr/lib/postgresql/16/bin/psql"
library_path="$postgres_root/usr/lib/x86_64-linux-gnu"

psql_in_namespace() {
  nsenter -t "$postgres_pid" -n env \
    LD_LIBRARY_PATH="$library_path" \
    "$psql" \
    -h 127.0.0.1 \
    -p "$postgres_port" \
    -U lmyzmail_test \
    -d postgres \
    "$@"
}

ready=0
for ((attempt = 0; attempt < 200; attempt++)); do
  if psql_in_namespace -Atc "SELECT 1" >/dev/null 2>&1; then
    ready=1
    break
  fi
  if [[ ! -r "/proc/$postgres_pid/stat" ]]; then
    break
  fi
  sleep 0.05
done
if ((ready == 0)); then
  echo "benchmark PostgreSQL did not become ready within 10 seconds" >&2
  exit 1
fi

psql_in_namespace -c "ALTER SYSTEM SET log_statement TO 'none'"
psql_in_namespace -c "ALTER SYSTEM SET log_min_duration_statement TO 0"
psql_in_namespace -c "ALTER SYSTEM SET log_parameter_max_length TO 0"
psql_in_namespace -c "SELECT pg_reload_conf()"
psql_in_namespace -Atc \
  "SELECT current_setting('log_statement'),
          current_setting('log_min_duration_statement'),
          current_setting('log_parameter_max_length')"
printf 'TRACE_PID=%s TRACE_PORT=%s TRACE_LOG=%s\n' \
  "$postgres_pid" "$postgres_port" "$postgres_log"

tail --pid="$postgres_pid" -n +1 -F "$postgres_log" >"$output"
