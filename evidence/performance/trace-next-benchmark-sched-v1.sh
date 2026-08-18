#!/usr/bin/env bash
set -euo pipefail

if (($# != 3)); then
  echo "usage: $0 OUTPUT CPU DURATION_SECONDS" >&2
  exit 2
fi
if ((EUID != 0)); then
  echo "scheduler tracing requires root" >&2
  exit 2
fi

repository="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
output="$1"
cpu="$2"
duration_seconds="$3"
if [[ "$output" != /* ]]; then
  output="$repository/$output"
fi
if [[ ! "$cpu" =~ ^[0-9]+$ || ! "$duration_seconds" =~ ^[1-9][0-9]*$ ]]; then
  echo "CPU and duration must be non-negative and positive integers" >&2
  exit 2
fi
if [[ -e "$output" ]]; then
  echo "trace output already exists: $output" >&2
  exit 2
fi

perf_binary="${LMYZMAIL_PERF_BINARY:-}"
if [[ -z "$perf_binary" ]]; then
  for candidate in /usr/lib/linux-tools/*/perf; do
    if [[ -x "$candidate" ]]; then
      perf_binary="$candidate"
    fi
  done
fi
if [[ -z "$perf_binary" || ! -x "$perf_binary" ]]; then
  echo "a real perf binary is required; the /usr/bin/perf wrapper is insufficient" >&2
  exit 2
fi

candidate_pid=""
for ((attempt = 0; attempt < 3600; attempt++)); do
  candidate_pid="$(
    pgrep -n -f '/target/profiling/x86_64-unknown-linux-gnu/release-with-debug/lmyzmail' \
      || true
  )"
  if [[ -n "$candidate_pid" && -r "/proc/$candidate_pid/stat" ]]; then
    break
  fi
  sleep 0.05
done
if [[ -z "$candidate_pid" || ! -r "/proc/$candidate_pid/stat" ]]; then
  echo "profiling candidate did not start within 180 seconds" >&2
  exit 1
fi

candidate_start_time="$(awk '{print $22}' "/proc/$candidate_pid/stat")"
printf 'TRACE_CANDIDATE_PID=%s TRACE_CANDIDATE_START=%s TRACE_CPU=%s TRACE_SECONDS=%s PERF=%s\n' \
  "$candidate_pid" "$candidate_start_time" "$cpu" "$duration_seconds" "$perf_binary"

exec "$perf_binary" record \
  -C "$cpu" \
  -e sched:sched_switch \
  -e sched:sched_wakeup \
  -e sched:sched_wakeup_new \
  -m 1024 \
  -o "$output" \
  -- sleep "$duration_seconds"
