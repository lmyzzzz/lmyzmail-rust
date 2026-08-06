#!/usr/bin/env bash
set -euo pipefail

repository="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
binary="${LMYZMAIL_BINARY:-$repository/target/release/lmyzmail}"
config="${LMYZMAIL_CONFIG:-$repository/config/lmyzmail.properties.example}"
http_port="${LMYZMAIL_SMOKE_HTTP_PORT:-18080}"
log_path="$(mktemp "${TMPDIR:-/tmp}/lmyzmail-smoke.XXXXXX.log")"
response_path="$(mktemp "${TMPDIR:-/tmp}/lmyzmail-smoke.XXXXXX.json")"
pid=""

cleanup() {
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        kill -TERM "$pid" 2>/dev/null || true
        for _ in $(seq 1 100); do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.1
        done
        if kill -0 "$pid" 2>/dev/null; then
            kill -KILL "$pid" 2>/dev/null || true
        fi
        wait "$pid" 2>/dev/null || true
    fi
    rm -f -- "$log_path" "$response_path"
}
trap cleanup EXIT

[[ -x "$binary" ]] || { printf 'binary is not executable: %s\n' "$binary" >&2; exit 2; }
"$binary" --config "$config" --check-config \
    "--lmyzmail.http.port=$http_port" \
    --lmyzmail.smtp.port=11025 \
    --lmyzmail.htcpcp.port=18888 \
    --lmyzmail.minecraft.port=25575 >/dev/null

"$binary" --config "$config" \
    "--lmyzmail.http.port=$http_port" \
    --lmyzmail.smtp.port=11025 \
    --lmyzmail.htcpcp.port=18888 \
    --lmyzmail.minecraft.port=25575 >"$log_path" 2>&1 &
pid=$!

for _ in $(seq 1 100); do
    if curl --silent --show-error --fail --max-time 1 \
        "http://127.0.0.1:$http_port/api/health" >"$response_path"; then
        break
    fi
    sleep 0.1
done

grep -Eq '^\{"status":"healthy","timestamp":"[^\"]+"\}$' "$response_path"
kill -TERM "$pid"
wait "$pid"
pid=""
printf 'lmyzmail smoke passed on HTTP port %s\n' "$http_port"
