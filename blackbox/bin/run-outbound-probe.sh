#!/usr/bin/env bash
set -euo pipefail

script_path="$(realpath -e -- "${BASH_SOURCE[0]}")"
script_dir="$(dirname "$script_path")"
repository="$(realpath -e -- "$script_dir/..")"
python_path="${LMYZMAIL_BLACKBOX_PYTHON:-python3}"

if [[ "${1:-}" == "__inside-outbound-netns" && "$#" == 1 ]]; then
    ip link set lo up
    ip addr add 93.184.216.34/32 dev lo
    exec "$python_path" -m lmyzmail_blackbox.outbound_oracle_probe --child
fi

exec unshare \
    --user \
    --net \
    --map-current-user \
    --keep-caps \
    --kill-child \
    --fork \
    env \
    LMYZMAIL_BLACKBOX_PYTHON="$python_path" \
    PYTHONPATH="$repository/src" \
    "$script_path" __inside-outbound-netns
