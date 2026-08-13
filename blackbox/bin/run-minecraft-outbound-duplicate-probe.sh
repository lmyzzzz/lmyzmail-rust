#!/usr/bin/env bash
set -euo pipefail

script_path="$(realpath -e -- "${BASH_SOURCE[0]}")"
script_dir="$(dirname "$script_path")"
blackbox_root="$(realpath -e -- "$script_dir/..")"
python_path="${LMYZMAIL_BLACKBOX_PYTHON:-python3}"

if [[ "${1:-}" == "__inside-minecraft-outbound-duplicate-netns" && "$#" == 1 ]]; then
    ip link set lo up
    ip addr add 93.184.216.34/32 dev lo
    exec env \
        PYTHONPATH="$blackbox_root/src:$blackbox_root/tools" \
        "$python_path" -m test_minecraft_outbound_duplicate --child
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
    LMYZMAIL_MINECRAFT_OUTBOUND_DUPLICATE_TARGET="${LMYZMAIL_MINECRAFT_OUTBOUND_DUPLICATE_TARGET:-java}" \
    "$script_path" __inside-minecraft-outbound-duplicate-netns
