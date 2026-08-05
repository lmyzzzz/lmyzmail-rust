#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "$script_dir/.." && pwd)"
blackbox_dir="$repo_dir/blackbox"
runtime_dir="$repo_dir/.blackbox/runtime"

for directory in jdk22 postgres-root redis-root; do
    [[ -d "$runtime_dir/$directory" ]] || {
        printf 'Missing extracted runtime directory: %s\n' "$runtime_dir/$directory" >&2
        exit 2
    }
done

hash_lock="$blackbox_dir/runtime-extracted.sha256"
link_lock="$blackbox_dir/runtime-extracted-links.lock"
mode_lock="$blackbox_dir/runtime-extracted-modes.lock"
for output in "$hash_lock" "$link_lock" "$mode_lock"; do
    [[ ! -e "$output" ]] || {
        printf 'Refusing to overwrite frozen runtime manifest: %s\n' "$output" >&2
        exit 3
    }
done

hash_temp="$(mktemp "$blackbox_dir/.runtime-hashes.XXXXXXXX")"
link_temp="$(mktemp "$blackbox_dir/.runtime-links.XXXXXXXX")"
mode_temp="$(mktemp "$blackbox_dir/.runtime-modes.XXXXXXXX")"
trap 'rm -f -- "$hash_temp" "$link_temp" "$mode_temp"' EXIT

(
    cd "$runtime_dir"
    find jdk22 postgres-root redis-root -type f -print0 \
        | sort -z \
        | xargs -0 sha256sum > "$hash_temp"
    find jdk22 postgres-root redis-root -type l -printf '%p\t%l\n' \
        | LC_ALL=C sort > "$link_temp"
    find jdk22 postgres-root redis-root -printf '%y\t%m\t%p\n' \
        | LC_ALL=C sort > "$mode_temp"
)

mv "$hash_temp" "$hash_lock"
mv "$link_temp" "$link_lock"
mv "$mode_temp" "$mode_lock"
trap - EXIT
printf 'Frozen extracted runtime: %s files, %s links, %s entries\n' \
    "$(wc -l < "$hash_lock")" \
    "$(wc -l < "$link_lock")" \
    "$(wc -l < "$mode_lock")"
