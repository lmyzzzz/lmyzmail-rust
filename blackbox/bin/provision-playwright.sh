#!/usr/bin/env bash
set -euo pipefail

# Restore the exact Playwright browser tree from an already-populated local cache.
# This script intentionally has no download path: browser bytes are an attested
# input to the black-box harness, not a dependency resolved at test time.

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
blackbox_dir="$(cd -- "$script_dir/.." && pwd -P)"
repo_dir="$(cd -- "$blackbox_dir/.." && pwd -P)"
state_root="$(realpath -m -- "$repo_dir/.blackbox")"
cache_input="${LMYZMAIL_PLAYWRIGHT_CACHE:-$state_root/playwright-cache}"
target_input="${LMYZMAIL_PLAYWRIGHT_ROOT:-$state_root/ms-playwright}"
[[ "$cache_input" == /* ]] || cache_input="$repo_dir/$cache_input"
[[ "$target_input" == /* ]] || target_input="$repo_dir/$target_input"
if [[ -L "$cache_input" || -L "$target_input" ]]; then
    printf 'Playwright cache and target must not be symlinks\n' >&2
    exit 2
fi
cache_root="$(realpath -m -- "$cache_input")"
target_root="$(realpath -m -- "$target_input")"
manifest_dir="$blackbox_dir/manifests"
hash_manifest="$manifest_dir/playwright-files.sha256"
link_manifest="$manifest_dir/playwright-links.lock"
mode_manifest="$manifest_dir/playwright-modes.lock"

for command_name in chmod cmp cp cut dirname find flock mktemp mv readlink realpath rm sed sha256sum sort stat; do
    command -v "$command_name" >/dev/null || {
        printf 'Missing required command: %s\n' "$command_name" >&2
        exit 2
    }
done

is_within() {
    local root="$1"
    local path="$2"
    case "$path" in
        "$root"|"$root"/*) return 0 ;;
        *) return 1 ;;
    esac
}

is_safe_relative_path() {
    local path="$1"
    [[ -n "$path" && "$path" != /* && "$path" != *$'\n'* && "$path" != *$'\t'* ]] || return 1
    case "$path" in
        .|./*|../*|*/../*|*/./*|*/.|*/..) return 1 ;;
    esac
    [[ "$(realpath -m -- "/$path")" == "/$path" ]]
}

if ! is_within "$state_root" "$cache_root" || ! is_within "$state_root" "$target_root"; then
    printf 'Refusing Playwright path outside %s\ncache: %s\ntarget: %s\n' \
        "$state_root" "$cache_root" "$target_root" >&2
    exit 2
fi
if [[ "$cache_root" == "$target_root" ]]; then
    printf 'Playwright cache and target must be distinct paths\n' >&2
    exit 2
fi
if is_within "$cache_root" "$target_root" || is_within "$target_root" "$cache_root"; then
    printf 'Playwright cache and target must not contain one another\n' >&2
    exit 2
fi
case "$cache_root" in
    "$target_root"/*) printf 'Playwright cache must not contain the target\n' >&2; exit 2 ;;
esac
case "$target_root" in
    "$cache_root"/*) printf 'Playwright target must not contain the cache\n' >&2; exit 2 ;;
esac
if [[ ! -d "$cache_root" || -L "$cache_root" ]]; then
    printf 'Playwright cache directory is missing or a symlink: %s\n' "$cache_root" >&2
    exit 2
fi
if [[ -L "$target_root" ]]; then
    printf 'Playwright target must not be a symlink: %s\n' "$target_root" >&2
    exit 2
fi
for manifest in "$hash_manifest" "$link_manifest" "$mode_manifest"; do
    [[ -f "$manifest" ]] || {
        printf 'Playwright manifest is missing: %s\n' "$manifest" >&2
        exit 2
    }
done

mkdir -p -- "$state_root"
exec 9>"$state_root/playwright-provision.lock"
flock -w "${LMYZMAIL_PLAYWRIGHT_LOCK_TIMEOUT:-30}" -x 9

mode_probe="$(mktemp "$state_root/.playwright-mode-probe.XXXXXXXX")"
chmod 600 "$mode_probe"
if [[ "$(stat -c '%a' -- "$mode_probe")" == "600" ]]; then
    enforce_modes=true
else
    enforce_modes=false
    printf 'Filesystem does not preserve chmod; verifying node types without mode bits: %s\n' \
        "$state_root" >&2
fi
rm -f -- "$mode_probe"

verify_tree() {
    local root="$1"
    local actual_modes actual_links actual_hashes expected_nodes actual_nodes
    local rel expected digest resolved link_target
    local link_dir resolved_target
    if [[ ! -d "$root" || -L "$root" ]]; then
        return 1
    fi
    root="$(realpath -m -- "$root")"

    actual_modes="$(mktemp "$state_root/.playwright-modes.XXXXXXXX")"
    actual_links="$(mktemp "$state_root/.playwright-links.XXXXXXXX")"
    actual_hashes="$(mktemp "$state_root/.playwright-hashes.XXXXXXXX")"
    (
        cd -- "$root"
        find -P . -mindepth 1 -printf '%y\t%m\t%p\n' \
            | sed 's#^\([fdl]\)\t\([0-9][0-9]*\)\t\./#\1\t\2\t#' \
            | LC_ALL=C sort >"$actual_modes"
        find -P . -type l -printf '%p\t%l\n' \
            | sed 's#^\./##' \
            | LC_ALL=C sort >"$actual_links"
        find -P . -type f -print0 \
            | while IFS= read -r -d '' rel; do
                rel="${rel#./}"
                [[ "$rel" != *$'\n'* && "$rel" != *$'\t'* ]] || exit 1
                digest="$(sha256sum -- "$rel")"
                digest="${digest%% *}"
                printf '%s\t%s\n' "$digest" "$rel"
            done \
            | LC_ALL=C sort >"$actual_hashes"
    )

    if [[ "$enforce_modes" == true ]]; then
        cmp --silent "$mode_manifest" "$actual_modes" || {
            rm -f -- "$actual_modes" "$actual_links" "$actual_hashes"
            return 1
        }
    else
        expected_nodes="$(mktemp "$state_root/.playwright-expected-nodes.XXXXXXXX")"
        actual_nodes="$(mktemp "$state_root/.playwright-actual-nodes.XXXXXXXX")"
        cut -f1,3 -- "$mode_manifest" | LC_ALL=C sort >"$expected_nodes"
        cut -f1,3 -- "$actual_modes" | LC_ALL=C sort >"$actual_nodes"
        if ! cmp --silent "$expected_nodes" "$actual_nodes"; then
            rm -f -- "$actual_modes" "$actual_links" "$actual_hashes" \
                "$expected_nodes" "$actual_nodes"
            return 1
        fi
        rm -f -- "$expected_nodes" "$actual_nodes"
    fi

    if ! cmp --silent "$link_manifest" "$actual_links" ||
       ! cmp --silent "$hash_manifest" "$actual_hashes"; then
        rm -f -- "$actual_modes" "$actual_links" "$actual_hashes"
        return 1
    fi

    while IFS=$'\t' read -r expected rel; do
        if [[ -z "$expected" || -z "$rel" ]] || ! is_safe_relative_path "$rel"; then
            rm -f -- "$actual_modes" "$actual_links" "$actual_hashes"
            return 1
        fi
        resolved="$(realpath -m -- "$root/$rel")"
        if ! is_within "$root" "$resolved" || [[ ! -f "$root/$rel" || -L "$root/$rel" ]]; then
            rm -f -- "$actual_modes" "$actual_links" "$actual_hashes"
            return 1
        fi
    done <"$hash_manifest"

    while IFS=$'\t' read -r rel link_target; do
        if [[ -z "$rel" || -z "$link_target" ]] || ! is_safe_relative_path "$rel" ||
           [[ "$link_target" == /* || "$link_target" == *$'\n'* || "$link_target" == *$'\t'* ]]; then
            rm -f -- "$actual_modes" "$actual_links" "$actual_hashes"
            return 1
        fi
        resolved="$(realpath -m -- "$root/$rel")"
        link_dir="${rel%/*}"
        [[ "$link_dir" == "$rel" ]] && link_dir='.'
        resolved_target="$(realpath -m -- "$root/$link_dir/$link_target")"
        if ! is_within "$root" "$resolved" || [[ ! -L "$root/$rel" ]] ||
           [[ "$(readlink -- "$root/$rel")" != "$link_target" ]] ||
           ! is_within "$root" "$resolved_target"; then
            rm -f -- "$actual_modes" "$actual_links" "$actual_hashes"
            return 1
        fi
    done <"$link_manifest"

    rm -f -- "$actual_modes" "$actual_links" "$actual_hashes"
}

if verify_tree "$cache_root"; then
    printf 'Playwright cache verified: %s\n' "$cache_root"
else
    printf 'Playwright cache does not match the frozen manifests: %s\n' "$cache_root" >&2
    exit 3
fi

if [[ -d "$target_root" ]] && verify_tree "$target_root"; then
    printf 'Playwright target already verified: %s\n' "$target_root"
    exit 0
fi

stage_root="$(mktemp -d "$state_root/.playwright-stage.XXXXXXXX")"
old_parent=''
old_root=''
cleanup() {
    if [[ -n "$stage_root" ]]; then
        rm -rf -- "$stage_root"
    fi
    if [[ -n "$old_parent" && -e "$old_parent" ]]; then
        rm -rf -- "$old_parent"
    fi
}
trap cleanup EXIT

cp -a -- "$cache_root/." "$stage_root/"
verify_tree "$stage_root" || {
    printf 'Staged Playwright tree does not match the frozen manifests\n' >&2
    exit 4
}

if [[ -e "$target_root" ]]; then
    old_parent="$(mktemp -d "$state_root/.playwright-old.XXXXXXXX")"
    old_root="$old_parent/root"
    mv -- "$target_root" "$old_root"
fi
mkdir -p -- "$(dirname -- "$target_root")"
if ! mv -- "$stage_root" "$target_root"; then
    if [[ -n "$old_root" && ! -e "$target_root" ]]; then
        mv -- "$old_root" "$target_root"
        old_root=''
    fi
    exit 5
fi
stage_root=''
if ! verify_tree "$target_root"; then
    printf 'Installed Playwright tree failed final verification\n' >&2
    rm -rf -- "$target_root"
    if [[ -n "$old_root" && -e "$old_root" ]]; then
        mv -- "$old_root" "$target_root"
        old_root=''
    fi
    exit 6
fi
printf 'Playwright ready: %s\n' "$target_root"
