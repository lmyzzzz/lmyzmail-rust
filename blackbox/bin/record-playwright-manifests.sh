#!/usr/bin/env bash
set -euo pipefail

# Deliberately separate from provisioning: refreshing a manifest is an explicit
# operator action and never happens as a side effect of a test run.
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
blackbox_dir="$(cd -- "$script_dir/.." && pwd -P)"
repo_dir="$(cd -- "$blackbox_dir/.." && pwd -P)"
if [[ "${LMYZMAIL_RECORD_PLAYWRIGHT_MANIFESTS:-}" != "1" ]]; then
    printf 'Set LMYZMAIL_RECORD_PLAYWRIGHT_MANIFESTS=1 for an explicit manifest refresh\n' >&2
    exit 2
fi
state_input="$repo_dir/.blackbox"
[[ ! -L "$state_input" ]] || {
    printf 'Refusing symlinked blackbox state directory: %s\n' "$state_input" >&2
    exit 2
}
mkdir -p -- "$state_input"
state_root="$(realpath -e -- "$state_input")"
root_input="${LMYZMAIL_PLAYWRIGHT_SOURCE:-${LMYZMAIL_PLAYWRIGHT_ROOT:-$state_root/ms-playwright}}"
[[ "$root_input" == /* ]] || root_input="$repo_dir/$root_input"
[[ ! -L "$root_input" ]] || {
    printf 'Playwright root must not be a symlink: %s\n' "$root_input" >&2
    exit 2
}
root="$(realpath -e -- "$root_input")"
manifest_dir="$blackbox_dir/manifests"

for command_name in find flock mkdir mktemp mv readlink realpath rm sed sha256sum sort stat; do
    command -v "$command_name" >/dev/null || {
        printf 'Missing required command: %s\n' "$command_name" >&2
        exit 2
    }
done
[[ -d "$root" && ! -L "$root" ]] || {
    printf 'Playwright root is missing or a symlink: %s\n' "$root" >&2
    exit 2
}
case "$root" in
    /|"$repo_dir"|"$blackbox_dir"|"$manifest_dir")
        printf 'Refusing overly broad Playwright source: %s\n' "$root" >&2
        exit 2
        ;;
esac
mkdir -p -- "$manifest_dir"
exec 9>"$state_root/playwright-provision.lock"
flock -w "${LMYZMAIL_PLAYWRIGHT_LOCK_TIMEOUT:-30}" -s 9
tmp_dir="$(mktemp -d "$manifest_dir/.playwright-record.XXXXXXXX")"
trap 'rm -rf -- "$tmp_dir"' EXIT

(
    cd -- "$root"
    while IFS= read -r -d '' rel; do
        rel="${rel#./}"
        [[ -n "$rel" && "$rel" != *$'\n'* && "$rel" != *$'\t'* ]] || {
            printf 'Unsupported Playwright path: %q\n' "$rel" >&2
            exit 2
        }
    done < <(find -P . -mindepth 1 -print0)
    while IFS= read -r -d '' rel; do
        target="$(readlink -- "$rel")"
        [[ -n "$target" && "$target" != /* && "$target" != *$'\n'* && "$target" != *$'\t'* ]] || {
            printf 'Unsupported Playwright symlink target: %q -> %q\n' "$rel" "$target" >&2
            exit 2
        }
    done < <(find -P . -type l -print0)
    find -P . -mindepth 1 -printf '%y\t%m\t%p\n' \
        | sed 's#^\([fdl]\)\t\([0-9][0-9]*\)\t\./#\1\t\2\t#' \
        | LC_ALL=C sort >"$tmp_dir/playwright-modes.lock"
    find -P . -type l -printf '%p\t%l\n' \
        | sed 's#^\./##' \
        | LC_ALL=C sort >"$tmp_dir/playwright-links.lock"
    find -P . -type f -print0 \
        | while IFS= read -r -d '' rel; do
            rel="${rel#./}"
            [[ "$rel" != *$'\n'* && "$rel" != *$'\t'* ]] || exit 1
            digest="$(sha256sum -- "$rel")"
            digest="${digest%% *}"
            printf '%s\t%s\n' "$digest" "$rel"
        done \
        | LC_ALL=C sort >"$tmp_dir/playwright-files.sha256"
)

mv -- "$tmp_dir/playwright-files.sha256" "$manifest_dir/playwright-files.sha256"
mv -- "$tmp_dir/playwright-links.lock" "$manifest_dir/playwright-links.lock"
mv -- "$tmp_dir/playwright-modes.lock" "$manifest_dir/playwright-modes.lock"
printf 'Recorded Playwright manifests for %s\n' "$root"
