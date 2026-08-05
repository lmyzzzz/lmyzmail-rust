#!/usr/bin/env bash
set -euo pipefail

# Runtime manifests are refreshed only from an explicitly selected, pristine
# extraction of the frozen JDK and Debian packages.
if [[ "${LMYZMAIL_RECORD_RUNTIME_MANIFESTS:-}" != "1" ]]; then
    printf 'Set LMYZMAIL_RECORD_RUNTIME_MANIFESTS=1 for an explicit manifest refresh\n' >&2
    exit 2
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
blackbox_dir="$(cd -- "$script_dir/.." && pwd -P)"
repo_dir="$(cd -- "$blackbox_dir/.." && pwd -P)"
state_input="$repo_dir/.blackbox"
[[ ! -L "$state_input" ]] || {
    printf 'Refusing symlinked blackbox state directory: %s\n' "$state_input" >&2
    exit 2
}
mkdir -p -- "$state_input"
state_root="$(realpath -e -- "$state_input")"
source_input="${LMYZMAIL_RUNTIME_SOURCE:-$state_root/runtime}"
[[ "$source_input" == /* ]] || source_input="$repo_dir/$source_input"
[[ ! -L "$source_input" ]] || {
    printf 'Runtime source must not be a symlink: %s\n' "$source_input" >&2
    exit 2
}
source_root="$(realpath -e -- "$source_input")"

for command_name in find flock mkdir mktemp mv readlink realpath rm sha256sum sort xargs; do
    command -v "$command_name" >/dev/null || {
        printf 'Missing required command: %s\n' "$command_name" >&2
        exit 2
    }
done
case "$source_root" in
    /|"$repo_dir"|"$blackbox_dir")
        printf 'Refusing overly broad runtime source: %s\n' "$source_root" >&2
        exit 2
        ;;
esac
for name in jdk22 postgres-root redis-root; do
    [[ -d "$source_root/$name" && ! -L "$source_root/$name" ]] || {
        printf 'Runtime source component is missing or symlinked: %s\n' "$source_root/$name" >&2
        exit 2
    }
done

exec 9>"$state_root/provision-runtime.lock"
flock -w "${LMYZMAIL_RUNTIME_LOCK_TIMEOUT:-30}" -s 9
temporary="$(mktemp -d "$blackbox_dir/.runtime-record.XXXXXXXX")"
trap 'rm -rf -- "$temporary"' EXIT

(
    cd -- "$source_root"
    while IFS= read -r -d '' relative; do
        relative="${relative#./}"
        [[ -n "$relative" && "$relative" != *$'\n'* && "$relative" != *$'\t'* ]] || {
            printf 'Unsupported runtime path: %q\n' "$relative" >&2
            exit 2
        }
    done < <(find -P jdk22 postgres-root redis-root -print0)
    while IFS= read -r -d '' relative; do
        target="$(readlink -- "$relative")"
        [[ -n "$target" && "$target" != /* && "$target" != *$'\n'* && "$target" != *$'\t'* ]] || {
            printf 'Unsupported runtime symlink target: %q -> %q\n' "$relative" "$target" >&2
            exit 2
        }
    done < <(find -P jdk22 postgres-root redis-root -type l -print0)

    find -P jdk22 postgres-root redis-root -type f -print0 \
        | LC_ALL=C sort -z \
        | xargs -0 -r sha256sum >"$temporary/runtime-extracted.sha256"
    find -P jdk22 postgres-root redis-root -type l -printf '%p\t%l\n' \
        | LC_ALL=C sort >"$temporary/runtime-extracted-links.lock"
    find -P jdk22 postgres-root redis-root -printf '%y\t%m\t%p\n' \
        | LC_ALL=C sort >"$temporary/runtime-extracted-modes.lock"
)

mv -- "$temporary/runtime-extracted.sha256" "$blackbox_dir/runtime-extracted.sha256"
mv -- "$temporary/runtime-extracted-links.lock" "$blackbox_dir/runtime-extracted-links.lock"
mv -- "$temporary/runtime-extracted-modes.lock" "$blackbox_dir/runtime-extracted-modes.lock"
printf 'Recorded runtime manifests for %s\n' "$source_root"
