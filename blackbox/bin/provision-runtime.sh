#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
blackbox_dir="$(cd "$script_dir/.." && pwd)"
repo_dir="$(cd "$blackbox_dir/.." && pwd)"
runtime_input="${LMYZMAIL_BLACKBOX_RUNTIME:-$repo_dir/.blackbox/runtime}"
lock_file="$blackbox_dir/runtime-packages.lock"
hash_lock="$blackbox_dir/runtime-extracted.sha256"
link_lock="$blackbox_dir/runtime-extracted-links.lock"
mode_lock="$blackbox_dir/runtime-extracted-modes.lock"
mkdir -p "$repo_dir/.blackbox"
blackbox_state="$(realpath -m -- "$repo_dir/.blackbox")"
runtime_dir="$(realpath -m -- "$runtime_input")"
cache_dir="$runtime_dir/downloads"

case "$runtime_dir" in
    "$blackbox_state"/*) ;;
    *)
        printf 'Refusing runtime path outside %s: %s\n' "$blackbox_state" "$runtime_dir" >&2
        exit 2
        ;;
esac

for command_name in apt-get awk chmod cmp curl cut dpkg-deb find flock mkdir mktemp mv realpath rm sha256sum sort stat tar xargs; do
    command -v "$command_name" >/dev/null || {
        printf 'Missing required command: %s\n' "$command_name" >&2
        exit 2
    }
done

mkdir -p "$cache_dir"
exec 9>"$blackbox_state/provision-runtime.lock"
flock 9

read -r _jdk_kind _jdk_name jdk_url jdk_sha < <(awk '$1 == "jdk" { print; exit }' "$lock_file")
if [[ -z "${jdk_url:-}" || -z "${jdk_sha:-}" ]]; then
    printf 'JDK entry is missing from %s\n' "$lock_file" >&2
    exit 2
fi

jdk_archive="$cache_dir/oracle-jdk-22.0.2-linux-x64.tar.gz"
if [[ ! -f "$jdk_archive" ]]; then
    curl --fail --location --retry 3 --output "$jdk_archive.part" "$jdk_url"
    mv "$jdk_archive.part" "$jdk_archive"
fi
printf '%s  %s\n' "$jdk_sha" "$jdk_archive" | sha256sum --check --status || {
    printf 'JDK archive checksum mismatch: %s\n' "$jdk_archive" >&2
    exit 3
}

if [[ ! -x "$runtime_dir/jdk22/bin/java" ]]; then
    jdk_staging="$(mktemp -d "$runtime_dir/.jdk22.XXXXXXXX")"
    if ! tar -xzf "$jdk_archive" --strip-components=1 -C "$jdk_staging"; then
        rm -rf -- "$jdk_staging"
        exit 4
    fi
    mv "$jdk_staging" "$runtime_dir/jdk22"
fi

download_deb() {
    local package_name="$1"
    local package_version="$2"
    local candidate
    while IFS= read -r candidate; do
        if [[ "$(dpkg-deb -f "$candidate" Package 2>/dev/null || true)" == "$package_name" ]] &&
           [[ "$(dpkg-deb -f "$candidate" Version 2>/dev/null || true)" == "$package_version" ]] &&
           [[ "$(dpkg-deb -f "$candidate" Architecture 2>/dev/null || true)" == "amd64" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done < <(find "$cache_dir" -maxdepth 1 -type f -name '*.deb' -print | sort)

    local download_staging
    download_staging="$(mktemp -d "$runtime_dir/.download.XXXXXXXX")"
    if ! (
        cd "$download_staging"
        apt-get download "${package_name}=${package_version}" >&2
    ); then
        rm -rf -- "$download_staging"
        return 4
    fi

    while IFS= read -r candidate; do
        if [[ "$(dpkg-deb -f "$candidate" Package 2>/dev/null || true)" == "$package_name" ]] &&
           [[ "$(dpkg-deb -f "$candidate" Version 2>/dev/null || true)" == "$package_version" ]] &&
           [[ "$(dpkg-deb -f "$candidate" Architecture 2>/dev/null || true)" == "amd64" ]]; then
            local cached_path="$cache_dir/$(basename "$candidate")"
            mv -f "$candidate" "$cached_path"
            rmdir "$download_staging"
            printf '%s\n' "$cached_path"
            return 0
        fi
    done < <(find "$download_staging" -maxdepth 1 -type f -name '*.deb' -print | sort)

    printf 'Downloaded package did not match lock: %s=%s\n' "$package_name" "$package_version" >&2
    rm -rf -- "$download_staging"
    return 4
}

declare -a postgres_packages=()
declare -a redis_packages=()
while read -r kind package_name package_version expected_sha; do
    [[ "$kind" == "deb" ]] || continue
    package_path="$(download_deb "$package_name" "$package_version")"
    if [[ "$expected_sha" != "-" ]]; then
        printf '%s  %s\n' "$expected_sha" "$package_path" | sha256sum --check --status || {
            printf 'Package checksum mismatch: %s\n' "$package_path" >&2
            exit 3
        }
    fi
    case "$package_name" in
        redis-*|libjemalloc2|liblua5.4-0|liblzf1) redis_packages+=("$package_path") ;;
        *) postgres_packages+=("$package_path") ;;
    esac
done < "$lock_file"

extract_root() {
    local destination="$1"
    shift
    if [[ -d "$destination" ]]; then
        return 0
    fi
    local staging
    staging="$(mktemp -d "$runtime_dir/.packages.XXXXXXXX")"
    for package_path in "$@"; do
        if ! dpkg-deb --extract "$package_path" "$staging"; then
            rm -rf -- "$staging"
            return 5
        fi
    done
    mv "$staging" "$destination"
}

extract_root "$runtime_dir/postgres-root" "${postgres_packages[@]}"
extract_root "$runtime_dir/redis-root" "${redis_packages[@]}"

postgres_bin="$runtime_dir/postgres-root/usr/lib/postgresql/16/bin/postgres"
redis_bin="$runtime_dir/redis-root/usr/bin/redis-server"
[[ -x "$postgres_bin" ]] || { printf 'PostgreSQL binary missing after extraction\n' >&2; exit 5; }
[[ -x "$redis_bin" ]] || { printf 'Redis binary missing after extraction\n' >&2; exit 5; }

for manifest in "$hash_lock" "$link_lock" "$mode_lock"; do
    [[ -f "$manifest" ]] || {
        printf 'Extracted runtime manifest is missing: %s\n' "$manifest" >&2
        exit 6
    }
done

mode_probe="$(mktemp "$runtime_dir/.mode-probe.XXXXXXXX")"
chmod 600 "$mode_probe"
if [[ "$(stat -c '%a' -- "$mode_probe")" == "600" ]]; then
    enforce_modes=true
else
    enforce_modes=false
    printf 'Filesystem does not preserve chmod; verifying runtime node types without mode bits: %s\n' \
        "$runtime_dir" >&2
fi
rm -f -- "$mode_probe"

(
    cd "$runtime_dir"
    sha256sum --check --status "$hash_lock" || {
        printf 'Extracted runtime file hash mismatch\n' >&2
        exit 6
    }
    actual_links="$(mktemp "$runtime_dir/.verify-links.XXXXXXXX")"
    actual_modes="$(mktemp "$runtime_dir/.verify-modes.XXXXXXXX")"
    trap 'rm -f -- "$actual_links" "$actual_modes"' EXIT
    find jdk22 postgres-root redis-root -type l -printf '%p\t%l\n' \
        | LC_ALL=C sort > "$actual_links"
    find jdk22 postgres-root redis-root -printf '%y\t%m\t%p\n' \
        | LC_ALL=C sort > "$actual_modes"
    cmp --silent "$link_lock" "$actual_links" || {
        printf 'Extracted runtime symlink manifest mismatch\n' >&2
        exit 6
    }
    if [[ "$enforce_modes" == true ]]; then
        cmp --silent "$mode_lock" "$actual_modes" || {
            printf 'Extracted runtime mode manifest mismatch\n' >&2
            exit 6
        }
    else
        expected_nodes="$(mktemp "$runtime_dir/.expected-nodes.XXXXXXXX")"
        actual_nodes="$(mktemp "$runtime_dir/.actual-nodes.XXXXXXXX")"
        trap 'rm -f -- "$actual_links" "$actual_modes" "$expected_nodes" "$actual_nodes"' EXIT
        cut -f1,3 -- "$mode_lock" | LC_ALL=C sort >"$expected_nodes"
        cut -f1,3 -- "$actual_modes" | LC_ALL=C sort >"$actual_nodes"
        cmp --silent "$expected_nodes" "$actual_nodes" || {
            printf 'Extracted runtime node type manifest mismatch\n' >&2
            exit 6
        }
    fi
)

"$runtime_dir/jdk22/bin/java" -version
"$postgres_bin" --version
LD_LIBRARY_PATH="$runtime_dir/redis-root/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
    "$redis_bin" --version

find "$cache_dir" -maxdepth 1 -type f \( -name '*.deb' -o -name '*.tar.gz' \) -print0 \
    | sort -z \
    | xargs -0 sha256sum > "$runtime_dir/downloads.sha256"
printf 'Runtime ready: %s\n' "$runtime_dir"
