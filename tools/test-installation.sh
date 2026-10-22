#!/usr/bin/env bash
set -euo pipefail

readonly REPOSITORY="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly BINARY="$REPOSITORY/target/x86_64-unknown-linux-gnu/release/lmyzmail"
readonly EXPECTED_BINARY_SHA256="$(sha256sum "$BINARY" | awk '{print $1}')"
STAGE="$(mktemp -d --tmpdir="${TMPDIR:-/tmp}" lmyzmail-install-smoke.XXXXXXXX)"
readonly STAGE

cleanup() {
    local resolved parent
    resolved="$(realpath -e "$STAGE" 2>/dev/null || true)"
    [[ -n "$resolved" ]] || return
    parent="$(realpath -e "${TMPDIR:-/tmp}")"
    if [[ $(dirname "$resolved") == "$parent" && $(basename "$resolved") == lmyzmail-install-smoke.* ]]; then
        rm -rf -- "$resolved"
    else
        printf 'refusing to remove unexpected smoke path: %s\n' "$resolved" >&2
    fi
}
trap cleanup EXIT

assert_mode() {
    local expected="$1"
    local path="$2"
    [[ $(stat -c %a "$path") == "$expected" ]] || {
        printf 'wrong mode for %s: expected=%s actual=%s\n' "$path" "$expected" "$(stat -c %a "$path")" >&2
        exit 1
    }
}

"$REPOSITORY/tools/install-lmyzmail.sh" --destdir "$STAGE" --binary "$BINARY"

MAINTENANCE_LOCK="$STAGE/run/lmyzmail-maintenance.lock"
[[ -f "$MAINTENANCE_LOCK" && ! -L "$MAINTENANCE_LOCK" ]]
assert_mode 600 "$MAINTENANCE_LOCK"
LOCK_PARENT_MODE="$(stat -c %a "$STAGE/run")"
[[ "$LOCK_PARENT_MODE" == 755 ]]
LOCKED_BINARY_SHA256="$(sha256sum "$STAGE/usr/bin/lmyzmail" | awk '{print $1}')"
LOCKED_UNIT_SHA256="$(sha256sum "$STAGE/usr/lib/systemd/system/lmyzmail.service" | awk '{print $1}')"
LOCK_READY="$STAGE/lock-ready"
(
    exec 8>"$MAINTENANCE_LOCK"
    flock 8
    : > "$LOCK_READY"
    sleep 5
) &
LOCK_HOLDER_PID=$!
for _ in {1..50}; do
    if [[ -e "$LOCK_READY" ]]; then
        break
    fi
    if ! kill -0 "$LOCK_HOLDER_PID" 2>/dev/null; then
        printf '%s\n' 'staged maintenance lock holder exited unexpectedly' >&2
        exit 1
    fi
    sleep 0.1
done
[[ -e "$LOCK_READY" ]] || {
    kill "$LOCK_HOLDER_PID" 2>/dev/null || true
    wait "$LOCK_HOLDER_PID" 2>/dev/null || true
    printf '%s\n' 'staged maintenance lock holder did not become ready' >&2
    exit 1
}
if "$REPOSITORY/tools/install-lmyzmail.sh" --destdir "$STAGE" --binary "$BINARY" \
    >/dev/null 2>&1
then
    kill "$LOCK_HOLDER_PID" 2>/dev/null || true
    wait "$LOCK_HOLDER_PID" 2>/dev/null || true
    printf '%s\n' 'installer unexpectedly ignored a held staged maintenance lock' >&2
    exit 1
fi
if "$REPOSITORY/tools/uninstall-lmyzmail.sh" --destdir "$STAGE" >/dev/null 2>&1; then
    kill "$LOCK_HOLDER_PID" 2>/dev/null || true
    wait "$LOCK_HOLDER_PID" 2>/dev/null || true
    printf '%s\n' 'uninstaller unexpectedly ignored a held staged maintenance lock' >&2
    exit 1
fi
kill "$LOCK_HOLDER_PID" 2>/dev/null || true
wait "$LOCK_HOLDER_PID" 2>/dev/null || true
[[ $(sha256sum "$STAGE/usr/bin/lmyzmail" | awk '{print $1}') == "$LOCKED_BINARY_SHA256" ]]
[[ $(sha256sum "$STAGE/usr/lib/systemd/system/lmyzmail.service" | awk '{print $1}') == "$LOCKED_UNIT_SHA256" ]]

LOCK_MODE_STAGE="$STAGE/lock-mode-stage"
mkdir -p -- "$LOCK_MODE_STAGE/run"
install -m 0644 -- /dev/null "$LOCK_MODE_STAGE/run/lmyzmail-maintenance.lock"
if "$REPOSITORY/tools/install-lmyzmail.sh" --destdir "$LOCK_MODE_STAGE" \
    --binary "$BINARY" >/dev/null 2>&1
then
    printf '%s\n' 'installer unexpectedly accepted a group-readable maintenance lock' >&2
    exit 1
fi
[[ ! -e "$LOCK_MODE_STAGE/usr/bin/lmyzmail" ]]

LOCK_SYMLINK_STAGE="$STAGE/lock-symlink-stage"
mkdir -p -- "$LOCK_SYMLINK_STAGE/run"
ln -s -- "$STAGE/lock-symlink-target" \
    "$LOCK_SYMLINK_STAGE/run/lmyzmail-maintenance.lock"
if "$REPOSITORY/tools/uninstall-lmyzmail.sh" --destdir "$LOCK_SYMLINK_STAGE" \
    >/dev/null 2>&1
then
    printf '%s\n' 'uninstaller unexpectedly accepted a symlinked maintenance lock' >&2
    exit 1
fi
[[ ! -e "$STAGE/lock-symlink-target" ]]

[[ $(sha256sum "$STAGE/usr/bin/lmyzmail" | awk '{print $1}') == "$EXPECTED_BINARY_SHA256" ]]
[[ $(sha256sum "$STAGE/usr/share/lmyzmail/models/skibidi-inferx/skibidi_ai.safetensors" | awk '{print $1}') == 4fc4f7a0eb5d7e1210ddd7fee63a756775f5b7155db210080cfd8cc759403428 ]]
[[ $(sha256sum "$STAGE/usr/share/lmyzmail/models/skibidi-inferx/tokenizer.json" | awk '{print $1}') == 6624adb41b9274bf0cc73c62ebd26eb2bcf281d533f30607ba415105917d81f3 ]]
[[ $(sha256sum "$STAGE/usr/share/lmyzmail/assets/skibidi_toilet_episode_1.mp4" | awk '{print $1}') == 0e76229bb77ebcf471aec692fa34709cfbbe3dc192127a852a518e34bdd0ecc7 ]]
assert_mode 755 "$STAGE/usr/bin/lmyzmail"
assert_mode 644 "$STAGE/usr/lib/systemd/system/lmyzmail.service"
assert_mode 640 "$STAGE/etc/lmyzmail/application.properties"
assert_mode 750 "$STAGE/var/lib/lmyzmail/data/mail/.lmyzmail-outbound"
assert_mode 750 "$STAGE/var/log/lmyzmail"
grep -Fq 'CapabilityBoundingSet=CAP_NET_BIND_SERVICE' "$STAGE/usr/lib/systemd/system/lmyzmail.service"
grep -Fq 'ProtectHome=true' "$STAGE/usr/lib/systemd/system/lmyzmail.service"
grep -Fq 'lmyzmail.xdp.enabled=false' "$STAGE/etc/lmyzmail/application.properties"
CONFIG_SUMMARY="$("$STAGE/usr/bin/lmyzmail" \
    --config "$STAGE/etc/lmyzmail/application.properties" --check-config)"
[[ " $CONFIG_SUMMARY " == *" config=$STAGE/etc/lmyzmail/application.properties "* ]]
[[ " $CONFIG_SUMMARY " == *" xdp=false "* ]]
cp -a /usr/lib/systemd/system/. "$STAGE/usr/lib/systemd/system/"
cp -- "$REPOSITORY/deploy/lmyzmail.service" \
    "$STAGE/usr/lib/systemd/system/lmyzmail.service"
systemd-analyze verify --root="$STAGE" \
    /usr/lib/systemd/system/lmyzmail.service

DROP_IN="$STAGE/etc/systemd/system/lmyzmail.service.d/legacy-paths.conf"
assert_mode 644 "$DROP_IN"
grep -Fxq '# Managed by install-lmyzmail.sh; regenerated on every installation.' "$DROP_IN"
if grep -Eq '^Bind(ReadOnly)?Paths=' "$DROP_IN"; then
    printf '%s\n' 'staged installer unexpectedly emitted a host path grant' >&2
    exit 1
fi

{
    printf '%s\n' '# Managed by install-lmyzmail.sh; regenerated on every installation.'
    printf '%s\n' '[Service]'
    printf '%s\n' 'BindPaths=/srv/stale-rw'
    printf '%s\n' 'BindReadOnlyPaths=/srv/stale-ro'
} > "$DROP_IN"
"$REPOSITORY/tools/install-lmyzmail.sh" --destdir "$STAGE" --binary "$BINARY"
grep -Fxq '# Managed by install-lmyzmail.sh; regenerated on every installation.' "$DROP_IN"
grep -Fxq '[Service]' "$DROP_IN"
if grep -Eq '^Bind(ReadOnly)?Paths=' "$DROP_IN"; then
    printf '%s\n' 'staged reinstall retained stale managed path grants' >&2
    exit 1
fi
[[ $(wc -l < "$DROP_IN") == 2 ]]

HOSTILE_ROOT_STAGE="$STAGE/hostile-root-mode-stage"
mkdir -p -- "$HOSTILE_ROOT_STAGE/etc/lmyzmail"
chmod 0775 -- "$HOSTILE_ROOT_STAGE/etc/lmyzmail"
if "$REPOSITORY/tools/install-lmyzmail.sh" --destdir "$HOSTILE_ROOT_STAGE" \
    --binary "$BINARY" >/dev/null 2>&1
then
    printf '%s\n' 'installer unexpectedly accepted a group-writable config directory' >&2
    exit 1
fi
[[ ! -e "$HOSTILE_ROOT_STAGE/usr/bin/lmyzmail" ]]
[[ $(stat -c %a "$HOSTILE_ROOT_STAGE/etc/lmyzmail") == 775 ]]

HOSTILE_STATE_STAGE="$STAGE/hostile-state-mode-stage"
mkdir -p -- "$HOSTILE_STATE_STAGE/var/lib/lmyzmail/data/mail"
chmod 0770 -- "$HOSTILE_STATE_STAGE/var/lib/lmyzmail/data/mail"
if "$REPOSITORY/tools/install-lmyzmail.sh" --destdir "$HOSTILE_STATE_STAGE" \
    --binary "$BINARY" >/dev/null 2>&1
then
    printf '%s\n' 'installer unexpectedly accepted a group-writable Maildir' >&2
    exit 1
fi
[[ ! -e "$HOSTILE_STATE_STAGE/usr/bin/lmyzmail" ]]
[[ $(stat -c %a "$HOSTILE_STATE_STAGE/var/lib/lmyzmail/data/mail") == 770 ]]

HOSTILE_DROP_IN_STAGE="$STAGE/hostile-drop-in-mode-stage"
mkdir -p -- "$HOSTILE_DROP_IN_STAGE/etc/systemd/system/lmyzmail.service.d"
chmod 0777 -- "$HOSTILE_DROP_IN_STAGE/etc/systemd/system/lmyzmail.service.d"
if "$REPOSITORY/tools/install-lmyzmail.sh" --destdir "$HOSTILE_DROP_IN_STAGE" \
    --binary "$BINARY" >/dev/null 2>&1
then
    printf '%s\n' 'installer unexpectedly accepted a writable systemd drop-in directory' >&2
    exit 1
fi
[[ ! -e "$HOSTILE_DROP_IN_STAGE/usr/bin/lmyzmail" ]]
[[ $(stat -c %a "$HOSTILE_DROP_IN_STAGE/etc/systemd/system/lmyzmail.service.d") == 777 ]]

if "$REPOSITORY/tools/install-lmyzmail.sh" --destdir / --binary "$BINARY" >/dev/null 2>&1; then
    printf '%s\n' 'installer unexpectedly accepted / as DESTDIR' >&2
    exit 1
fi
if "$REPOSITORY/tools/install-lmyzmail.sh" --destdir "$STAGE" --binary "$BINARY" \
    --legacy-ro /srv/legacy-mail >/dev/null 2>&1
then
    printf '%s\n' 'installer unexpectedly accepted legacy adoption with DESTDIR' >&2
    exit 1
fi

SYMLINK_STAGE="$STAGE/symlink-stage"
mkdir -p -- "$SYMLINK_STAGE" "$STAGE/symlink-target"
ln -s -- "$STAGE/symlink-target" "$SYMLINK_STAGE/etc"
if "$REPOSITORY/tools/install-lmyzmail.sh" --destdir "$SYMLINK_STAGE" \
    --binary "$BINARY" >/dev/null 2>&1
then
    printf '%s\n' 'installer unexpectedly followed a managed-path symlink' >&2
    exit 1
fi

if (( EUID != 0 )) \
    && "$REPOSITORY/tools/install-lmyzmail.sh" --binary "$BINARY" >/dev/null 2>&1
then
    printf '%s\n' 'non-root live installer unexpectedly succeeded' >&2
    exit 1
fi

UNINSTALL_SYMLINK_STAGE="$STAGE/uninstall-symlink-stage"
mkdir -p -- "$UNINSTALL_SYMLINK_STAGE/usr" "$STAGE/uninstall-symlink-target/bin"
mkdir -p -- "$UNINSTALL_SYMLINK_STAGE/usr/bin"
printf '%s\n' retained-binary > "$UNINSTALL_SYMLINK_STAGE/usr/bin/lmyzmail"
ln -s -- "$STAGE/uninstall-symlink-target" "$UNINSTALL_SYMLINK_STAGE/usr/share"
printf '%s\n' retained > "$STAGE/uninstall-symlink-target/application.properties.example"
if "$REPOSITORY/tools/uninstall-lmyzmail.sh" --destdir "$UNINSTALL_SYMLINK_STAGE" \
    >/dev/null 2>&1
then
    printf '%s\n' 'uninstaller unexpectedly followed a managed-path symlink' >&2
    exit 1
fi
grep -Fxq retained "$STAGE/uninstall-symlink-target/application.properties.example"
grep -Fxq retained-binary "$UNINSTALL_SYMLINK_STAGE/usr/bin/lmyzmail"

PREFLIGHT_STAGE="$STAGE/preflight-stage"
mkdir -p -- "$PREFLIGHT_STAGE/etc/lmyzmail/application.properties"
if "$REPOSITORY/tools/install-lmyzmail.sh" --destdir "$PREFLIGHT_STAGE" \
    --binary "$BINARY" >/dev/null 2>&1
then
    printf '%s\n' 'installer unexpectedly accepted a directory as configuration' >&2
    exit 1
fi
[[ ! -e "$PREFLIGHT_STAGE/usr/bin/lmyzmail" ]]

UNMANAGED_DROP_IN_STAGE="$STAGE/unmanaged-drop-in-stage"
mkdir -p -- "$UNMANAGED_DROP_IN_STAGE/etc/systemd/system/lmyzmail.service.d"
printf '%s\n' '# administrator-owned grant' > \
    "$UNMANAGED_DROP_IN_STAGE/etc/systemd/system/lmyzmail.service.d/legacy-paths.conf"
if "$REPOSITORY/tools/install-lmyzmail.sh" --destdir "$UNMANAGED_DROP_IN_STAGE" \
    --binary "$BINARY" >/dev/null 2>&1
then
    printf '%s\n' 'installer unexpectedly replaced an unmanaged path grant' >&2
    exit 1
fi
grep -Fxq '# administrator-owned grant' \
    "$UNMANAGED_DROP_IN_STAGE/etc/systemd/system/lmyzmail.service.d/legacy-paths.conf"
if "$REPOSITORY/tools/uninstall-lmyzmail.sh" --destdir "$UNMANAGED_DROP_IN_STAGE" \
    >/dev/null 2>&1
then
    printf '%s\n' 'uninstaller unexpectedly removed an unmanaged path grant' >&2
    exit 1
fi
grep -Fxq '# administrator-owned grant' \
    "$UNMANAGED_DROP_IN_STAGE/etc/systemd/system/lmyzmail.service.d/legacy-paths.conf"

printf '%s\n' 'installation-smoke-config-marker' > "$STAGE/etc/lmyzmail/application.properties"
printf '%s\n' 'installation-smoke-state-marker' > "$STAGE/var/lib/lmyzmail/state.marker"
chmod 0600 -- "$STAGE/etc/lmyzmail/application.properties"
ln -- "$STAGE/etc/lmyzmail/application.properties" "$STAGE/config-hardlink-marker"
CONFIG_INODE="$(stat -c %i "$STAGE/etc/lmyzmail/application.properties")"
printf '%s\n' 'pre-upgrade-binary' > "$STAGE/usr/bin/lmyzmail"
printf '%s\n' 'pre-upgrade-unit' > "$STAGE/usr/lib/systemd/system/lmyzmail.service"
if LMYZMAIL_TEST_INSTALL_FAIL_AFTER=2 \
    "$REPOSITORY/tools/install-lmyzmail.sh" --destdir "$STAGE" --binary "$BINARY" \
    >/dev/null 2>&1
then
    printf '%s\n' 'injected installation failure unexpectedly succeeded' >&2
    exit 1
fi
grep -Fxq 'pre-upgrade-binary' "$STAGE/usr/bin/lmyzmail"
grep -Fxq 'pre-upgrade-unit' "$STAGE/usr/lib/systemd/system/lmyzmail.service"
grep -Fxq 'installation-smoke-config-marker' "$STAGE/etc/lmyzmail/application.properties"
[[ $(stat -c %a "$STAGE/etc/lmyzmail/application.properties") == 600 ]]
[[ $(stat -c %i "$STAGE/etc/lmyzmail/application.properties") == "$CONFIG_INODE" ]]
grep -Fxq 'installation-smoke-config-marker' "$STAGE/config-hardlink-marker"

"$REPOSITORY/tools/install-lmyzmail.sh" --destdir "$STAGE" --binary "$BINARY"
grep -Fxq 'installation-smoke-config-marker' "$STAGE/etc/lmyzmail/application.properties"
grep -Fxq 'installation-smoke-state-marker' "$STAGE/var/lib/lmyzmail/state.marker"
[[ $(stat -c %a "$STAGE/etc/lmyzmail/application.properties") == 600 ]]
[[ $(stat -c %i "$STAGE/etc/lmyzmail/application.properties") == "$CONFIG_INODE" ]]
[[ $(sha256sum "$STAGE/usr/bin/lmyzmail" | awk '{print $1}') == "$EXPECTED_BINARY_SHA256" ]]

declare -a LATE_FAILURE_FILES=(
    /usr/bin/lmyzmail
    /usr/lib/systemd/system/lmyzmail.service
    /usr/share/doc/lmyzmail/application.properties.example
    /usr/share/lmyzmail/models/skibidi-inferx/skibidi_ai.safetensors
    /usr/share/lmyzmail/models/skibidi-inferx/tokenizer.json
    /usr/share/lmyzmail/assets/skibidi_toilet_episode_1.mp4
    /etc/systemd/system/lmyzmail.service.d/legacy-paths.conf
)
declare -A LATE_FAILURE_SHA256=()
for logical in "${LATE_FAILURE_FILES[@]}"; do
    LATE_FAILURE_SHA256["$logical"]="$(sha256sum "$STAGE$logical" | awk '{print $1}')"
done
if LMYZMAIL_TEST_INSTALL_FAIL_AFTER=7 \
    "$REPOSITORY/tools/install-lmyzmail.sh" --destdir "$STAGE" --binary "$BINARY" \
    >/dev/null 2>&1
then
    printf '%s\n' 'late injected installation failure unexpectedly succeeded' >&2
    exit 1
fi
for logical in "${LATE_FAILURE_FILES[@]}"; do
    [[ $(sha256sum "$STAGE$logical" | awk '{print $1}') == \
        "${LATE_FAILURE_SHA256[$logical]}" ]]
done
grep -Fxq 'installation-smoke-config-marker' "$STAGE/etc/lmyzmail/application.properties"
grep -Fxq 'installation-smoke-state-marker' "$STAGE/var/lib/lmyzmail/state.marker"
[[ $(stat -c %a "$STAGE/etc/lmyzmail/application.properties") == 600 ]]
[[ $(stat -c %i "$STAGE/etc/lmyzmail/application.properties") == "$CONFIG_INODE" ]]

grep -Fq 'mktemp -d /run/lmyzmail-install.XXXXXXXX' \
    "$REPOSITORY/tools/install-lmyzmail.sh"
if grep -Eq 'TMPDIR.*(release|config-check|install-backup|legacy-paths)' \
    "$REPOSITORY/tools/install-lmyzmail.sh"
then
    printf '%s\n' 'live installer still trusts TMPDIR for transaction artifacts' >&2
    exit 1
fi

UNINSTALL_BINARY_SHA256="$(sha256sum "$STAGE/usr/bin/lmyzmail" | awk '{print $1}')"
UNINSTALL_UNIT_SHA256="$(sha256sum "$STAGE/usr/lib/systemd/system/lmyzmail.service" | awk '{print $1}')"
UNINSTALL_EXAMPLE_SHA256="$(sha256sum "$STAGE/usr/share/doc/lmyzmail/application.properties.example" | awk '{print $1}')"
UNINSTALL_DROP_IN_SHA256="$(sha256sum "$DROP_IN" | awk '{print $1}')"
if LMYZMAIL_TEST_UNINSTALL_FAIL_AFTER=2 \
    "$REPOSITORY/tools/uninstall-lmyzmail.sh" --destdir "$STAGE" \
    >/dev/null 2>&1
then
    printf '%s\n' 'injected uninstall failure unexpectedly succeeded' >&2
    exit 1
fi
[[ $(sha256sum "$STAGE/usr/bin/lmyzmail" | awk '{print $1}') == "$UNINSTALL_BINARY_SHA256" ]]
[[ $(sha256sum "$STAGE/usr/lib/systemd/system/lmyzmail.service" | awk '{print $1}') == "$UNINSTALL_UNIT_SHA256" ]]
[[ $(sha256sum "$STAGE/usr/share/doc/lmyzmail/application.properties.example" | awk '{print $1}') == "$UNINSTALL_EXAMPLE_SHA256" ]]
[[ $(sha256sum "$DROP_IN" | awk '{print $1}') == "$UNINSTALL_DROP_IN_SHA256" ]]
grep -Fxq 'installation-smoke-config-marker' "$STAGE/etc/lmyzmail/application.properties"
grep -Fxq 'installation-smoke-state-marker' "$STAGE/var/lib/lmyzmail/state.marker"

if LMYZMAIL_TEST_UNINSTALL_DAEMON_RELOAD_FAIL=1 \
    "$REPOSITORY/tools/uninstall-lmyzmail.sh" --destdir "$STAGE" \
    >/dev/null 2>&1
then
    printf '%s\n' 'injected daemon-reload uninstall failure unexpectedly succeeded' >&2
    exit 1
fi
[[ $(sha256sum "$STAGE/usr/bin/lmyzmail" | awk '{print $1}') == "$UNINSTALL_BINARY_SHA256" ]]
[[ $(sha256sum "$STAGE/usr/lib/systemd/system/lmyzmail.service" | awk '{print $1}') == "$UNINSTALL_UNIT_SHA256" ]]
[[ $(sha256sum "$STAGE/usr/share/doc/lmyzmail/application.properties.example" | awk '{print $1}') == "$UNINSTALL_EXAMPLE_SHA256" ]]
[[ $(sha256sum "$DROP_IN" | awk '{print $1}') == "$UNINSTALL_DROP_IN_SHA256" ]]
grep -Fxq 'installation-smoke-config-marker' "$STAGE/etc/lmyzmail/application.properties"
grep -Fxq 'installation-smoke-state-marker' "$STAGE/var/lib/lmyzmail/state.marker"

"$REPOSITORY/tools/uninstall-lmyzmail.sh" --destdir "$STAGE"
[[ ! -e "$STAGE/usr/bin/lmyzmail" ]]
[[ ! -e "$STAGE/usr/lib/systemd/system/lmyzmail.service" ]]
[[ ! -e "$STAGE/usr/share/doc/lmyzmail/application.properties.example" ]]
[[ ! -e "$DROP_IN" ]]
grep -Fxq 'installation-smoke-config-marker' "$STAGE/etc/lmyzmail/application.properties"
grep -Fxq 'installation-smoke-state-marker' "$STAGE/var/lib/lmyzmail/state.marker"
[[ -f "$STAGE/usr/share/lmyzmail/models/skibidi-inferx/skibidi_ai.safetensors" ]]
[[ -f "$STAGE/usr/share/lmyzmail/assets/skibidi_toilet_episode_1.mp4" ]]

if grep -Eq 'systemctl .*\|\| true' "$REPOSITORY/tools/uninstall-lmyzmail.sh"; then
    printf '%s\n' 'uninstaller still ignores a systemctl failure' >&2
    exit 1
fi
grep -Fq 'SERVICE_RESULT="$(systemctl_value Result)"' \
    "$REPOSITORY/tools/uninstall-lmyzmail.sh"
grep -Fq 'LOCK_OPEN_ID="$(stat -Lc' "$REPOSITORY/tools/install-lmyzmail.sh"
grep -Fq 'LOCK_OPEN_ID="$(stat -Lc' "$REPOSITORY/tools/uninstall-lmyzmail.sh"
grep -Fq 'systemctl stop lmyzmail.service' "$REPOSITORY/tools/uninstall-lmyzmail.sh"
grep -Fq 'RESTORED_RESULT="$(systemctl_value Result' "$REPOSITORY/tools/uninstall-lmyzmail.sh"

printf 'lmyzmail staged install/upgrade/uninstall smoke passed: binary_sha256=%s\n' "$EXPECTED_BINARY_SHA256"
