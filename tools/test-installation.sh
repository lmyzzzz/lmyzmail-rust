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

"$REPOSITORY/tools/install-lmyzmail.sh" --destdir "$STAGE" --binary "$BINARY"

assert_mode() {
    local expected="$1"
    local path="$2"
    [[ $(stat -c %a "$path") == "$expected" ]] || {
        printf 'wrong mode for %s: expected=%s actual=%s\n' "$path" "$expected" "$(stat -c %a "$path")" >&2
        exit 1
    }
}

[[ $(sha256sum "$STAGE/usr/bin/lmyzmail" | awk '{print $1}') == "$EXPECTED_BINARY_SHA256" ]]
[[ $(sha256sum "$STAGE/usr/share/lmyzmail/models/skibidi-inferx/skibidi_ai.safetensors" | awk '{print $1}') == 343966cefa61b375b5e7ac8f82efffd1187dcc33e6f6122c7860ea05f1e1932c ]]
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

grep -Fq 'TEMP_CONFIG_CHECK=""' "$REPOSITORY/tools/install-lmyzmail.sh"
grep -Fq 'rm -f -- "$TEMP_CONFIG_CHECK"' "$REPOSITORY/tools/install-lmyzmail.sh"
if grep -Fq 'rm -f -- "$CONFIG_CHECK_SOURCE"' "$REPOSITORY/tools/install-lmyzmail.sh"; then
    printf '%s\n' 'installer cleanup can delete a preserved configuration source' >&2
    exit 1
fi

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

printf 'lmyzmail staged install/upgrade/uninstall smoke passed: binary_sha256=%s\n' "$EXPECTED_BINARY_SHA256"
