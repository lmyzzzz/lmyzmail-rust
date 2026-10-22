#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: tools/install-lmyzmail.sh [OPTIONS]

Options:
  --binary PATH    Release binary to install (default: workspace release target)
  --destdir PATH   Stage below PATH without user or systemd changes
  --legacy-rw PATH Expose one existing legacy path read-write to the service
  --legacy-ro PATH Expose one existing legacy path read-only to the service
  --enable         Enable and start lmyzmail after a live install
  -h, --help       Show this help

Existing /etc/lmyzmail/application.properties is never overwritten. XDP is
disabled in the installed default configuration and requires a separately
validated privileged deployment profile.
EOF
}

readonly REPOSITORY="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
BINARY="$REPOSITORY/target/x86_64-unknown-linux-gnu/release/lmyzmail"
if [[ -f "$REPOSITORY/bin/lmyzmail" ]]; then
    BINARY="$REPOSITORY/bin/lmyzmail"
fi
DESTDIR=""
ENABLE=0
declare -a LEGACY_RW_PATHS=() LEGACY_RO_PATHS=()

while (( $# > 0 )); do
    case "$1" in
        --binary)
            (( $# >= 2 )) || { printf '%s\n' '--binary requires a path' >&2; exit 2; }
            BINARY="$2"
            shift 2
            ;;
        --destdir)
            (( $# >= 2 )) || { printf '%s\n' '--destdir requires a path' >&2; exit 2; }
            DESTDIR="$2"
            shift 2
            ;;
        --enable)
            ENABLE=1
            shift
            ;;
        --legacy-rw)
            (( $# >= 2 )) || { printf '%s\n' '--legacy-rw requires a path' >&2; exit 2; }
            LEGACY_RW_PATHS+=("$2")
            shift 2
            ;;
        --legacy-ro)
            (( $# >= 2 )) || { printf '%s\n' '--legacy-ro requires a path' >&2; exit 2; }
            LEGACY_RO_PATHS+=("$2")
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'unknown option: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ -n "$DESTDIR" ]]; then
    [[ "$DESTDIR" == /* ]] || { printf '%s\n' '--destdir must be absolute' >&2; exit 2; }
    (( ENABLE == 0 )) || { printf '%s\n' '--enable is not allowed with --destdir' >&2; exit 2; }
    (( ${#LEGACY_RW_PATHS[@]} == 0 && ${#LEGACY_RO_PATHS[@]} == 0 )) || {
        printf '%s\n' 'legacy path adoption is not allowed with --destdir' >&2
        exit 2
    }
    mkdir -p -- "$DESTDIR"
    DESTDIR="$(realpath -e "$DESTDIR")"
    [[ "$DESTDIR" != / ]] || { printf '%s\n' '--destdir must not resolve to /' >&2; exit 2; }
elif (( EUID != 0 )); then
    printf '%s\n' 'live installation must run as root; use --destdir for staging' >&2
    exit 1
fi

for command in awk cp file flock install ldconfig mkdir mktemp mv python3 readelf realpath sed sha256sum stat; do
    command -v "$command" >/dev/null 2>&1 || {
        printf 'required command is unavailable: %s\n' "$command" >&2
        exit 1
    }
done
if [[ -z "$DESTDIR" ]]; then
    for command in chown getent groupadd id passwd pgrep runuser systemctl useradd; do
        command -v "$command" >/dev/null 2>&1 || {
            printf 'required live-install command is unavailable: %s\n' "$command" >&2
            exit 1
        }
    done
fi

LOCK_PATH=""
if [[ -z "$DESTDIR" ]]; then
    [[ -d /run && ! -L /run && $(stat -c %u /run) == 0 && $(( 8#$(stat -c %a /run) & 0022 )) == 0 ]] || {
        printf '%s\n' '/run must be a root-owned directory that is not group/other writable' >&2
        exit 1
    }
    LOCK_PATH=/run/lmyzmail-maintenance.lock
else
    LOCK_PARENT="$DESTDIR/run"
    if [[ -e "$LOCK_PARENT" || -L "$LOCK_PARENT" ]]; then
        [[ -d "$LOCK_PARENT" && ! -L "$LOCK_PARENT" ]] || {
            printf 'staged maintenance lock parent is not a directory: %s\n' "$LOCK_PARENT" >&2
            exit 1
        }
        LOCK_PARENT_MODE="$(stat -c %a "$LOCK_PARENT")"
        (( (8#$LOCK_PARENT_MODE & 0022) == 0 )) || {
            printf 'staged maintenance lock parent is group/other writable: %s mode=%s\n' "$LOCK_PARENT" "$LOCK_PARENT_MODE" >&2
            exit 1
        }
    else
        install -d -m 0755 -- "$LOCK_PARENT"
    fi
    [[ "$(stat -c %u "$LOCK_PARENT")" == "$(stat -c %u "$DESTDIR")" ]] || {
        printf 'staged maintenance lock parent owner differs from destination root: %s\n' "$LOCK_PARENT" >&2
        exit 1
    }
    LOCK_PATH="$LOCK_PARENT/lmyzmail-maintenance.lock"
fi
if [[ -L "$LOCK_PATH" || ( -e "$LOCK_PATH" && ! -f "$LOCK_PATH" ) ]]; then
    printf 'maintenance lock is not a regular file: %s\n' "$LOCK_PATH" >&2
    exit 1
fi
if [[ -e "$LOCK_PATH" ]]; then
    LOCK_MODE="$(stat -c %a "$LOCK_PATH")"
    (( (8#$LOCK_MODE & 0077) == 0 )) || {
        printf 'maintenance lock is accessible by group/other: %s mode=%s\n' "$LOCK_PATH" "$LOCK_MODE" >&2
        exit 1
    }
    if [[ -z "$DESTDIR" && $(stat -c %u "$LOCK_PATH") != 0 ]]; then
        printf 'live maintenance lock is not root-owned: %s owner=%s\n' "$LOCK_PATH" "$(stat -c %u "$LOCK_PATH")" >&2
        exit 1
    fi
    if [[ -n "$DESTDIR" && $(stat -c %u "$LOCK_PATH") != $(stat -c %u "$LOCK_PARENT") ]]; then
        printf 'staged maintenance lock owner differs from its parent: %s owner=%s\n' \
            "$LOCK_PATH" "$(stat -c %u "$LOCK_PATH")" >&2
        exit 1
    fi
else
    install -m 0600 -- /dev/null "$LOCK_PATH"
fi
exec 9>"$LOCK_PATH"
flock -n 9 || {
    printf '%s\n' 'another lmyzmail installation or uninstallation is in progress' >&2
    exit 75
}
LOCK_OPEN_ID="$(stat -Lc '%d:%i' /proc/$$/fd/9 2>/dev/null || true)"
LOCK_PATH_ID="$(stat -Lc '%d:%i' "$LOCK_PATH" 2>/dev/null || true)"
[[ -n "$LOCK_OPEN_ID" && "$LOCK_OPEN_ID" == "$LOCK_PATH_ID" ]] || {
    printf '%s\n' 'maintenance lock changed while it was being opened' >&2
    exit 75
}

readonly MODEL="$REPOSITORY/models/skibidi-inferx-compact-20261022/skibidi_ai.safetensors"
readonly TOKENIZER="$REPOSITORY/models/skibidi-inferx-compact-20261022/tokenizer.json"
readonly VIDEO="$REPOSITORY/crates/lmyzmail/assets/skibidi_toilet_episode_1.mp4"
readonly CONFIG_EXAMPLE="$REPOSITORY/config/lmyzmail.properties.example"
readonly SERVICE_UNIT="$REPOSITORY/deploy/lmyzmail.service"
readonly RELEASE_EVIDENCE="${LMYZMAIL_RELEASE_EVIDENCE:-$REPOSITORY/evidence/build/release-reproducibility-v1.json}"

require_sha256() {
    local path="$1"
    local expected="$2"
    local actual
    [[ -f "$path" && ! -L "$path" ]] || { printf 'source is not a regular file: %s\n' "$path" >&2; exit 1; }
    actual="$(sha256sum "$path" | awk '{print $1}')"
    [[ "$actual" == "$expected" ]] || {
        printf 'source hash mismatch: %s\nexpected=%s\nactual=%s\n' "$path" "$expected" "$actual" >&2
        exit 1
    }
}

[[ -x "$BINARY" && -f "$BINARY" && ! -L "$BINARY" ]] || {
    printf 'release binary is unavailable or not executable: %s\n' "$BINARY" >&2
    exit 1
}
EXPECTED_BINARY_SHA256="$(python3 - "$RELEASE_EVIDENCE" <<'PY'
import json
import pathlib
import sys

evidence = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if evidence.get("schema_version") not in (2, 3) or not evidence.get("verification", {}).get("byte_identical"):
    raise SystemExit("release evidence is not a successful reproducibility record")
value = evidence.get("artifact", {}).get("sha256", "")
if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
    raise SystemExit("release evidence contains an invalid artifact SHA-256")
print(value)
PY
)"
require_sha256 "$BINARY" "$EXPECTED_BINARY_SHA256"
file "$BINARY" | grep -Eq 'ELF 64-bit LSB .*x86-64' || {
    printf 'release binary is not a Linux x86_64 ELF: %s\n' "$BINARY" >&2
    exit 1
}
readelf -h "$BINARY" | grep -Fq 'Machine:                           Advanced Micro Devices X86-64' || {
    printf 'release ELF machine is not x86_64: %s\n' "$BINARY" >&2
    exit 1
}
INTERPRETER="$(readelf -l "$BINARY" \
    | sed -n 's@.*Requesting program interpreter: \(.*\)]@\1@p')"
[[ "$INTERPRETER" == /lib64/ld-linux-x86-64.so.2 && -x "$INTERPRETER" ]] || {
    printf 'release binary has an unsupported or unavailable interpreter: %s\n' \
        "${INTERPRETER:-missing}" >&2
    exit 1
}
mapfile -t NEEDED_LIBRARIES < <(
    readelf -d "$BINARY" | sed -n 's/.*Shared library: \[\(.*\)\]/\1/p'
)
for library in "${NEEDED_LIBRARIES[@]}"; do
    ldconfig -p | awk -v library="$library" \
        '$1 == library && /x86-64/ { found = 1 } END { exit !found }' || {
        printf 'release binary dependency is unavailable: %s\n' "$library" >&2
        exit 1
    }
done
if readelf -d "$BINARY" | grep -Eiq '\[(lib)?(java|jvm|jli)[^]]*\]'; then
    printf 'release binary has a forbidden Java/JVM dependency: %s\n' "$BINARY" >&2
    exit 1
fi
if readelf --dyn-syms --wide "$BINARY" \
    | grep -Eiq '(^|[^[:alnum:]_])(JNI_|Java_|JVM_)([[:alnum:]_]|$)'
then
    printf 'release binary imports a forbidden JNI/JVM dynamic symbol: %s\n' "$BINARY" >&2
    exit 1
fi

require_sha256 "$MODEL" 4fc4f7a0eb5d7e1210ddd7fee63a756775f5b7155db210080cfd8cc759403428
require_sha256 "$TOKENIZER" 6624adb41b9274bf0cc73c62ebd26eb2bcf281d533f30607ba415105917d81f3
require_sha256 "$VIDEO" 0e76229bb77ebcf471aec692fa34709cfbbe3dc192127a852a518e34bdd0ecc7

TRANSACTION_DIRECTORY=""
TRANSACTION_PARENT=""
cleanup_early_transaction() {
    if [[ -z "$DESTDIR" && "$TRANSACTION_DIRECTORY" == /run/lmyzmail-install.* \
        && -d "$TRANSACTION_DIRECTORY" && ! -L "$TRANSACTION_DIRECTORY" \
        && $(stat -c %u "$TRANSACTION_DIRECTORY") == 0 \
        && $(stat -c %a "$TRANSACTION_DIRECTORY") == 700 ]]
    then
        rm -rf -- "$TRANSACTION_DIRECTORY"
    elif [[ -n "$DESTDIR" && -n "$TRANSACTION_DIRECTORY" \
        && -d "$TRANSACTION_DIRECTORY" && ! -L "$TRANSACTION_DIRECTORY" \
        && $(dirname "$TRANSACTION_DIRECTORY") == "$TRANSACTION_PARENT" \
        && $(basename "$TRANSACTION_DIRECTORY") == lmyzmail-install.* ]]
    then
        rm -rf -- "$TRANSACTION_DIRECTORY"
    fi
}
trap cleanup_early_transaction EXIT
if [[ -z "$DESTDIR" ]]; then
    [[ -d /run && ! -L /run && $(stat -c %u /run) == 0 \
        && $(( 8#$(stat -c %a /run) & 0022 )) == 0 ]] || {
        printf '%s\n' '/run must be a root-owned directory that is not group/other writable' >&2
        exit 1
    }
    TRANSACTION_DIRECTORY="$(mktemp -d /run/lmyzmail-install.XXXXXXXX)"
    chown root:root "$TRANSACTION_DIRECTORY"
    chmod 0700 "$TRANSACTION_DIRECTORY"
    [[ "$TRANSACTION_DIRECTORY" == /run/lmyzmail-install.* \
        && -d "$TRANSACTION_DIRECTORY" && ! -L "$TRANSACTION_DIRECTORY" \
        && $(stat -c %u "$TRANSACTION_DIRECTORY") == 0 \
        && $(stat -c %a "$TRANSACTION_DIRECTORY") == 700 ]] || {
        printf '%s\n' 'failed to establish a secure live installation transaction directory' >&2
        exit 1
    }
else
    TRANSACTION_PARENT="$(realpath -e "${TMPDIR:-/tmp}")"
    TRANSACTION_DIRECTORY="$(mktemp -d --tmpdir="$TRANSACTION_PARENT" \
        lmyzmail-install.XXXXXXXX)"
    chmod 0700 "$TRANSACTION_DIRECTORY"
fi
STABLE_BINARY="$TRANSACTION_DIRECTORY/release"
DROP_IN_SOURCE=""
TRANSACTION_BACKUP=""
TRANSACTION_STARTED=0
INSTALL_COMMITTED=0
CONFIG_CREATED=0
SERVICE_START_ATTEMPTED=0
DAEMON_RELOAD_ATTEMPTED=0
ROLLBACK_FAILED=0
readonly DROP_IN_MARKER='# Managed by install-lmyzmail.sh; regenerated on every installation.'
declare -a PACKAGE_FILES=(
    /usr/bin/lmyzmail
    /usr/lib/systemd/system/lmyzmail.service
    /usr/share/doc/lmyzmail/application.properties.example
    /usr/share/lmyzmail/models/skibidi-inferx/skibidi_ai.safetensors
    /usr/share/lmyzmail/models/skibidi-inferx/tokenizer.json
    /usr/share/lmyzmail/assets/skibidi_toilet_episode_1.mp4
    /etc/systemd/system/lmyzmail.service.d/legacy-paths.conf
)
rollback_installation() {
    local logical backup target
    local failed=0
    (( TRANSACTION_STARTED == 1 && INSTALL_COMMITTED == 0 )) || return 0
    for logical in "${PACKAGE_FILES[@]}"; do
        backup="$TRANSACTION_BACKUP$logical"
        target="$DESTDIR$logical"
        if [[ -e "$backup" ]]; then
            rm -f -- "$target" || failed=1
            cp -a -- "$backup" "$target" || failed=1
        else
            rm -f -- "$target" || failed=1
        fi
    done
    if (( CONFIG_CREATED == 1 )); then
        rm -f -- "$DESTDIR/etc/lmyzmail/application.properties" || failed=1
    fi
    if (( failed != 0 )); then
        ROLLBACK_FAILED=1
        printf 'installation rollback was incomplete; recovery backup retained at %s\n' \
            "$TRANSACTION_BACKUP" >&2
        return 1
    fi
    printf '%s\n' 'installation failed; restored all previously managed package files' >&2
}
stop_failed_fresh_service() {
    local active_state main_pid stop_status=0
    systemctl stop lmyzmail.service || stop_status=$?
    systemctl reset-failed lmyzmail.service >/dev/null 2>&1 || true
    active_state="$(systemctl show lmyzmail.service --property=ActiveState --value)" || {
        printf '%s\n' 'cannot verify service inactivity after failed fresh installation' >&2
        return 1
    }
    main_pid="$(systemctl show lmyzmail.service --property=MainPID --value)" || {
        printf '%s\n' 'cannot verify MainPID after failed fresh installation' >&2
        return 1
    }
    if [[ "$active_state" != inactive || "$main_pid" != 0 ]]; then
        printf 'unsafe failed-install state: ActiveState=%s MainPID=%s\n' \
            "${active_state:-unknown}" "${main_pid:-unknown}" >&2
        return 1
    fi
    if pgrep -x lmyzmail >/dev/null; then
        printf '%s\n' 'an lmyzmail process remains after the failed fresh installation was stopped' >&2
        return 1
    fi
    if (( stop_status != 0 )); then
        printf '%s\n' 'systemctl stop failed, but inactive state and MainPID=0 were verified' >&2
    fi
    if ! systemctl disable lmyzmail.service; then
        printf '%s\n' 'failed to disable the unsuccessful fresh lmyzmail service' >&2
        return 1
    fi
}
cleanup_install_temporaries() {
    local rollback_allowed=1
    set +e
    if (( SERVICE_START_ATTEMPTED == 1 && INSTALL_COMMITTED == 0 )); then
        if ! stop_failed_fresh_service; then
            rollback_allowed=0
            ROLLBACK_FAILED=1
            printf 'installation rollback blocked: deployed recovery files and backup at %s were preserved\n' \
                "$TRANSACTION_BACKUP" >&2
        fi
    fi
    if (( rollback_allowed == 1 )); then
        rollback_installation || true
    fi
    if (( rollback_allowed == 1 && ROLLBACK_FAILED == 0 \
        && DAEMON_RELOAD_ATTEMPTED == 1 && INSTALL_COMMITTED == 0 )); then
        if ! systemctl daemon-reload >/dev/null 2>&1; then
            ROLLBACK_FAILED=1
            printf 'restored files but systemd reload failed; recovery backup retained at %s\n' \
                "$TRANSACTION_BACKUP" >&2
        fi
    fi
    if (( ROLLBACK_FAILED == 0 )); then
        if [[ -n "$DESTDIR" ]]; then
            if [[ -d "$TRANSACTION_DIRECTORY" && ! -L "$TRANSACTION_DIRECTORY" \
                && $(dirname "$TRANSACTION_DIRECTORY") == "$TRANSACTION_PARENT" \
                && $(basename "$TRANSACTION_DIRECTORY") == lmyzmail-install.* ]]
            then
                rm -rf -- "$TRANSACTION_DIRECTORY" || ROLLBACK_FAILED=1
            else
                ROLLBACK_FAILED=1
                printf 'refusing to remove unexpected staged transaction path: %s\n' \
                    "$TRANSACTION_DIRECTORY" >&2
            fi
        elif [[ "$TRANSACTION_DIRECTORY" == /run/lmyzmail-install.* \
            && -d "$TRANSACTION_DIRECTORY" && ! -L "$TRANSACTION_DIRECTORY" \
            && $(stat -c %u "$TRANSACTION_DIRECTORY") == 0 \
            && $(stat -c %a "$TRANSACTION_DIRECTORY") == 700 ]]
        then
            rm -rf -- "$TRANSACTION_DIRECTORY" || ROLLBACK_FAILED=1
        else
            ROLLBACK_FAILED=1
            printf 'refusing to remove unexpected installation transaction path: %s\n' \
                "$TRANSACTION_DIRECTORY" >&2
        fi
    fi
}
trap cleanup_install_temporaries EXIT
install -m 0755 -- "$BINARY" "$STABLE_BINARY"
require_sha256 "$STABLE_BINARY" "$EXPECTED_BINARY_SHA256"

if [[ -z "$DESTDIR" ]]; then
    if ! getent -s files group lmyzmail >/dev/null; then
        groupadd --system lmyzmail
    fi
    IFS=: read -r existing_group _ existing_group_gid _ \
        < <(getent -s files group lmyzmail)
    [[ "$existing_group" == lmyzmail && "$existing_group_gid" != 0 ]] || {
        printf '%s\n' 'lmyzmail group must be a non-root local group' >&2
        exit 1
    }
    if ! getent -s files passwd lmyzmail >/dev/null; then
        useradd --system --gid lmyzmail --home-dir /var/lib/lmyzmail \
            --shell /usr/sbin/nologin lmyzmail
    else
        IFS=: read -r existing_name _ existing_uid existing_gid _ existing_home existing_shell \
            < <(getent -s files passwd lmyzmail)
        expected_gid="$existing_group_gid"
        if [[ "$existing_name" != lmyzmail \
            || "$existing_uid" == 0 \
            || "$existing_gid" == 0 \
            || "$existing_gid" != "$expected_gid" \
            || "$existing_home" != /var/lib/lmyzmail \
            || "$existing_shell" != /usr/sbin/nologin ]]
        then
            printf 'existing lmyzmail account does not match the locked service identity\n' >&2
            exit 1
        fi
    fi
    IFS=: read -r _ _ service_uid service_gid _ _ _ < <(getent -s files passwd lmyzmail)
    [[ "$service_uid" != 0 && "$service_gid" != 0 ]] || {
        printf '%s\n' 'lmyzmail service identity must not be root-equivalent' >&2
        exit 1
    }
    [[ "$(id -G lmyzmail)" == "$service_gid" ]] || {
        printf '%s\n' 'lmyzmail service identity has unexpected supplementary groups' >&2
        exit 1
    }
    ACCOUNT_STATUS="$(passwd --status lmyzmail | awk '{print $2}')"
    [[ "$ACCOUNT_STATUS" == L ]] || {
        printf 'lmyzmail service account is not locked: status=%s\n' "$ACCOUNT_STATUS" >&2
        exit 1
    }
fi

root_path() {
    printf '%s%s\n' "$DESTDIR" "$1"
}

assert_no_symlink_components() {
    local logical="$1"
    local current="$DESTDIR"
    local component
    local -a components
    IFS='/' read -r -a components <<<"${logical#/}"
    for component in "${components[@]}"; do
        [[ -n "$component" ]] || continue
        current="$current/$component"
        if [[ -L "$current" ]]; then
            printf 'refusing symlinked installation path component: %s\n' "$current" >&2
            exit 1
        fi
    done
}

install_directory() {
    local path="$1"
    local mode="$2"
    local owner="$3"
    local group="$4"
    local target
    target="$(root_path "$path")"
    assert_no_symlink_components "$path"
    if [[ -e "$target" ]]; then
        [[ -d "$target" && ! -L "$target" ]] || {
            printf 'installation directory is not a real directory: %s\n' "$target" >&2
            exit 1
        }
        validate_existing_install_directory "$path" "$owner"
        return
    fi
    if [[ -n "$DESTDIR" ]]; then
        install -d -m "$mode" -- "$target"
    else
        install -d -m "$mode" -o "$owner" -g "$group" -- "$path"
    fi
}

validate_existing_install_directory() {
    local path="$1"
    local owner="$2"
    local target actual_mode actual_uid expected_uid
    target="$(root_path "$path")"
    [[ -e "$target" || -L "$target" ]] || return 0
    assert_no_symlink_components "$path"
    [[ -d "$target" && ! -L "$target" ]] || {
        printf 'installation directory is not a real directory: %s\n' "$target" >&2
        exit 1
    }
    actual_mode="$(stat -c %a "$target")"
    (( (8#$actual_mode & 0022) == 0 )) || {
        printf 'installation directory is group/other writable: %s mode=%s\n' \
            "$target" "$actual_mode" >&2
        exit 1
    }
    if [[ -z "$DESTDIR" ]]; then
        expected_uid="$(id -u "$owner")"
        actual_uid="$(stat -c %u "$target")"
        [[ "$actual_uid" == "$expected_uid" ]] || {
            printf 'installation directory has unsafe owner: %s expected=%s actual=%s\n' \
                "$target" "$expected_uid" "$actual_uid" >&2
            exit 1
        }
    fi
    if [[ "$owner" == lmyzmail ]]; then
        (( (8#$actual_mode & 0300) == 0300 )) || {
            printf 'service-owned directory lacks owner write/execute access: %s mode=%s\n' \
                "$target" "$actual_mode" >&2
            exit 1
        }
    fi
}

require_live_directory() {
    local path="$1"
    if [[ -n "$DESTDIR" ]]; then
        install_directory "$path" 0755 root root
        return
    fi
    [[ -d "$path" && ! -L "$path" ]] || {
        printf 'required system directory is missing or symlinked: %s\n' "$path" >&2
        exit 1
    }
    validate_existing_install_directory "$path" root
}

install_file_atomic() {
    local source="$1"
    local destination="$2"
    local mode="$3"
    local owner="$4"
    local group="$5"
    local target directory temporary
    target="$(root_path "$destination")"
    assert_no_symlink_components "$destination"
    directory="$(dirname "$target")"
    validate_existing_install_directory "$(dirname "$destination")" root
    [[ -d "$directory" && ! -L "$directory" ]] || {
        printf 'installation directory is missing or symlinked: %s\n' "$directory" >&2
        exit 1
    }
    temporary="$(mktemp "$directory/.lmyzmail-install.XXXXXXXX")"
    if ! install -m "$mode" -- "$source" "$temporary"; then
        rm -f -- "$temporary"
        return 1
    fi
    if [[ -z "$DESTDIR" ]] && ! chown "$owner:$group" "$temporary"; then
        rm -f -- "$temporary"
        return 1
    fi
    if ! mv -fT -- "$temporary" "$target"; then
        rm -f -- "$temporary"
        return 1
    fi
    INSTALL_WRITE_COUNT=$((INSTALL_WRITE_COUNT + 1))
    if (( INSTALL_FAIL_AFTER > 0 && INSTALL_WRITE_COUNT == INSTALL_FAIL_AFTER )); then
        printf 'injected staged installation failure after %d managed writes\n' \
            "$INSTALL_WRITE_COUNT" >&2
        return 1
    fi
}

canonical_legacy_path() {
    local requested="$1"
    local canonical
    [[ "$requested" == /* ]] || { printf 'legacy path must be absolute: %s\n' "$requested" >&2; exit 2; }
    canonical="$(realpath -e "$requested")" || {
        printf 'legacy path does not exist: %s\n' "$requested" >&2
        exit 1
    }
    [[ "$canonical" == "$requested" && ! -L "$requested" ]] || {
        printf 'legacy path must be canonical and not symlinked: requested=%s canonical=%s\n' \
            "$requested" "$canonical" >&2
        exit 1
    }
    case "$canonical" in
        /|/dev|/etc|/home|/opt|/proc|/root|/run|/srv|/sys|/tmp|/usr|/var)
            printf 'legacy path is too broad for service exposure: %s\n' "$canonical" >&2
            exit 1
            ;;
    esac
    if [[ "$canonical" =~ [[:space:]\\\"%:] ]]; then
        printf 'legacy path contains characters unsupported by the systemd drop-in: %s\n' "$canonical" >&2
        exit 1
    fi
    printf '%s\n' "$canonical"
}

validate_legacy_ancestors() {
    local canonical="$1"
    local ancestor="/"
    local component owner mode
    local -a components
    IFS='/' read -r -a components <<<"${canonical#/}"
    for component in "${components[@]:0:${#components[@]}-1}"; do
        [[ -n "$component" ]] || continue
        ancestor="${ancestor%/}/$component"
        [[ -d "$ancestor" && ! -L "$ancestor" ]] || {
            printf 'legacy path ancestor is not a stable directory: %s\n' "$ancestor" >&2
            exit 1
        }
        owner="$(stat -c %u "$ancestor")"
        mode="$(stat -c %a "$ancestor")"
        [[ "$owner" == 0 && $(( 8#$mode & 0022 )) == 0 ]] || {
            printf 'legacy path ancestor must be root-owned and not group/other writable: %s\n' \
                "$ancestor" >&2
            exit 1
        }
    done
}

declare -a VALIDATED_LEGACY_RW_PATHS=() VALIDATED_LEGACY_RO_PATHS=()
for path in "${LEGACY_RW_PATHS[@]}"; do
    canonical="$(canonical_legacy_path "$path")"
    validate_legacy_ancestors "$canonical"
    [[ -d "$canonical" ]] || {
        printf 'read-write legacy path must be a directory: %s\n' "$canonical" >&2
        exit 1
    }
    if [[ -z "$DESTDIR" ]]; then
        runuser -u lmyzmail -- sh -c '
            set -eu
            probe="$(mktemp "$1/.lmyzmail-adoption.XXXXXXXX")"
            trap '\''rm -f -- "$probe" "${probe}.renamed"'\'' EXIT
            mv -- "$probe" "${probe}.renamed"
            rm -- "${probe}.renamed"
            trap - EXIT
        ' sh "$canonical" || {
            printf 'lmyzmail cannot atomically create, rename, and remove in legacy path: %s\n' \
                "$canonical" >&2
            exit 1
        }
    fi
    VALIDATED_LEGACY_RW_PATHS+=("$canonical")
done
for path in "${LEGACY_RO_PATHS[@]}"; do
    canonical="$(canonical_legacy_path "$path")"
    validate_legacy_ancestors "$canonical"
    if [[ -z "$DESTDIR" ]]; then
        runuser -u lmyzmail -- test -r "$canonical" \
            || { printf 'lmyzmail user cannot read legacy path: %s\n' "$canonical" >&2; exit 1; }
        if [[ -d "$canonical" ]]; then
            runuser -u lmyzmail -- test -x "$canonical" || {
                printf 'lmyzmail user cannot traverse legacy directory: %s\n' "$canonical" >&2
                exit 1
            }
        fi
    fi
    VALIDATED_LEGACY_RO_PATHS+=("$canonical")
done

declare -a MANAGED_PATHS=(
    /usr/bin
    /usr/bin/lmyzmail
    /usr/lib/systemd/system
    /usr/lib/systemd/system/lmyzmail.service
    /usr/share/doc/lmyzmail
    /usr/share/doc/lmyzmail/application.properties.example
    /usr/share/lmyzmail
    /usr/share/lmyzmail/models
    /usr/share/lmyzmail/models/skibidi-inferx
    /usr/share/lmyzmail/models/skibidi-inferx/skibidi_ai.safetensors
    /usr/share/lmyzmail/models/skibidi-inferx/tokenizer.json
    /usr/share/lmyzmail/assets
    /usr/share/lmyzmail/assets/skibidi_toilet_episode_1.mp4
    /etc/lmyzmail
    /etc/lmyzmail/application.properties
    /var/lib/lmyzmail
    /var/lib/lmyzmail/data
    /var/lib/lmyzmail/data/mail
    /var/lib/lmyzmail/data/mail/.lmyzmail-outbound
    /var/log/lmyzmail
    /etc/systemd/system/lmyzmail.service.d
    /etc/systemd/system/lmyzmail.service.d/legacy-paths.conf
)
for path in "${MANAGED_PATHS[@]}"; do
    assert_no_symlink_components "$path"
done
validate_existing_install_directory /usr/bin root
validate_existing_install_directory /usr/lib/systemd/system root
validate_existing_install_directory /usr/share/doc/lmyzmail root
validate_existing_install_directory /usr/share/lmyzmail root
validate_existing_install_directory /usr/share/lmyzmail/models root
validate_existing_install_directory /usr/share/lmyzmail/models/skibidi-inferx root
validate_existing_install_directory /usr/share/lmyzmail/assets root
validate_existing_install_directory /etc/lmyzmail root
validate_existing_install_directory /var/lib/lmyzmail lmyzmail
validate_existing_install_directory /var/lib/lmyzmail/data lmyzmail
validate_existing_install_directory /var/lib/lmyzmail/data/mail lmyzmail
validate_existing_install_directory /var/lib/lmyzmail/data/mail/.lmyzmail-outbound \
    lmyzmail
validate_existing_install_directory /var/log/lmyzmail lmyzmail
validate_existing_install_directory /etc/systemd/system/lmyzmail.service.d root
CONFIG_TARGET="$(root_path /etc/lmyzmail/application.properties)"
if [[ -e "$CONFIG_TARGET" && ! -f "$CONFIG_TARGET" ]]; then
    printf 'refusing non-regular configuration: %s\n' "$CONFIG_TARGET" >&2
    exit 1
fi
if [[ -e "$CONFIG_TARGET" ]]; then
    CONFIG_MODE="$(stat -c %a "$CONFIG_TARGET")"
    (( (8#$CONFIG_MODE & 0022) == 0 )) || {
        printf 'existing configuration is group/other writable: %s mode=%s\n' \
            "$CONFIG_TARGET" "$CONFIG_MODE" >&2
        exit 1
    }
    if [[ -z "$DESTDIR" && $(stat -c %u "$CONFIG_TARGET") != 0 ]]; then
        printf 'existing configuration is not root-owned: %s owner=%s\n' \
            "$CONFIG_TARGET" "$(stat -c %u "$CONFIG_TARGET")" >&2
        exit 1
    fi
fi
DROP_IN_TARGET="$(root_path /etc/systemd/system/lmyzmail.service.d/legacy-paths.conf)"
if [[ -e "$DROP_IN_TARGET" ]]; then
    [[ -f "$DROP_IN_TARGET" ]] || {
        printf 'refusing non-regular legacy path grant: %s\n' "$DROP_IN_TARGET" >&2
        exit 1
    }
    IFS= read -r DROP_IN_FIRST_LINE < "$DROP_IN_TARGET" || true
    [[ "$DROP_IN_FIRST_LINE" == "$DROP_IN_MARKER" ]] || {
        printf 'refusing to replace an unmanaged legacy path grant: %s\n' "$DROP_IN_TARGET" >&2
        exit 1
    }
fi

CONFIG_SOURCE="$CONFIG_EXAMPLE"
if [[ -e "$CONFIG_TARGET" ]]; then
    CONFIG_SOURCE="$CONFIG_TARGET"
fi
if [[ -z "$DESTDIR" ]]; then
    LOAD_STATE="$(systemctl show lmyzmail.service --property=LoadState --value)" || {
        printf '%s\n' 'cannot query lmyzmail service state; no package files were replaced' >&2
        exit 1
    }
    PREEXISTING_UNIT=0
    if [[ "$LOAD_STATE" != not-found ]]; then
        PREEXISTING_UNIT=1
        ACTIVE_STATE="$(systemctl show lmyzmail.service --property=ActiveState --value)"
        MAIN_PID="$(systemctl show lmyzmail.service --property=MainPID --value)"
        SERVICE_RESULT="$(systemctl show lmyzmail.service --property=Result --value)"
        UNIT_FILE_STATE="$(systemctl show lmyzmail.service --property=UnitFileState --value)"
        [[ "$ACTIVE_STATE" != active && "$ACTIVE_STATE" != activating \
            && "$ACTIVE_STATE" != deactivating && "$MAIN_PID" == 0 ]] || {
            printf '%s\n' 'refusing to replace a live lmyzmail installation; stop it cleanly first' >&2
            exit 1
        }
        [[ "$SERVICE_RESULT" == success ]] || {
            printf 'refusing to replace lmyzmail after unsuccessful service result: %s\n' \
                "${SERVICE_RESULT:-unknown}" >&2
            exit 1
        }
        case "$UNIT_FILE_STATE" in
            enabled|enabled-runtime|linked|linked-runtime|alias)
                printf 'refusing to upgrade an enabled lmyzmail unit: state=%s\n' \
                    "$UNIT_FILE_STATE" >&2
                exit 1
                ;;
        esac
    fi
    if (( ENABLE == 1 )) && { (( PREEXISTING_UNIT == 1 )) \
        || [[ -e /usr/bin/lmyzmail || -e /usr/lib/systemd/system/lmyzmail.service ]]; }
    then
        printf '%s\n' '--enable is only allowed for a fresh installation; start an upgraded unit explicitly after inspection' >&2
        exit 1
    fi
    if pgrep -x lmyzmail >/dev/null; then
        printf '%s\n' 'refusing to replace files while an unmanaged lmyzmail process is running' >&2
        exit 1
    fi
else
    CONFIG_SUMMARY="$("$STABLE_BINARY" --config "$CONFIG_SOURCE" --check-config)" || {
        printf '%s\n' 'staged lmyzmail configuration validation failed; no package files were replaced' >&2
        exit 1
    }
fi
if [[ -n "$DESTDIR" ]]; then
    [[ " $CONFIG_SUMMARY " == *" xdp=false "* ]] || {
        printf '%s\n' 'installation requires XDP to be disabled until the privileged deployment profile is available' >&2
        exit 1
    }
fi

INSTALL_FAIL_AFTER=0
INSTALL_WRITE_COUNT=0
if [[ -n ${LMYZMAIL_TEST_INSTALL_FAIL_AFTER:-} ]]; then
    [[ -n "$DESTDIR" && ${LMYZMAIL_TEST_INSTALL_FAIL_AFTER} =~ ^[1-9][0-9]*$ ]] || {
        printf '%s\n' 'LMYZMAIL_TEST_INSTALL_FAIL_AFTER is valid only as a positive integer with --destdir' >&2
        exit 2
    }
    INSTALL_FAIL_AFTER="$LMYZMAIL_TEST_INSTALL_FAIL_AFTER"
fi

TRANSACTION_BACKUP="$TRANSACTION_DIRECTORY/backup"
install -d -m 0700 -- "$TRANSACTION_BACKUP"
for logical in "${PACKAGE_FILES[@]}"; do
    target="$DESTDIR$logical"
    if [[ -e "$target" ]]; then
        mkdir -p -- "$TRANSACTION_BACKUP$(dirname "$logical")"
        cp -a -- "$target" "$TRANSACTION_BACKUP$logical"
    fi
done
TRANSACTION_STARTED=1

require_live_directory /usr/bin
require_live_directory /usr/lib/systemd/system
install_directory /usr/share/doc/lmyzmail 0755 root root
install_directory /usr/share/lmyzmail 0755 root root
install_directory /usr/share/lmyzmail/models 0755 root root
install_directory /usr/share/lmyzmail/models/skibidi-inferx 0755 root root
install_directory /usr/share/lmyzmail/assets 0755 root root
install_directory /etc/lmyzmail 0750 root lmyzmail
install_directory /var/lib/lmyzmail 0750 lmyzmail lmyzmail
install_directory /var/lib/lmyzmail/data 0750 lmyzmail lmyzmail
install_directory /var/lib/lmyzmail/data/mail 0750 lmyzmail lmyzmail
install_directory /var/lib/lmyzmail/data/mail/.lmyzmail-outbound 0750 lmyzmail lmyzmail
install_directory /var/log/lmyzmail 0750 lmyzmail lmyzmail

install_file_atomic "$STABLE_BINARY" /usr/bin/lmyzmail 0755 root root
install_file_atomic "$SERVICE_UNIT" /usr/lib/systemd/system/lmyzmail.service 0644 root root
install_file_atomic "$CONFIG_EXAMPLE" /usr/share/doc/lmyzmail/application.properties.example 0644 root root
install_file_atomic "$MODEL" /usr/share/lmyzmail/models/skibidi-inferx/skibidi_ai.safetensors 0644 root root
install_file_atomic "$TOKENIZER" /usr/share/lmyzmail/models/skibidi-inferx/tokenizer.json 0644 root root
install_file_atomic "$VIDEO" /usr/share/lmyzmail/assets/skibidi_toilet_episode_1.mp4 0644 root root

if [[ ! -e "$CONFIG_TARGET" ]]; then
    CONFIG_CREATED=1
    install_file_atomic "$CONFIG_EXAMPLE" /etc/lmyzmail/application.properties 0640 root lmyzmail
else
    printf 'preserved existing configuration: %s\n' "$CONFIG_TARGET"
fi

LEGACY_DROP_IN_DIRECTORY=/etc/systemd/system/lmyzmail.service.d
install_directory "$LEGACY_DROP_IN_DIRECTORY" 0755 root root
DROP_IN_SOURCE="$TRANSACTION_DIRECTORY/legacy-paths.conf"
{
    printf '%s\n' "$DROP_IN_MARKER"
    printf '%s\n' '[Service]'
    for path in "${VALIDATED_LEGACY_RW_PATHS[@]}"; do
        printf 'BindPaths=%s\n' "$path"
    done
    for path in "${VALIDATED_LEGACY_RO_PATHS[@]}"; do
        printf 'BindReadOnlyPaths=%s\n' "$path"
    done
} > "$DROP_IN_SOURCE"
install_file_atomic "$DROP_IN_SOURCE" \
    "$LEGACY_DROP_IN_DIRECTORY/legacy-paths.conf" 0644 root root
rm -f -- "$DROP_IN_SOURCE"
DROP_IN_SOURCE=""

if [[ -n "$DESTDIR" ]]; then
    INSTALL_COMMITTED=1
    cleanup_install_temporaries
    (( ROLLBACK_FAILED == 0 )) || exit 1
    trap - EXIT
    printf 'staged lmyzmail installation under %s\n' "$DESTDIR"
    exit 0
fi

CONFIG_SUMMARY="$(runuser -u lmyzmail -- /usr/bin/lmyzmail \
    --config /etc/lmyzmail/application.properties --check-config)" || {
    printf '%s\n' 'installed lmyzmail configuration validation failed; package files will be restored' >&2
    exit 1
}
[[ " $CONFIG_SUMMARY " == *" xdp=false "* ]] || {
    printf '%s\n' 'installation requires XDP to be disabled until the privileged deployment profile is available' >&2
    exit 1
}

DAEMON_RELOAD_ATTEMPTED=1
systemctl daemon-reload
if (( ENABLE == 1 )); then
    SERVICE_START_ATTEMPTED=1
    systemctl enable --now lmyzmail.service
    systemctl is-active --quiet lmyzmail.service
    MAIN_PID="$(systemctl show lmyzmail.service --property=MainPID --value)"
    [[ "$MAIN_PID" =~ ^[1-9][0-9]*$ ]] || {
        printf '%s\n' 'lmyzmail did not reach a running systemd state after installation' >&2
        exit 1
    }
else
    systemctl disable lmyzmail.service >/dev/null
fi
INSTALL_COMMITTED=1
cleanup_install_temporaries
(( ROLLBACK_FAILED == 0 )) || exit 1
trap - EXIT
printf '%s\n' 'installed lmyzmail; configuration and state are preserved on upgrades'
