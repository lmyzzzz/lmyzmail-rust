#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: tools/uninstall-lmyzmail.sh [--destdir PATH]

Stops and disables a live lmyzmail service, then removes only the binary,
systemd unit, and packaged configuration example. Configuration, PostgreSQL,
Redis, Maildir, spool, models, video assets, logs, the service user, and BPF
pins are deliberately preserved for rollback or reinstall.
EOF
}

DESTDIR=""
while (( $# > 0 )); do
    case "$1" in
        --destdir)
            (( $# >= 2 )) || { printf '%s\n' '--destdir requires a path' >&2; exit 2; }
            DESTDIR="$2"
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
    DESTDIR="$(realpath -e "$DESTDIR")"
    [[ "$DESTDIR" != / ]] || { printf '%s\n' '--destdir must not resolve to /' >&2; exit 2; }
elif (( EUID != 0 )); then
    printf '%s\n' 'live uninstall must run as root; use --destdir for staging' >&2
    exit 1
fi

for command in cp flock install mkdir mktemp realpath rm stat; do
    command -v "$command" >/dev/null 2>&1 || {
        printf 'required uninstall command is unavailable: %s\n' "$command" >&2
        exit 1
    }
done
if [[ -z "$DESTDIR" ]]; then
    for command in chown chmod pgrep runuser systemctl; do
        command -v "$command" >/dev/null 2>&1 || {
            printf 'required live-uninstall command is unavailable: %s\n' "$command" >&2
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

systemctl_value() {
    local property="$1"
    systemctl show lmyzmail.service --property="$property" --value
}

readonly DROP_IN_MARKER='# Managed by install-lmyzmail.sh; regenerated on every installation.'

TRANSACTION_DIRECTORY=""
TRANSACTION_PARENT=""
TRANSACTION_BACKUP=""
TRANSACTION_STARTED=0
UNINSTALL_COMMITTED=0
DAEMON_RELOAD_ATTEMPTED=0
SERVICE_STATE_MUTATED=0
ORIGINAL_SERVICE_PRESENT=0
ORIGINAL_ACTIVE_STATE=""
ORIGINAL_UNIT_FILE_STATE=""
ORIGINAL_WAS_ACTIVE=0
ROLLBACK_FAILED=0

cleanup_early_uninstall_transaction() {
    if [[ -z "$DESTDIR" && "$TRANSACTION_DIRECTORY" == /run/lmyzmail-uninstall.* \
        && -d "$TRANSACTION_DIRECTORY" && ! -L "$TRANSACTION_DIRECTORY" \
        && $(stat -c %u "$TRANSACTION_DIRECTORY") == 0 \
        && $(stat -c %a "$TRANSACTION_DIRECTORY") == 700 ]]
    then
        rm -rf -- "$TRANSACTION_DIRECTORY"
    elif [[ -n "$DESTDIR" && -n "$TRANSACTION_DIRECTORY" \
        && -d "$TRANSACTION_DIRECTORY" && ! -L "$TRANSACTION_DIRECTORY" \
        && $(dirname "$TRANSACTION_DIRECTORY") == "$TRANSACTION_PARENT" \
        && $(basename "$TRANSACTION_DIRECTORY") == lmyzmail-uninstall.* ]]
    then
        rm -rf -- "$TRANSACTION_DIRECTORY"
    fi
}
trap cleanup_early_uninstall_transaction EXIT

if [[ -z "$DESTDIR" ]]; then
    LOAD_STATE="$(systemctl_value LoadState)" || {
        printf '%s\n' 'cannot query lmyzmail service state; no files were removed' >&2
        exit 1
    }
    if [[ "$LOAD_STATE" != not-found ]]; then
        ORIGINAL_SERVICE_PRESENT=1
        ORIGINAL_ACTIVE_STATE="$(systemctl_value ActiveState)" || {
            printf '%s\n' 'cannot query whether lmyzmail is active; no files were removed' >&2
            exit 1
        }
        ORIGINAL_UNIT_FILE_STATE="$(systemctl_value UnitFileState)" || {
            printf '%s\n' 'cannot query whether lmyzmail is enabled; no files were removed' >&2
            exit 1
        }
        ORIGINAL_WAS_ACTIVE=0
        case "$ORIGINAL_ACTIVE_STATE" in
            active) ORIGINAL_WAS_ACTIVE=1 ;;
            inactive) ;;
            *)
                printf 'lmyzmail is in transitional or failed state %s; no files were removed\n' \
                    "$ORIGINAL_ACTIVE_STATE" >&2
                exit 1
                ;;
        esac
        case "$ORIGINAL_UNIT_FILE_STATE" in
            enabled|enabled-runtime|disabled|static) ;;
            *)
                printf 'lmyzmail has unsupported unit-file state %s; no files were removed\n' \
                    "$ORIGINAL_UNIT_FILE_STATE" >&2
                exit 1
                ;;
        esac
        MAIN_PID="$(systemctl_value MainPID)" || {
            printf '%s\n' 'cannot verify the lmyzmail main process; no files were removed' >&2
            exit 1
        }
        if (( ORIGINAL_WAS_ACTIVE == 0 )); then
            [[ "$MAIN_PID" == 0 ]] || {
                printf 'lmyzmail reports inactive state with MainPID=%s; no files were removed\n' "$MAIN_PID" >&2
                exit 1
            }
        fi
        ORIGINAL_SERVICE_RESULT="$(systemctl_value Result)" || {
            printf '%s\n' 'cannot verify the lmyzmail shutdown result; no files were removed' >&2
            exit 1
        }
        if (( ORIGINAL_WAS_ACTIVE == 0 )) && [[ "$ORIGINAL_SERVICE_RESULT" != success ]]; then
            printf 'lmyzmail is in an unsafe inactive state: ActiveState=%s Result=%s; no files were removed\n' \
                "$ORIGINAL_ACTIVE_STATE" "${ORIGINAL_SERVICE_RESULT:-unknown}" >&2
            exit 1
        fi
    fi
    if (( ORIGINAL_WAS_ACTIVE == 0 )) && pgrep -x lmyzmail >/dev/null; then
        printf '%s\n' 'an unmanaged lmyzmail process is still running; no files were removed' >&2
        exit 1
    fi
    if [[ -e /usr/bin/lmyzmail || -e /usr/lib/systemd/system/lmyzmail.service ]]; then
        [[ -x /usr/bin/lmyzmail && -f /etc/lmyzmail/application.properties ]] || {
            printf '%s\n' 'installed binary/configuration state is incomplete; no files were removed' >&2
            exit 1
        }
        CONFIG_SUMMARY="$(runuser -u lmyzmail -- /usr/bin/lmyzmail \
            --config /etc/lmyzmail/application.properties --check-config)" || {
            printf '%s\n' 'cannot validate the installed configuration; no files were removed' >&2
            exit 1
        }
        [[ " $CONFIG_SUMMARY " == *" xdp=false "* ]] || {
            printf '%s\n' 'refusing uninstall while XDP is configured; use the verified detach maintenance command first' >&2
            exit 1
        }
    fi
fi

DROP_IN_TARGET="$DESTDIR/etc/systemd/system/lmyzmail.service.d/legacy-paths.conf"
if [[ -e "$DROP_IN_TARGET" ]]; then
    [[ -f "$DROP_IN_TARGET" ]] || {
        printf 'refusing non-regular legacy path grant: %s\n' "$DROP_IN_TARGET" >&2
        exit 1
    }
    IFS= read -r DROP_IN_FIRST_LINE < "$DROP_IN_TARGET" || true
    [[ "$DROP_IN_FIRST_LINE" == "$DROP_IN_MARKER" ]] || {
        printf 'refusing to remove an unmanaged legacy path grant: %s\n' "$DROP_IN_TARGET" >&2
        exit 1
    }
fi

validate_remove_file() {
    local logical="$1"
    local target="$DESTDIR$logical"
    local parent resolved_parent root current component
    local -a components
    current="$DESTDIR"
    IFS='/' read -r -a components <<<"${logical#/}"
    for component in "${components[@]:0:${#components[@]}-1}"; do
        [[ -n "$component" ]] || continue
        current="$current/$component"
        if [[ -L "$current" ]]; then
            printf 'refusing symlinked uninstall path component: %s\n' "$current" >&2
            exit 1
        fi
    done
    parent="$(dirname "$target")"
    [[ -e "$parent" ]] || return
    resolved_parent="$(realpath -e "$parent")"
    root="$(realpath -e "${DESTDIR:-/}")"
    if [[ "$root" != / && "$resolved_parent" != "$root"/* ]]; then
        printf 'refusing uninstall path outside destination root: %s\n' "$resolved_parent" >&2
        exit 1
    fi
    [[ ! -e "$target" || -f "$target" || -L "$target" ]] || {
        printf 'refusing to remove non-file installation target: %s\n' "$target" >&2
        exit 1
    }
}

declare -a REMOVE_TARGETS=(
    /usr/bin/lmyzmail
    /usr/lib/systemd/system/lmyzmail.service
    /usr/share/doc/lmyzmail/application.properties.example
    /etc/systemd/system/lmyzmail.service.d/legacy-paths.conf
)
for target in "${REMOVE_TARGETS[@]}"; do
    validate_remove_file "$target"
done

UNINSTALL_FAIL_AFTER=0
UNINSTALL_REMOVE_COUNT=0
UNINSTALL_DAEMON_RELOAD_FAIL=0
if [[ -n ${LMYZMAIL_TEST_UNINSTALL_FAIL_AFTER:-} ]]; then
    [[ ${LMYZMAIL_TEST_UNINSTALL_FAIL_AFTER} =~ ^[1-9][0-9]*$ ]] || {
        printf '%s\n' 'LMYZMAIL_TEST_UNINSTALL_FAIL_AFTER must be a positive integer' >&2
        exit 2
    }
    UNINSTALL_FAIL_AFTER="$LMYZMAIL_TEST_UNINSTALL_FAIL_AFTER"
fi
if [[ -n ${LMYZMAIL_TEST_UNINSTALL_DAEMON_RELOAD_FAIL:-} ]]; then
    [[ -n "$DESTDIR" && ${LMYZMAIL_TEST_UNINSTALL_DAEMON_RELOAD_FAIL} == 1 ]] || {
        printf '%s\n' 'LMYZMAIL_TEST_UNINSTALL_DAEMON_RELOAD_FAIL is valid only as 1 with --destdir' >&2
        exit 2
    }
    UNINSTALL_DAEMON_RELOAD_FAIL=1
fi

if [[ -z "$DESTDIR" ]]; then
    [[ -d /run && ! -L /run && $(stat -c %u /run) == 0 \
        && $(( 8#$(stat -c %a /run) & 0022 )) == 0 ]] || {
        printf '%s\n' '/run must be a root-owned directory that is not group/other writable' >&2
        exit 1
    }
    TRANSACTION_DIRECTORY="$(mktemp -d /run/lmyzmail-uninstall.XXXXXXXX)"
    chown root:root "$TRANSACTION_DIRECTORY"
    chmod 0700 "$TRANSACTION_DIRECTORY"
    [[ "$TRANSACTION_DIRECTORY" == /run/lmyzmail-uninstall.* \
        && -d "$TRANSACTION_DIRECTORY" && ! -L "$TRANSACTION_DIRECTORY" \
        && $(stat -c %u "$TRANSACTION_DIRECTORY") == 0 \
        && $(stat -c %a "$TRANSACTION_DIRECTORY") == 700 ]] || {
        printf '%s\n' 'failed to establish a secure live uninstall transaction directory' >&2
        exit 1
    }
else
    TRANSACTION_PARENT="$(realpath -e "${TMPDIR:-/tmp}")"
    TRANSACTION_DIRECTORY="$(mktemp -d --tmpdir="$TRANSACTION_PARENT" \
        lmyzmail-uninstall.XXXXXXXX)"
    chmod 0700 "$TRANSACTION_DIRECTORY"
fi
TRANSACTION_BACKUP="$TRANSACTION_DIRECTORY/backup"
install -d -m 0700 -- "$TRANSACTION_BACKUP"

rollback_uninstallation() {
    local logical backup target parent
    local rollback_failed=0
    (( TRANSACTION_STARTED == 1 && UNINSTALL_COMMITTED == 0 )) || return 0
    for logical in "${REMOVE_TARGETS[@]}"; do
        backup="$TRANSACTION_BACKUP$logical"
        target="$DESTDIR$logical"
        if [[ -e "$backup" || -L "$backup" ]]; then
            rm -f -- "$target" || rollback_failed=1
            parent="$(dirname "$target")"
            [[ -d "$parent" ]] || mkdir -p -- "$parent" || rollback_failed=1
            cp -a -- "$backup" "$target" || rollback_failed=1
        elif [[ -e "$target" || -L "$target" ]]; then
            rm -f -- "$target" || rollback_failed=1
        fi
    done
    if [[ -z "$DESTDIR" ]] \
        && (( DAEMON_RELOAD_ATTEMPTED == 1 || SERVICE_STATE_MUTATED == 1 )); then
        systemctl daemon-reload >/dev/null 2>&1 || rollback_failed=1
    fi
    if [[ -z "$DESTDIR" ]] && (( SERVICE_STATE_MUTATED == 1 )); then
        case "$ORIGINAL_UNIT_FILE_STATE" in
            enabled) systemctl enable lmyzmail.service >/dev/null 2>&1 || rollback_failed=1 ;;
            enabled-runtime) systemctl enable --runtime lmyzmail.service >/dev/null 2>&1 || rollback_failed=1 ;;
            disabled) systemctl disable lmyzmail.service >/dev/null 2>&1 || rollback_failed=1 ;;
            static) ;;
            *) rollback_failed=1 ;;
        esac
        if (( ORIGINAL_WAS_ACTIVE == 1 )); then
            systemctl start lmyzmail.service >/dev/null 2>&1 || rollback_failed=1
        else
            systemctl reset-failed lmyzmail.service >/dev/null 2>&1 || rollback_failed=1
        fi
        RESTORED_ACTIVE_STATE="$(systemctl_value ActiveState 2>/dev/null || true)"
        RESTORED_MAIN_PID="$(systemctl_value MainPID 2>/dev/null || true)"
        RESTORED_UNIT_FILE_STATE="$(systemctl_value UnitFileState 2>/dev/null || true)"
        if (( ORIGINAL_WAS_ACTIVE == 1 )); then
            [[ "$RESTORED_ACTIVE_STATE" == active && "$RESTORED_MAIN_PID" != 0 ]] || rollback_failed=1
        else
            [[ "$RESTORED_ACTIVE_STATE" == inactive && "$RESTORED_MAIN_PID" == 0 ]] || rollback_failed=1
        fi
        [[ "$RESTORED_UNIT_FILE_STATE" == "$ORIGINAL_UNIT_FILE_STATE" \
            || ( "$ORIGINAL_UNIT_FILE_STATE" == enabled-runtime \
                && "$RESTORED_UNIT_FILE_STATE" == enabled-runtime ) ]] || rollback_failed=1
    fi
    if (( rollback_failed == 0 )); then
        printf '%s\n' 'uninstall failed; restored all previously managed package files' >&2
    else
        ROLLBACK_FAILED=1
        printf 'uninstall failed; restoration also failed; recovery backup retained at %s\n' \
            "$TRANSACTION_BACKUP" >&2
        return 1
    fi
}

cleanup_uninstallation() {
    set +e
    rollback_uninstallation || true
    if (( ROLLBACK_FAILED == 0 )); then
        if [[ -n "$DESTDIR" && -d "$TRANSACTION_DIRECTORY" \
            && ! -L "$TRANSACTION_DIRECTORY" \
            && $(dirname "$TRANSACTION_DIRECTORY") == "$TRANSACTION_PARENT" \
            && $(basename "$TRANSACTION_DIRECTORY") == lmyzmail-uninstall.* ]]
        then
            rm -rf -- "$TRANSACTION_DIRECTORY" || ROLLBACK_FAILED=1
        elif [[ -z "$DESTDIR" && "$TRANSACTION_DIRECTORY" == /run/lmyzmail-uninstall.* \
            && -d "$TRANSACTION_DIRECTORY" && ! -L "$TRANSACTION_DIRECTORY" \
            && $(stat -c %u "$TRANSACTION_DIRECTORY") == 0 \
            && $(stat -c %a "$TRANSACTION_DIRECTORY") == 700 ]]
        then
            rm -rf -- "$TRANSACTION_DIRECTORY" || ROLLBACK_FAILED=1
        else
            ROLLBACK_FAILED=1
            printf 'refusing to remove unexpected uninstall transaction path: %s\n' \
                "$TRANSACTION_DIRECTORY" >&2
        fi
    fi
}
trap cleanup_uninstallation EXIT

for logical in "${REMOVE_TARGETS[@]}"; do
    target="$DESTDIR$logical"
    if [[ -e "$target" || -L "$target" ]]; then
        validate_remove_file "$logical"
        mkdir -p -- "$TRANSACTION_BACKUP$(dirname "$logical")"
        cp -a -- "$target" "$TRANSACTION_BACKUP$logical"
    fi
done
TRANSACTION_STARTED=1

if [[ -z "$DESTDIR" && "$ORIGINAL_SERVICE_PRESENT" == 1 ]]; then
    SERVICE_STATE_MUTATED=1
    if (( ORIGINAL_WAS_ACTIVE == 1 )); then
        systemctl stop lmyzmail.service
    fi
    ACTIVE_STATE="$(systemctl_value ActiveState)"
    MAIN_PID="$(systemctl_value MainPID)"
    [[ "$ACTIVE_STATE" == inactive && "$MAIN_PID" == 0 ]] || {
        printf 'lmyzmail did not stop cleanly; no files were removed\n' >&2
        exit 1
    }
    SERVICE_RESULT="$(systemctl_value Result)"
    [[ "$SERVICE_RESULT" == success ]] || {
        printf 'lmyzmail shutdown result is %s; no files were removed\n' \
            "${SERVICE_RESULT:-unknown}" >&2
        exit 1
    }
    case "$ORIGINAL_UNIT_FILE_STATE" in
        enabled) systemctl disable lmyzmail.service ;;
        enabled-runtime) systemctl disable --runtime lmyzmail.service ;;
        disabled|static) ;;
    esac
fi
if [[ -z "$DESTDIR" ]] && pgrep -x lmyzmail >/dev/null; then
    printf '%s\n' 'an unmanaged lmyzmail process is still running; no files were removed' >&2
    exit 1
fi
remove_managed_file() {
    local logical="$1"
    local target="$DESTDIR$logical"
    validate_remove_file "$logical"
    if [[ -e "$target" || -L "$target" ]]; then
        rm -f -- "$target"
        UNINSTALL_REMOVE_COUNT=$((UNINSTALL_REMOVE_COUNT + 1))
        if (( UNINSTALL_FAIL_AFTER > 0 && UNINSTALL_REMOVE_COUNT == UNINSTALL_FAIL_AFTER )); then
            printf 'injected staged uninstall failure after %d managed removals\n' \
                "$UNINSTALL_REMOVE_COUNT" >&2
            return 1
        fi
    fi
}

for target in "${REMOVE_TARGETS[@]}"; do
    remove_managed_file "$target"
done

if [[ -z "$DESTDIR" || $UNINSTALL_DAEMON_RELOAD_FAIL == 1 ]]; then
    DAEMON_RELOAD_ATTEMPTED=1
    if (( UNINSTALL_DAEMON_RELOAD_FAIL == 1 )); then
        printf '%s\n' 'injected staged daemon-reload failure' >&2
        false
    fi
    systemctl daemon-reload
fi

UNINSTALL_COMMITTED=1
trap - EXIT
cleanup_uninstallation
(( ROLLBACK_FAILED == 0 )) || exit 1

printf '%s\n' 'removed lmyzmail executable, unit, example, and generated path grants; configuration, data, assets, user, and BPF pins were preserved'
