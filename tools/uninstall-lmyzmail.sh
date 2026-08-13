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

if [[ -z "$DESTDIR" ]]; then
    for command in pgrep runuser systemctl; do
        command -v "$command" >/dev/null 2>&1 || {
            printf 'required live-uninstall command is unavailable: %s\n' "$command" >&2
            exit 1
        }
    done
fi

systemctl_value() {
    local property="$1"
    systemctl show lmyzmail.service --property="$property" --value
}

readonly DROP_IN_MARKER='# Managed by install-lmyzmail.sh; regenerated on every installation.'

if [[ -z "$DESTDIR" ]]; then
    LOAD_STATE="$(systemctl_value LoadState)" || {
        printf '%s\n' 'cannot query lmyzmail service state; no files were removed' >&2
        exit 1
    }
    if [[ "$LOAD_STATE" != not-found ]]; then
        ACTIVE_STATE="$(systemctl_value ActiveState)" || {
            printf '%s\n' 'cannot query whether lmyzmail is active; no files were removed' >&2
            exit 1
        }
        case "$ACTIVE_STATE" in
            active|activating|deactivating|reloading|refreshing)
                systemctl stop lmyzmail.service || {
                    printf '%s\n' 'lmyzmail did not stop cleanly; no files were removed' >&2
                    exit 1
                }
                ;;
        esac
        ACTIVE_STATE="$(systemctl_value ActiveState)" || {
            printf '%s\n' 'cannot verify that lmyzmail stopped; no files were removed' >&2
            exit 1
        }
        case "$ACTIVE_STATE" in
            inactive|failed) ;;
            *)
                printf 'lmyzmail remains in state %s; no files were removed\n' "$ACTIVE_STATE" >&2
                exit 1
                ;;
        esac
        MAIN_PID="$(systemctl_value MainPID)" || {
            printf '%s\n' 'cannot verify the lmyzmail main process; no files were removed' >&2
            exit 1
        }
        [[ "$MAIN_PID" == 0 ]] || {
            printf 'lmyzmail still has MainPID=%s; no files were removed\n' "$MAIN_PID" >&2
            exit 1
        }
        SERVICE_RESULT="$(systemctl_value Result)" || {
            printf '%s\n' 'cannot verify the lmyzmail shutdown result; no files were removed' >&2
            exit 1
        }
        if [[ "$SERVICE_RESULT" != success ]]; then
            printf 'lmyzmail shutdown result is %s; resolve service and XDP state before uninstalling\n' \
                "${SERVICE_RESULT:-unknown}" >&2
            exit 1
        fi
        UNIT_FILE_STATE="$(systemctl_value UnitFileState)" || {
            printf '%s\n' 'cannot query whether lmyzmail is enabled; no files were removed' >&2
            exit 1
        }
        case "$UNIT_FILE_STATE" in
            enabled|enabled-runtime|linked|linked-runtime|alias)
                systemctl disable lmyzmail.service || {
                    printf '%s\n' 'lmyzmail could not be disabled; no files were removed' >&2
                    exit 1
                }
                ;;
        esac
    fi
    if pgrep -x lmyzmail >/dev/null; then
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
for target in "${REMOVE_TARGETS[@]}"; do
    rm -f -- "$DESTDIR$target"
done

if [[ -z "$DESTDIR" ]]; then
    systemctl daemon-reload
fi

printf '%s\n' 'removed lmyzmail executable, unit, example, and generated path grants; configuration, data, assets, user, and BPF pins were preserved'
