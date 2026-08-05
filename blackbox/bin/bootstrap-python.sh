#!/usr/bin/env bash
set -euo pipefail

for command_name in cmp diff flock realpath; do
    command -v "$command_name" >/dev/null || {
        printf 'Missing required command: %s\n' "$command_name" >&2
        exit 2
    }
done
command -v python3 >/dev/null || {
    printf 'Missing required command: python3\n' >&2
    exit 2
}

script_path="$(realpath -e -- "${BASH_SOURCE[0]}")"
script_dir="$(dirname "$script_path")"
blackbox_dir="$(realpath -e -- "$script_dir/..")"
repo_dir="$(realpath -e -- "$blackbox_dir/..")"
requirements_lock="$blackbox_dir/requirements.lock"
installed_lock="$blackbox_dir/python-installed.lock"
state_input="$repo_dir/.blackbox"

if [[ -L "$state_input" ]]; then
    printf 'Refusing symlinked blackbox state directory: %s\n' "$state_input" >&2
    exit 2
fi
mkdir -p -- "$state_input"
blackbox_state="$(realpath -e -- "$state_input")"
if [[ "$blackbox_state" != "$state_input" ]]; then
    printf 'Refusing blackbox state directory outside the repository: %s\n' \
        "$blackbox_state" >&2
    exit 2
fi

for lock_path in "$requirements_lock" "$installed_lock"; do
    [[ -f "$lock_path" && ! -L "$lock_path" ]] || {
        printf 'Python dependency lock is missing or symlinked: %s\n' "$lock_path" >&2
        exit 2
    }
done

venv_input="${LMYZMAIL_BLACKBOX_VENV:-$blackbox_state/venv}"
venv_logical="$(realpath -m -s -- "$venv_input")"
venv_resolved="$(realpath -m -- "$venv_input")"
case "$venv_logical" in
    "$blackbox_state"/*) ;;
    *)
        printf 'Refusing venv path outside %s: %s\n' "$blackbox_state" "$venv_logical" >&2
        exit 2
        ;;
esac
if [[ "$venv_resolved" != "$venv_logical" ]]; then
    printf 'Refusing venv path containing a symlink: %s -> %s\n' \
        "$venv_logical" "$venv_resolved" >&2
    exit 2
fi
venv_dir="$venv_logical"

exec 9>"$blackbox_state/bootstrap-python.lock"
flock 9

# Recheck after acquiring the lock so concurrent provisioning cannot replace a
# validated path component with a symlink before it is used.
venv_parent="$(dirname "$venv_dir")"
mkdir -p -- "$venv_parent"
venv_parent_resolved="$(realpath -e -- "$venv_parent")"
case "$venv_parent_resolved" in
    "$blackbox_state"|"$blackbox_state"/*) ;;
    *)
        printf 'Refusing resolved venv parent outside %s: %s\n' \
            "$blackbox_state" "$venv_parent_resolved" >&2
        exit 2
        ;;
esac
if [[ "$venv_parent_resolved" != "$venv_parent" ]]; then
    printf 'Refusing venv parent containing a symlink: %s -> %s\n' \
        "$venv_parent" "$venv_parent_resolved" >&2
    exit 2
fi
if [[ -e "$venv_dir" && ! -d "$venv_dir" ]]; then
    printf 'Refusing non-directory venv path: %s\n' "$venv_dir" >&2
    exit 2
fi
if [[ -L "$venv_dir" ]]; then
    printf 'Refusing symlinked venv directory: %s\n' "$venv_dir" >&2
    exit 2
fi

python3 -c 'import sys; raise SystemExit(sys.version_info[:2] != (3, 12))' || {
    printf 'Python 3.12 is required to provision the black-box harness\n' >&2
    exit 2
}
if [[ ! -x "$venv_dir/bin/python" ]]; then
    python3 -m venv "$venv_dir"
fi
venv_python="$venv_dir/bin/python"
"$venv_python" -c 'import sys; raise SystemExit(sys.version_info[:2] != (3, 12))' || {
    printf 'Existing venv does not use Python 3.12: %s\n' "$venv_dir" >&2
    exit 2
}

"$venv_python" -m pip install \
    --disable-pip-version-check \
    --no-build-isolation \
    --no-deps \
    --only-binary=:all: \
    --require-hashes \
    --upgrade \
    --requirement "$requirements_lock"
"$venv_python" -m pip install \
    --disable-pip-version-check \
    --no-build-isolation \
    --no-deps \
    --editable "$blackbox_dir"

actual_lock="$(mktemp "$blackbox_state/.python-installed.XXXXXXXX")"
trap 'rm -f -- "$actual_lock"' EXIT
"$venv_python" - "$blackbox_dir" > "$actual_lock" <<'PY'
import importlib.metadata
import json
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

expected_project = Path(sys.argv[1]).resolve(strict=True)
installed: dict[str, str] = {}
editable_projects = 0

for distribution in importlib.metadata.distributions():
    raw_name = distribution.metadata.get("Name")
    if not raw_name:
        raise SystemExit("Installed distribution has no Name metadata")
    name = re.sub(r"[-_.]+", "-", raw_name).lower()
    if name in installed:
        raise SystemExit(f"Duplicate installed distribution: {name}")
    installed[name] = distribution.version

    if name != "lmyzmail-blackbox":
        continue
    editable_projects += 1
    direct_url_text = distribution.read_text("direct_url.json")
    if direct_url_text is None:
        raise SystemExit("lmyzmail-blackbox is not installed as an editable project")
    direct_url = json.loads(direct_url_text)
    if direct_url.get("dir_info", {}).get("editable") is not True:
        raise SystemExit("lmyzmail-blackbox editable marker is missing")
    parsed_url = urllib.parse.urlparse(direct_url.get("url", ""))
    if parsed_url.scheme != "file" or parsed_url.netloc not in ("", "localhost"):
        raise SystemExit("lmyzmail-blackbox editable source is not a local file URL")
    source_path = Path(
        urllib.request.url2pathname(urllib.parse.unquote(parsed_url.path))
    ).resolve(strict=True)
    if source_path != expected_project:
        raise SystemExit(
            f"lmyzmail-blackbox editable source mismatch: {source_path} != {expected_project}"
        )

if editable_projects != 1:
    raise SystemExit(
        f"Expected exactly one lmyzmail-blackbox distribution, found {editable_projects}"
    )
for name, version in sorted(installed.items()):
    print(f"{name}=={version}")
PY

if ! cmp --silent "$installed_lock" "$actual_lock"; then
    printf 'Installed Python distributions do not match %s:\n' "$installed_lock" >&2
    diff --unified "$installed_lock" "$actual_lock" >&2 || true
    exit 3
fi
cp -- "$actual_lock" "$blackbox_state/python-environment.txt"
printf 'Python harness ready: %s\n' "$venv_dir"
