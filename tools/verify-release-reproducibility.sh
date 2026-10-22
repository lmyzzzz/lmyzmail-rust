#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: tools/verify-release-reproducibility.sh [OUTPUT.json]

Builds lmyzmail twice from a clean commit in independent temporary Cargo target
directories, then verifies byte identity, ELF Build ID identity, and the absence
of unresolved or Java/JVM runtime dependencies. JSON is written to stdout unless
OUTPUT.json is provided.

Set LMYZMAIL_REPRO_BINARY to a new absolute path to retain the verified ELF.
EOF
}

if [[ ${1:-} == "--help" || ${1:-} == "-h" ]]; then
    usage
    exit 0
fi
if (( $# > 1 )); then
    usage >&2
    exit 2
fi

readonly TARGET="x86_64-unknown-linux-gnu"
readonly OUTPUT_PATH="${1:-}"
readonly REPOSITORY="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

for command in \
    awk cargo cc clang-18 cmp date git grep install ldd mktemp python3 readelf realpath \
    rm rustc sed sha256sum sort stat
do
    if ! command -v "$command" >/dev/null 2>&1; then
        printf 'required command is unavailable: %s\n' "$command" >&2
        exit 1
    fi
done

cd "$REPOSITORY"
if [[ -n $(git status --porcelain=v1 --untracked-files=all) ]]; then
    printf 'release reproducibility requires a clean Git worktree\n' >&2
    git status --short >&2
    exit 1
fi

readonly COMMIT="$(git rev-parse --verify HEAD^{commit})"
readonly SOURCE_DATE_EPOCH="$(git show -s --format=%ct "$COMMIT")"
readonly CARGO_LOCK_SHA256="$(sha256sum Cargo.lock | awk '{print $1}')"
readonly TEMP_PARENT="$(realpath -e "${TMPDIR:-/tmp}")"
WORK_DIRECTORY="$(mktemp -d --tmpdir="$TEMP_PARENT" lmyzmail-release-repro.XXXXXXXX)"
readonly WORK_DIRECTORY

cleanup() {
    local resolved
    resolved="$(realpath -e "$WORK_DIRECTORY" 2>/dev/null || true)"
    if [[ -z "$resolved" ]]; then
        return
    fi
    if [[ $(dirname "$resolved") != "$TEMP_PARENT" || $(basename "$resolved") != lmyzmail-release-repro.* ]]; then
        printf 'refusing to remove unexpected reproducibility path: %s\n' "$resolved" >&2
        return
    fi
    rm -rf -- "$resolved"
}
trap cleanup EXIT

declare -a BUILD_SHA256 BUILD_ID BUILD_BYTES BUILD_SECONDS

build_once() {
    local index="$1"
    local target_directory="$WORK_DIRECTORY/build-$index"
    local artifact="$target_directory/$TARGET/release/lmyzmail"
    local started finished

    started="$(date +%s)"
    env \
        CARGO_TARGET_DIR="$target_directory" \
        SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
        TZ=UTC \
        LC_ALL=C \
        LANG=C \
        cargo build --frozen --release -p lmyzmail
    finished="$(date +%s)"

    if [[ ! -x "$artifact" ]]; then
        printf 'release artifact was not produced: %s\n' "$artifact" >&2
        exit 1
    fi
    BUILD_SHA256[$index]="$(sha256sum "$artifact" | awk '{print $1}')"
    BUILD_ID[$index]="$(readelf -n "$artifact" | awk '/Build ID:/ {print $3; exit}')"
    BUILD_BYTES[$index]="$(stat -c %s "$artifact")"
    BUILD_SECONDS[$index]="$((finished - started))"
    if [[ -z ${BUILD_ID[$index]} ]]; then
        printf 'release artifact has no ELF Build ID: %s\n' "$artifact" >&2
        exit 1
    fi
}

build_once 1
build_once 2

readonly ARTIFACT_ONE="$WORK_DIRECTORY/build-1/$TARGET/release/lmyzmail"
readonly ARTIFACT_TWO="$WORK_DIRECTORY/build-2/$TARGET/release/lmyzmail"
if ! cmp -s "$ARTIFACT_ONE" "$ARTIFACT_TWO"; then
    printf 'independent release builds are not byte-identical\n' >&2
    printf 'build-1 sha256=%s build-id=%s\n' "${BUILD_SHA256[1]}" "${BUILD_ID[1]}" >&2
    printf 'build-2 sha256=%s build-id=%s\n' "${BUILD_SHA256[2]}" "${BUILD_ID[2]}" >&2
    exit 1
fi
if [[ ${BUILD_ID[1]} != "${BUILD_ID[2]}" ]]; then
    printf 'byte-identical releases unexpectedly have different Build IDs\n' >&2
    exit 1
fi

if ldd "$ARTIFACT_ONE" | grep -q 'not found'; then
    printf 'release artifact has unresolved dynamic dependencies\n' >&2
    ldd "$ARTIFACT_ONE" >&2
    exit 1
fi

NEEDED_LIBRARIES="$({
    readelf -d "$ARTIFACT_ONE" \
        | sed -n 's/.*(NEEDED).*\[\([^]]*\)\].*/\1/p'
} | LC_ALL=C sort -u)"
readonly NEEDED_LIBRARIES
if grep -Eiq '(^|[^[:alnum:]])(lib)?(java|jvm|jli)([^[:alnum:]]|$)' <<<"$NEEDED_LIBRARIES"; then
    printf 'release artifact has a forbidden Java/JVM dynamic dependency\n' >&2
    printf '%s\n' "$NEEDED_LIBRARIES" >&2
    exit 1
fi
if readelf --dyn-syms --wide "$ARTIFACT_ONE" \
    | grep -Eiq '(^|[^[:alnum:]_])(JNI_|Java_|JVM_)([[:alnum:]_]|$)'
then
    printf 'release artifact imports a forbidden JNI/JVM dynamic symbol\n' >&2
    exit 1
fi

export COMMIT SOURCE_DATE_EPOCH CARGO_LOCK_SHA256 TARGET NEEDED_LIBRARIES
export BUILD_ONE_SHA256="${BUILD_SHA256[1]}"
export BUILD_TWO_SHA256="${BUILD_SHA256[2]}"
export BUILD_ONE_ID="${BUILD_ID[1]}"
export BUILD_TWO_ID="${BUILD_ID[2]}"
export BUILD_ONE_BYTES="${BUILD_BYTES[1]}"
export BUILD_TWO_BYTES="${BUILD_BYTES[2]}"
export BUILD_ONE_SECONDS="${BUILD_SECONDS[1]}"
export BUILD_TWO_SECONDS="${BUILD_SECONDS[2]}"
export RUSTC_VERSION="$(rustc --version --verbose)"
export CARGO_VERSION="$(cargo --version)"
export CLANG_VERSION="$(clang-18 --version | sed -n '1p')"
export CC_VERSION="$(cc --version | sed -n '1p')"

if [[ -n ${LMYZMAIL_REPRO_BINARY:-} ]]; then
    [[ "$LMYZMAIL_REPRO_BINARY" == /* && ! -e "$LMYZMAIL_REPRO_BINARY" && ! -L "$LMYZMAIL_REPRO_BINARY" ]] || {
        printf '%s\n' 'LMYZMAIL_REPRO_BINARY must be a new absolute output path' >&2
        exit 1
    }
    install -m 0755 -- "$ARTIFACT_ONE" "$LMYZMAIL_REPRO_BINARY"
fi

python3 - "$OUTPUT_PATH" <<'PY'
import json
import os
import sys
import tempfile
from pathlib import Path

artifact = {
    "path": "target/x86_64-unknown-linux-gnu/release/lmyzmail",
    "sha256": os.environ["BUILD_ONE_SHA256"],
    "bytes": int(os.environ["BUILD_ONE_BYTES"]),
    "build_id": os.environ["BUILD_ONE_ID"],
}
document = {
    "schema_version": 2,
    "commit": os.environ["COMMIT"],
    "target": os.environ["TARGET"],
    "source_date_epoch": int(os.environ["SOURCE_DATE_EPOCH"]),
    "cargo_lock_sha256": os.environ["CARGO_LOCK_SHA256"],
    "toolchain": {
        "rustc": os.environ["RUSTC_VERSION"],
        "cargo": os.environ["CARGO_VERSION"],
        "clang": os.environ["CLANG_VERSION"],
        "cc": os.environ["CC_VERSION"],
    },
    "environment": {
        "cargo_network": "frozen",
        "locale": "C",
        "timezone": "UTC",
        "independent_target_directories": True,
    },
    "artifact": artifact,
    "clean_builds": [
        {
            "label": "build-1",
            "command": "cargo build --frozen --release -p lmyzmail",
            "sha256": os.environ["BUILD_ONE_SHA256"],
            "bytes": int(os.environ["BUILD_ONE_BYTES"]),
            "build_id": os.environ["BUILD_ONE_ID"],
            "elapsed_seconds": int(os.environ["BUILD_ONE_SECONDS"]),
        },
        {
            "label": "build-2",
            "command": "cargo build --frozen --release -p lmyzmail",
            "sha256": os.environ["BUILD_TWO_SHA256"],
            "bytes": int(os.environ["BUILD_TWO_BYTES"]),
            "build_id": os.environ["BUILD_TWO_ID"],
            "elapsed_seconds": int(os.environ["BUILD_TWO_SECONDS"]),
        },
    ],
    "verification": {
        "byte_identical": True,
        "build_id_identical": True,
        "unresolved_dynamic_dependencies": [],
        "forbidden_dynamic_dependencies": ["libjava", "libjvm", "libjli"],
        "forbidden_dynamic_symbol_prefixes": ["JNI_", "Java_", "JVM_"],
        "needed_dynamic_libraries": [
            line for line in os.environ["NEEDED_LIBRARIES"].splitlines() if line
        ],
    },
}

payload = json.dumps(document, indent=2, sort_keys=True) + "\n"
if sys.argv[1]:
    output = Path(sys.argv[1])
    if output.is_symlink():
        raise SystemExit(f"refusing symlinked evidence output: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() and not output.is_file():
        raise SystemExit(f"evidence output is not a regular file: {output}")
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        newline="\n",
        dir=output.parent,
        prefix=f".{output.name}.",
        delete=False,
    ) as stream:
        temporary = Path(stream.name)
        os.fchmod(stream.fileno(), 0o644)
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(output)
else:
    sys.stdout.write(payload)
PY
