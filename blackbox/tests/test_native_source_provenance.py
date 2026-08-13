from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

_FROZEN_COMMIT = "4bc484c15b780d578ee8e53cab968f2819958215"
_REQUIRED_ABI_HASHES = {
    "skibidi_avx.c": "7e8e7f3ee5bea0ac8d0857bd5bc8d806b44e5142c17ec8b5b6583db7c62fc613",
    "skibidi_avx.h": "bde8e9d19d6668c644aba1cdd81fb9f56c2236ff827ddd16fb366369bc68bbea",
}


def _repository() -> Path:
    return Path(__file__).resolve().parents[2]


def test_skibidi_upstream_bytes_are_pinned_to_frozen_1_8_0_source() -> None:
    root = _repository()
    source_root = root / "native/lmyzmail-skibidi/upstream"
    manifest = json.loads(
        (root / "native/lmyzmail-skibidi/SOURCE.json").read_text(encoding="utf-8")
    )

    assert manifest["schema_version"] == 1
    assert manifest["version"] == "1.8.0"
    assert manifest["source_commit"] == _FROZEN_COMMIT
    assert manifest["byte_source"] == "frozen_worktree"
    assert {
        name: manifest["files"][name] for name in _REQUIRED_ABI_HASHES
    } == _REQUIRED_ABI_HASHES

    assert set(manifest["files"]) == {
        "LICENSE",
        "skibidi_avx.c",
        "skibidi_avx.h",
        "tests/test_skibidi.c",
    }
    for relative, expected in manifest["files"].items():
        with (source_root / relative).open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        assert actual == expected, relative


def test_release_artifact_has_no_skibidi_or_jvm_runtime_dependency() -> None:
    root = _repository()
    artifact = root / "target/x86_64-unknown-linux-gnu/release/lmyzmail"
    assert artifact.is_file(), f"release artifact is missing: {artifact}"
    readelf = shutil.which("readelf")
    assert readelf is not None, "readelf is required for the release artifact gate"
    dynamic = subprocess.run(  # noqa: S603 - fixed local tool and artifact path.
        [readelf, "-d", str(artifact)],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.lower()
    assert "libskibidi" not in dynamic
    assert "libjvm" not in dynamic
    assert "libjava" not in dynamic

    symbols = subprocess.run(  # noqa: S603 - fixed local tool and artifact path.
        [readelf, "--dyn-syms", str(artifact)],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.lower()
    assert "skibidi" not in symbols
    assert "jvm" not in symbols
