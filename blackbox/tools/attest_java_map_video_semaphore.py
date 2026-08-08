from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

_MAP_PLAYER = "src/main/java/net/lmyz/lmyzmail/netty/minecraft/video/MapVideoPlayer.java"
_SERVER = "src/main/java/net/lmyz/lmyzmail/netty/minecraft/MinecraftServer.java"
_PROPERTIES = "src/main/java/net/lmyz/lmyzmail/netty/minecraft/MinecraftProperties.java"
_EXPECTED_HASHES = {
    _MAP_PLAYER: "e7b15fb65ef8671e91b4ad427153285504b646c01a22b37ed453c275d22185b6",
    _SERVER: "c83c853b411ec9299a8509a34fe5ca6fa2e4141262e3488ed7453e1f0b2b3797",
    _PROPERTIES: "07a3b56cc170437ecfe29420d1b44b8f203a37cfc565e22329b9669857ebaaf9",
}


def _git_blob(repository: Path, commit: str, path: str) -> bytes:
    return subprocess.check_output(  # noqa: S603 - explicit read-only command
        [  # noqa: S607 - Git is the required repository object reader
            "git",
            "-C",
            str(repository),
            "cat-file",
            "blob",
            f"{commit}:{path}",
        ],
        stderr=subprocess.PIPE,
    )


def _line_number(lines: list[str], needle: str) -> int:
    matches = [index for index, line in enumerate(lines, start=1) if needle in line]
    if len(matches) != 1:
        raise RuntimeError(f"expected one {needle!r} line, found {matches}")
    return matches[0]


def attest(repository: Path, commit: str) -> dict[str, object]:
    blobs = {path: _git_blob(repository, commit, path) for path in _EXPECTED_HASHES}
    hashes = {path: hashlib.sha256(value).hexdigest() for path, value in blobs.items()}
    if hashes != _EXPECTED_HASHES:
        raise RuntimeError(f"frozen Java source hashes changed: {hashes}")

    map_lines = blobs[_MAP_PLAYER].decode("utf-8").splitlines()
    acquire_line = _line_number(map_lines, "videoSemaphore().tryAcquire()")
    release_line = _line_number(map_lines, "videoSemaphore().release()")
    execute_line = _line_number(map_lines, "videoExecutor().execute(() ->")
    if not acquire_line < release_line < execute_line:
        raise RuntimeError("map video permit is no longer released before worker submission")

    server_text = blobs[_SERVER].decode("utf-8")
    properties_text = blobs[_PROPERTIES].decode("utf-8")
    if "videoSemaphore = new Semaphore(properties.getMaxConcurrentVideos());" not in server_text:
        raise RuntimeError("video semaphore construction changed")
    if "private int maxConcurrentVideos = 2;" not in properties_text:
        raise RuntimeError("default video concurrency changed")

    return {
        "schema_version": 1,
        "commit": commit,
        "source_sha256": hashes,
        "default_max_concurrent_videos": 2,
        "map_video_lines": {
            "try_acquire": acquire_line,
            "release": release_line,
            "worker_execute": execute_line,
        },
        "observation": {
            "release_precedes_worker_submission": True,
            "permit_held_for_playback_lifecycle": False,
            "configured_map_video_concurrency_enforced": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--java-repository", required=True, type=Path)
    parser.add_argument(
        "--commit",
        default="5dac2ab2922c30c726c4a83d7626c95ad4e231c8",
    )
    arguments = parser.parse_args()
    print(json.dumps(attest(arguments.java_repository, arguments.commit), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
