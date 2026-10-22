from __future__ import annotations

import contextlib
import errno
import secrets
import socket
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path


def _non_ephemeral_ports() -> Iterator[int]:
    # Child processes cannot inherit these sockets, so reservations must be
    # released before they bind. Linux may otherwise reuse a released service
    # port as a PostgreSQL/Redis client's source port during application startup.
    fields = Path("/proc/sys/net/ipv4/ip_local_port_range").read_text(encoding="ascii").split()
    if len(fields) != 2:
        raise ValueError("invalid Linux ephemeral port range")
    low, high = map(int, fields)
    if not 1 <= low <= high <= 65535:
        raise ValueError("invalid Linux ephemeral port range")
    below = max(0, low - 1024)
    above_start = max(1024, high + 1)
    count = below + 65536 - above_start
    if count == 0:
        raise ValueError("Linux ephemeral range leaves no unprivileged service port")
    start = secrets.randbelow(count)
    for offset in range(count):
        index = (start + offset) % count
        yield 1024 + index if index < below else above_start + index - below


@dataclass(frozen=True, slots=True)
class PortSet:
    postgres: int
    redis: int
    http: int
    smtp: int
    htcpcp: int
    minecraft: int
    honeypots: tuple[int, ...]


class PortAllocator:
    """Reserve loopback ports until the complete launch configuration exists."""

    def __init__(self) -> None:
        self._sockets: list[socket.socket] = []

    def _reserve(self, port: int = 0, *, reuse_address: bool = False) -> int:
        if port == 0 and sys.platform.startswith("linux"):
            for candidate in _non_ephemeral_ports():
                try:
                    return self._reserve(candidate)
                except OSError as error:
                    if error.errno not in (errno.EADDRINUSE, errno.EACCES):
                        raise
            raise OSError(errno.EADDRINUSE, "no available non-ephemeral loopback port")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            elif reuse_address:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", port))
        except BaseException:
            listener.close()
            raise
        self._sockets.append(listener)
        return int(listener.getsockname()[1])

    def reserve_port(self, port: int) -> None:
        """Re-reserve one known loopback port between process generations."""
        if isinstance(port, bool) or not 1 <= port <= 65535:
            raise ValueError("port must be an integer from 1 through 65535")
        if any(int(listener.getsockname()[1]) == port for listener in self._sockets):
            raise RuntimeError(f"port is already reserved by this allocator: {port}")
        self._reserve(port, reuse_address=True)

    def reserve_all(self, *, honeypot_count: int = 8) -> PortSet:
        if self._sockets:
            raise RuntimeError("PortAllocator instances may only reserve once")
        try:
            values = [self._reserve() for _ in range(6 + honeypot_count)]
        except BaseException:
            self.release()
            raise
        return PortSet(
            postgres=values[0],
            redis=values[1],
            http=values[2],
            smtp=values[3],
            htcpcp=values[4],
            minecraft=values[5],
            honeypots=tuple(values[6:]),
        )

    def release(self) -> None:
        while self._sockets:
            with contextlib.suppress(OSError):
                self._sockets.pop().close()

    def release_port(self, port: int) -> None:
        for index, listener in enumerate(self._sockets):
            if int(listener.getsockname()[1]) == port:
                self._sockets.pop(index).close()
                return
        raise KeyError(f"port is not reserved by this allocator: {port}")

    def __enter__(self) -> PortAllocator:
        return self

    def __exit__(self, *_: object) -> None:
        self.release()
