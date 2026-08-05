from __future__ import annotations

import contextlib
import socket
from dataclasses import dataclass


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
        values = [self._reserve() for _ in range(6 + honeypot_count)]
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
