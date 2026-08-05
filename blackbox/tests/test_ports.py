import socket

import pytest

from lmyzmail_blackbox.ports import PortAllocator


def test_port_set_is_unique_and_reserved_until_release() -> None:
    allocator = PortAllocator()
    ports = allocator.reserve_all(honeypot_count=8)
    values = {
        ports.postgres,
        ports.redis,
        ports.http,
        ports.smtp,
        ports.htcpcp,
        ports.minecraft,
        *ports.honeypots,
    }
    assert len(values) == 14
    allocator.release()


def test_individual_port_can_be_released_without_dropping_other_reservations() -> None:
    allocator = PortAllocator()
    ports = allocator.reserve_all(honeypot_count=1)
    allocator.release_port(ports.postgres)

    released = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    held = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        released.bind(("127.0.0.1", ports.postgres))
        with pytest.raises(OSError):
            held.bind(("127.0.0.1", ports.redis))
    finally:
        released.close()
        held.close()

    allocator.release()


def test_released_port_can_be_reserved_again_by_the_same_allocator() -> None:
    allocator = PortAllocator()
    ports = allocator.reserve_all(honeypot_count=1)
    allocator.release_port(ports.postgres)
    allocator.reserve_port(ports.postgres)

    competing = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(OSError):
            competing.bind(("127.0.0.1", ports.postgres))
    finally:
        competing.close()
        allocator.release()


@pytest.mark.parametrize("port", [-1, 0, 65536, True])
def test_exact_port_reservation_rejects_invalid_values(port: int) -> None:
    with pytest.raises(ValueError):
        PortAllocator().reserve_port(port)
