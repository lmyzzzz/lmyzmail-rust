import socket
from pathlib import Path

import pytest

import lmyzmail_blackbox.ports as ports_module
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


def test_linux_service_ports_do_not_overlap_client_ephemeral_range() -> None:
    low, high = map(int, Path("/proc/sys/net/ipv4/ip_local_port_range").read_text().split())
    with PortAllocator() as allocator:
        ports = allocator.reserve_all()
        values = (ports.postgres, ports.redis, ports.http, ports.smtp,
                  ports.htcpcp, ports.minecraft, *ports.honeypots)
        assert all(not low <= port <= high for port in values)


def test_non_ephemeral_allocation_skips_occupied_port(monkeypatch: pytest.MonkeyPatch) -> None:
    with socket.socket() as occupied, socket.socket() as available:
        occupied.bind(("127.0.0.1", 0))
        available.bind(("127.0.0.1", 0))
        busy_port, free_port = occupied.getsockname()[1], available.getsockname()[1]
        available.close()
        monkeypatch.setattr(ports_module, "_non_ephemeral_ports", lambda: iter((busy_port, free_port)))
        with PortAllocator() as allocator:
            assert allocator._reserve() == free_port


def test_failed_port_set_releases_partial_reservations(monkeypatch: pytest.MonkeyPatch) -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    monkeypatch.setattr(ports_module, "_non_ephemeral_ports", lambda: iter((port,)))
    allocator = PortAllocator()
    with pytest.raises(OSError, match="non-ephemeral"):
        allocator.reserve_all()
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", port))


def test_service_candidate_cycle_visits_each_allowed_port_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    low, high = map(int, Path("/proc/sys/net/ipv4/ip_local_port_range").read_text().split())
    expected = set(range(1024, 65536)) - set(range(low, high + 1))
    count = len(expected)
    # Exercise a cycle crossing the excluded range, rather than mapping all
    # random choices inside it to the same first port after that range.
    monkeypatch.setattr(ports_module.secrets, "randbelow", lambda size: max(0, low - 1025))
    candidates = list(ports_module._non_ephemeral_ports())
    assert len(candidates) == count
    assert set(candidates) == expected
