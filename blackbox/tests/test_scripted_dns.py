from __future__ import annotations

import socket
import struct

import pytest

from lmyzmail_blackbox.errors import HarnessError
from lmyzmail_blackbox.scripted_dns import DnsAnswer, ScriptedDnsServer, TxtAnswer

_TXT = 16
_IN = 1


def _query(name: str, *, transaction_id: int, edns: bool = False) -> bytes:
    labels = b"".join(bytes((len(label),)) + label.encode("ascii") for label in name.split("."))
    question = labels + b"\x00" + struct.pack("!HH", _TXT, _IN)
    additional = b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 0) if edns else b""
    return (
        struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, int(edns))
        + question
        + additional
    )


def _exchange(server: ScriptedDnsServer, packet: bytes) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(2.0)
        client.sendto(packet, (server.host, server.port))
        return client.recv(4096)


def test_scripted_dns_returns_fragmented_txt_and_accepts_edns() -> None:
    server = ScriptedDnsServer(
        {
            ("_dmarc.example.test", _TXT): DnsAnswer(
                txt=(TxtAnswer(("v=DMARC1; ", "rua=mailto:reports@example.test")),)
            )
        }
    )
    with server:
        response = _exchange(
            server,
            _query("_dmarc.example.test", transaction_id=0x1234, edns=True),
        )

    transaction_id, flags, questions, answers, authorities, additional = struct.unpack(
        "!HHHHHH", response[:12]
    )
    assert transaction_id == 0x1234
    assert flags & 0x800F == 0x8000
    assert (questions, answers, authorities, additional) == (1, 1, 0, 0)
    first_chunk = b"v=DMARC1; "
    assert bytes((len(first_chunk),)) + first_chunk in response
    second_chunk = b"rua=mailto:reports@example.test"
    assert bytes((len(second_chunk),)) + second_chunk in response
    assert server.queries()[0].qname == "_dmarc.example.test"


def test_scripted_dns_unknown_name_returns_nxdomain() -> None:
    server = ScriptedDnsServer({})
    with server:
        response = _exchange(
            server,
            _query("missing.example.test", transaction_id=0x4321),
        )

    _, flags, questions, answers, authorities, additional = struct.unpack("!HHHHHH", response[:12])
    assert flags & 0x000F == 3
    assert (questions, answers, authorities, additional) == (1, 0, 0, 0)
    assert server.queries()[0].qname == "missing.example.test"


def test_scripted_dns_rejects_compressed_question_names() -> None:
    packet = struct.pack("!HHHHHH", 7, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c" + struct.pack(
        "!HH", _TXT, _IN
    )
    server = ScriptedDnsServer({})
    with pytest.raises(HarnessError, match="compressed DNS questions"):
        with server:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.sendto(packet, (server.host, server.port))
                client.settimeout(0.25)
                with pytest.raises(TimeoutError):
                    client.recv(4096)
