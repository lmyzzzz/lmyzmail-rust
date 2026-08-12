from __future__ import annotations

import socket
import ssl
from pathlib import Path
from typing import Any

import pytest

from lmyzmail_blackbox.errors import HarnessError
from lmyzmail_blackbox.scripted_https import HttpsScenario, ScriptedHttpsServer
from lmyzmail_blackbox.tls_fixture import (
    create_server_ssl_context,
    provision_ephemeral_tls_material,
)


def _client_context(certificate_pem: bytes) -> ssl.SSLContext:
    context = ssl.create_default_context(cadata=certificate_pem.decode("ascii"))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def test_scripted_https_records_bounded_request_tls_and_response(tmp_path: Path) -> None:
    material = provision_ephemeral_tls_material(tmp_path)
    server = ScriptedHttpsServer(
        HttpsScenario(
            headers=(("Content-Type", "text/plain; charset=utf-8"),),
            body=b"version: STSv1\r\nmode: enforce\r\n",
            response_chunk_bytes=5,
        ),
        tls_context=create_server_ssl_context(material),
    )

    with server:
        with socket.create_connection((server.host, server.port), timeout=2.0) as plain:
            with _client_context(material.certificate_pem).wrap_socket(
                plain,
                server_hostname="smtp.example.test",
            ) as connection:
                connection.sendall(
                    b"GET /.well-known/mta-sts.txt HTTP/1.1\r\n"
                    b"Host: smtp.example.test\r\n"
                    b"User-Agent: lmyzmail-test\r\n\r\n"
                )
                response = bytearray()
                while chunk := connection.recv(4096):
                    response.extend(chunk)

        assert bytes(response).startswith(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n"
        )
        assert bytes(response).endswith(b"version: STSv1\r\nmode: enforce\r\n")
        assert server.requests() == (
            server.requests()[0],
        )
        request = server.requests()[0]
        assert request.connection_id == 1
        assert (request.method, request.target, request.version) == (
            "GET",
            "/.well-known/mta-sts.txt",
            "HTTP/1.1",
        )
        assert dict(request.headers) == {
            "Host": "smtp.example.test",
            "User-Agent": "lmyzmail-test",
        }
        assert request.body == b""
        assert request.sni == "smtp.example.test"
        assert request.tls_protocol in {"TLSv1.2", "TLSv1.3"}
        assert request.tls_cipher
        assert request.tls_secret_bits in {128, 256}


@pytest.mark.parametrize(
    "kwargs, match",
    [
        ({"status": 99}, "status"),
        ({"reason": "bad\rreason"}, "reason"),
        ({"headers": (("Bad Header", "x"),)}, "header"),
        ({"body": b"x" * (128 * 1024 + 1)}, "response"),
        ({"response_chunk_bytes": 0}, "chunk"),
        ({"response_delay_seconds": 61}, "delay"),
    ],
)
def test_scripted_https_scenario_validation(kwargs: dict[str, Any], match: str) -> None:
    with pytest.raises(ValueError, match=match):
        HttpsScenario(**kwargs)


def test_scripted_https_records_bounded_post_body(tmp_path: Path) -> None:
    material = provision_ephemeral_tls_material(tmp_path)
    body = b"\x1f\x8b\x08\x00tlsrpt"
    server = ScriptedHttpsServer(
        HttpsScenario(status=204, reason="No Content"),
        tls_context=create_server_ssl_context(material),
        max_request_body_bytes=len(body),
    )

    with server:
        with socket.create_connection((server.host, server.port), timeout=2.0) as plain:
            with _client_context(material.certificate_pem).wrap_socket(
                plain,
                server_hostname="smtp.example.test",
            ) as connection:
                connection.sendall(
                    b"POST /tls?token=%2Fvalue HTTP/1.1\r\n"
                    b"Host: smtp.example.test\r\n"
                    b"Content-Type: application/tlsrpt+gzip\r\n"
                    + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
                    + body
                )
                response = bytearray()
                while chunk := connection.recv(4096):
                    response.extend(chunk)

        assert bytes(response).startswith(b"HTTP/1.1 204 No Content\r\n")
        request = server.requests()[0]
        assert (request.method, request.target, request.body) == (
            "POST",
            "/tls?token=%2Fvalue",
            body,
        )


def test_scripted_https_rejects_request_body_above_instance_limit(tmp_path: Path) -> None:
    material = provision_ephemeral_tls_material(tmp_path)
    server = ScriptedHttpsServer(
        HttpsScenario(),
        tls_context=create_server_ssl_context(material),
    )

    with pytest.raises(HarnessError, match="byte budget"):
        with server:
            with socket.create_connection((server.host, server.port), timeout=2.0) as plain:
                with _client_context(material.certificate_pem).wrap_socket(
                    plain,
                    server_hostname="smtp.example.test",
                ) as connection:
                    connection.sendall(
                        b"POST / HTTP/1.1\r\nHost: smtp.example.test\r\n"
                        b"Content-Length: 1\r\n\r\nx"
                    )
                    while connection.recv(4096):
                        pass
