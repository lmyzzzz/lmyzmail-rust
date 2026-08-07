from __future__ import annotations

import hashlib
import ssl
import warnings
from typing import Any, cast

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.hashes import HashAlgorithm
from cryptography.x509.oid import ExtendedKeyUsageOID

from .differential import RuntimeTarget, Scenario
from .protocols import RawSmtpClient, read_smtp_reply
from .smtp_contract import (
    capture_delivery,
    open_smtp_client,
    smtp_ehlo,
    smtp_greeting_snapshot,
    smtp_reply_snapshot,
)
from .snapshots import bytes_snapshot

_SERVER_NAME = "smtp.example.test"
_BAD_SEQUENCE = (b"503 5.5.1 Bad sequence of commands\r\n",)
_READY_FOR_TLS = (b"220 2.0.0 Ready to start TLS\r\n",)
_TLS_MESSAGE_ID = "<bb-starttls-data-001@example.test>"
_TLS_SUBJECT = "bb-starttls-data-001"
_TLS_MESSAGE = (
    b"Subject: bb-starttls-data-001\r\n"
    b"Message-ID: <bb-starttls-data-001@example.test>\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/plain; charset=us-ascii\r\n"
    b"\r\n"
    b"STARTTLS body\r\n"
)


def _check(condition: bool, details: object) -> None:
    if not condition:
        raise AssertionError(f"SMTP STARTTLS contract violation: {details!r}")


def _certificate_pem(target: RuntimeTarget) -> bytes:
    value = getattr(target, "tls_certificate_pem", None)
    _check(isinstance(value, bytes), "target did not expose its ephemeral TLS certificate")
    return cast(bytes, value)


def _client_context(
    target: RuntimeTarget,
    *,
    minimum: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2,
    maximum: ssl.TLSVersion = ssl.TLSVersion.TLSv1_3,
) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = minimum
    context.maximum_version = maximum
    context.load_verify_locations(cadata=_certificate_pem(target).decode("ascii"))
    return context


def _legacy_client_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        context.minimum_version = ssl.TLSVersion.TLSv1_1
        context.maximum_version = ssl.TLSVersion.TLSv1_1
    context.set_ciphers("DEFAULT:@SECLEVEL=0")
    return context


def _tls_socket(client: RawSmtpClient) -> ssl.SSLSocket:
    sock = client.stream.sock
    _check(isinstance(sock, ssl.SSLSocket), type(sock))
    return cast(ssl.SSLSocket, sock)


def _tls_snapshot(sock: ssl.SSLSocket) -> dict[str, Any]:
    cipher = sock.cipher()
    _check(cipher is not None, "TLS socket did not report a cipher")
    cipher = cast(tuple[str, str, int], cipher)
    return {
        "protocol": sock.version(),
        "cipher": cipher[0],
        "cipher_protocol": cipher[1],
        "secret_bits": cipher[2],
        "compression": sock.compression(),
        "alpn": sock.selected_alpn_protocol(),
    }


def _certificate_snapshot(sock: ssl.SSLSocket) -> dict[str, Any]:
    encoded = sock.getpeercert(binary_form=True)
    _check(isinstance(encoded, bytes), "TLS peer did not provide a certificate")
    certificate = x509.load_der_x509_certificate(cast(bytes, encoded))
    public_key = certificate.public_key()
    _check(isinstance(public_key, rsa.RSAPublicKey), type(public_key))
    public_key = cast(rsa.RSAPublicKey, public_key)
    public_numbers = public_key.public_numbers()
    alternative_names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    basic_constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
    key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage)
    extended_key_usage = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    signature_hash = certificate.signature_hash_algorithm
    _check(signature_hash is not None, certificate.signature_algorithm_oid)
    signature_hash = cast(HashAlgorithm, signature_hash)
    return {
        "version": certificate.version.name,
        "subject": [
            [attribute.oid.dotted_string, attribute.value]
            for relative_name in certificate.subject.rdns
            for attribute in relative_name
        ],
        "issuer": [
            [attribute.oid.dotted_string, attribute.value]
            for relative_name in certificate.issuer.rdns
            for attribute in relative_name
        ],
        "serial_number": "<ephemeral-random>",
        "not_valid_before": certificate.not_valid_before_utc.isoformat(),
        "not_valid_after": certificate.not_valid_after_utc.isoformat(),
        "signature": {
            "algorithm_oid": certificate.signature_algorithm_oid.dotted_string,
            "hash": signature_hash.name,
        },
        "public_key": {
            "algorithm": "RSA",
            "bits": public_key.key_size,
            "exponent": public_numbers.e,
            "identity": "<ephemeral-random>",
        },
        "subject_alternative_name": {
            "critical": alternative_names.critical,
            "dns": alternative_names.value.get_values_for_type(x509.DNSName),
            "ip": [
                str(value) for value in alternative_names.value.get_values_for_type(x509.IPAddress)
            ],
        },
        "basic_constraints": {
            "critical": basic_constraints.critical,
            "ca": basic_constraints.value.ca,
            "path_length": basic_constraints.value.path_length,
        },
        "key_usage": {
            "critical": key_usage.critical,
            "digital_signature": key_usage.value.digital_signature,
            "key_encipherment": key_usage.value.key_encipherment,
            "key_agreement": key_usage.value.key_agreement,
            "key_cert_sign": key_usage.value.key_cert_sign,
            "crl_sign": key_usage.value.crl_sign,
        },
        "extended_key_usage": {
            "critical": extended_key_usage.critical,
            "oids": [value.dotted_string for value in extended_key_usage.value],
            "server_auth_only": list(extended_key_usage.value) == [ExtendedKeyUsageOID.SERVER_AUTH],
        },
    }


def _upgrade_session(
    target: RuntimeTarget,
    client: RawSmtpClient,
    hostname: bytes,
) -> dict[str, Any]:
    ehlo_before = smtp_ehlo(client, hostname, advertise_starttls=True)
    ready = client.start_tls(_client_context(target), server_hostname=_SERVER_NAME)
    _check(ready == _READY_FOR_TLS, ready)
    sock = _tls_socket(client)

    mail_before_ehlo = client.command(b"MAIL FROM:<>")
    _check(mail_before_ehlo == _BAD_SEQUENCE, mail_before_ehlo)
    ehlo_after = smtp_ehlo(client, hostname)
    repeated_starttls = client.command(b"STARTTLS")
    _check(repeated_starttls == _BAD_SEQUENCE, repeated_starttls)

    return {
        "ehlo_before_tls": smtp_reply_snapshot(ehlo_before, hostname),
        "starttls": smtp_reply_snapshot(ready, hostname),
        "negotiated": _tls_snapshot(sock),
        "certificate": _certificate_snapshot(sock),
        "mail_before_post_tls_ehlo": smtp_reply_snapshot(mail_before_ehlo, hostname),
        "ehlo_after_tls": smtp_reply_snapshot(ehlo_after, hostname),
        "repeated_starttls": smtp_reply_snapshot(repeated_starttls, hostname),
    }


def _capture_starttls_delivery(target: RuntimeTarget) -> dict[str, Any]:
    return capture_delivery(
        target,
        mode="data",
        subject=_TLS_SUBJECT,
        message_id=_TLS_MESSAGE_ID,
        message=_TLS_MESSAGE,
        session_setup=_upgrade_session,
        received_protocol=b"ESMTPS",
    )


def _successful_version(
    target: RuntimeTarget,
    version: ssl.TLSVersion,
) -> dict[str, Any]:
    client, hostname = open_smtp_client(target)
    with client:
        ehlo_before = smtp_ehlo(client, hostname, advertise_starttls=True)
        ready = client.start_tls(
            _client_context(target, minimum=version, maximum=version),
            server_hostname=_SERVER_NAME,
        )
        _check(ready == _READY_FOR_TLS, ready)
        negotiated = _tls_snapshot(_tls_socket(client))
        ehlo_after = smtp_ehlo(client, hostname)
        quit_reply = client.quit()
    return {
        "greeting": smtp_greeting_snapshot(),
        "ehlo_before_tls": smtp_reply_snapshot(ehlo_before, hostname),
        "starttls": smtp_reply_snapshot(ready, hostname),
        "negotiated": negotiated,
        "ehlo_after_tls": smtp_reply_snapshot(ehlo_after, hostname),
        "quit": smtp_reply_snapshot(quit_reply, hostname),
    }


def _rejected_legacy_version(target: RuntimeTarget) -> dict[str, Any]:
    client, hostname = open_smtp_client(target)
    try:
        ehlo = smtp_ehlo(client, hostname, advertise_starttls=True)
        ready = client.command(b"STARTTLS")
        _check(ready == _READY_FOR_TLS, ready)
        _check(not client.stream.buffer, client.stream.buffer)
        try:
            client.stream.sock.settimeout(client.stream._remaining())
            client.stream.sock = _legacy_client_context().wrap_socket(
                client.stream.sock,
                server_hostname=None,
            )
        except ssl.SSLError as error:
            library = getattr(error, "library", None)
            reason = getattr(error, "reason", None)
            _check(isinstance(library, str) and isinstance(reason, str), error)
            return {
                "greeting": smtp_greeting_snapshot(),
                "ehlo": smtp_reply_snapshot(ehlo, hostname),
                "starttls": smtp_reply_snapshot(ready, hostname),
                "offered_protocol": "TLSv1.1",
                "error": {
                    "type": type(error).__name__,
                    "library": library,
                    "reason": reason,
                },
                "connection_closed": True,
            }
        raise AssertionError("SMTP STARTTLS contract violation: TLS 1.1 was accepted")
    finally:
        client.close()


def _capture_protocol_policy(target: RuntimeTarget) -> dict[str, Any]:
    return {
        "tls_1_2": _successful_version(target, ssl.TLSVersion.TLSv1_2),
        "tls_1_3": _successful_version(target, ssl.TLSVersion.TLSv1_3),
        "tls_1_1": _rejected_legacy_version(target),
    }


def _capture_state_machine(target: RuntimeTarget) -> dict[str, Any]:
    transaction_client, transaction_hostname = open_smtp_client(target)
    with transaction_client:
        transaction_ehlo = smtp_ehlo(
            transaction_client,
            transaction_hostname,
            advertise_starttls=True,
        )
        mail_from = transaction_client.command(b"MAIL FROM:<>")
        _check(mail_from == (b"250 2.1.0 Sender OK\r\n",), mail_from)
        rejected_starttls = transaction_client.command(b"STARTTLS")
        _check(rejected_starttls == _BAD_SEQUENCE, rejected_starttls)
        reset = transaction_client.command(b"RSET")
        _check(reset == (b"250 2.0.0 Reset OK\r\n",), reset)
        transaction_quit = transaction_client.quit()

    direct_client, direct_hostname = open_smtp_client(target)
    with direct_client:
        ready = direct_client.start_tls(
            _client_context(
                target,
                minimum=ssl.TLSVersion.TLSv1_3,
                maximum=ssl.TLSVersion.TLSv1_3,
            ),
            server_hostname=_SERVER_NAME,
        )
        _check(ready == _READY_FOR_TLS, ready)
        direct_negotiated = _tls_snapshot(_tls_socket(direct_client))
        noop = direct_client.command(b"NOOP")
        _check(noop == (b"250 OK\r\n",), noop)
        mail_before_ehlo = direct_client.command(b"MAIL FROM:<>")
        _check(mail_before_ehlo == _BAD_SEQUENCE, mail_before_ehlo)
        direct_ehlo = smtp_ehlo(direct_client, direct_hostname)
        direct_quit = direct_client.quit()

    return {
        "transaction_rejection": {
            "greeting": smtp_greeting_snapshot(),
            "ehlo": smtp_reply_snapshot(transaction_ehlo, transaction_hostname),
            "mail_from": smtp_reply_snapshot(mail_from, transaction_hostname),
            "starttls": smtp_reply_snapshot(rejected_starttls, transaction_hostname),
            "rset": smtp_reply_snapshot(reset, transaction_hostname),
            "quit": smtp_reply_snapshot(transaction_quit, transaction_hostname),
        },
        "direct_upgrade": {
            "greeting": smtp_greeting_snapshot(),
            "starttls": smtp_reply_snapshot(ready, direct_hostname),
            "negotiated": direct_negotiated,
            "noop": smtp_reply_snapshot(noop, direct_hostname),
            "mail_before_ehlo": smtp_reply_snapshot(mail_before_ehlo, direct_hostname),
            "ehlo": smtp_reply_snapshot(direct_ehlo, direct_hostname),
            "quit": smtp_reply_snapshot(direct_quit, direct_hostname),
        },
    }


def _read_until_eof(client: RawSmtpClient, *, limit: int = 4096) -> bytes:
    captured = bytearray()
    while True:
        chunk = client.stream.recv_some(min(1024, limit - len(captured)))
        if not chunk:
            return bytes(captured)
        captured.extend(chunk)
        _check(len(captured) < limit, "malformed TLS response exceeded receive budget")


def _capture_malformed_handshake(target: RuntimeTarget) -> dict[str, Any]:
    client, hostname = open_smtp_client(target)
    try:
        ehlo = smtp_ehlo(client, hostname, advertise_starttls=True)
        ready = client.command(b"STARTTLS")
        _check(ready == _READY_FOR_TLS, ready)
        client.stream.sendall(b"not a tls client\r\n")
        trailing = _read_until_eof(client)
        _check(trailing == b"", trailing)
    finally:
        client.close()

    recovery_client, recovery_hostname = open_smtp_client(target)
    with recovery_client:
        recovery_ehlo_before = smtp_ehlo(
            recovery_client,
            recovery_hostname,
            advertise_starttls=True,
        )
        recovery_ready = recovery_client.start_tls(
            _client_context(target),
            server_hostname=_SERVER_NAME,
        )
        recovery_ehlo_after = smtp_ehlo(recovery_client, recovery_hostname)
        recovery_quit = recovery_client.quit()

    return {
        "malformed": {
            "greeting": smtp_greeting_snapshot(),
            "ehlo": smtp_reply_snapshot(ehlo, hostname),
            "starttls": smtp_reply_snapshot(ready, hostname),
            "post_input_bytes": bytes_snapshot(trailing),
            "connection_closed": True,
        },
        "recovery": {
            "greeting": smtp_greeting_snapshot(),
            "ehlo_before_tls": smtp_reply_snapshot(recovery_ehlo_before, recovery_hostname),
            "starttls": smtp_reply_snapshot(recovery_ready, recovery_hostname),
            "ehlo_after_tls": smtp_reply_snapshot(recovery_ehlo_after, recovery_hostname),
            "quit": smtp_reply_snapshot(recovery_quit, recovery_hostname),
        },
    }


def _capture_plaintext_smuggling_evidence(target: RuntimeTarget) -> dict[str, Any]:
    client, hostname = open_smtp_client(target)
    with client:
        ehlo_before = smtp_ehlo(client, hostname, advertise_starttls=True)
        client.stream.sendall(b"STARTTLS\r\nNOOP\r\n")
        ready = read_smtp_reply(client.stream)
        _check(ready == _READY_FOR_TLS, ready)
        _check(not client.stream.buffer, client.stream.buffer)
        client.stream.sock.settimeout(client.stream._remaining())
        client.stream.sock = _client_context(target).wrap_socket(
            client.stream.sock,
            server_hostname=_SERVER_NAME,
        )
        negotiated = _tls_snapshot(_tls_socket(client))
        unsolicited = client.stream.read_line()
        _check(unsolicited == b"250 OK\r\n", unsolicited)
        mail_before_ehlo = client.command(b"MAIL FROM:<>")
        _check(mail_before_ehlo == _BAD_SEQUENCE, mail_before_ehlo)
        ehlo_after = smtp_ehlo(client, hostname)
        quit_reply = client.quit()

    return {
        "difference_id": "starttls-buffered-plaintext-command",
        "sent_plaintext": bytes_snapshot(b"STARTTLS\r\nNOOP\r\n"),
        "wire": {
            "greeting": smtp_greeting_snapshot(),
            "ehlo_before_tls": smtp_reply_snapshot(ehlo_before, hostname),
            "starttls": smtp_reply_snapshot(ready, hostname),
            "negotiated": negotiated,
            "unsolicited_post_handshake_reply": unsolicited.decode("ascii"),
            "mail_before_ehlo": smtp_reply_snapshot(mail_before_ehlo, hostname),
            "ehlo_after_tls": smtp_reply_snapshot(ehlo_after, hostname),
            "quit": smtp_reply_snapshot(quit_reply, hostname),
        },
        "oracle_executed_buffered_plaintext_command": True,
    }


_SMTP_NORMALIZERS = (
    "smtp:greeting-skibidi-grammar",
    "smtp:server-hostname",
    "smtp:session-id",
)
_TLS_NORMALIZERS = ("tls:ephemeral-certificate-key-and-serial",)

STARTTLS_SCENARIOS = (
    Scenario(
        "smtp/starttls/data-storage",
        _capture_starttls_delivery,
        _SMTP_NORMALIZERS
        + _TLS_NORMALIZERS
        + (
            "maildir:generated-filename",
            "maildir:server-hostname",
            "maildir:received-id",
            "maildir:received-at",
            "postgres:identity-timestamps-and-hostname-derived-size",
            "smtp:data-dot-unstuff",
        ),
        {
            "protocol": "smtp",
            "operation": "inbound-starttls-delivery",
            "server_name": _SERVER_NAME,
            "message_id": _TLS_MESSAGE_ID,
            "message_sha256": hashlib.sha256(_TLS_MESSAGE).hexdigest(),
            "certificate": "ephemeral-rsa-2048-pkcs12",
            "side_effects": ["maildir", "postgres:email_index", "redis:mail-count"],
            "delivery_cardinality": "exactly-once",
            "storage_visibility": "joint-15-second-absolute-deadline",
        },
    ),
    Scenario(
        "smtp/starttls/protocol-policy",
        _capture_protocol_policy,
        _SMTP_NORMALIZERS,
        {
            "protocol": "smtp",
            "operation": "starttls-version-and-cipher-policy",
            "accepted_versions": ["TLSv1.2", "TLSv1.3"],
            "rejected_versions": ["TLSv1.1"],
        },
    ),
    Scenario(
        "smtp/starttls/state-machine",
        _capture_state_machine,
        _SMTP_NORMALIZERS,
        {
            "protocol": "smtp",
            "operation": "starttls-state-machine",
            "states": ["CONNECT", "HELO", "MAIL", "TLS-CONNECT"],
            "post_tls_ehlo_required_for_mail": True,
        },
    ),
    Scenario(
        "smtp/starttls/malformed-handshake-recovery",
        _capture_malformed_handshake,
        _SMTP_NORMALIZERS,
        {
            "protocol": "smtp",
            "operation": "starttls-malformed-handshake",
            "malformed_input_sha256": hashlib.sha256(b"not a tls client\r\n").hexdigest(),
            "failure_action": "close-connection",
            "server_recovery": "new-starttls-session-succeeds",
        },
    ),
)

STARTTLS_ORACLE_EVIDENCE_SCENARIOS = (
    Scenario(
        "smtp/starttls/plaintext-command-smuggling",
        _capture_plaintext_smuggling_evidence,
        _SMTP_NORMALIZERS,
        {
            "protocol": "smtp",
            "operation": "starttls-buffered-plaintext-evidence",
            "difference_id": "starttls-buffered-plaintext-command",
            "payload_sha256": hashlib.sha256(b"STARTTLS\r\nNOOP\r\n").hexdigest(),
            "candidate_requirement": "close-without-executing-buffered-plaintext",
        },
    ),
)
