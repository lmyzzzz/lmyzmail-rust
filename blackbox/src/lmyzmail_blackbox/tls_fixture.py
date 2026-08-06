from __future__ import annotations

import ipaddress
import os
import secrets
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .errors import HarnessError

_CERTIFICATE_NAME = "smtp.example.test"
_CERTIFICATE_ORGANIZATION = "lmyzmail blackbox"
_NOT_VALID_BEFORE = datetime(2020, 1, 1, tzinfo=UTC)
_NOT_VALID_AFTER = datetime(2040, 1, 1, tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class EphemeralTlsMaterial:
    keystore_path: Path
    keystore_password: str
    certificate_pem: bytes


def create_server_ssl_context(material: EphemeralTlsMaterial) -> ssl.SSLContext:
    """Load the ephemeral PKCS#12 identity without leaving PEM key material behind."""
    keystore = material.keystore_path
    if keystore.is_symlink() or not keystore.is_file():
        raise HarnessError(f"TLS keystore must be a real file: {keystore}")

    private_key, certificate, additional = pkcs12.load_key_and_certificates(
        keystore.read_bytes(),
        material.keystore_password.encode("ascii"),
    )
    if private_key is None or certificate is None:
        raise HarnessError("TLS keystore does not contain a private key and certificate")

    suffix = secrets.token_hex(16)
    certificate_path = keystore.parent / f".server-certificate-{suffix}.pem"
    private_key_path = keystore.parent / f".server-private-key-{suffix}.pem"
    certificate_bytes = certificate.public_bytes(serialization.Encoding.PEM)
    certificate_bytes += b"".join(
        value.public_bytes(serialization.Encoding.PEM) for value in additional
    )
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    try:
        _write_private_file(certificate_path, certificate_bytes)
        _write_private_file(private_key_path, private_key_bytes)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certificate_path, private_key_path)
        return context
    finally:
        certificate_path.unlink(missing_ok=True)
        private_key_path.unlink(missing_ok=True)


def _write_private_file(path: Path, value: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        path.chmod(0o600)
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        path.unlink(missing_ok=True)
        raise


def provision_ephemeral_tls_material(workspace: Path) -> EphemeralTlsMaterial:
    if workspace.is_symlink() or not workspace.is_dir():
        raise HarnessError(f"TLS workspace must be a real directory: {workspace}")

    tls_directory = workspace / "tls"
    try:
        tls_directory.mkdir(mode=0o700)
    except FileExistsError as error:
        raise HarnessError(f"TLS workspace already contains material: {tls_directory}") from error
    tls_directory.chmod(0o700)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        (
            x509.NameAttribute(NameOID.COMMON_NAME, _CERTIFICATE_NAME),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, _CERTIFICATE_ORGANIZATION),
        )
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOT_VALID_BEFORE)
        .not_valid_after(_NOT_VALID_AFTER)
        .add_extension(
            x509.SubjectAlternativeName(
                (
                    x509.DNSName(_CERTIFICATE_NAME),
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                )
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage((ExtendedKeyUsageOID.SERVER_AUTH,)),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    password = secrets.token_urlsafe(32)
    pkcs12_bytes = pkcs12.serialize_key_and_certificates(
        name=b"lmyzmail-blackbox",
        key=private_key,
        cert=certificate,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode("ascii")),
    )
    keystore_path = tls_directory / "smtp-server.p12"
    try:
        _write_private_file(keystore_path, pkcs12_bytes)
    except BaseException:
        tls_directory.rmdir()
        raise

    return EphemeralTlsMaterial(
        keystore_path=keystore_path,
        keystore_password=password,
        certificate_pem=certificate.public_bytes(serialization.Encoding.PEM),
    )
