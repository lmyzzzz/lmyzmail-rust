from __future__ import annotations

import ipaddress
import os
import secrets
import ssl
import subprocess
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


@dataclass(frozen=True, slots=True)
class EphemeralOutboundTlsMaterial:
    matching_server: EphemeralTlsMaterial
    mismatched_server: EphemeralTlsMaterial
    untrusted_server: EphemeralTlsMaterial
    java_truststore_path: Path
    java_truststore_password: str
    ca_certificate_path: Path
    ca_certificate_pem: bytes


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


def provision_ephemeral_outbound_tls_material(
    workspace: Path,
    *,
    mx_hostname: str,
    mismatched_hostname: str = "mismatch.fixture.test",
) -> EphemeralOutboundTlsMaterial:
    if workspace.is_symlink() or not workspace.is_dir():
        raise HarnessError(f"TLS workspace must be a real directory: {workspace}")
    _validate_dns_name(mx_hostname)
    _validate_dns_name(mismatched_hostname)
    if mx_hostname.casefold() == mismatched_hostname.casefold():
        raise HarnessError("outbound TLS mismatch hostname must differ from the MX hostname")

    tls_directory = workspace / "outbound-tls"
    try:
        tls_directory.mkdir(mode=0o700)
    except FileExistsError as error:
        raise HarnessError(f"TLS workspace already contains material: {tls_directory}") from error
    tls_directory.chmod(0o700)

    trusted_ca_key, trusted_ca = _create_certificate_authority("lmyzmail blackbox outbound root")
    untrusted_ca_key, untrusted_ca = _create_certificate_authority(
        "lmyzmail blackbox untrusted root"
    )
    matching_server = _provision_signed_server_identity(
        tls_directory,
        filename="matching-server.p12",
        hostname=mx_hostname,
        issuer_key=trusted_ca_key,
        issuer_certificate=trusted_ca,
    )
    mismatched_server = _provision_signed_server_identity(
        tls_directory,
        filename="mismatched-server.p12",
        hostname=mismatched_hostname,
        issuer_key=trusted_ca_key,
        issuer_certificate=trusted_ca,
    )
    untrusted_server = _provision_signed_server_identity(
        tls_directory,
        filename="untrusted-server.p12",
        hostname=mx_hostname,
        issuer_key=untrusted_ca_key,
        issuer_certificate=untrusted_ca,
    )

    truststore_password = secrets.token_urlsafe(32)
    truststore_path = tls_directory / "java-truststore.p12"
    ca_certificate_path = tls_directory / "outbound-root-ca.pem"
    try:
        ca_certificate_pem = trusted_ca.public_bytes(serialization.Encoding.PEM)
        _write_private_file(ca_certificate_path, ca_certificate_pem)
        _create_java_truststore(
            ca_certificate_path,
            truststore_path,
            truststore_password,
        )
    except BaseException:
        for path in tls_directory.iterdir():
            path.unlink(missing_ok=True)
        tls_directory.rmdir()
        raise

    return EphemeralOutboundTlsMaterial(
        matching_server=matching_server,
        mismatched_server=mismatched_server,
        untrusted_server=untrusted_server,
        java_truststore_path=truststore_path,
        java_truststore_password=truststore_password,
        ca_certificate_path=ca_certificate_path,
        ca_certificate_pem=ca_certificate_pem,
    )


def _create_java_truststore(
    certificate_path: Path,
    truststore_path: Path,
    password: str,
) -> None:
    keytool = os.environ.get("LMYZMAIL_BLACKBOX_KEYTOOL")
    if keytool is None:
        repository = Path(__file__).resolve().parents[3]
        keytool = str(repository / ".blackbox/runtime/jdk22/bin/keytool")
    keytool_path = Path(keytool)
    if not keytool_path.is_absolute() or not keytool_path.is_file():
        raise HarnessError(f"pinned keytool is unavailable: {keytool_path}")
    completed = subprocess.run(  # noqa: S603
        (
            str(keytool_path),
            "-importcert",
            "-noprompt",
            "-alias",
            "lmyzmail-blackbox-outbound-root",
            "-file",
            str(certificate_path),
            "-keystore",
            str(truststore_path),
            "-storetype",
            "PKCS12",
            "-storepass",
            password,
        ),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=30.0,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace")[-4096:]
        raise HarnessError(f"pinned keytool could not create the truststore: {detail}")
    if truststore_path.is_symlink() or not truststore_path.is_file():
        raise HarnessError("pinned keytool did not create a real truststore file")
    truststore_path.chmod(0o600)


def _validate_dns_name(value: str) -> None:
    try:
        encoded = value.encode("ascii", errors="strict")
    except UnicodeEncodeError as error:
        raise HarnessError("outbound TLS hostname must be ASCII") from error
    if (
        not encoded
        or len(encoded) > 253
        or value.startswith(".")
        or value.endswith(".")
        or any(not label or len(label) > 63 for label in value.split("."))
        or any(
            not (character.isascii() and (character.isalnum() or character == "-"))
            for character in value
            if character != "."
        )
        or any(label.startswith("-") or label.endswith("-") for label in value.split("."))
    ):
        raise HarnessError(f"invalid outbound TLS hostname: {value!r}")


def _create_certificate_authority(
    common_name: str,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        (
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
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
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )
    return private_key, certificate


def _provision_signed_server_identity(
    directory: Path,
    *,
    filename: str,
    hostname: str,
    issuer_key: rsa.RSAPrivateKey,
    issuer_certificate: x509.Certificate,
) -> EphemeralTlsMaterial:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        (
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, _CERTIFICATE_ORGANIZATION),
        )
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_certificate.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOT_VALID_BEFORE)
        .not_valid_after(_NOT_VALID_AFTER)
        .add_extension(
            x509.SubjectAlternativeName((x509.DNSName(hostname),)),
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
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
        .sign(issuer_key, hashes.SHA256())
    )
    password = secrets.token_urlsafe(32)
    keystore_bytes = pkcs12.serialize_key_and_certificates(
        name=b"lmyzmail-blackbox-outbound-server",
        key=private_key,
        cert=certificate,
        cas=(issuer_certificate,),
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode("ascii")),
    )
    keystore_path = directory / filename
    _write_private_file(keystore_path, keystore_bytes)
    return EphemeralTlsMaterial(
        keystore_path=keystore_path,
        keystore_password=password,
        certificate_pem=certificate.public_bytes(serialization.Encoding.PEM),
    )
