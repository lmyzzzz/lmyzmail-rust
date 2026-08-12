from __future__ import annotations

import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from lmyzmail_blackbox.errors import HarnessError
from lmyzmail_blackbox.tls_fixture import (
    create_server_ssl_context,
    provision_ephemeral_outbound_tls_material,
    provision_ephemeral_tls_material,
)


def test_ephemeral_pkcs12_is_private_and_has_expected_certificate(tmp_path: Path) -> None:
    material = provision_ephemeral_tls_material(tmp_path)

    assert stat.S_IMODE(material.keystore_path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(material.keystore_path.stat().st_mode) == 0o600
    assert tuple(material.keystore_path.parent.iterdir()) == (material.keystore_path,)

    private_key, certificate, additional = pkcs12.load_key_and_certificates(
        material.keystore_path.read_bytes(),
        material.keystore_password.encode("ascii"),
    )
    assert isinstance(private_key, rsa.RSAPrivateKey)
    assert private_key.key_size == 2048
    assert certificate is not None
    assert additional == []
    assert certificate.subject == certificate.issuer
    assert certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == (
        "smtp.example.test"
    )
    assert certificate.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value == (
        "lmyzmail blackbox"
    )
    names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert names.get_values_for_type(x509.DNSName) == ["smtp.example.test", "localhost"]
    assert [str(value) for value in names.get_values_for_type(x509.IPAddress)] == ["127.0.0.1"]
    assert certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    assert certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value == (
        x509.ExtendedKeyUsage((ExtendedKeyUsageOID.SERVER_AUTH,))
    )
    assert x509.load_pem_x509_certificate(material.certificate_pem) == certificate

    with pytest.raises(ValueError, match="Invalid password or PKCS12 data"):
        pkcs12.load_key_and_certificates(material.keystore_path.read_bytes(), b"wrong-password")


def test_ephemeral_pkcs12_rejects_reuse_and_symlink_workspace(tmp_path: Path) -> None:
    provision_ephemeral_tls_material(tmp_path)
    with pytest.raises(HarnessError, match="already contains material"):
        provision_ephemeral_tls_material(tmp_path)

    real_workspace = tmp_path / "real-workspace"
    real_workspace.mkdir()
    linked_workspace = tmp_path / "linked-workspace"
    linked_workspace.symlink_to(real_workspace, target_is_directory=True)
    with pytest.raises(HarnessError, match="real directory"):
        provision_ephemeral_tls_material(linked_workspace)


def test_server_context_loads_pkcs12_without_leaving_pem_keys(tmp_path: Path) -> None:
    material = provision_ephemeral_tls_material(tmp_path)
    context = create_server_ssl_context(material)

    assert context.minimum_version.name == "TLSv1_2"
    assert tuple(material.keystore_path.parent.iterdir()) == (material.keystore_path,)


def test_outbound_tls_material_separates_identity_hostname_and_trust(tmp_path: Path) -> None:
    material = provision_ephemeral_outbound_tls_material(
        tmp_path,
        mx_hostname="mx.outbound.fixture.test",
    )

    assert stat.S_IMODE(material.java_truststore_path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(material.java_truststore_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(material.ca_certificate_path.stat().st_mode) == 0o600
    assert material.java_truststore_path.parent == material.ca_certificate_path.parent

    trusted_ca = x509.load_pem_x509_certificate(material.ca_certificate_pem)
    assert trusted_ca.extensions.get_extension_for_class(x509.BasicConstraints).value == (
        x509.BasicConstraints(ca=True, path_length=0)
    )
    assert material.java_truststore_path.read_bytes().startswith(b"0")

    identities = (
        (material.matching_server, "mx.outbound.fixture.test", trusted_ca),
        (material.mismatched_server, "mismatch.fixture.test", trusted_ca),
    )
    for identity, hostname, issuer in identities:
        private_key, certificate, chain = pkcs12.load_key_and_certificates(
            identity.keystore_path.read_bytes(),
            identity.keystore_password.encode("ascii"),
        )
        assert isinstance(private_key, rsa.RSAPrivateKey)
        assert certificate is not None
        assert certificate.issuer == issuer.subject
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        assert names.get_values_for_type(x509.DNSName) == [hostname]
        assert chain == [issuer]

    _, untrusted_certificate, untrusted_chain = pkcs12.load_key_and_certificates(
        material.untrusted_server.keystore_path.read_bytes(),
        material.untrusted_server.keystore_password.encode("ascii"),
    )
    assert untrusted_certificate is not None
    assert untrusted_chain is not None and len(untrusted_chain) == 1
    assert untrusted_chain[0] != trusted_ca
    assert untrusted_certificate.issuer == untrusted_chain[0].subject

    expected_validity = {
        material.expired_server: (
            datetime(2020, 2, 1, tzinfo=UTC),
            datetime(2021, 2, 1, tzinfo=UTC),
        ),
        material.future_server: (
            datetime(2035, 2, 1, tzinfo=UTC),
            datetime(2039, 2, 1, tzinfo=UTC),
        ),
    }
    for identity, (not_before, not_after) in expected_validity.items():
        _, certificate, chain = pkcs12.load_key_and_certificates(
            identity.keystore_path.read_bytes(),
            identity.keystore_password.encode("ascii"),
        )
        assert certificate is not None
        assert certificate.not_valid_before_utc == not_before
        assert certificate.not_valid_after_utc == not_after
        assert chain == [trusted_ca]


def test_outbound_tls_material_rejects_reuse_and_invalid_names(tmp_path: Path) -> None:
    provision_ephemeral_outbound_tls_material(tmp_path, mx_hostname="mx.fixture.test")
    with pytest.raises(HarnessError, match="already contains material"):
        provision_ephemeral_outbound_tls_material(tmp_path, mx_hostname="mx.fixture.test")

    for hostname in ("", ".fixture.test", "fixture.test.", "bad_name.fixture.test"):
        workspace = tmp_path / f"invalid-{len(list(tmp_path.iterdir()))}"
        workspace.mkdir()
        with pytest.raises(HarnessError, match="invalid outbound TLS hostname"):
            provision_ephemeral_outbound_tls_material(workspace, mx_hostname=hostname)
