from __future__ import annotations

import stat
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from lmyzmail_blackbox.errors import HarnessError
from lmyzmail_blackbox.tls_fixture import provision_ephemeral_tls_material


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
