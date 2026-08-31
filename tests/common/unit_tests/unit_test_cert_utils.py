"""Unit tests for shared TLS certificate generation helpers."""

import importlib.util
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding


MODULE_PATH = Path(__file__).resolve().parents[1] / "cert_utils.py"


def _load_cert_utils():
    spec = importlib.util.spec_from_file_location(
        "unit_target_cert_utils", MODULE_PATH
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generate_revoked_cert_with_same_ca_and_distribution_point(tmp_path):
    crl_url = "http://192.0.2.10:1234/crl"
    cert_utils = _load_cert_utils()
    generator = cert_utils.create_gnmi_cert_generator(server_ip="192.0.2.1")
    generator.write_all(str(tmp_path))

    generator.generate_revoked_cert_with_crl(crl_url, str(tmp_path))

    ca_cert = x509.load_pem_x509_certificate(
        (tmp_path / "gnmiCA.cer").read_bytes()
    )
    revoked_cert = x509.load_pem_x509_certificate(
        (tmp_path / "gnmiclient.revoked.cer").read_bytes()
    )
    revoked_key = serialization.load_pem_private_key(
        (tmp_path / "gnmiclient.revoked.key").read_bytes(),
        password=None,
    )
    crl = x509.load_pem_x509_crl((tmp_path / "sonic.crl.pem").read_bytes())

    ca_cert.public_key().verify(
        revoked_cert.signature,
        revoked_cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        revoked_cert.signature_hash_algorithm,
    )
    ca_cert.public_key().verify(
        crl.signature,
        crl.tbs_certlist_bytes,
        padding.PKCS1v15(),
        crl.signature_hash_algorithm,
    )

    distribution_points = revoked_cert.extensions.get_extension_for_class(
        x509.CRLDistributionPoints
    ).value
    assert distribution_points[0].full_name[0].value == crl_url
    assert revoked_cert.issuer == ca_cert.subject == crl.issuer
    assert (
        revoked_key.public_key().public_numbers()
        == revoked_cert.public_key().public_numbers()
    )
    assert [entry.serial_number for entry in crl] == [revoked_cert.serial_number]
