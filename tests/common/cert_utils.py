"""
Certificate generation utilities for TLS testing.

This module provides Python-native certificate generation using the cryptography
library, replacing shell-based openssl commands for better control and reliability.

Can be used for any TLS-based service testing: gNOI, gNMI, REST API, etc.
"""
import os
import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, List

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class TlsCertificateGenerator:
    """
    Generate TLS certificates for testing.

    This class generates a complete certificate chain (CA, server, client) with
    configurable validity periods and Subject Alternative Names. By default,
    certificates are backdated by 1 day to handle clock skew between test hosts.

    Can be used for any TLS-based service: gNOI, gNMI, REST API, etc.

    Attributes:
        server_ip: IP address to include in server certificate SAN
        validity_days: Number of days certificates are valid (default: 825)
        backdate_days: Days to backdate not_valid_before (default: 1)

    Example:
        generator = TlsCertificateGenerator(server_ip="10.0.0.1")
        generator.write_all("/tmp/certs")
        # Creates: ca.crt, ca.key, server.crt, server.key, client.crt, client.key
    """

    # Default certificate file names
    DEFAULT_CA_CERT = "ca.crt"
    DEFAULT_CA_KEY = "ca.key"
    DEFAULT_SERVER_CERT = "server.crt"
    DEFAULT_SERVER_KEY = "server.key"
    DEFAULT_CLIENT_CERT = "client.crt"
    DEFAULT_CLIENT_KEY = "client.key"

    # Default certificate subjects
    DEFAULT_CA_CN = "test.ca.sonic"
    DEFAULT_SERVER_CN = "test.server.sonic"
    DEFAULT_CLIENT_CN = "test.client.sonic"

    def __init__(
        self,
        server_ip: str,
        validity_days: int = 825,
        backdate_days: int = 1,
        dns_names: Optional[List[str]] = None,
        key_size: int = 2048,
        ca_cn: Optional[str] = None,
        server_cn: Optional[str] = None,
        client_cn: Optional[str] = None,
        ca_cert_name: Optional[str] = None,
        ca_key_name: Optional[str] = None,
        server_cert_name: Optional[str] = None,
        server_key_name: Optional[str] = None,
        client_cert_name: Optional[str] = None,
        client_key_name: Optional[str] = None,
    ):
        """
        Initialize the certificate generator.

        Args:
            server_ip: IP address to include in server certificate SAN
            validity_days: Certificate validity period in days
            backdate_days: Days to backdate not_valid_before to handle clock skew
            dns_names: List of DNS names to include in server certificate SAN
            key_size: RSA key size in bits
            ca_cn: Common Name for CA certificate
            server_cn: Common Name for server certificate
            client_cn: Common Name for client certificate
            ca_cert_name: Filename for CA certificate
            ca_key_name: Filename for CA private key
            server_cert_name: Filename for server certificate
            server_key_name: Filename for server private key
            client_cert_name: Filename for client certificate
            client_key_name: Filename for client private key
        """
        self.server_ip = server_ip
        self.validity_days = validity_days
        self.backdate_days = backdate_days
        self.dns_names = dns_names or ["localhost"]
        self.key_size = key_size

        # Certificate subject names (configurable)
        self.ca_cn = ca_cn or self.DEFAULT_CA_CN
        self.server_cn = server_cn or self.DEFAULT_SERVER_CN
        self.client_cn = client_cn or self.DEFAULT_CLIENT_CN

        # Certificate file names (configurable)
        self.ca_cert_name = ca_cert_name or self.DEFAULT_CA_CERT
        self.ca_key_name = ca_key_name or self.DEFAULT_CA_KEY
        self.server_cert_name = server_cert_name or self.DEFAULT_SERVER_CERT
        self.server_key_name = server_key_name or self.DEFAULT_SERVER_KEY
        self.client_cert_name = client_cert_name or self.DEFAULT_CLIENT_CERT
        self.client_key_name = client_key_name or self.DEFAULT_CLIENT_KEY

        # Generated keys and certificates (populated by generate_all)
        self._ca_key: Optional[rsa.RSAPrivateKey] = None
        self._ca_cert: Optional[x509.Certificate] = None
        self._server_key: Optional[rsa.RSAPrivateKey] = None
        self._server_cert: Optional[x509.Certificate] = None
        self._client_key: Optional[rsa.RSAPrivateKey] = None
        self._client_cert: Optional[x509.Certificate] = None

    def _generate_key(self) -> rsa.RSAPrivateKey:
        """Generate an RSA private key."""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
        )

    def _get_validity_period(self) -> Tuple[datetime, datetime]:
        """Get certificate validity period with backdating for clock skew tolerance."""
        now = datetime.now(timezone.utc)
        not_valid_before = now - timedelta(days=self.backdate_days)
        not_valid_after = now + timedelta(days=self.validity_days)
        return not_valid_before, not_valid_after

    def _generate_ca(self) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
        """Generate CA certificate and key."""
        key = self._generate_key()
        not_valid_before, not_valid_after = self._get_validity_period()

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.ca_cn),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_valid_before)
            .not_valid_after(not_valid_after)
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )

        return key, cert

    def _generate_server(
        self, ca_key: rsa.RSAPrivateKey, ca_cert: x509.Certificate
    ) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
        """Generate server certificate signed by CA."""
        key = self._generate_key()
        not_valid_before, not_valid_after = self._get_validity_period()

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.server_cn),
        ])

        # Build SAN with DNS names and server IP address
        san_entries = [x509.DNSName(name) for name in self.dns_names]
        san_entries.append(x509.IPAddress(ipaddress.ip_address(self.server_ip)))

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_valid_before)
            .not_valid_after(not_valid_after)
            .add_extension(
                x509.SubjectAlternativeName(san_entries),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        return key, cert

    def _generate_client(
        self, ca_key: rsa.RSAPrivateKey, ca_cert: x509.Certificate
    ) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
        """Generate client certificate signed by CA."""
        key = self._generate_key()
        not_valid_before, not_valid_after = self._get_validity_period()

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.client_cn),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_valid_before)
            .not_valid_after(not_valid_after)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        return key, cert

    def generate_all(self) -> None:
        """Generate complete certificate chain (CA, server, client)."""
        self._ca_key, self._ca_cert = self._generate_ca()
        self._server_key, self._server_cert = self._generate_server(
            self._ca_key, self._ca_cert
        )
        self._client_key, self._client_cert = self._generate_client(
            self._ca_key, self._ca_cert
        )

    def _serialize_cert(self, cert: x509.Certificate) -> bytes:
        """Serialize certificate to PEM format."""
        return cert.public_bytes(serialization.Encoding.PEM)

    def _serialize_key(self, key: rsa.RSAPrivateKey) -> bytes:
        """Serialize private key to PEM format (unencrypted)."""
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def write_all(self, output_dir: str) -> None:
        """
        Generate and write all certificates to the specified directory.

        Args:
            output_dir: Directory to write certificate files

        Creates files based on configured names (defaults shown):
            - ca.crt, ca.key (CA certificate and key)
            - server.crt, server.key (Server certificate and key)
            - client.crt, client.key (Client certificate and key)
        """
        os.makedirs(output_dir, exist_ok=True)

        # Generate all certificates
        self.generate_all()

        # Write CA files
        with open(os.path.join(output_dir, self.ca_cert_name), "wb") as f:
            f.write(self._serialize_cert(self._ca_cert))
        with open(os.path.join(output_dir, self.ca_key_name), "wb") as f:
            f.write(self._serialize_key(self._ca_key))

        # Write server files
        with open(os.path.join(output_dir, self.server_cert_name), "wb") as f:
            f.write(self._serialize_cert(self._server_cert))
        with open(os.path.join(output_dir, self.server_key_name), "wb") as f:
            f.write(self._serialize_key(self._server_key))

        # Write client files
        with open(os.path.join(output_dir, self.client_cert_name), "wb") as f:
            f.write(self._serialize_cert(self._client_cert))
        with open(os.path.join(output_dir, self.client_key_name), "wb") as f:
            f.write(self._serialize_key(self._client_key))

    def get_client_cn(self) -> str:
        """Return the client certificate Common Name (e.g., for GNMI_CLIENT_CERT config)."""
        return self.client_cn

    def get_cert_bytes(self) -> dict:
        """
        Get all certificates and keys as bytes (for in-memory usage).

        Returns:
            Dict with keys: ca_cert, ca_key, server_cert, server_key,
                           client_cert, client_key
        """
        if self._ca_cert is None:
            self.generate_all()

        return {
            "ca_cert": self._serialize_cert(self._ca_cert),
            "ca_key": self._serialize_key(self._ca_key),
            "server_cert": self._serialize_cert(self._server_cert),
            "server_key": self._serialize_key(self._server_key),
            "client_cert": self._serialize_cert(self._client_cert),
            "client_key": self._serialize_key(self._client_key),
        }


def create_gnmi_cert_generator(server_ip: str, **kwargs) -> TlsCertificateGenerator:
    """
    Factory function to create a certificate generator with gNMI/gNOI naming conventions.

    This preserves backward compatibility with existing file naming (gnmiCA.cer,
    gnmiserver.cer, etc.) while using the generic TlsCertificateGenerator.

    Args:
        server_ip: IP address of the server (DUT) to include in server cert SAN
        **kwargs: Additional arguments passed to TlsCertificateGenerator

    Returns:
        TlsCertificateGenerator configured with gNMI naming conventions

    Example:
        generator = create_gnmi_cert_generator(server_ip="10.0.0.1")
        generator.write_all("/tmp/gnoi_certs")
        # Creates: gnmiCA.cer, gnmiCA.key, gnmiserver.cer, gnmiserver.key,
        #          gnmiclient.cer, gnmiclient.key
    """
    gnmi_defaults = {
        "ca_cn": "test.gnmi.sonic",
        "server_cn": "test.server.gnmi.sonic",
        "client_cn": "test.client.gnmi.sonic",
        "ca_cert_name": "gnmiCA.cer",
        "ca_key_name": "gnmiCA.key",
        "server_cert_name": "gnmiserver.cer",
        "server_key_name": "gnmiserver.key",
        "client_cert_name": "gnmiclient.cer",
        "client_key_name": "gnmiclient.key",
        "dns_names": ["hostname.com"],
    }

    # User-provided kwargs override defaults
    gnmi_defaults.update(kwargs)

    return TlsCertificateGenerator(server_ip=server_ip, **gnmi_defaults)
