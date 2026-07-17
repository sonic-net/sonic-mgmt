"""
Centralized configuration for gRPC client certificate management.

This module provides a centralized configuration for managing certificate paths
and settings for gRPC operations (gNOI, gNMI, etc.) across different host types.
"""
import os
from typing import Dict, Tuple


class GrpcCertificateConfig:
    """
    Centralized configuration for gRPC certificate paths and settings.

    This class provides a single location to manage certificate file names,
    directory paths, and connection settings for different host types (DUT vs PTF).
    """

    # Certificate file names (consistent across all hosts)
    CA_CERT = "gnmiCA.cer"
    SERVER_CERT = "gnmiserver.cer"
    SERVER_KEY = "gnmiserver.key"
    CLIENT_CERT = "gnmiclient.cer"
    CLIENT_KEY = "gnmiclient.key"

    # Host-specific certificate directories
    DUT_CERT_DIR = "/etc/sonic/telemetry"
    PTF_CERT_DIR = "/etc/ssl/certs"

    # Default gRPC connection settings
    DEFAULT_TLS_PORT = 50052
    DEFAULT_PLAINTEXT_PORT = 8080

    @classmethod
    def get_dut_cert_paths(cls) -> Dict[str, str]:
        """
        Get full certificate paths for DUT (server) side.

        Returns:
            Dict containing full paths for server certificates on DUT
        """
        return {
            'ca_cert': os.path.join(cls.DUT_CERT_DIR, cls.CA_CERT),
            'server_cert': os.path.join(cls.DUT_CERT_DIR, cls.SERVER_CERT),
            'server_key': os.path.join(cls.DUT_CERT_DIR, cls.SERVER_KEY)
        }

    @classmethod
    def get_ptf_cert_paths(cls) -> Dict[str, str]:
        """
        Get full certificate paths for PTF (client) side.

        Returns:
            Dict containing full paths for client certificates on PTF
        """
        return {
            'ca_cert': os.path.join(cls.PTF_CERT_DIR, cls.CA_CERT),
            'client_cert': os.path.join(cls.PTF_CERT_DIR, cls.CLIENT_CERT),
            'client_key': os.path.join(cls.PTF_CERT_DIR, cls.CLIENT_KEY)
        }

    @classmethod
    def get_grpcurl_cert_args(cls) -> Tuple[str, str, str]:
        """
        Get grpcurl command-line arguments for TLS certificates.

        Returns:
            Tuple of (cacert_arg, cert_arg, key_arg) for grpcurl command
        """
        paths = cls.get_ptf_cert_paths()
        return (
            f"-cacert {paths['ca_cert']}",
            f"-cert {paths['client_cert']}",
            f"-key {paths['client_key']}"
        )

    @classmethod
    def get_cert_copy_destinations(cls) -> Dict[str, Dict[str, str]]:
        """
        Get certificate copy destinations for both DUT and PTF hosts.

        Returns:
            Dict with 'dut' and 'ptf' keys containing destination paths
        """
        return {
            'dut': {
                cls.CA_CERT: f"{cls.DUT_CERT_DIR}/",
                cls.SERVER_CERT: f"{cls.DUT_CERT_DIR}/",
                cls.SERVER_KEY: f"{cls.DUT_CERT_DIR}/"
            },
            'ptf': {
                cls.CA_CERT: os.path.join(cls.PTF_CERT_DIR, cls.CA_CERT),
                cls.CLIENT_CERT: os.path.join(cls.PTF_CERT_DIR, cls.CLIENT_CERT),
                cls.CLIENT_KEY: os.path.join(cls.PTF_CERT_DIR, cls.CLIENT_KEY)
            }
        }

    @classmethod
    def get_config_db_cert_settings(cls) -> Dict[str, str]:
        """
        Get CONFIG_DB certificate settings for DUT configuration.

        Returns:
            Dict with CONFIG_DB keys and certificate paths
        """
        dut_paths = cls.get_dut_cert_paths()
        return {
            'ca_crt': dut_paths['ca_cert'],
            'server_crt': dut_paths['server_cert'],
            'server_key': dut_paths['server_key']
        }


# Convenience instance for easy importing
grpc_config = GrpcCertificateConfig()
