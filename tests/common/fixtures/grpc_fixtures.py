"""
Pytest fixtures for gRPC clients (gNOI, gNMI, etc.)

This module provides coupled pytest fixtures that bundle server configuration
with matched clients, preventing misuse from decoupled server/client setup.

Primary fixtures:
    gnmi_tls:       Module-scoped fixture that sets up TLS and yields GnmiFixture
    gnmi_plaintext: Module-scoped fixture for plaintext mode, yields GnmiFixture

Deprecated fixtures (kept for backward compatibility):
    setup_gnoi_tls_server: Thin wrapper around gnmi_tls, yields None
    ptf_grpc:              Auto-configured gRPC client via GNMIEnvironment
    ptf_gnoi:              gNOI wrapper around ptf_grpc
"""
import os
import pytest
import logging
from dataclasses import dataclass
from typing import Optional
from tests.common.grpc_config import grpc_config

logger = logging.getLogger(__name__)


@dataclass
class CertPaths:
    """PTF-side TLS certificate paths."""
    ca_cert: str
    client_cert: str
    client_key: str


@dataclass
class GnmiFixture:
    """Coupled server config + matched clients for gNMI/gNOI testing."""
    host: str
    port: int
    tls: bool
    cert_paths: Optional[CertPaths]
    grpc: "PtfGrpc"    # correctly configured client
    gnoi: "PtfGnoi"    # convenience wrapper


@pytest.fixture(scope="module")
def gnmi_tls(duthost, ptfhost):
    """
    Set up TLS-secured gNMI/gNOI environment and yield a coupled GnmiFixture.

    This fixture:
    1. Creates a configuration checkpoint for rollback
    2. Generates TLS certificates (backdated for clock skew)
    3. Distributes certificates to DUT and PTF
    4. Configures CONFIG_DB for TLS mode (port 50052)
    5. Restarts the gNMI server process
    6. Verifies TLS connectivity
    7. Constructs PtfGrpc/PtfGnoi with the exact config it just set up
    8. Yields GnmiFixture with everything bundled
    9. Rolls back CONFIG_DB and cleans up certs on teardown

    Usage:
        def test_system_time(gnmi_tls):
            result = gnmi_tls.gnoi.system_time()
            assert isinstance(result["time"], int)
            assert gnmi_tls.port == 50052
    """
    from tests.common.gu_utils import create_checkpoint, rollback
    from tests.common.ptf_grpc import PtfGrpc
    from tests.common.ptf_gnoi import PtfGnoi

    checkpoint_name = "gnoi_tls_setup"
    cert_dir = "/tmp/gnoi_certs"

    logger.info("Setting up gNOI TLS server environment")

    create_checkpoint(duthost, checkpoint_name)

    try:
        _create_gnoi_certs(duthost, ptfhost, cert_dir)
        _configure_gnoi_tls_server(duthost)
        _restart_gnoi_server(duthost)
        _verify_gnoi_tls_connectivity(duthost, ptfhost)

        # Build coupled client with the exact config we just set up
        host = duthost.mgmt_ip
        port = grpc_config.DEFAULT_TLS_PORT
        target = f"{host}:{port}"

        ptf_cert_paths = grpc_config.get_ptf_cert_paths()
        cert_paths = CertPaths(
            ca_cert=ptf_cert_paths['ca_cert'],
            client_cert=ptf_cert_paths['client_cert'],
            client_key=ptf_cert_paths['client_key'],
        )

        client = PtfGrpc(ptfhost, target, plaintext=False)
        client.configure_tls_certificates(
            ca_cert=cert_paths.ca_cert,
            client_cert=cert_paths.client_cert,
            client_key=cert_paths.client_key,
        )
        gnoi_client = PtfGnoi(client)

        fixture = GnmiFixture(
            host=host,
            port=port,
            tls=True,
            cert_paths=cert_paths,
            grpc=client,
            gnoi=gnoi_client,
        )

        logger.info("gNOI TLS server setup completed successfully")
        yield fixture

    finally:
        logger.info("Cleaning up gNOI TLS server environment")
        try:
            rollback(duthost, checkpoint_name)
            logger.info("Configuration rollback completed")
        except Exception as e:
            logger.error(f"Failed to rollback configuration: {e}")

        try:
            _delete_gnoi_certs(cert_dir)
            logger.info("Certificate cleanup completed")
        except Exception as e:
            logger.error(f"Failed to cleanup certificates: {e}")


@pytest.fixture(scope="module")
def gnmi_plaintext(duthost, ptfhost):
    """
    Plaintext gNMI/gNOI fixture — no TLS, no server reconfiguration.

    Reads the existing plaintext port from config and builds a matched client.
    No CONFIG_DB changes are made; assumes the DUT already accepts plaintext
    connections on the default port.

    Usage:
        def test_plaintext(gnmi_plaintext):
            services = gnmi_plaintext.grpc.list_services()
    """
    from tests.common.ptf_grpc import PtfGrpc
    from tests.common.ptf_gnoi import PtfGnoi

    host = duthost.mgmt_ip
    port = grpc_config.DEFAULT_PLAINTEXT_PORT
    target = f"{host}:{port}"

    client = PtfGrpc(ptfhost, target, plaintext=True)
    gnoi_client = PtfGnoi(client)

    fixture = GnmiFixture(
        host=host,
        port=port,
        tls=False,
        cert_paths=None,
        grpc=client,
        gnoi=gnoi_client,
    )

    logger.info(f"Created plaintext GnmiFixture: {target}")
    yield fixture


# ---------------------------------------------------------------------------
# Deprecated fixtures — kept for backward compatibility during migration
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def setup_gnoi_tls_server(gnmi_tls):
    """
    Deprecated: use gnmi_tls instead.

    Thin wrapper that depends on gnmi_tls and yields None so that
    unconverted tests using @pytest.mark.usefixtures("setup_gnoi_tls_server")
    continue to work.
    """
    yield


@pytest.fixture
def ptf_grpc(ptfhost, duthost):
    """
    Deprecated: use gnmi_tls.grpc or gnmi_plaintext.grpc instead.

    Auto-configured gRPC client using GNMIEnvironment for discovery.
    """
    from tests.common.helpers.gnmi_utils import GNMIEnvironment
    from tests.common.ptf_grpc import PtfGrpc

    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    client = PtfGrpc(ptfhost, env, duthost=duthost, insecure=True)

    logger.info(f"Created auto-configured gRPC client: {client}")
    return client


@pytest.fixture
def ptf_gnoi(ptf_grpc):
    """
    Deprecated: use gnmi_tls.gnoi or gnmi_plaintext.gnoi instead.

    gNOI-specific client using auto-configured gRPC client.
    """
    from tests.common.ptf_gnoi import PtfGnoi

    gnoi_client = PtfGnoi(ptf_grpc)
    logger.info(f"Created gNOI wrapper: {gnoi_client}")
    return gnoi_client


# ---------------------------------------------------------------------------
# Internal helpers (unchanged)
# ---------------------------------------------------------------------------

def _create_gnoi_certs(duthost, ptfhost, cert_dir):
    """
    Generate and distribute gNOI TLS certificates.

    Certificates are backdated by 1 day to handle clock skew between hosts.
    """
    from tests.common.cert_utils import create_gnmi_cert_generator

    logger.info("Generating gNOI TLS certificates")

    generator = create_gnmi_cert_generator(server_ip=duthost.mgmt_ip)
    generator.write_all(cert_dir)

    logger.info(f"Certificates generated in {cert_dir}")

    copy_destinations = grpc_config.get_cert_copy_destinations()

    duthost.copy(src=f'{cert_dir}/{grpc_config.CA_CERT}', dest=copy_destinations['dut'][grpc_config.CA_CERT])
    duthost.copy(src=f'{cert_dir}/{grpc_config.SERVER_CERT}', dest=copy_destinations['dut'][grpc_config.SERVER_CERT])
    duthost.copy(src=f'{cert_dir}/{grpc_config.SERVER_KEY}', dest=copy_destinations['dut'][grpc_config.SERVER_KEY])

    ptfhost.copy(src=f'{cert_dir}/{grpc_config.CA_CERT}', dest=copy_destinations['ptf'][grpc_config.CA_CERT])
    ptfhost.copy(src=f'{cert_dir}/{grpc_config.CLIENT_CERT}', dest=copy_destinations['ptf'][grpc_config.CLIENT_CERT])
    ptfhost.copy(src=f'{cert_dir}/{grpc_config.CLIENT_KEY}', dest=copy_destinations['ptf'][grpc_config.CLIENT_KEY])

    logger.info("Certificate generation and distribution completed")


def _configure_gnoi_tls_server(duthost):
    """Configure CONFIG_DB for TLS mode."""
    logger.info("Configuring gNOI server for TLS mode")

    duthost.shell('sonic-db-cli CONFIG_DB hset "GNMI|gnmi" port 50052')
    duthost.shell('sonic-db-cli CONFIG_DB hset "GNMI|gnmi" client_auth true')
    duthost.shell('sonic-db-cli CONFIG_DB hset "GNMI|gnmi" log_level 2')

    config_db_settings = grpc_config.get_config_db_cert_settings()
    duthost.shell(f'sonic-db-cli CONFIG_DB hset "GNMI|certs" ca_crt "{config_db_settings["ca_crt"]}"')
    duthost.shell(f'sonic-db-cli CONFIG_DB hset "GNMI|certs" server_crt "{config_db_settings["server_crt"]}"')
    duthost.shell(f'sonic-db-cli CONFIG_DB hset "GNMI|certs" server_key "{config_db_settings["server_key"]}"')

    duthost.shell(
        '''sonic-db-cli CONFIG_DB hset "GNMI_CLIENT_CERT|test.client.gnmi.sonic" "role@" '''
        '''"gnmi_readwrite,gnmi_config_db_readwrite,gnmi_appl_db_readwrite,'''
        '''gnmi_dpu_appl_db_readwrite,gnoi_readwrite"'''
    )

    logger.info("TLS configuration completed")


def _restart_gnoi_server(duthost):
    """Restart gNOI server to pick up new TLS configuration."""
    logger.info("Restarting gNOI server process")

    container_check = duthost.shell(r"docker ps --format \{\{.Names\}\} | grep '^gnmi$'",
                                    module_ignore_errors=True)

    if container_check.get('rc', 1) != 0:
        raise Exception("The 'gnmi' container does not exist.")

    result = duthost.shell("docker exec gnmi supervisorctl restart gnmi-native", module_ignore_errors=True)

    if result['rc'] != 0:
        raise Exception(f"Failed to restart gnmi-native: {result['stderr']}")

    import time
    time.sleep(3)

    status_result = duthost.shell("docker exec gnmi supervisorctl status gnmi-native", module_ignore_errors=True)
    if "RUNNING" not in status_result['stdout']:
        raise Exception(f"gnmi-native failed to start: {status_result['stdout']}")

    logger.info("gNOI server restart completed")


def _verify_gnoi_tls_connectivity(duthost, ptfhost):
    """Verify TLS connectivity to gNOI server."""
    logger.info("Verifying gNOI TLS connectivity")

    cacert_arg, cert_arg, key_arg = grpc_config.get_grpcurl_cert_args()
    test_cmd = f"""grpcurl {cacert_arg} {cert_arg} {key_arg} \
                         {duthost.mgmt_ip}:{grpc_config.DEFAULT_TLS_PORT} list"""

    result = ptfhost.shell(test_cmd, module_ignore_errors=True)

    if result['rc'] != 0:
        raise Exception(f"TLS connectivity test failed: {result['stderr']}")

    if "gnoi.system.System" not in result['stdout']:
        raise Exception(f"gNOI services not found in response: {result['stdout']}")

    time_cmd = f"""grpcurl {cacert_arg} {cert_arg} {key_arg} \
                         {duthost.mgmt_ip}:{grpc_config.DEFAULT_TLS_PORT} gnoi.system.System.Time"""

    result = ptfhost.shell(time_cmd, module_ignore_errors=True)

    if result['rc'] != 0:
        raise Exception(f"gNOI System.Time test failed: {result['stderr']}")

    if "time" not in result['stdout']:
        raise Exception(f"Invalid System.Time response: {result['stdout']}")

    logger.info("TLS connectivity verification completed successfully")


def _delete_gnoi_certs(cert_dir):
    """Clean up generated certificate files."""
    import shutil

    logger.info("Cleaning up certificate files")

    if os.path.exists(cert_dir):
        shutil.rmtree(cert_dir, ignore_errors=True)
