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
import shutil
import subprocess
import tarfile
import tempfile
import time
import pytest
import logging
from dataclasses import dataclass
from typing import Optional
from tests.common.cert_utils import create_gnmi_cert_generator
from tests.common.grpc_config import grpc_config
from tests.common.gu_utils import create_checkpoint, rollback
from tests.common.helpers.gnmi_utils import GNMIEnvironment
from tests.common.ptf_grpc import PtfGrpc
from tests.common.ptf_gnoi import PtfGnoi
from tests.common.ptf_gnmic import PtfGnmic
from tests.common.dut_grpc import DutGrpc
from tests.common.dut_gnoi import DutGnoi

logger = logging.getLogger(__name__)

GRPCURL_VERSION = "1.9.3"

# Architecture mapping: dpkg --print-architecture → grpcurl release suffix
_GRPCURL_ARCH_MAP = {
    "amd64": "linux_x86_64",
    "arm64": "linux_arm64",
    "armhf": "linux_armv6",
}


def _ensure_grpcurl_on_dut(duthost):
    """
    Ensure grpcurl is available on the DUT host.

    Downloads the correct architecture binary from GitHub releases to the
    local machine (sonic-mgmt container), then copies it to the DUT.
    Idempotent: skips download if grpcurl is already installed on the DUT.

    Args:
        duthost: DUT host instance.

    Raises:
        pytest.skip: If grpcurl cannot be provisioned.
    """
    # Check if already installed
    check = duthost.shell("which grpcurl", module_ignore_errors=True)
    if check["rc"] == 0:
        logger.info("grpcurl already installed on DUT at %s", check["stdout"].strip())
        return

    # Detect DUT architecture
    arch_result = duthost.shell("dpkg --print-architecture", module_ignore_errors=True)
    if arch_result["rc"] != 0:
        pytest.skip("Cannot detect DUT architecture via dpkg")
    dut_arch = arch_result["stdout"].strip()
    grpcurl_arch = _GRPCURL_ARCH_MAP.get(dut_arch)
    if not grpcurl_arch:
        pytest.skip(f"Unsupported DUT architecture for grpcurl: {dut_arch}")

    tarball = f"grpcurl_{GRPCURL_VERSION}_{grpcurl_arch}.tar.gz"
    url = f"https://github.com/fullstorydev/grpcurl/releases/download/v{GRPCURL_VERSION}/{tarball}"

    logger.info("Downloading grpcurl %s for %s from %s", GRPCURL_VERSION, dut_arch, url)

    # Download to local temp dir (sonic-mgmt container has internet)
    local_tmp = tempfile.mkdtemp(prefix="grpcurl_")
    local_tarball = os.path.join(local_tmp, tarball)
    local_binary = os.path.join(local_tmp, "grpcurl")

    try:
        subprocess.check_call(["curl", "-fsSL", "-o", local_tarball, url], timeout=120)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        shutil.rmtree(local_tmp, ignore_errors=True)
        pytest.skip(f"Failed to download grpcurl: {e}")

    # Extract binary from tarball
    try:
        with tarfile.open(local_tarball, "r:gz") as tar:
            member = tar.getmember("grpcurl")
            # Validate extraction path to prevent path traversal
            extracted = os.path.realpath(os.path.join(local_tmp, member.name))
            if not extracted.startswith(os.path.realpath(local_tmp)):
                shutil.rmtree(local_tmp, ignore_errors=True)
                pytest.skip("Tarball member has unexpected path")
            tar.extract(member, path=local_tmp)
    except (tarfile.TarError, KeyError) as e:
        shutil.rmtree(local_tmp, ignore_errors=True)
        pytest.skip(f"Failed to extract grpcurl from tarball: {e}")

    # Copy to DUT
    try:
        duthost.copy(src=local_binary, dest="/usr/local/bin/grpcurl", mode="0755")
    except Exception as e:
        shutil.rmtree(local_tmp, ignore_errors=True)
        pytest.skip(f"Failed to copy grpcurl to DUT: {e}")

    shutil.rmtree(local_tmp, ignore_errors=True)

    # Verify
    verify = duthost.shell("grpcurl --version", module_ignore_errors=True)
    if verify["rc"] != 0:
        pytest.skip("grpcurl installed but --version check failed")

    logger.info("grpcurl %s installed on DUT", GRPCURL_VERSION)


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
    grpc: object        # PtfGrpc (TLS/plaintext) or DutGrpc (UDS)
    gnoi: object        # PtfGnoi or DutGnoi
    gnmic: Optional[PtfGnmic]   # None for UDS transport
    transport: str = 'tls'      # 'tls' or 'uds'
    _duthost: object = None  # For post-reboot reconfiguration

    def reconfigure_after_reboot(self):
        """
        Reconfigure gNMI server after a DUT reboot.

        After a COLD or WARM reboot, the gNMI server may start with default
        configuration. This method re-applies the TLS configuration and
        restarts the server so the existing client can reconnect.

        Usage:
            # After reboot completes and DUT is back up:
            gnmi_tls.reconfigure_after_reboot()
            # Now gNOI calls work again:
            status = gnmi_tls.gnoi.reboot_status()
        """
        if self._duthost is None:
            raise RuntimeError("GnmiFixture was not initialized with duthost reference")
        if not self.tls:
            logger.info("Plaintext mode - no TLS reconfiguration needed")
            return

        logger.info("Reconfiguring gNMI server after reboot")
        _configure_gnoi_tls_server(self._duthost)
        _restart_gnoi_server(self._duthost)
        logger.info("Post-reboot TLS reconfiguration completed")


@pytest.fixture(scope="module")
def gnmi_tls(request, duthost, ptfhost):
    """
    Set up gNMI/gNOI environment and yield a coupled GnmiFixture.

    Supports two transports:
    - 'tls' (default): TCP+TLS from PTF container (existing behavior)
    - 'uds': Unix domain socket from DUT host (no TLS, no server restart)

    Opt-in to UDS via indirect parametrize:
        @pytest.mark.parametrize("gnmi_tls", ["tls", "uds"], indirect=True)

    Without parametrize, defaults to TLS (backward compatible).

    TLS flow:
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
    transport = getattr(request, 'param', 'tls')

    if transport == 'uds':
        yield from _gnmi_uds_flow(duthost)
        return

    # --- existing TLS flow below (unchanged) ---
    checkpoint_name = "gnoi_tls_setup"
    cert_dir = "/tmp/gnoi_certs"

    logger.info("Setting up gNOI TLS server environment")

    # 1. Create checkpoint for rollback
    create_checkpoint(duthost, checkpoint_name)

    try:
        # 2. Generate and distribute certificates
        _create_gnoi_certs(duthost, ptfhost, cert_dir)

        # 3. Configure server for TLS mode
        _configure_gnoi_tls_server(duthost)

        # 4. Restart gNOI server process
        _restart_gnoi_server(duthost)

        # 5. Verify TLS connectivity
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

        gnmic_client = PtfGnmic(ptfhost, target, plaintext=False)
        gnmic_client.configure_tls_certificates(
            ca_cert=cert_paths.ca_cert,
            client_cert=cert_paths.client_cert,
            client_key=cert_paths.client_key,
        )

        fixture = GnmiFixture(
            host=host,
            port=port,
            tls=True,
            cert_paths=cert_paths,
            grpc=client,
            gnoi=gnoi_client,
            gnmic=gnmic_client,
            transport='tls',
            _duthost=duthost,
        )

        logger.info("Constructed PtfGnmic client: %s", gnmic_client)
        logger.info("gNOI TLS server setup completed successfully")
        yield fixture

    finally:
        # 6. Cleanup: rollback configuration
        logger.info("Cleaning up gNOI TLS server environment")
        try:
            output = rollback(duthost, checkpoint_name)
            stdout = output.get('stdout', '')
            if output.get('rc') or "Config rolled back successfully" not in stdout:
                error_msg = output.get('stdout', output.get('msg', 'unknown error'))
                logger.error("Configuration rollback failed: %s", error_msg)
            else:
                logger.info("Configuration rollback completed")
        except Exception as e:
            logger.error("Configuration rollback failed with exception: %s", e)

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
    host = duthost.mgmt_ip
    port = grpc_config.DEFAULT_PLAINTEXT_PORT
    target = f"{host}:{port}"

    client = PtfGrpc(ptfhost, target, plaintext=True)
    gnoi_client = PtfGnoi(client)
    gnmic_client = PtfGnmic(ptfhost, target, plaintext=True)

    fixture = GnmiFixture(
        host=host,
        port=port,
        tls=False,
        cert_paths=None,
        grpc=client,
        gnoi=gnoi_client,
        gnmic=gnmic_client,
        transport='plaintext',
    )

    logger.info(f"Created plaintext GnmiFixture: {target}")
    yield fixture


def _gnmi_uds_flow(duthost):
    """
    UDS transport flow — no TLS, no server restart, no CONFIG_DB changes.

    Ensures grpcurl is on the DUT, validates the UDS socket exists,
    and yields a GnmiFixture with DutGrpc/DutGnoi clients.
    """
    _ensure_grpcurl_on_dut(duthost)

    # Validate UDS socket exists
    socket_check = duthost.shell("test -S /var/run/gnmi/gnmi.sock", module_ignore_errors=True)
    if socket_check["rc"] != 0:
        pytest.skip("UDS socket /var/run/gnmi/gnmi.sock does not exist")

    grpc_client = DutGrpc(duthost)
    gnoi_client = DutGnoi(grpc_client)

    fixture = GnmiFixture(
        host="localhost",
        port=0,
        tls=False,
        cert_paths=None,
        grpc=grpc_client,
        gnoi=gnoi_client,
        gnmic=None,
        transport="uds",
    )

    logger.info("UDS transport ready: %s", grpc_client)
    yield fixture
    # No teardown needed for UDS


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

    Args:
        duthost: DUT host instance (for IP and copying server certs)
        ptfhost: PTF host instance (for copying client certs)
        cert_dir: Local directory to store generated certificates
    """
    logger.info("Generating gNOI TLS certificates")

    # Generate certificates with 1-day backdating to handle clock skew
    generator = create_gnmi_cert_generator(server_ip=duthost.mgmt_ip)
    generator.write_all(cert_dir)

    logger.info(f"Certificates generated in {cert_dir}")

    # Get certificate copy destinations from centralized config
    copy_destinations = grpc_config.get_cert_copy_destinations()

    # Copy certificates to DUT
    duthost.copy(src=f'{cert_dir}/{grpc_config.CA_CERT}', dest=copy_destinations['dut'][grpc_config.CA_CERT])
    duthost.copy(src=f'{cert_dir}/{grpc_config.SERVER_CERT}', dest=copy_destinations['dut'][grpc_config.SERVER_CERT])
    duthost.copy(src=f'{cert_dir}/{grpc_config.SERVER_KEY}', dest=copy_destinations['dut'][grpc_config.SERVER_KEY])

    # Copy client certificates to PTF container
    ptfhost.copy(src=f'{cert_dir}/{grpc_config.CA_CERT}', dest=copy_destinations['ptf'][grpc_config.CA_CERT])
    ptfhost.copy(src=f'{cert_dir}/{grpc_config.CLIENT_CERT}', dest=copy_destinations['ptf'][grpc_config.CLIENT_CERT])
    ptfhost.copy(src=f'{cert_dir}/{grpc_config.CLIENT_KEY}', dest=copy_destinations['ptf'][grpc_config.CLIENT_KEY])

    logger.info("Certificate generation and distribution completed")


def _configure_gnoi_tls_server(duthost):
    """Configure CONFIG_DB for TLS mode."""
    logger.info("Configuring gNOI server for TLS mode")

    # Configure GNMI table for TLS mode
    duthost.shell('sonic-db-cli CONFIG_DB hset "GNMI|gnmi" port 50052')
    duthost.shell('sonic-db-cli CONFIG_DB hset "GNMI|gnmi" client_auth true')
    duthost.shell('sonic-db-cli CONFIG_DB hset "GNMI|gnmi" log_level 2')
    duthost.shell('sonic-db-cli CONFIG_DB hset "GNMI|gnmi" user_auth cert')

    # Configure certificate paths using centralized config
    config_db_settings = grpc_config.get_config_db_cert_settings()
    duthost.shell(f'sonic-db-cli CONFIG_DB hset "GNMI|certs" ca_crt "{config_db_settings["ca_crt"]}"')
    duthost.shell(f'sonic-db-cli CONFIG_DB hset "GNMI|certs" server_crt "{config_db_settings["server_crt"]}"')
    duthost.shell(f'sonic-db-cli CONFIG_DB hset "GNMI|certs" server_key "{config_db_settings["server_key"]}"')

    # Register client certificate with appropriate roles
    duthost.shell(
        '''sonic-db-cli CONFIG_DB hset "GNMI_CLIENT_CERT|test.client.gnmi.sonic" "role@" '''
        '''"gnmi_readwrite,gnmi_config_db_readwrite,gnmi_appl_db_readwrite,'''
        '''gnmi_dpu_appl_db_readwrite,gnoi_readwrite"'''
    )

    logger.info("TLS configuration completed")


def _restart_gnoi_server(duthost):
    """Restart gNOI server to pick up new TLS configuration."""
    logger.info("Restarting gNOI server process")

    # Check if the 'gnmi' container exists
    container_check = duthost.shell(r"docker ps --format \{\{.Names\}\} | grep '^gnmi$'",
                                    module_ignore_errors=True)

    if container_check.get('rc', 1) != 0:
        raise Exception("The 'gnmi' container does not exist.")

    # Restart gnmi-native process to pick up new configuration
    result = duthost.shell("docker exec gnmi supervisorctl restart gnmi-native", module_ignore_errors=True)

    if result['rc'] != 0:
        raise Exception(f"Failed to restart gnmi-native: {result['stderr']}")

    # Verify process is running
    time.sleep(3)  # Give process time to start

    status_result = duthost.shell("docker exec gnmi supervisorctl status gnmi-native", module_ignore_errors=True)
    if "RUNNING" not in status_result['stdout']:
        raise Exception(f"gnmi-native failed to start: {status_result['stdout']}")

    logger.info("gNOI server restart completed")


def _verify_gnoi_tls_connectivity(duthost, ptfhost):
    """Verify TLS connectivity to gNOI server."""
    logger.info("Verifying gNOI TLS connectivity")

    # Test basic gRPC service listing with TLS
    cacert_arg, cert_arg, key_arg = grpc_config.get_grpcurl_cert_args()
    test_cmd = f"""grpcurl {cacert_arg} {cert_arg} {key_arg} \
                         {duthost.mgmt_ip}:{grpc_config.DEFAULT_TLS_PORT} list"""

    result = ptfhost.shell(test_cmd, module_ignore_errors=True)

    if result['rc'] != 0:
        raise Exception(f"TLS connectivity test failed: {result['stderr']}")

    if "gnoi.system.System" not in result['stdout']:
        raise Exception(f"gNOI services not found in response: {result['stdout']}")

    # Test basic gNOI call
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

    logger.info("Cleaning up certificate files")

    # Remove the entire certificate directory
    if os.path.exists(cert_dir):
        shutil.rmtree(cert_dir, ignore_errors=True)
