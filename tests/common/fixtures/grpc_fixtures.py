"""
Pytest fixtures for gRPC clients (gNOI, gNMI, etc.)

This module provides coupled pytest fixtures that bundle server configuration
with matched clients, preventing misuse from decoupled server/client setup.

Primary fixtures:
    gnmi_tls:       Function-scoped fixture that sets up TLS and yields GnmiFixture
    gnmi_plaintext: Function-scoped fixture for plaintext mode, yields GnmiFixture

Deprecated fixtures (kept for backward compatibility):
    setup_gnoi_tls_server: Thin wrapper around gnmi_tls, yields None
    ptf_grpc:              Auto-configured gRPC client via GNMIEnvironment
    ptf_gnoi:              gNOI wrapper around ptf_grpc
"""
import ipaddress
import os
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import uuid
import pytest
import logging
from dataclasses import dataclass
from typing import Optional
from tests.common.cert_utils import create_gnmi_cert_generator
from tests.common.grpc_config import grpc_config
from tests.common.gu_utils import create_checkpoint, delete_checkpoint, rollback
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.helpers.gnmi_utils import GNMIEnvironment
from tests.common.helpers.gnmi_log import (
    MARK_LOG_SCRIPT,
    READ_LOG_SCRIPT,
    decode_log_bytes,
    parse_log_marker,
)
from tests.common.ptf_grpc import PtfGrpc
from tests.common.ptf_gnoi import PtfGnoi
from tests.common.pygnmi_client import PygnmiClient
from tests.common.dut_grpc import DutGrpc
from tests.common.dut_gnoi import DutGnoi
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

GRPCURL_VERSION = "1.9.3"
REVOKED_CLIENT_CERT = "gnmiclient.revoked.cer"
REVOKED_CLIENT_KEY = "gnmiclient.revoked.key"
CRL_FILE = "sonic.crl.pem"
CRL_PORT = 1234

# Architecture mapping: dpkg --print-architecture → grpcurl release suffix
_GRPCURL_ARCH_MAP = {
    "amd64": "linux_x86_64",
    "arm64": "linux_arm64",
    "armhf": "linux_armv6",
}


def _get_target_duthost(duthosts, request):
    """
    Select DUT based on test parametrization or fallback to duthosts[0].

    Args:
        duthosts: All DUT host instances
        request: Pytest request object for introspection

    Returns:
        duthost: The selected DUT host instance
    """
    dut_selectors = [
        'enum_rand_one_per_hwsku_frontend_hostname',
        'enum_rand_one_per_hwsku_hostname',
        'rand_one_dut_hostname'
    ]

    for selector in dut_selectors:
        if selector in request.fixturenames:
            dut_name = request.getfixturevalue(selector)
            duthost = duthosts[dut_name]
            logger.info(f"_get_target_duthost: selected DUT {duthost.hostname}")
            return duthost

    return duthosts[0]


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
    pygnmi_client: Optional[PygnmiClient]   # None for UDS transport
    transport: str = 'tls'      # 'tls', 'tls_crl', 'plaintext' or 'uds'
    _duthost: object = None  # Fixture-selected DUT (post-reboot reconfig, DB cross-checks)
    _ptfhost: object = None  # For post-upgrade cert redistribution
    _cert_dir: Optional[str] = None  # Local cert dir used during setup
    _crl_enabled: bool = False

    @property
    def duthost(self):
        """The DUT this fixture targets; use it for any cross-checks against
        the device so multi-DUT runs cannot compare against a different DUT."""
        if self._duthost is None:
            raise RuntimeError("GnmiFixture was not initialized with duthost reference")
        return self._duthost

    def revoked_client(self):
        """Construct a lazy PygnmiClient using the CRL-revoked identity."""
        if not self._crl_enabled or self._cert_dir is None:
            raise RuntimeError("gnmi_tls was not configured with CRL support")
        return PygnmiClient(
            self.host,
            self.port,
            plaintext=False,
            ca_cert=os.path.join(self._cert_dir, grpc_config.CA_CERT),
            client_cert=os.path.join(self._cert_dir, REVOKED_CLIENT_CERT),
            client_key=os.path.join(self._cert_dir, REVOKED_CLIENT_KEY),
            connect=False,
        )

    def mark_gnmi_log(self):
        """Record a rotation-aware byte position in /var/log/gnmi.log."""
        result = self.duthost.shell(
            "sudo python3 -c {} {}".format(
                shlex.quote(MARK_LOG_SCRIPT),
                shlex.quote("/var/log/gnmi.log"),
            ),
            module_ignore_errors=True,
        )
        if result.get("rc") != 0:
            raise RuntimeError(
                "Failed to mark /var/log/gnmi.log: {}".format(result)
            )
        return parse_log_marker(result.get("stdout", ""))

    def gnmi_log_since(self, marker):
        """Read only log bytes after marker, including across rotation/truncation."""
        result = self.duthost.shell(
            "sudo python3 -c {} {} {} {} {}".format(
                shlex.quote(READ_LOG_SCRIPT),
                shlex.quote("/var/log/gnmi.log"),
                marker.inode,
                marker.offset,
                shlex.quote(marker.anchor),
            ),
            module_ignore_errors=True,
        )
        if result.get("rc") != 0:
            raise RuntimeError(
                "Failed to read new gNMI log bytes: {}".format(result)
            )
        try:
            return decode_log_bytes(result.get("stdout", ""))
        except (ValueError, TypeError):
            raise RuntimeError(
                "Failed to decode new gNMI log bytes: {}".format(result)
            )

    def reconfigure_after_reboot(self):
        """
        Re-apply TLS config + restart server after a reboot so the client can
        reconnect. Certs survive the reboot, so they are reused (not regenerated).
        """
        # Reboot/upgrade helpers need the stored duthost reference.
        if self._duthost is None:
            raise RuntimeError("GnmiFixture was not initialized with duthost reference")
        # Plaintext transport has no TLS server to reconfigure.
        if not self.tls:
            logger.info("Plaintext mode - no TLS reconfiguration needed")
            return

        logger.info("Reconfiguring gNMI server after reboot")
        # regen_certs=False: rootfs (and cert files) survived the reboot.
        _establish_gnoi_tls_handshake(
            self._duthost,
            regen_certs=False,
            enable_crl=self._crl_enabled,
        )
        logger.info("Post-reboot TLS reconfiguration completed")

    def reinstall_certs_after_upgrade(self):
        """
        Regenerate certs + re-apply TLS config after an image upgrade. An upgrade
        replaces the rootfs, wiping the cert files, so reconfigure alone is not
        enough; certs must be recreated and redistributed to DUT and PTF.
        """
        # Cert regen needs duthost, ptfhost and the local cert dir.
        if self._duthost is None or self._ptfhost is None or self._cert_dir is None:
            raise RuntimeError(
                "GnmiFixture was not initialized with duthost/ptfhost/cert_dir "
                "references required for post-upgrade cert reinstall"
            )
        # Plaintext transport has no TLS certs to reinstall.
        if not self.tls:
            logger.info("Plaintext mode - no TLS cert reinstall needed")
            return
        if self._crl_enabled:
            raise RuntimeError("CRL-enabled gnmi_tls does not support image upgrades")

        logger.info("Reinstalling gNOI TLS certificates after upgrade")
        # regen_certs=True: upgrade wiped the certs, so recreate them.
        _establish_gnoi_tls_handshake(
            self._duthost, ptfhost=self._ptfhost, cert_dir=self._cert_dir, regen_certs=True
        )
        logger.info("Post-upgrade TLS cert reinstall completed")


@pytest.fixture(scope="function")
def gnmi_tls(request, duthosts, ptfhost):
    """
    Set up gNMI/gNOI environment and yield a coupled GnmiFixture.

    Supports three transports:
    - 'tls' (default): TCP+TLS from PTF container (existing behavior)
    - 'tls_crl': TLS plus a revoked client identity and bounded CRL server
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
    duthost = _get_target_duthost(duthosts, request)

    transport = getattr(request, 'param', 'tls')
    if transport not in ('tls', 'tls_crl', 'uds'):
        raise ValueError("Unsupported gnmi_tls transport: {}".format(transport))

    if transport == 'uds':
        yield from _gnmi_uds_flow(duthost)
        return

    # --- existing TLS flow below (unchanged) ---
    checkpoint_name = "gnoi_tls_setup"
    cert_dir = "/tmp/gnoi_certs"
    enable_crl = transport == 'tls_crl'
    crl_server = None
    teardown_errors = []
    rollback_succeeded = False
    restored_service_running = False
    critical_processes_healthy = False

    logger.info("Setting up gNOI TLS server environment")

    # 1. Create checkpoint for rollback
    create_checkpoint(duthost, checkpoint_name)

    pygnmi_client = None
    try:
        # 2-5. Generate/distribute certs, configure + restart server, verify handshake
        if enable_crl:
            crl_url, crl_bind_address = _get_crl_endpoint(duthost, ptfhost)
            _create_gnoi_certs(
                duthost, ptfhost, cert_dir, crl_url=crl_url
            )
            crl_server = _start_crl_server(
                duthost, ptfhost, cert_dir, crl_url, crl_bind_address
            )
            _establish_gnoi_tls_handshake(
                duthost,
                ptfhost=ptfhost,
                regen_certs=False,
                verify=True,
                enable_crl=True,
            )
        else:
            _establish_gnoi_tls_handshake(
                duthost, ptfhost=ptfhost, cert_dir=cert_dir,
                regen_certs=True, verify=True
            )

        # Build coupled client with the exact config we just set up
        host = duthost.mgmt_ip
        port = grpc_config.DEFAULT_TLS_PORT
        target = f"[{host}]:{port}"

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

        # PygnmiClient runs in the sonic-mgmt orchestrator and reads the locally
        # generated certs in cert_dir (not the PTF-side copies).
        pygnmi_client = PygnmiClient(
            host, port, plaintext=False,
            ca_cert=f"{cert_dir}/{grpc_config.CA_CERT}",
            client_cert=f"{cert_dir}/{grpc_config.CLIENT_CERT}",
            client_key=f"{cert_dir}/{grpc_config.CLIENT_KEY}",
        )

        fixture = GnmiFixture(
            host=host,
            port=port,
            tls=True,
            cert_paths=cert_paths,
            grpc=client,
            gnoi=gnoi_client,
            pygnmi_client=pygnmi_client,
            transport=transport,
            _duthost=duthost,
            _ptfhost=ptfhost,
            _cert_dir=cert_dir,
            _crl_enabled=enable_crl,
        )

        logger.info("Constructed PygnmiClient: %s", pygnmi_client)
        logger.info("gNOI TLS server setup completed successfully")
        yield fixture

    finally:
        # 6. Cleanup: close the reused gNMI channel, then rollback configuration
        logger.info("Cleaning up gNOI TLS server environment")
        if pygnmi_client is not None:
            try:
                pygnmi_client.close()
            except Exception as e:
                logger.error("Failed to close PygnmiClient: %s", e)

        try:
            output = rollback(duthost, checkpoint_name)
            stdout = output.get('stdout', '')
            if output.get('rc') or "Config rolled back successfully" not in stdout:
                error_msg = output.get('stdout', output.get('msg', 'unknown error'))
                logger.error("Configuration rollback failed: %s", error_msg)
                teardown_errors.append(
                    "configuration rollback failed: {}".format(error_msg)
                )
            else:
                logger.info("Configuration rollback completed")
                rollback_succeeded = True
        except Exception as e:
            logger.error("Configuration rollback failed with exception: %s", e)
            teardown_errors.append(
                "configuration rollback failed with exception: {}".format(e)
            )

        if enable_crl and rollback_succeeded:
            try:
                _restart_gnoi_server(
                    duthost,
                    expected_port=_get_configured_gnmi_port(duthost),
                )
                restored_service_running = True
            except Exception as e:
                logger.error("Failed to restart restored gNMI server: %s", e)
                teardown_errors.append(
                    "restart restored gNMI server failed: {}".format(e)
                )

        if crl_server is not None:
            try:
                _stop_crl_server(ptfhost, *crl_server)
            except Exception as e:
                logger.error("Failed to stop CRL server: %s", e)
                teardown_errors.append("stop CRL server failed: {}".format(e))

        if rollback_succeeded:
            try:
                logger.info("Waiting for critical processes to be healthy after rollback")
                wait_critical_processes(duthost)
                logger.info("All critical processes are healthy")
                critical_processes_healthy = True
            except Exception as e:
                logger.error("Waiting for critical processes failed with exception: %s", e)
                teardown_errors.append(
                    "critical process recovery failed: {}".format(e)
                )

        if (enable_crl and rollback_succeeded and restored_service_running
                and critical_processes_healthy):
            try:
                delete_checkpoint(duthost, checkpoint_name)
                logger.info("Configuration checkpoint deleted")
            except Exception as e:
                logger.error("Failed to delete configuration checkpoint: %s", e)
                teardown_errors.append(
                    "delete configuration checkpoint failed: {}".format(e)
                )

        try:
            _delete_gnoi_certs(cert_dir)
            logger.info("Certificate cleanup completed")
        except Exception as e:
            logger.error(f"Failed to cleanup certificates: {e}")

        if enable_crl and teardown_errors:
            raise RuntimeError("; ".join(teardown_errors))


@pytest.fixture(scope="function")
def gnmi_plaintext(request, duthosts, ptfhost):
    """
    Plaintext gNMI/gNOI fixture — no TLS, no server reconfiguration.

    Reads the existing plaintext port from config and builds a matched client.
    No CONFIG_DB changes are made; assumes the DUT already accepts plaintext
    connections on the default port.

    Usage:
        def test_plaintext(gnmi_plaintext):
            services = gnmi_plaintext.grpc.list_services()
    """
    duthost = _get_target_duthost(duthosts, request)

    host = duthost.mgmt_ip
    port = grpc_config.DEFAULT_PLAINTEXT_PORT
    target = f"{host}:{port}"

    client = PtfGrpc(ptfhost, target, plaintext=True)
    gnoi_client = PtfGnoi(client)

    with PygnmiClient(host, port, plaintext=True) as pygnmi_client:
        fixture = GnmiFixture(
            host=host,
            port=port,
            tls=False,
            cert_paths=None,
            grpc=client,
            gnoi=gnoi_client,
            pygnmi_client=pygnmi_client,
            transport='plaintext',
            _duthost=duthost,
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
        pygnmi_client=None,
        transport="uds",
        _duthost=duthost,
    )

    logger.info("UDS transport ready: %s", grpc_client)
    yield fixture
    # No teardown needed for UDS


# ---------------------------------------------------------------------------
# Deprecated fixtures — kept for backward compatibility during migration
# ---------------------------------------------------------------------------

@pytest.fixture(scope="function")
def setup_gnoi_tls_server(gnmi_tls):
    """
    Deprecated: use gnmi_tls instead.

    Thin wrapper that depends on gnmi_tls and yields None so that
    unconverted tests using @pytest.mark.usefixtures("setup_gnoi_tls_server")
    continue to work.
    """
    yield


@pytest.fixture
def ptf_grpc(ptfhost, duthosts, request):
    """
    Deprecated: use gnmi_tls.grpc or gnmi_plaintext.grpc instead.

    Auto-configured gRPC client using GNMIEnvironment for discovery.
    """

    duthost = _get_target_duthost(duthosts, request)

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
# Internal helpers
# ---------------------------------------------------------------------------

def _establish_gnoi_tls_handshake(duthost, ptfhost=None, cert_dir=None,
                                  regen_certs=True, verify=False,
                                  enable_crl=False):
    """
    Bring the gNOI TLS server into a state where the PTF client can connect.
    Single source of truth called at setup, after reboot, and after upgrade.

    regen_certs: recreate + redistribute certs (needs ptfhost, cert_dir).
    verify: check TLS connectivity afterwards (needs ptfhost).
    """
    if regen_certs:
        # Certs are gone (fresh setup / upgrade wiped rootfs) - recreate them.
        if ptfhost is None or cert_dir is None:
            raise RuntimeError("regen_certs=True requires ptfhost and cert_dir")
        duthost.shell(f"mkdir -p {grpc_config.DUT_CERT_DIR}")  # ensure DUT cert dir exists
        _create_gnoi_certs(duthost, ptfhost, cert_dir)         # gen + copy to DUT/PTF

    _configure_gnoi_tls_server(
        duthost, enable_crl=enable_crl
    )  # write TLS settings into CONFIG_DB
    _restart_gnoi_server(duthost)        # restart so server picks up new config

    if verify:
        # Confirm the client can actually complete a TLS call before returning.
        if ptfhost is None:
            raise RuntimeError("verify=True requires ptfhost")
        _verify_gnoi_tls_connectivity(duthost, ptfhost)


def _create_gnoi_certs(duthost, ptfhost, cert_dir, crl_url=None):
    """
    Generate and distribute gNOI TLS certificates.

    Certificates are backdated by 1 day to handle clock skew between hosts.

    Args:
        duthost: DUT host instance (for IP and copying server certs)
        ptfhost: PTF host instance (for copying client certs)
        cert_dir: Local directory to store generated certificates
    """
    logger.info("Generating gNOI TLS certificates")

    # Match the existing gNMI test PKI's tolerance for lab clock skew.
    generator = create_gnmi_cert_generator(
        server_ip=duthost.mgmt_ip,
        backdate_days=7,
    )
    generator.write_all(cert_dir)
    if crl_url:
        generator.generate_revoked_cert_with_crl(crl_url, cert_dir)

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


def _configure_gnoi_tls_server(duthost, enable_crl=False):
    """Configure CONFIG_DB for TLS mode."""
    logger.info("Configuring gNOI server for TLS mode")

    # Configure GNMI table for TLS mode
    duthost.shell('sonic-db-cli CONFIG_DB hset "GNMI|gnmi" port 50052')
    duthost.shell('sonic-db-cli CONFIG_DB hset "GNMI|gnmi" client_auth true')
    log_level = 10 if enable_crl else 2
    duthost.shell(
        'sonic-db-cli CONFIG_DB hset "GNMI|gnmi" log_level {}'.format(
            log_level
        )
    )
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

    if enable_crl:
        duthost.shell('sonic-db-cli CONFIG_DB hset "GNMI|gnmi" enable_crl true')
        duthost.shell(
            '''sonic-db-cli CONFIG_DB hset "GNMI_CLIENT_CERT|'''
            '''test.client.revoked.gnmi.sonic" "role@" '''
            '''"gnmi_readwrite,gnmi_config_db_readwrite,'''
            '''gnmi_appl_db_readwrite,gnmi_dpu_appl_db_readwrite,'''
            '''gnoi_readwrite"'''
        )

    logger.info("TLS configuration completed")


def _get_crl_endpoint(duthost, ptfhost):
    """Return the DUT-reachable CRL URL and optional IPv6 bind address."""
    facts = duthost.dut_basic_facts()['ansible_facts']['dut_basic_facts']
    if facts.get('is_mgmt_ipv6_only', False):
        if not ptfhost.mgmt_ipv6:
            raise RuntimeError("IPv6-only DUT requires a PTF management IPv6 address")
        ptf_ipv6 = str(ipaddress.ip_interface(ptfhost.mgmt_ipv6).ip)
        return (
            "http://[{}]:{}/crl".format(ptf_ipv6, CRL_PORT),
            ptf_ipv6,
        )
    return "http://{}:{}/crl".format(ptfhost.mgmt_ip, CRL_PORT), None


def _start_crl_server(duthost, ptfhost, cert_dir, crl_url,
                      bind_address=None):
    """Start an isolated PTF CRL server and return its exact PID and directory."""
    listener = ptfhost.shell(
        "ss -ltnH | grep -E '[:.]{}[[:space:]]'".format(CRL_PORT),
        module_ignore_errors=True,
    )
    if listener.get('rc') not in (0, 1):
        raise RuntimeError("Failed to inspect CRL port on the PTF: {}".format(listener))
    if listener.get('rc') == 0:
        raise RuntimeError("CRL port {} is already in use on the PTF".format(CRL_PORT))

    server_dir = "/root/sonic-mgmt-gnmi-crl-{}".format(uuid.uuid4().hex[:8])
    ptfhost.shell("mkdir -p {}".format(server_dir))
    server_source = os.path.normpath(os.path.join(
        os.path.dirname(__file__), "..", "..", "gnmi", "crl", "crl_server.py"
    ))
    pid = None
    try:
        ptfhost.copy(src=server_source, dest="{}/crl_server.py".format(server_dir))
        ptfhost.copy(
            src=os.path.join(cert_dir, CRL_FILE),
            dest="{}/{}".format(server_dir, CRL_FILE),
        )
        bind_arg = ""
        if bind_address:
            bind_arg = " --bind {}".format(shlex.quote(bind_address))
        result = ptfhost.shell(
            "cd {directory}; /root/env-python3/bin/python crl_server.py "
            "--port {port}{bind} </dev/null >/dev/null 2>&1 & echo $!".format(
                directory=shlex.quote(server_dir),
                port=CRL_PORT,
                bind=bind_arg,
            )
        )
        pid = int(result.get('stdout', '').strip())

        def _server_ready():
            process = ptfhost.shell(
                "kill -0 {} 2>/dev/null".format(pid),
                module_ignore_errors=True,
            )
            ready = ptfhost.shell(
                "grep -q 'Ready handle request' {}/crl.log".format(
                    shlex.quote(server_dir)
                ),
                module_ignore_errors=True,
            )
            return process.get('rc') == 0 and ready.get('rc') == 0

        if not wait_until(30, 1, 0, _server_ready):
            raise RuntimeError("CRL server failed to become ready")

        def _server_reachable_from_dut():
            result = duthost.shell(
                "curl --noproxy '*' -fsS --max-time 5 {} >/dev/null".format(
                    shlex.quote(crl_url)
                ),
                module_ignore_errors=True,
            )
            return result.get('rc') == 0

        if not wait_until(30, 2, 0, _server_reachable_from_dut):
            raise RuntimeError(
                "CRL endpoint is not reachable from the DUT: {}".format(
                    crl_url
                )
            )
        logger.info("CRL server started with PID %s in %s", pid, server_dir)
        return pid, server_dir
    except Exception:
        if pid is not None:
            _stop_crl_server(ptfhost, pid, server_dir)
        else:
            ptfhost.shell(
                "rm -rf {}".format(shlex.quote(server_dir)),
                module_ignore_errors=True,
            )
        raise


def _stop_crl_server(ptfhost, pid, server_dir):
    """Stop only the CRL server started by this fixture and remove its files."""
    ptfhost.shell("kill {} 2>/dev/null || true".format(pid),
                  module_ignore_errors=True)

    def _server_stopped():
        result = ptfhost.shell(
            "kill -0 {} 2>/dev/null".format(pid),
            module_ignore_errors=True,
        )
        return result.get('rc') != 0

    if not wait_until(10, 1, 0, _server_stopped):
        ptfhost.shell("kill -9 {} 2>/dev/null || true".format(pid),
                      module_ignore_errors=True)
        if not wait_until(5, 1, 0, _server_stopped):
            raise RuntimeError("CRL server PID {} did not stop".format(pid))
    remove_result = ptfhost.shell(
        "rm -rf {}".format(shlex.quote(server_dir)),
        module_ignore_errors=True,
    )
    if remove_result.get('rc') != 0:
        raise RuntimeError(
            "Failed to remove CRL server directory: {}".format(
                remove_result
            )
        )
    verify_result = ptfhost.shell(
        "test ! -e {}".format(shlex.quote(server_dir)),
        module_ignore_errors=True,
    )
    if verify_result.get('rc') != 0:
        raise RuntimeError(
            "CRL server directory still exists: {}".format(server_dir)
        )


def _get_configured_gnmi_port(duthost):
    """Return the restored configured gNMI port, or the image default."""
    result = duthost.shell(
        'sonic-db-cli CONFIG_DB hget "GNMI|gnmi" port',
        module_ignore_errors=True,
    )
    value = (result.get('stdout') or '').strip()
    if value.isdigit():
        return int(value)
    return grpc_config.DEFAULT_PLAINTEXT_PORT


def _restart_gnoi_server(duthost,
                         expected_port=grpc_config.DEFAULT_TLS_PORT):
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

    # Wait for supervisor to report RUNNING as a guard against immediate
    # crash loops.
    def _supervisor_running():
        status = duthost.shell("docker exec gnmi supervisorctl status gnmi-native",
                               module_ignore_errors=True)
        return "RUNNING" in status.get('stdout', '')

    if not wait_until(30, 1, 0, _supervisor_running):
        status = duthost.shell("docker exec gnmi supervisorctl status gnmi-native",
                               module_ignore_errors=True)
        raise Exception(
            f"gnmi-native failed to reach RUNNING within 30s: {status.get('stdout', '')}"
        )

    # Supervisor can report RUNNING before telemetry binds its TLS listener,
    # especially on slower platforms. Do not return until callers can safely
    # start a client connection. Full TLS/RPC validation remains in
    # _verify_gnoi_tls_connectivity.
    def _tls_listener_ready():
        status = duthost.shell(
            "sudo ss -ltn | grep -q ':{} '".format(
                expected_port
            ),
            module_ignore_errors=True,
        )
        return status.get('rc', 1) == 0

    if not wait_until(60, 2, 0, _tls_listener_ready):
        status = duthost.shell(
            "sudo ss -ltn | grep ':{} '".format(
                expected_port
            ),
            module_ignore_errors=True,
        )
        raise Exception(
            "gNOI server failed to listen on port {} within 60s: {}".format(
                expected_port,
                status.get('stdout', ''),
            )
        )

    logger.info(
        "gNOI server restart completed (supervisor RUNNING, port %s listening)",
        expected_port,
    )


def _verify_gnoi_tls_connectivity(duthost, ptfhost):
    """Verify TLS connectivity to gNOI server with retry on transient errors.

    Retries each grpcurl call with a bounded per-attempt timeout. This absorbs
    the brief window between supervisor reporting gnmi-native RUNNING and the
    telemetry process actually accepting connections on the TLS port. On slow
    armhf platforms (e.g. marvell-prestera) that window can be several
    seconds, manifesting as `connect: connection refused` errors from PTF.
    """
    logger.info("Verifying gNOI TLS connectivity")

    cacert_arg, cert_arg, key_arg = grpc_config.get_grpcurl_cert_args()
    target = f"[{duthost.mgmt_ip}]:{grpc_config.DEFAULT_TLS_PORT}"

    # -connect-timeout bounds the TCP/TLS handshake portion; -max-time bounds
    # the whole call. Both keep a single retry attempt from hanging if packets
    # are blackholed instead of refused.
    grpcurl_timeouts = "-connect-timeout 5 -max-time 10"

    list_cmd = (
        f"grpcurl {grpcurl_timeouts} {cacert_arg} {cert_arg} {key_arg} "
        f"{target} list"
    )
    time_cmd = (
        f"grpcurl {grpcurl_timeouts} {cacert_arg} {cert_arg} {key_arg} "
        f"{target} gnoi.system.System.Time"
    )

    list_last = {}

    def _list_ok():
        res = ptfhost.shell(list_cmd, module_ignore_errors=True)
        list_last.clear()
        list_last.update(res)
        return res.get('rc', 1) == 0 and "gnoi.system.System" in res.get('stdout', '')

    if not wait_until(60, 2, 0, _list_ok):
        raise Exception(
            "TLS connectivity test failed after retries: "
            f"rc={list_last.get('rc')} stderr={list_last.get('stderr', '')} "
            f"stdout={list_last.get('stdout', '')}"
        )

    time_last = {}

    def _time_ok():
        res = ptfhost.shell(time_cmd, module_ignore_errors=True)
        time_last.clear()
        time_last.update(res)
        return res.get('rc', 1) == 0 and "time" in res.get('stdout', '')

    if not wait_until(30, 2, 0, _time_ok):
        raise Exception(
            "gNOI System.Time test failed after retries: "
            f"rc={time_last.get('rc')} stderr={time_last.get('stderr', '')} "
            f"stdout={time_last.get('stdout', '')}"
        )

    logger.info("TLS connectivity verification completed successfully")


def _delete_gnoi_certs(cert_dir):
    """Clean up generated certificate files."""

    logger.info("Cleaning up certificate files")

    # Remove the entire certificate directory
    if os.path.exists(cert_dir):
        shutil.rmtree(cert_dir, ignore_errors=True)


def reprovision_gnoi_tls(duthost, ptfhost, cert_dir="/tmp/gnoi_certs"):
    """Re-run cert + CONFIG_DB + gNMI restart steps after a DUT reboot.

    Use this between phases of an upgrade test where the NPU rebooted into a
    new image and its gNMI server is no longer using the test-provisioned certs.
    """
    logger.info("Re-provisioning gNOI TLS after DUT reboot")
    _create_gnoi_certs(duthost, ptfhost, cert_dir)
    _configure_gnoi_tls_server(duthost)
    _restart_gnoi_server(duthost)
    _verify_gnoi_tls_connectivity(duthost, ptfhost)
    logger.info("gNOI TLS re-provisioning complete")
