"""
Pytest fixtures for gRPC clients (gNOI, gNMI, etc.)

This module provides pytest fixtures for easy access to gRPC clients with
automatic configuration discovery, making it simple to write gRPC-based tests.
"""
import os
import pytest
import logging
from tests.common.grpc_config import grpc_config

logger = logging.getLogger(__name__)


@pytest.fixture
def ptf_grpc(ptfhost, duthost):
    """
    Auto-configured gRPC client using GNMIEnvironment for discovery.

    This fixture provides a ready-to-use PtfGrpc client that automatically
    detects the correct gRPC endpoint configuration from the specified DUT.

    Args:
        ptfhost: PTF host fixture for command execution
        duthost: DUT host instance to target

    Returns:
        PtfGrpc: Configured gRPC client ready for use

    Example:
        def test_grpc_services(ptf_grpc):
            services = ptf_grpc.list_services()
            assert "gnoi.system.System" in services
    """
    from tests.common.helpers.gnmi_utils import GNMIEnvironment
    from tests.common.ptf_grpc import PtfGrpc

    # Auto-configure using GNMIEnvironment
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    client = PtfGrpc(ptfhost, env, duthost=duthost)

    logger.info(f"Created auto-configured gRPC client: {client}")
    return client


@pytest.fixture
def ptf_gnoi(ptf_grpc):
    """
    gNOI-specific client using auto-configured gRPC client.

    This fixture provides a high-level PtfGnoi wrapper that exposes clean
    Python method interfaces for gNOI operations, hiding gRPC complexity.

    Args:
        ptf_grpc: Auto-configured gRPC client fixture

    Returns:
        PtfGnoi: High-level gNOI client wrapper

    Example:
        def test_system_time(ptf_gnoi):
            result = ptf_gnoi.system_time()
            assert "time" in result
            assert "formatted_time" in result
    """
    from tests.common.ptf_gnoi import PtfGnoi

    gnoi_client = PtfGnoi(ptf_grpc)
    logger.info(f"Created gNOI wrapper: {gnoi_client}")
    return gnoi_client


@pytest.fixture
def ptf_grpc_custom(ptfhost, duthost):
    """
    Factory fixture for custom gRPC client configuration.

    This fixture returns a factory function that allows creating gRPC clients
    with custom configuration when auto-detection is not sufficient.

    Args:
        ptfhost: PTF host fixture for command execution
        duthost: DUT host instance to target

    Returns:
        Callable: Factory function for creating custom gRPC clients

    Example:
        def test_custom_grpc(ptf_grpc_custom):
            # Custom TLS configuration
            tls_client = ptf_grpc_custom(
                host="192.168.1.1",
                port=8080,
                plaintext=False
            )

            # Custom timeout
            fast_client = ptf_grpc_custom(timeout=1.0)

            services = fast_client.list_services()
    """
    from tests.common.helpers.gnmi_utils import GNMIEnvironment
    from tests.common.ptf_grpc import PtfGrpc

    def _create_custom_client(host=None, port=None, plaintext=None, timeout=None, **kwargs):
        """
        Create a custom gRPC client with specified configuration.

        Args:
            host: Target host (defaults to DUT mgmt IP)
            port: Target port (defaults to auto-detected port)
            plaintext: Use plaintext connection (defaults to auto-detected)
            timeout: Connection timeout in seconds
            **kwargs: Additional PtfGrpc configuration options

        Returns:
            PtfGrpc: Configured gRPC client
        """
        # Use GNMIEnvironment for defaults if specific values not provided
        if host is None or port is None:
            env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
            if host is None:
                host = duthost.mgmt_ip
            if port is None:
                port = env.gnmi_port
            if plaintext is None:
                plaintext = not env.use_tls

        # Construct target string
        if ':' not in str(host):
            target = f"{host}:{port}"
        else:
            target = str(host)

        # Create client with custom configuration
        client = PtfGrpc(ptfhost, target, plaintext=plaintext, **kwargs)

        # Apply additional configuration
        if timeout is not None:
            client.configure_timeout(timeout)

        logger.info(f"Created custom gRPC client: {client}")
        return client

    return _create_custom_client


@pytest.fixture
def ptf_gnmi(ptf_grpc):
    """
    gNMI-specific client using auto-configured gRPC client.

    This fixture provides a gNMI wrapper for future gNMI operations.
    Currently returns the base gRPC client until a dedicated gNMI wrapper is needed.

    Args:
        ptf_grpc: Auto-configured gRPC client fixture

    Returns:
        PtfGrpc: gRPC client configured for gNMI operations

    Note:
        This fixture is a placeholder for future gNMI-specific functionality.
        For now, it returns the base gRPC client which can call gNMI services directly.

    Example:
        def test_gnmi_get(ptf_gnmi):
            # Use generic gRPC interface for gNMI calls
            response = ptf_gnmi.call_unary("gnmi.gNMI", "Get", {
                "path": [{"elem": [{"name": "system"}, {"name": "state"}]}]
            })
    """
    # For now, return the base gRPC client
    # TODO: Create dedicated PtfGnmi wrapper class when needed
    logger.info("Created gNMI client (using base gRPC client)")
    return ptf_grpc


@pytest.fixture(scope="module")
def setup_gnoi_tls_server(duthost, ptfhost):
    """
    Set up gNOI server with TLS certificates and configuration.

    This fixture creates a complete TLS environment that client fixtures
    automatically detect through GNMIEnvironment configuration discovery.

    The fixture:
    1. Creates a configuration checkpoint for rollback
    2. Generates TLS certificates with proper SAN for DUT IP (backdated to handle clock skew)
    3. Distributes certificates to DUT and PTF container
    4. Configures CONFIG_DB for TLS mode (port 50052)
    5. Restarts the gNOI server process
    6. Verifies TLS connectivity
    7. Provides cleanup on teardown

    Args:
        duthost: DUT host instance to configure
        ptfhost: PTF host instance for client certificates

    Usage:
        @pytest.mark.usefixtures("setup_gnoi_tls_server")
        def test_gnoi_with_tls(ptf_gnoi):
            # Client automatically detects TLS configuration
            result = ptf_gnoi.system_time()
            assert "time" in result

    Note:
        Client fixtures (ptf_grpc, ptf_gnoi) automatically adapt to TLS mode
        when this fixture is active through GNMIEnvironment detection.

        Certificates are backdated by 1 day to handle clock skew between
        the test host, DUT, and PTF container.
    """
    from tests.common.gu_utils import create_checkpoint, rollback

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

        logger.info("gNOI TLS server setup completed successfully")
        yield  # Tests run with TLS environment active

    finally:
        # 6. Cleanup: rollback configuration
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


def _create_gnoi_certs(duthost, ptfhost, cert_dir):
    """
    Generate and distribute gNOI TLS certificates.

    Certificates are backdated by 1 day to handle clock skew between hosts.

    Args:
        duthost: DUT host instance (for IP and copying server certs)
        ptfhost: PTF host instance (for copying client certs)
        cert_dir: Local directory to store generated certificates
    """
    from tests.common.cert_utils import create_gnmi_cert_generator

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
    import time
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
    import shutil

    logger.info("Cleaning up certificate files")

    # Remove the entire certificate directory
    if os.path.exists(cert_dir):
        shutil.rmtree(cert_dir, ignore_errors=True)
