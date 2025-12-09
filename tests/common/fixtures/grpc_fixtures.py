"""
Pytest fixtures for gRPC clients (gNOI, gNMI, etc.)

This module provides pytest fixtures for easy access to gRPC clients with
automatic configuration discovery, making it simple to write gRPC-based tests.
"""
import pytest
import logging

logger = logging.getLogger(__name__)


@pytest.fixture
def ptf_grpc(ptfhost, duthosts, enum_rand_one_per_hwsku_hostname):
    """
    Auto-configured gRPC client using GNMIEnvironment for discovery.

    This fixture provides a ready-to-use PtfGrpc client that automatically
    detects the correct gRPC endpoint configuration from the DUT.

    Args:
        ptfhost: PTF host fixture for command execution
        duthosts: DUT hosts fixture
        enum_rand_one_per_hwsku_hostname: Random DUT selection fixture

    Returns:
        PtfGrpc: Configured gRPC client ready for use

    Example:
        def test_grpc_services(ptf_grpc):
            services = ptf_grpc.list_services()
            assert "gnoi.system.System" in services
    """
    from tests.common.helpers.gnmi_utils import GNMIEnvironment
    from tests.common.ptf_grpc import PtfGrpc

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

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
def ptf_grpc_custom(ptfhost, duthosts, enum_rand_one_per_hwsku_hostname):
    """
    Factory fixture for custom gRPC client configuration.

    This fixture returns a factory function that allows creating gRPC clients
    with custom configuration when auto-detection is not sufficient.

    Args:
        ptfhost: PTF host fixture for command execution
        duthosts: DUT hosts fixture
        enum_rand_one_per_hwsku_hostname: Random DUT selection fixture

    Returns:
        Callable: Factory function for creating custom gRPC clients

    Example:
        def test_custom_grpc(ptf_grpc_custom, duthost):
            # Custom TLS configuration
            tls_client = ptf_grpc_custom(
                host=f"{duthost.mgmt_ip}:8080",
                plaintext=False,
                cert_path="/path/to/cert.pem"
            )

            # Custom timeout
            fast_client = ptf_grpc_custom(timeout=1.0)

            services = fast_client.list_services()
    """
    from tests.common.helpers.gnmi_utils import GNMIEnvironment
    from tests.common.ptf_grpc import PtfGrpc

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

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
def setup_gnoi_tls_server(duthosts, enum_rand_one_per_hwsku_hostname, localhost, ptfhost):
    """
    Set up gNOI server with TLS certificates and configuration.

    This fixture creates a complete TLS environment that client fixtures
    automatically detect through GNMIEnvironment configuration discovery.

    The fixture:
    1. Creates a configuration checkpoint for rollback
    2. Generates TLS certificates with proper SAN for DUT IP
    3. Distributes certificates to DUT and PTF container
    4. Configures CONFIG_DB for TLS mode (port 50052)
    5. Restarts the gNOI server process
    6. Verifies TLS connectivity
    7. Provides cleanup on teardown

    Usage:
        @pytest.mark.usefixtures("setup_gnoi_tls_server")
        def test_gnoi_with_tls(ptf_gnoi):
            # Client automatically detects TLS configuration
            result = ptf_gnoi.system_time()
            assert "time" in result

    Note:
        Client fixtures (ptf_grpc, ptf_gnoi) automatically adapt to TLS mode
        when this fixture is active through GNMIEnvironment detection.
    """
    from tests.common.gu_utils import create_checkpoint, rollback

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    checkpoint_name = "gnoi_tls_setup"

    logger.info("Setting up gNOI TLS server environment")

    # 1. Create checkpoint for rollback
    create_checkpoint(duthost, checkpoint_name)

    try:
        # 2. Generate certificates
        _create_gnoi_certs(duthost, localhost, ptfhost)

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
            _delete_gnoi_certs(localhost)
            logger.info("Certificate cleanup completed")
        except Exception as e:
            logger.error(f"Failed to cleanup certificates: {e}")


def _create_gnoi_certs(duthost, localhost, ptfhost):
    """Generate gNOI TLS certificates with proper SAN for DUT IP."""
    logger.info("Generating gNOI TLS certificates")

    # Create all certificate files in /tmp to avoid polluting working directory
    cert_dir = "/tmp/gnoi_certs"
    localhost.shell(f"mkdir -p {cert_dir}")
    localhost.shell(f"cd {cert_dir}")

    # Create Root key
    localhost.shell(f"cd {cert_dir} && openssl genrsa -out gnmiCA.key 2048")

    # Create Root cert
    localhost.shell(f"""cd {cert_dir} && openssl req -x509 -new -nodes -key gnmiCA.key -sha256 -days 1825 \
                       -subj '/CN=test.gnmi.sonic' -out gnmiCA.cer""")

    # Create server key
    localhost.shell(f"cd {cert_dir} && openssl genrsa -out gnmiserver.key 2048")

    # Create server CSR
    localhost.shell(f"""cd {cert_dir} && openssl req -new -key gnmiserver.key \
                       -subj '/CN=test.server.gnmi.sonic' -out gnmiserver.csr""")

    # Create extension file with DUT IP SAN
    ext_conf_content = f"""[ req_ext ]
subjectAltName = @alt_names
[alt_names]
DNS.1   = hostname.com
IP      = {duthost.mgmt_ip}"""

    localhost.shell(f"cd {cert_dir} && echo '{ext_conf_content}' > extfile.cnf")

    # Sign server certificate with SAN extension
    localhost.shell(f"""cd {cert_dir} && openssl x509 -req -in gnmiserver.csr -CA gnmiCA.cer -CAkey gnmiCA.key \
                       -CAcreateserial -out gnmiserver.cer -days 825 -sha256 \
                       -extensions req_ext -extfile extfile.cnf""")

    # Create client key
    localhost.shell(f"cd {cert_dir} && openssl genrsa -out gnmiclient.key 2048")

    # Create client CSR
    localhost.shell(f"""cd {cert_dir} && openssl req -new -key gnmiclient.key \
                       -subj '/CN=test.client.gnmi.sonic' -out gnmiclient.csr""")

    # Sign client certificate
    localhost.shell(f"""cd {cert_dir} && openssl x509 -req -in gnmiclient.csr -CA gnmiCA.cer -CAkey gnmiCA.key \
                       -CAcreateserial -out gnmiclient.cer -days 825 -sha256""")

    # Copy certificates to DUT
    duthost.copy(src=f'{cert_dir}/gnmiCA.cer', dest='/etc/sonic/telemetry/')
    duthost.copy(src=f'{cert_dir}/gnmiserver.cer', dest='/etc/sonic/telemetry/')
    duthost.copy(src=f'{cert_dir}/gnmiserver.key', dest='/etc/sonic/telemetry/')

    # Copy client certificates to PTF container
    ptfhost.copy(src=f'{cert_dir}/gnmiCA.cer', dest='/etc/sonic/telemetry/gnmiCA.cer')
    ptfhost.copy(src=f'{cert_dir}/gnmiclient.cer', dest='/etc/sonic/telemetry/gnmiclient.cer')
    ptfhost.copy(src=f'{cert_dir}/gnmiclient.key', dest='/etc/sonic/telemetry/gnmiclient.key')

    logger.info("Certificate generation and distribution completed")


def _configure_gnoi_tls_server(duthost):
    """Configure CONFIG_DB for TLS mode."""
    logger.info("Configuring gNOI server for TLS mode")

    # Configure GNMI table for TLS mode
    duthost.shell('sonic-db-cli CONFIG_DB hset "GNMI|gnmi" port 50052')
    duthost.shell('sonic-db-cli CONFIG_DB hset "GNMI|gnmi" client_auth true')
    duthost.shell('sonic-db-cli CONFIG_DB hset "GNMI|gnmi" log_level 2')

    # Configure certificate paths
    duthost.shell('sonic-db-cli CONFIG_DB hset "GNMI|certs" ca_crt "/etc/sonic/telemetry/gnmiCA.cer"')
    duthost.shell('sonic-db-cli CONFIG_DB hset "GNMI|certs" server_crt "/etc/sonic/telemetry/gnmiserver.cer"')
    duthost.shell('sonic-db-cli CONFIG_DB hset "GNMI|certs" server_key "/etc/sonic/telemetry/gnmiserver.key"')

    # Register client certificate with appropriate roles
    duthost.shell('''sonic-db-cli CONFIG_DB hset "GNMI_CLIENT_CERT|test.client.gnmi.sonic" "role@" \
                     "gnmi_readwrite,gnmi_config_db_readwrite,gnmi_appl_db_readwrite,gnmi_dpu_appl_db_readwrite,gnoi_readwrite"''')

    logger.info("TLS configuration completed")


def _restart_gnoi_server(duthost):
    """Restart gNOI server to pick up new TLS configuration."""
    logger.info("Restarting gNOI server process")

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
    test_cmd = """grpcurl -cacert /etc/sonic/telemetry/gnmiCA.cer \
                         -cert /etc/sonic/telemetry/gnmiclient.cer \
                         -key /etc/sonic/telemetry/gnmiclient.key \
                         {}:50052 list""".format(duthost.mgmt_ip)

    result = ptfhost.shell(test_cmd, module_ignore_errors=True)

    if result['rc'] != 0:
        raise Exception(f"TLS connectivity test failed: {result['stderr']}")

    if "gnoi.system.System" not in result['stdout']:
        raise Exception(f"gNOI services not found in response: {result['stdout']}")

    # Test basic gNOI call
    time_cmd = """grpcurl -cacert /etc/sonic/telemetry/gnmiCA.cer \
                         -cert /etc/sonic/telemetry/gnmiclient.cer \
                         -key /etc/sonic/telemetry/gnmiclient.key \
                         {}:50052 gnoi.system.System.Time""".format(duthost.mgmt_ip)

    result = ptfhost.shell(time_cmd, module_ignore_errors=True)

    if result['rc'] != 0:
        raise Exception(f"gNOI System.Time test failed: {result['stderr']}")

    if "time" not in result['stdout']:
        raise Exception(f"Invalid System.Time response: {result['stdout']}")

    logger.info("TLS connectivity verification completed successfully")


def _delete_gnoi_certs(localhost):
    """Clean up generated certificate files."""
    logger.info("Cleaning up certificate files")

    # Remove the entire certificate directory in /tmp
    cert_dir = "/tmp/gnoi_certs"
    localhost.shell(f"rm -rf {cert_dir}", module_ignore_errors=True)
