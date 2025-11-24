"""
gNxI Test Suite Configuration

This module provides fixtures for testing gNxI (gNOI, gNMI, gNSI, etc.) features with a clean setup.
Setup ensures gnmi container runs with default settings (port 8080, noTLS, insecure).
"""
import pytest
import logging
import time

from tests.common.helpers.assertions import pytest_require as pyrequire
from tests.common.helpers.dut_utils import check_container_state
from tests.common.gu_utils import create_checkpoint, rollback
from tests.gnxi.grpc_client import create_grpc_client

logger = logging.getLogger(__name__)

GNXI_CHECKPOINT = "gnxi_test_checkpoint"
GNMI_RESTART_WAIT_SECONDS = 3


def verify_gnmi_running(duthost):
    """Verify gnmi container is running with expected process."""
    output = duthost.shell("docker exec gnmi ps aux | grep telemetry", module_ignore_errors=True)
    if output['rc'] != 0:
        return False

    # Check for expected flags: --noTLS --port 8080 --allow_no_client_auth
    expected_flags = ["--noTLS", "--port 8080", "--allow_no_client_auth"]
    for flag in expected_flags:
        if flag not in output['stdout']:
            logger.warning(f"Missing expected flag: {flag}")
            return False

    return True


def cleanup_gnmi_config(duthost):
    """Remove GNMI|gnmi and GNMI|certs tables from config."""
    logger.info("Cleaning up GNMI config tables")

    # Delete GNMI|gnmi table
    cmd = "sonic-db-cli CONFIG_DB del 'GNMI|gnmi'"
    duthost.shell(cmd, module_ignore_errors=True)

    # Delete GNMI|certs table
    cmd = "sonic-db-cli CONFIG_DB del 'GNMI|certs'"
    duthost.shell(cmd, module_ignore_errors=True)


def restart_gnmi_process(duthost):
    """Restart gnmi telemetry process using supervisorctl."""
    logger.info("Restarting gnmi-native process via supervisorctl")
    duthost.shell("docker exec gnmi supervisorctl restart gnmi-native")

    # Wait for telemetry process to restart
    time.sleep(GNMI_RESTART_WAIT_SECONDS)

    # Verify process is running
    output = duthost.shell("docker exec gnmi supervisorctl status gnmi-native")
    pyrequire("RUNNING" in output['stdout'], "gnmi-native process failed to start")


@pytest.fixture(scope="module", autouse=True)
def setup_gnxi_environment(duthosts, rand_one_dut_hostname):
    """
    Setup clean gNxI test environment (runs automatically for all gnxi tests).

    This fixture runs automatically for every test in the gnxi module to ensure
    a clean environment. Tests should use standard framework fixtures (duthost,
    grpc_client) rather than referencing this fixture directly.

    Setup:
    1. Create checkpoint of current configuration
    2. Delete GNMI|gnmi and GNMI|certs tables
    3. Restart gnmi process
    4. Verify gnmi is running with default settings (port 8080, noTLS, insecure)

    Teardown:
    1. Rollback to checkpoint
    2. Restart gnmi process to apply restored config
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Check if gnmi container exists
    pyrequire(
        check_container_state(duthost, "gnmi", should_be_running=True),
        "gnmi container is not available on this device"
    )

    logger.info("Setting up clean gNxI test environment")

    # Create checkpoint before making changes
    create_checkpoint(duthost, GNXI_CHECKPOINT)

    # Clean GNMI config tables
    cleanup_gnmi_config(duthost)

    # Restart gnmi process
    restart_gnmi_process(duthost)

    # Verify gnmi is running with default settings
    is_running = verify_gnmi_running(duthost)
    pyrequire(
        is_running,
        "gnmi container is not running with expected default settings"
    )

    logger.info("gNxI test environment setup complete - gnmi running on port 8080 with noTLS")

    yield

    # Teardown: Rollback configuration
    logger.info("Tearing down gNxI test environment")
    rollback(duthost, GNXI_CHECKPOINT)

    # Restart gnmi process to apply restored configuration
    restart_gnmi_process(duthost)

    logger.info("gNxI test environment teardown complete")


@pytest.fixture(scope="module")
def grpc_client(setup_gnxi_environment, duthosts, rand_one_dut_hostname, localhost):
    """
    Create and initialize gRPC client for testing.

    This fixture depends on setup_gnxi_environment to ensure a clean test
    environment before creating the gRPC client.

    This fixture:
    1. Creates CLI-based gRPC client using grpcurl
    2. Connects to DUT on port 8080 (insecure)
    3. Downloads grpcurl on first use
    4. Yields connected client for test use
    5. Closes client on teardown

    Args:
        setup_gnxi_environment: Ensures clean environment (implicit dependency)
        duthosts: DUT host objects
        rand_one_dut_hostname: Selected DUT hostname
        localhost: VM host where grpcurl will run

    Yields:
        GrpcCliClient: Connected gRPC client ready for RPC calls
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Get DUT management IP
    dut_ip = duthost.mgmt_ip

    logger.info(f"Creating gRPC client for {dut_ip}")

    # Create CLI client
    client = create_grpc_client(
        client_type="cli",
        vmhost=localhost,
        target=dut_ip,
        port=8080,
        insecure=True
    )

    # Initialize client (download grpcurl if needed)
    client.connect()

    logger.info("gRPC client connected and ready")

    yield client

    # Cleanup
    client.close()
    logger.info("gRPC client closed")
