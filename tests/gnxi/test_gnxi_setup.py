"""
Test gNxI Environment Setup

This test verifies that the gNxI test environment is properly configured
with gnmi container running on port 8080 with noTLS and insecure mode.
"""
import pytest
import logging

pytestmark = [
    pytest.mark.topology('any'),
]

logger = logging.getLogger(__name__)


def test_gnmi_default_config(duthost):
    """
    Verify gnmi container is running with default configuration.

    This test checks that:
    - gnmi container is running
    - telemetry process is running with --noTLS flag
    - telemetry process is listening on port 8080
    - telemetry process has --allow_no_client_auth flag
    """

    # Get telemetry process info
    output = duthost.shell("docker exec gnmi ps aux | grep telemetry | grep -v grep")

    assert output['rc'] == 0, "telemetry process not found in gnmi container"

    telemetry_cmd = output['stdout']
    logger.info(f"Telemetry command: {telemetry_cmd}")

    # Verify expected flags
    assert "--noTLS" in telemetry_cmd, "telemetry should be running with --noTLS"
    assert "--port 8080" in telemetry_cmd, "telemetry should be listening on port 8080"
    assert "--allow_no_client_auth" in telemetry_cmd, \
        "telemetry should allow unauthenticated clients"

    logger.info("✓ gnmi container is running with default configuration")


def test_gnmi_config_tables_empty(duthost):
    """
    Verify GNMI config tables are empty after setup.

    This test checks that:
    - GNMI|gnmi table does not exist
    - GNMI|certs table does not exist
    """

    # Check GNMI|gnmi table
    output = duthost.shell("sonic-db-cli CONFIG_DB get 'GNMI|gnmi'", module_ignore_errors=True)
    assert output['rc'] != 0 or not output['stdout'], \
        "GNMI|gnmi table should not exist in clean environment"

    # Check GNMI|certs table
    output = duthost.shell("sonic-db-cli CONFIG_DB get 'GNMI|certs'", module_ignore_errors=True)
    assert output['rc'] != 0 or not output['stdout'], \
        "GNMI|certs table should not exist in clean environment"

    logger.info("✓ GNMI config tables are empty")


def test_gnmi_container_running(duthost):
    """
    Verify gnmi container is running and healthy.

    This test checks that:
    - gnmi container is in running state
    - All expected processes are running (supervisord, telemetry, dialout_client_cli)
    """

    # Check container is running
    output = duthost.shell("docker ps | grep gnmi | grep -v grep")
    assert output['rc'] == 0, "gnmi container should be running"
    assert "Up" in output['stdout'], "gnmi container should be in Up state"

    # Check expected processes
    expected_processes = [
        "supervisord",
        "telemetry",
        "dialout_client_cli"
    ]

    output = duthost.shell("docker exec gnmi ps aux")
    for process in expected_processes:
        assert process in output['stdout'], f"{process} should be running in gnmi container"

    logger.info("✓ gnmi container is running with all expected processes")
