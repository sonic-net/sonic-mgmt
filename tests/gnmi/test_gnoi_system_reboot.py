"""
This module contains tests for the gNOI System Reboot API.
"""
import pytest
import logging

from tests.common.helpers.assertions import pytest_assert
from tests.common.reboot import wait_for_startup
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.utilities import wait_until

from tests.common.fixtures.grpc_fixtures import gnmi_tls    # noqa: F401


pytestmark = [
    pytest.mark.topology('any'),
    # Reboot triggers kernel warnings on VS.
    pytest.mark.disable_loganalyzer,
]


REBOOT_MESSAGE = "gnoi test reboot"


def is_gnmi_container_running(duthost):
    """Check if the gNMI container is running on the DUT."""
    return duthost.is_container_running("gnmi")


def check_reboot_status(gnmi_tls, expected_active, expected_reason, expected_method):    # noqa: F811
    """
    Call gNOI System.RebootStatus and assert the fields and values of the response.

    Args:
        gnmi_tls: GnmiFixture instance
        expected_active: Expected value of 'active' field
        expected_reason: Expected value of 'reason' field
        expected_method: Expected method name as string (e.g., "COLD", "WARM")
                         Note: grpcurl JSON output returns proto enums as strings
    """
    status = gnmi_tls.gnoi.reboot_status()
    pytest_assert(status is not None, "Failed to get reboot status")

    pytest_assert("active" in status, "Missing 'active' in RebootStatus")
    pytest_assert("when" in status, "Missing 'when' in RebootStatus")
    pytest_assert("reason" in status, "Missing 'reason' in RebootStatus")
    pytest_assert("count" in status, "Missing 'count' in RebootStatus")
    pytest_assert("method" in status, "Missing 'method' in RebootStatus")
    pytest_assert(status["active"] is expected_active, "'active' should be True after reboot")
    pytest_assert(status["reason"] == expected_reason,
                  "'reason' should be '{}'".format(expected_reason))
    # grpcurl JSON returns proto enum values as strings (e.g., "COLD" not 1)
    pytest_assert(status["method"] == expected_method,
                  "'method' should be '{}', got '{}'".format(expected_method, status['method']))
    # Protobuf3 JSON encoding: int64 is serialized as string to preserve precision
    when_value = int(status["when"]) if isinstance(status["when"], str) else status["when"]
    pytest_assert(isinstance(when_value, int) and when_value > 0, "'when' should be a positive integer")
    # Protobuf3 JSON encoding: uint32 may also be serialized as string
    count_value = int(status["count"]) if isinstance(status["count"], str) else status["count"]
    pytest_assert(isinstance(count_value, int) and count_value >= 1, "'count' should be >= 1")


def test_gnoi_system_reboot_cold(duthosts, rand_one_dut_hostname, localhost, gnmi_tls):  # noqa: F811
    """
    Test gNOI System.Reboot API with COLD method.

    Verifies that the reboot is triggered, RebootStatus is correct before and after reboot,
    and the system recovers with all critical processes running.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Record uptime before reboot
    uptime_before = duthost.get_up_time(utc_timezone=True)

    # Trigger reboot via gNOI using gnmi_tls fixture
    reboot_response = gnmi_tls.gnoi.system_reboot(
        method="COLD",
        message=REBOOT_MESSAGE
    )
    logging.info("System.Reboot API returned: {}".format(reboot_response))

    check_reboot_status(
        gnmi_tls,
        expected_active=True,
        expected_reason=REBOOT_MESSAGE,
        expected_method="COLD"
    )

    # Wait until the system is back up
    wait_for_startup(duthost, localhost, delay=20, timeout=600)
    logging.info("System is back up after reboot")

    # Wait for critical processes before ending
    wait_critical_processes(duthost)

    # Wait for gNMI container to be running
    wait_until(120, 10, 0, is_gnmi_container_running, duthost)

    # Reconfigure gNMI server for TLS after reboot
    gnmi_tls.reconfigure_after_reboot()

    # Check device is actually rebooted by comparing uptime
    uptime_after = duthost.get_up_time(utc_timezone=True)
    logging.info('Uptime before reboot: %s, after reboot: %s', uptime_before, uptime_after)
    pytest_assert(uptime_after > uptime_before, "Device did not reboot, uptime did not reset")


def test_gnoi_system_reboot_warm(duthosts, rand_one_dut_hostname, localhost, gnmi_tls):  # noqa: F811
    """
    Test gNOI System.Reboot API with WARM method.

    Verifies that the reboot is triggered, RebootStatus is correct before reboot,
    and the system recovers with all critical processes running.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Trigger reboot via gNOI using gnmi_tls fixture
    reboot_response = gnmi_tls.gnoi.system_reboot(
        method="WARM",
        message=REBOOT_MESSAGE
    )
    logging.info("System.Reboot API returned: {}".format(reboot_response))

    check_reboot_status(
        gnmi_tls,
        expected_active=True,
        expected_reason=REBOOT_MESSAGE,
        expected_method="WARM"
    )

    # Wait until the system is back up
    wait_for_startup(duthost, localhost, delay=20, timeout=600)
    logging.info("System is back up after reboot")

    # Wait for critical processes before ending
    # Warm reboot takes longer for containers to restart; use an extended timeout
    wait_critical_processes(duthost, timeout=360)

    # Wait for gNMI container to be running
    wait_until(120, 10, 0, is_gnmi_container_running, duthost)

    # Reconfigure gNMI server for TLS after reboot
    gnmi_tls.reconfigure_after_reboot()
