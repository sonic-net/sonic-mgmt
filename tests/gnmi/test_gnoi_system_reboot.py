import pytest
import logging
import json

from .helper import gnoi_request, extract_gnoi_response, apply_cert_config
from tests.common.helpers.assertions import pytest_assert
from tests.common.reboot import wait_for_startup
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.utilities import wait_until
from tests.common.plugins.ansible_fixtures import ansible_adhoc
from tests.common.platform.device_utils import create_npu_host_based_on_dpu_info


pytestmark = [
    pytest.mark.topology('any'),
    # Reboot triggers kernel warnings on VS.
    pytest.mark.disable_loganalyzer,
]


"""
This module contains tests for the gNOI System API.
"""

# Enum mapping for RebootMethod for readability
RebootMethod = {
    "UNKNOWN": 0,
    "COLD": 1,
    "POWERDOWN": 2,
    "HALT": 3,
    "WARM": 4,
    "NSF": 5,
    # 6 is reserved
    "POWERUP": 7
}

REBOOT_MESSAGE = "gnoi test reboot"


def is_gnmi_container_running(duthost):
    """
    Check if the gNMI container is running on the DUT.
    """
    return duthost.is_container_running("gnmi")


def check_reboot_status(duthost, localhost, expected_active, expected_reason, expected_method):
    """
    Call gNOI System.RebootStatus and assert the fields and values of the response.
    """
    ret, msg = gnoi_request(duthost, localhost, "System", "RebootStatus", "")
    pytest_assert(ret == 0, "System.RebootStatus API reported failure (rc = {}) with message: {}".format(ret, msg))
    logging.info("System.RebootStatus API returned msg: {}".format(msg))

    status = extract_gnoi_response(msg)
    pytest_assert(status is not None, "Failed to extract JSON from gNOI response")

    pytest_assert("active" in status, "Missing 'active' in RebootStatus")
    pytest_assert("when" in status, "Missing 'when' in RebootStatus")
    pytest_assert("reason" in status, "Missing 'reason' in RebootStatus")
    pytest_assert("count" in status, "Missing 'count' in RebootStatus")
    pytest_assert("method" in status, "Missing 'method' in RebootStatus")
    pytest_assert(status["active"] is expected_active, "'active' should be True after reboot")
    pytest_assert(status["reason"] == expected_reason, f"'reason' should be '{expected_reason}'")
    pytest_assert(status["method"] == expected_method, f"'method' should be {expected_method}")
    pytest_assert(isinstance(status["when"], int) and status["when"] > 0, "'when' should be a positive integer")
    pytest_assert(isinstance(status["count"], int) and status["count"] >= 1, "'count' should be >= 1")


def is_reboot_inactive(duthost, localhost):
    ret, msg = gnoi_request(duthost, localhost, "System", "RebootStatus", "")
    if ret != 0:
        return False
    status = extract_gnoi_response(msg)
    return status and not status.get("active", True)


def test_gnoi_system_reboot_cold(duthosts, rand_one_dut_hostname, localhost):
    """
    Test gNOI System.Reboot API with COLD method.
    Verifies that the reboot is triggered, RebootStatus is correct before and after reboot,
    and the system recovers with all critical processes running.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Skip the test if duthost is DPU only
    if duthost.is_dpu():
        pytest.skip("Test is not applicable for DPU hosts")

    reboot_args = {
        "message": REBOOT_MESSAGE,
        "method": RebootMethod["COLD"]
    }
    # Record uptime before reboot
    uptime_before = duthost.get_up_time(utc_timezone=True)

    ret, msg = gnoi_request(duthost, localhost, "System", "Reboot", json.dumps(reboot_args))
    pytest_assert(ret == 0, "System.Reboot API reported failure (rc = {}) with message: {}".format(ret, msg))
    logging.info("System.Reboot API returned msg: {}".format(msg))

    check_reboot_status(
        duthost, localhost,
        expected_active=True,
        expected_reason=REBOOT_MESSAGE,
        expected_method=RebootMethod["COLD"]
    )

    # Wait until the system is back up
    wait_for_startup(duthost, localhost, delay=20, timeout=600)
    logging.info("System is back up after reboot")

    # Wait for critical processses before ending
    wait_critical_processes(duthost)

    # Wait for gNMI container to be running
    wait_until(120, 10, 0, is_gnmi_container_running, duthost)

    # This is an adhoc workaround because the cert config is cleared after reboot.
    # We should refactor the test to always use the default config.
    apply_cert_config(duthost)

    # Check device is actually rebooted by comparing uptime
    uptime_after = duthost.get_up_time(utc_timezone=True)
    logging.info('Uptime before reboot: %s, after reboot: %s', uptime_before, uptime_after)
    assert uptime_after > uptime_before, "Device did not reboot, uptime did not reset"


def test_gnoi_system_reboot_warm(duthosts, rand_one_dut_hostname, localhost):
    """
    Test gNOI System.Reboot API with WARM method.
    Verifies that the reboot is triggered, RebootStatus is correct before reboot,
    and the system recovers with all critical processes running.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Skip the test if duthost is DPU only
    if duthost.is_dpu():
        pytest.skip("Test is not applicable for DPU hosts")

    reboot_args = {
        "message": REBOOT_MESSAGE,
        "method": RebootMethod["WARM"]
    }

    ret, msg = gnoi_request(duthost, localhost, "System", "Reboot", json.dumps(reboot_args))
    pytest_assert(ret == 0, "System.Reboot API reported failure (rc = {}) with message: {}".format(ret, msg))
    logging.info("System.Reboot API returned msg: {}".format(msg))

    check_reboot_status(
        duthost, localhost,
        expected_active=True,
        expected_reason=REBOOT_MESSAGE,
        expected_method=RebootMethod["WARM"]
    )

    # Wait until the system is back up
    wait_for_startup(duthost, localhost, delay=20, timeout=600)
    logging.info("System is back up after reboot")

    # Wait for critical processes before ending
    wait_critical_processes(duthost)

    # This is an adhoc workaround because the cert config is cleared after reboot.
    # We should refactor the test to always use the default config.
    apply_cert_config(duthost)


def test_gnoi_system_reboot_halt(duthosts, rand_one_dut_hostname, localhost, tbinfo, ansible_adhoc, request):
    """
    Test gNOI System.Reboot API with HALT method.
    Verifies that the reboot is triggered, RebootStatus is correct before reboot,
    and the system recovers with all critical processes running.
    """
    duthost = duthosts[rand_one_dut_hostname]

    reboot_args = {
        "message": REBOOT_MESSAGE,
        "method": RebootMethod["HALT"]
    }

    # Proceed only if duthost is DPU only
    if not duthost.is_dpu():
        pytest.skip("Test is applicable only for DPU hosts")

    ret, msg = gnoi_request(duthost, localhost, "System", "Reboot", json.dumps(reboot_args))
    pytest_assert(ret == 0, "System.Reboot API reported failure (rc = {}) with message: {}".format(ret, msg))
    logging.info("System.Reboot API returned msg: {}".format(msg))

    check_reboot_status(
        duthost, localhost,
        expected_active=True,
        expected_reason=REBOOT_MESSAGE,
        expected_method=RebootMethod["HALT"]
    )

    wait_until(120, 10, 0, is_reboot_inactive)
    logging.info("HALT reboot is completed")

    npu_host = create_npu_host_based_on_dpu_info(ansible_adhoc, tbinfo, request, duthost)

    # Extract the last number from the duthost name
    dpu_number = int(duthost.hostname.split('-')[-1])

    # Validate dpu_number and log error if out of range
    if not (0 <= dpu_number <= 8):
        pytest.fail(f"Invalid dpu_number {dpu_number}, must be between 0 and 8")

    npu_host.command(f"sudo reboot -d DPU{dpu_number}")

    # Wait until the system is back up
    wait_for_startup(duthost, localhost, delay=20, timeout=600)
    logging.info("System is back up after reboot")

    # Wait for critical processes before ending
    wait_critical_processes(duthost)

    # Wait for gNMI container to be running
    wait_until(120, 10, 0, is_gnmi_container_running, duthost)

    # This is an adhoc workaround because the cert config is cleared after reboot.
    # We should refactor the test to always use the default config.
    apply_cert_config(duthost)
