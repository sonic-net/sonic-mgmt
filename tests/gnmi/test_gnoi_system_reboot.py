import pytest
import logging
import json

from .helper import gnoi_request, extract_gnoi_response, apply_cert_config, gnoi_request_dpu, handle_dpu_reboot, \
                    is_reboot_inactive
from tests.common.helpers.assertions import pytest_assert
from tests.common.reboot import wait_for_startup
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.utilities import wait_until
from tests.conftest import get_specified_dpus


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


def check_reboot_status(duthost, localhost, dpu_index, expected_active, expected_reason, expected_method):
    """
    Call gNOI System.RebootStatus and assert the fields and values of the response.
    """
    if expected_method == RebootMethod["HALT"]:
        ret, msg = gnoi_request_dpu(duthost, localhost, dpu_index, "System", "RebootStatus", "")
    else:
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


def test_gnoi_system_reboot_cold(duthosts, rand_one_dut_hostname, localhost):
    """
    Test gNOI System.Reboot API with COLD method.
    Verifies that the reboot is triggered, RebootStatus is correct before and after reboot,
    and the system recovers with all critical processes running.
    """
    duthost = duthosts[rand_one_dut_hostname]

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
        duthost, localhost, dpu_index=None,
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

    reboot_args = {
        "message": REBOOT_MESSAGE,
        "method": RebootMethod["WARM"]
    }

    ret, msg = gnoi_request(duthost, localhost, "System", "Reboot", json.dumps(reboot_args))
    pytest_assert(ret == 0, "System.Reboot API reported failure (rc = {}) with message: {}".format(ret, msg))
    logging.info("System.Reboot API returned msg: {}".format(msg))

    check_reboot_status(
        duthost, localhost, dpu_index=None,
        expected_active=True,
        expected_reason=REBOOT_MESSAGE,
        expected_method=RebootMethod["WARM"]
    )

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


def test_gnoi_system_reboot_halt(duthosts, rand_one_dut_hostname, localhost, tbinfo, ansible_adhoc, request):
    """
    Test gNOI System.Reboot API with HALT method.
    Verifies that the reboot is triggered, RebootStatus is correct before reboot,
    and the system recovers with all critical processes running.
    """
    duthost = duthosts[rand_one_dut_hostname]

    dpuhost_names = get_specified_dpus(request)
    if dpuhost_names:
        logging.info(f"dpuhost_names: {dpuhost_names}")
    else:
        pytest.skip("No DPUs specified, skipping HALT reboot test.")

    reboot_args = {
        "message": REBOOT_MESSAGE,
        "method": RebootMethod["HALT"]
    }

    for dpuhost_name in dpuhost_names:
        # Extract the last number from the duthost name
        dpu_index = int(dpuhost_name.split('-')[-1])

        # Validate dpu_index and log error if out of range
        if not (0 <= dpu_index <= 8):
            pytest.fail(f"Invalid dpu_index {dpu_index}, must be between 0 and 8")

        ret, msg = gnoi_request_dpu(duthost, localhost, dpu_index, "System", "Reboot", json.dumps(reboot_args))
        pytest_assert(ret == 0, "System.Reboot API reported failure (rc = {}) with message: {}".format(ret, msg))
        logging.info("System.Reboot API returned msg: {}".format(msg))

        check_reboot_status(
            duthost, localhost, dpu_index,
            expected_active=True,
            expected_reason=REBOOT_MESSAGE,
            expected_method=RebootMethod["HALT"]
        )

        wait_until(120, 10, 0, is_reboot_inactive, duthost, localhost)
        logging.info("HALT reboot is completed")

        dpu_reboot_status = handle_dpu_reboot(duthost, localhost, dpuhost_name, dpu_index, ansible_adhoc)
        if not dpu_reboot_status:
            pytest.fail(f"DPU {dpuhost_name} (DPU index: {dpu_index}) failed to reboot properly")

        logging.info(f"DPU {dpuhost_name} (DPU index: {dpu_index}) rebooted successfully")
