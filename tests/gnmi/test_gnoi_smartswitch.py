"""
This module contains gNOI tests specific to SmartSwitch/DPU platforms.
"""
import pytest
import logging
import json

from .helper import gnoi_request_dpu, extract_gnoi_response, is_reboot_inactive
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.conftest import get_specified_dpus
from tests.common.platform.device_utils import reboot_dpu_and_wait_for_start_up


pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.usefixtures("setup_gnmi_ntp_client_server", "setup_gnmi_server",
                            "setup_gnmi_rotated_server", "check_dut_timestamp")
]


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


def check_dpu_reboot_status(duthost, localhost, dpu_index, expected_active, expected_reason, expected_method):
    """
    Call gNOI System.RebootStatus for DPU and assert the fields and values of the response.
    """
    ret, msg = gnoi_request_dpu(duthost, localhost, dpu_index, "System", "RebootStatus", "")
    pytest_assert(ret == 0,
                  "System.RebootStatus API reported failure (rc = {}) with message: {}".format(ret, msg))
    logging.info("System.RebootStatus API returned msg: {}".format(msg))

    status = extract_gnoi_response(msg)
    pytest_assert(status is not None, "Failed to extract JSON from gNOI response")

    pytest_assert("active" in status, "Missing 'active' in RebootStatus")
    pytest_assert("when" in status, "Missing 'when' in RebootStatus")
    pytest_assert("reason" in status, "Missing 'reason' in RebootStatus")
    pytest_assert("count" in status, "Missing 'count' in RebootStatus")
    pytest_assert("method" in status, "Missing 'method' in RebootStatus")
    pytest_assert(status["active"] is expected_active,
                  "'active' should be {} after reboot".format(expected_active))
    pytest_assert(status["reason"] == expected_reason,
                  "'reason' should be '{}'".format(expected_reason))
    pytest_assert(status["method"] == expected_method,
                  "'method' should be {}".format(expected_method))
    pytest_assert(isinstance(status["when"], int) and status["when"] > 0,
                  "'when' should be a positive integer")
    pytest_assert(isinstance(status["count"], int) and status["count"] >= 1,
                  "'count' should be >= 1")


def test_gnoi_system_reboot_halt_dpus(duthosts, rand_one_dut_hostname, localhost, request):
    """
    Test gNOI System.Reboot API with HALT method for DPUs.

    Verifies that the reboot is triggered, RebootStatus is correct before reboot,
    and the DPU recovers properly.
    """
    duthost = duthosts[rand_one_dut_hostname]

    dpuhost_names = get_specified_dpus(request)
    if dpuhost_names:
        logging.info("dpuhost_names: {}".format(dpuhost_names))
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
            pytest.fail("Invalid dpu_index {}, must be between 0 and 8".format(dpu_index))

        ret, msg = gnoi_request_dpu(duthost, localhost, dpu_index, "System", "Reboot", json.dumps(reboot_args))
        pytest_assert(ret == 0,
                      "System.Reboot API reported failure (rc = {}) with message: {}".format(ret, msg))
        logging.info("System.Reboot API returned msg: {}".format(msg))

        check_dpu_reboot_status(
            duthost, localhost, dpu_index,
            expected_active=True,
            expected_reason=REBOOT_MESSAGE,
            expected_method=RebootMethod["HALT"]
        )

        wait_until(120, 10, 0, is_reboot_inactive, duthost, localhost)
        logging.info("HALT reboot is completed")

        dpu_reboot_status = reboot_dpu_and_wait_for_start_up(duthost, dpuhost_name, dpu_index)
        if not dpu_reboot_status:
            pytest.fail("DPU {} (DPU index: {}) failed to reboot properly".format(dpuhost_name, dpu_index))

        logging.info("DPU {} (DPU index: {}) rebooted successfully".format(dpuhost_name, dpu_index))
