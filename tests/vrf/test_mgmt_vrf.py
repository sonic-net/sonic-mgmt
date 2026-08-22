import time
import logging

import pytest
import allure

from tests.common.helpers.assertions import pytest_assert

pytestmark = [pytest.mark.topology("t0")]

logger = logging.getLogger(__name__)


def test_mgmt_vrf_configuration(ptfhost, duthosts, rand_one_dut_hostname, tbinfo):
    """
    Test management VRF configuration and connectivity.

    Purpose:
        Verify that management VRF can be enabled and disabled on the DUT
        and that management traffic works correctly when the VRF is enabled.

    Test Steps:
        1. Enable management VRF using "config vrf add mgmt".
        2. Verify management VRF is enabled using "show mgmt-vrf".
        3. Verify that management interface (eth0) is associated with mgmt VRF.
        4. Verify connectivity by pinging the PTF host management IP using
           "ip vrf exec mgmt ping".
        5. Remove management VRF using "config vrf del mgmt".
        6. Verify management VRF is disabled.
        7. Verify that ping via mgmt VRF fails after VRF removal.

    Expected Result:
        - Management VRF is successfully enabled and eth0 is attached to it.
        - Ping through mgmt VRF succeeds when VRF is enabled.
        - After removing mgmt VRF, ping through mgmt VRF fails.
    """

    duthost = duthosts[rand_one_dut_hostname]
    server_ip = ptfhost.mgmt_ip

    with allure.step("Enable mgmt VRF"):
        logger.info("Configuring management VRF")
        duthost.shell("sudo config vrf add mgmt", module_ignore_errors=True)
        time.sleep(5)

    with allure.step("Verify mgmt VRF is enabled"):
        result = duthost.shell("show mgmt-vrf", module_ignore_errors=True)
        pytest_assert(
            "Enabled" in result.get("stdout", ""),
            "Management VRF is not enabled on DUT"
        )

    with allure.step("Verify eth0 is associated with mgmt VRF"):
        result = duthost.shell("ip link show eth0", module_ignore_errors=True)
        pytest_assert(
            "master mgmt" in result.get("stdout", ""),
            "eth0 is not attached to mgmt VRF"
        )

    with allure.step("Verify connectivity through mgmt VRF"):
        ping_cmd = f"sudo ip vrf exec mgmt ping -c 5 -I {duthost.mgmt_ip} {server_ip}"
        result = duthost.shell(ping_cmd, module_ignore_errors=True)
        pytest_assert(
            result.get("rc", 1) == 0,
            f"Unable to ping server ({server_ip}) via mgmt VRF"
        )

    with allure.step("Remove mgmt VRF"):
        logger.info("Removing management VRF")
        duthost.shell("sudo config vrf del mgmt", module_ignore_errors=True)
        time.sleep(10)

    with allure.step("Verify mgmt VRF is disabled"):
        result = duthost.shell("show mgmt-vrf", module_ignore_errors=True)
        pytest_assert(
            "Disabled" in result.get("stdout", ""),
            "Management VRF was not removed"
        )

    with allure.step("Verify ping fails after mgmt VRF removal"):
        result = duthost.shell(ping_cmd, module_ignore_errors=True)
        pytest_assert(
            result.get("rc", 0) != 0,
            "Ping via mgmt VRF should fail after VRF deletion"
        )
