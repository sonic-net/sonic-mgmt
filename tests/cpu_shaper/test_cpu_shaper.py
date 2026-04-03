"""
    Tests the cpu queue shaper configuration in BRCM platforms
    is as expected across reboot/warm-reboots.
    Mellanox and Cisco platforms do not have CPU shaper
    configurations and are not included in this test.

"""

import logging
import pytest
import re

from tests.common import config_reload
from tests.common.reboot import reboot
from tests.common.platform.processes_utils import wait_critical_processes

pytestmark = [
    pytest.mark.topology("t0", "t1"),
    pytest.mark.asic("broadcom")
]

logger = logging.getLogger(__name__)

BCM_CINT_FILENAME = "get_shaper.c"
DEST_DIR = "/tmp"
CMD_GET_SHAPER = "bcmcmd 'cint {}'".format(BCM_CINT_FILENAME)


def verify_cpu_queue_shaper(dut):
    """
    Verify cpu queue shaper configuration is as expected

    Args:
        dut (SonicHost): The target device
    """
    # Copy cint script to /tmp on the device
    dut.copy(src="cpu_shaper/scripts/{}".format(BCM_CINT_FILENAME), dest=DEST_DIR)

    # Copy cint script to the syncd container
    dut.shell("docker cp {}/{} syncd:/".format(DEST_DIR, BCM_CINT_FILENAME))

    # Execute the cint script and parse the output
    res = dut.shell(CMD_GET_SHAPER)['stdout']

    # Expected shaper PPS configuration for CPU queues 0, and 7
    expected_pps = {0: 600, 7: 600}
    pattern = r'cos=(\d+) pps_max=(\d+)'
    matches = re.findall(pattern, res)
    actual_pps = {int(cos): int(pps) for cos, pps in matches}
    assert (expected_pps == actual_pps)


@pytest.mark.disable_loganalyzer
def test_cpu_queue_shaper(duthosts, localhost, enum_rand_one_per_hwsku_frontend_hostname, request):
    """
    Validates the cpu queue shaper configuration after reboot(reboot, warm-reboot)

    """
    try:
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        reboot_type = request.config.getoption("--cpu_shaper_reboot_type")

        # Perform reboot as specified via the reboot_type parameter
        logger.info("Do {} reboot".format(reboot_type))
        reboot(duthost, localhost, reboot_type=reboot_type, reboot_helper=None, reboot_kwargs=None)

        # Wait for critical processes to be up
        wait_critical_processes(duthost)
        logger.info("Verify cpu queue shaper config after {} reboot".format(reboot_type))

        # Verify cpu queue shaper configuration
        verify_cpu_queue_shaper(duthost)

    finally:
        duthost.shell("rm {}/{}".format(DEST_DIR, BCM_CINT_FILENAME))
        config_reload(duthost)
