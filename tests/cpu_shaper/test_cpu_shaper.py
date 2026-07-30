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
EXPECTED_COS_QUEUES = {0, 7}
EXPECTED_PPS = 600
PPS_TOLERANCE = 0.05  # Allow 5% tolerance in PPS values


def get_cpu_queue_shaper(dut):
    """
    Read cpu queue shaper PPS configuration from the ASIC.

    Args:
        dut (SonicHost): The target device

    Returns:
        dict: Mapping of cos queue index to PPS max value, e.g. {0: 600, 7: 600}
    """
    # Copy cint script to /tmp on the device
    dut.copy(src="cpu_shaper/scripts/{}".format(BCM_CINT_FILENAME), dest=DEST_DIR)

    # Copy cint script to the syncd container
    dut.shell("docker cp {}/{} syncd:/".format(DEST_DIR, BCM_CINT_FILENAME))

    # Execute the cint script and parse the output
    res = dut.shell(CMD_GET_SHAPER)['stdout']

    pattern = r'cos=(\d+) pps_max=(\d+)'
    matches = re.findall(pattern, res)
    return {int(cos): int(pps) for cos, pps in matches}


@pytest.mark.disable_loganalyzer
def test_cpu_queue_shaper(duthosts, localhost, enum_rand_one_per_hwsku_frontend_hostname, request):
    """
    Validates the cpu queue shaper configuration survives reboot by comparing
    shaper values before and after reboot.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    try:
        reboot_type = request.config.getoption("--cpu_shaper_reboot_type")
        # Read shaper config before reboot
        before_pps = get_cpu_queue_shaper(duthost)
        logger.info("CPU queue shaper before reboot: {}".format(before_pps))

        # Validate all expected queues are present with non-zero shaper values
        missing = EXPECTED_COS_QUEUES - set(before_pps.keys())
        assert not missing, \
            "CPU queue shaper missing for cos queues {} before reboot. Got: {}".format(missing, before_pps)
        assert all(before_pps[cos] > 0 for cos in EXPECTED_COS_QUEUES), \
            "CPU queue shaper has zero PPS before reboot: {}".format(before_pps)
        # Validate shaper values are close to original 600 PPS (allowing 5% tolerance)
        pps_low, pps_high = int(EXPECTED_PPS * (1 - PPS_TOLERANCE)), int(EXPECTED_PPS * (1 + PPS_TOLERANCE))
        for cos in EXPECTED_COS_QUEUES:
            assert pps_low <= before_pps[cos] <= pps_high, \
                "CPU queue {} shaper PPS {} is outside {}% tolerance of {} PPS".format(
                    cos, before_pps[cos], int(PPS_TOLERANCE * 100), EXPECTED_PPS)

        # Perform reboot
        logger.info("Do {} reboot".format(reboot_type))
        reboot(duthost, localhost, reboot_type=reboot_type, reboot_helper=None, reboot_kwargs=None)

        # Wait for critical processes to be up
        wait_critical_processes(duthost)

        # Read shaper config after reboot
        after_pps = get_cpu_queue_shaper(duthost)
        logger.info("CPU queue shaper after {} reboot: {}".format(reboot_type, after_pps))

        # Verify shaper config survived reboot unchanged
        assert before_pps == after_pps, \
            "CPU queue shaper changed after {} reboot: before={}, after={}".format(
                reboot_type, before_pps, after_pps)

    finally:
        duthost.shell("rm -f {}/{}".format(DEST_DIR, BCM_CINT_FILENAME))
        config_reload(duthost)
