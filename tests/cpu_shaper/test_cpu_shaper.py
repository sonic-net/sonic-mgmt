"""
    Tests that the CPU queue shaper configuration on Broadcom platforms
    PERSISTS across reboot/warm-reboot.

    The absolute shaper PPS values are platform-quantized: each ASIC rounds the
    configured CoPP rate to its own nearest representable step (e.g. 600 -> 608
    on TH5, 600 -> 640 on TH6). The test therefore validates persistence
    (before == after) rather than a hardcoded expected PPS, so it stays correct
    as new Broadcom SKUs/ASIC generations are onboarded without per-platform
    tuning.

    Mellanox and Cisco platforms do not have CPU shaper configurations and are
    not included in this test.
"""

import logging
import pytest
import re

from tests.common import config_reload
from tests.common.reboot import reboot
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.utilities import wait_until

pytestmark = [
    pytest.mark.topology("t0", "t1"),
    pytest.mark.asic("broadcom")
]

logger = logging.getLogger(__name__)

BCM_CINT_FILENAME = "get_shaper.c"
DEST_DIR = "/tmp"
CMD_GET_SHAPER = "bcmcmd 'cint {}'".format(BCM_CINT_FILENAME)
EXPECTED_COS_QUEUES = {0, 7}


def get_cpu_queue_shaper(dut):
    """
    Read the CPU queue shaper PPS configuration from the ASIC.

    Args:
        dut (SonicHost): The target device

    Returns:
        dict: Mapping of cos queue index to the platform-reported PPS max value,
            e.g. {0: <pps>, 7: <pps>}. The values are platform-quantized and must
            NOT be compared against a hardcoded expected PPS. Returns {} (and logs
            a warning) if the bcmcmd output cannot be parsed.
    """
    # Copy cint script to /tmp on the device
    dut.copy(src="cpu_shaper/scripts/{}".format(BCM_CINT_FILENAME), dest=DEST_DIR)

    # Copy cint script to the syncd container
    dut.shell("docker cp {}/{} syncd:/".format(DEST_DIR, BCM_CINT_FILENAME))

    # Execute the cint script and parse the output
    res = dut.shell(CMD_GET_SHAPER)['stdout']

    pattern = r'cos=(\d+) pps_max=(\d+)'
    matches = re.findall(pattern, res)
    if not matches:
        logger.warning("No cos/pps_max pairs found in bcmcmd output: %s", res)
    return {int(cos): int(pps) for cos, pps in matches}


@pytest.mark.disable_loganalyzer
def test_cpu_queue_shaper(duthosts, localhost, enum_rand_one_per_hwsku_frontend_hostname, request):
    """
    Validates the CPU queue shaper configuration survives reboot by comparing
    the per-queue shaper values before and after reboot.

    The absolute PPS values are platform-quantized (see module docstring), so we
    only assert that the expected queues are programmed (present and non-zero)
    and that the values are unchanged across the reboot. We intentionally do NOT
    assert an absolute PPS, to remain correct across Broadcom ASIC generations.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    def cos_queues_present():
        before_pps = get_cpu_queue_shaper(duthost)
        missing = EXPECTED_COS_QUEUES - set(before_pps.keys())
        return not bool(missing)

    try:
        reboot_type = request.config.getoption("--cpu_shaper_reboot_type")

        # Validate all expected queues are present with non-zero shaper values
        if not wait_until(300, 10, 1, cos_queues_present):
            before_pps = get_cpu_queue_shaper(duthost)
            missing = EXPECTED_COS_QUEUES - set(before_pps.keys())
            assert False, f"CPU queue shaper missing for cos queues {missing} before reboot. Got: {before_pps}"

        # Read shaper config before reboot
        before_pps = get_cpu_queue_shaper(duthost)
        logger.info("CPU queue shaper before reboot: {}".format(before_pps))

        assert all(before_pps[cos] > 0 for cos in EXPECTED_COS_QUEUES), \
            "CPU queue shaper has zero PPS before reboot: {}".format(before_pps)

        # Perform reboot
        logger.info("Do {} reboot".format(reboot_type))
        reboot(duthost, localhost, reboot_type=reboot_type, reboot_helper=None, reboot_kwargs=None)

        # Wait for critical processes to be up
        wait_critical_processes(duthost)

        # Verify shaper config survived reboot unchanged
        assert wait_until(300, 10, 1, lambda: get_cpu_queue_shaper(duthost) == before_pps), (
                "CPU queue shaper changed after {} reboot: before={}, after={}".format(
                    reboot_type, before_pps, get_cpu_queue_shaper(duthost)))

        # Read shaper config after reboot
        logger.info("CPU queue shaper after {} reboot: {}".format(reboot_type, get_cpu_queue_shaper(duthost)))

    finally:
        duthost.shell("rm -f {}/{}".format(DEST_DIR, BCM_CINT_FILENAME))
        config_reload(duthost)
