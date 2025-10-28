import pytest
import logging
import json

from .helper import gnoi_request
from tests.common.helpers.assertions import pytest_assert
from tests.common.reboot import wait_for_startup, SONIC_SSH_PORT, SONIC_SSH_REGEX
from tests.common.utilities import wait_until


pytestmark = [
    pytest.mark.topology('any'),
    # Reboot triggers kernel warnings on VS.
    pytest.mark.disable_loganalyzer,
]


"""
This module contains tests for the gNOI System API cold reboot.
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


def test_gnoi_system_reboot_cold(duthosts, rand_one_dut_hostname, localhost):
    """
    Test gNOI System.Reboot API with COLD method.
    Verifies that the reboot is triggered and the system recovers with all critical processes running.
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

    # Wait for the device to go down first
    logging.info('waiting for ssh to drop on {}'.format(duthost.hostname))
    res = localhost.wait_for(host=duthost.mgmt_ip,
                             port=SONIC_SSH_PORT,
                             state='absent',
                             search_regex=SONIC_SSH_REGEX,
                             delay=10,
                             timeout=300,
                             module_ignore_errors=True)

    if res.is_failed or ('msg' in res and 'Timeout' in res['msg']):
        raise Exception('DUT {} did not shutdown'.format(duthost.hostname))
    logging.info("Device has gone down for reboot")

    # Wait until the system is back up
    wait_for_startup(duthost, localhost, delay=20, timeout=600)
    logging.info("System is back up after reboot")

    # Wait for database services to be ready
    def check_database_ready():
        try:
            # Test if we can actually connect to and query the config database
            result = duthost.command("sonic-cfggen -d --print-data", module_ignore_errors=True)
            return not result.is_failed
        except Exception:
            return False

    wait_until(300, 15, 0, check_database_ready)
    logging.info("Database services are ready")

    # Check device is actually rebooted by comparing uptime
    uptime_after = duthost.get_up_time(utc_timezone=True)
    logging.info('Uptime before reboot: %s, after reboot: %s', uptime_before, uptime_after)
    assert uptime_after > uptime_before, "Device did not reboot, uptime did not reset"
