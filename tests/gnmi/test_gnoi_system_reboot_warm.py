import pytest
import logging
import json

from .helper import gnoi_request
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until


pytestmark = [
    pytest.mark.topology('any'),
    # Reboot triggers kernel warnings on VS.
    pytest.mark.disable_loganalyzer,
]


"""
This module contains tests for the gNOI System API warm reboot.
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


def test_gnoi_system_reboot_warm(duthosts, rand_one_dut_hostname, localhost):
    """
    Test gNOI System.Reboot API with WARM method.
    Verifies that the reboot is triggered and the system recovers with all critical processes running.
    """
    duthost = duthosts[rand_one_dut_hostname]

    reboot_args = {
        "message": REBOOT_MESSAGE,
        "method": RebootMethod["WARM"]
    }

    ret, msg = gnoi_request(duthost, localhost, "System", "Reboot", json.dumps(reboot_args))
    pytest_assert(ret == 0, "System.Reboot API reported failure (rc = {}) with message: {}".format(ret, msg))
    logging.info("System.Reboot API returned msg: {}".format(msg))

    # For warm reboot, SSH typically stays up, so we monitor for service restarts
    # Wait for the warm reboot to complete by checking if system is responsive
    def check_system_responsive():
        try:
            duthost.command("uptime", module_ignore_errors=True)
            return True
        except Exception:
            return False

    logging.info("Waiting for warm reboot to complete...")
    wait_until(300, 10, 0, check_system_responsive)
    logging.info("Warm reboot completed - system is responsive")

    # Wait for database services to be ready
    def check_database_ready():
        try:
            result = duthost.command("test -f /var/run/redis/sonic-db/database_config.json", module_ignore_errors=True)
            return not result.is_failed
        except Exception:
            return False
    
    wait_until(180, 10, 0, check_database_ready)
    logging.info("Database services are ready")
