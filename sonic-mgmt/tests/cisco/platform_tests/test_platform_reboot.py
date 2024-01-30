
"""
Cisco specific reboot tests
"""
import time
import logging
import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.reboot import wait_for_startup, reboot, REBOOT_TYPE_COLD
from tests.common.utilities import wait_until
from tests.common.platform.processes_utils import wait_critical_processes


pytestmark = [
    pytest.mark.topology('any')
]

def check_watchdog_service_status(duthost):

    result = duthost.shell("systemctl status watchdog-control.service | grep Active")
    if "Active: inactive (dead)" in result['stdout']:
        return True
    else:
        return False

def test_reboot_watchdog(duthosts, enum_rand_one_per_hwsku_hostname, localhost):
    """
    @summary: Inject an fault on midplane link and check the recovery"`
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    reboot(duthost, localhost, reboot_type=REBOOT_TYPE_COLD, wait_for_ssh=False)

    # SSH will drop and will be available after recovery
    wait_for_startup(duthost, localhost, 10, 300)

    pytest_assert(wait_until(300, 5, 0, check_watchdog_service_status, duthost),
            "Watchdog service did not start")

    time.sleep(1)

    result = duthost.shell("cat /sys/class/watchdog/*/cisco_status")
    assert "Disabled" in str(result), "Watchdog failed to stop during boot"

    wait_critical_processes(duthost)

