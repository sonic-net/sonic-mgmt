
"""
Cisco specific reboot tests
"""
import time
import logging
import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.reboot import wait_for_startup, reboot, REBOOT_TYPE_COLD, REBOOT_TYPE_WATCHDOG
from tests.platform_tests.test_reboot import check_interfaces_and_services
from tests.common.utilities import wait_until
from tests.common.platform.processes_utils import wait_critical_processes
import tests.platform_tests.test_kdump
from tests.platform_tests.test_kdump import TestKernelPanic
from tests.platform_tests.conftest import xcvr_skip_list
from tests.cisco.common.utils import skip_if_sim


pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]

def check_watchdog_service_status(duthost):

    result = duthost.shell("systemctl status watchdog-control.service | grep status")
    if "code=exited, status=0/SUCCESS" in result['stdout']:
        return True
    else:
        return False

def test_reboot_watchdog(duthosts, enum_rand_one_per_hwsku_hostname, localhost):
    """
    @summary: Check cisco watchdog is disabled in boot by watchdog control service
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


class TestKdumpCisco(TestKernelPanic):

    def test_kdump_enabled(self, duthosts, enum_rand_one_per_hwsku_hostname):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]

        out = duthost.command('show kdump config')
        assert "Enabled" in out["stdout"]

    def test_watchdog_kdump(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost,
            conn_graph_facts, xcvr_skip_list, skip_if_sim):

        duthost = duthosts[enum_rand_one_per_hwsku_hostname]

        hostname = duthost.hostname

        out = duthost.command('show kdump config')
        if "Enabled" not in out["stdout"]:
            pytest.skip('DUT {}: Skip test since kdump is not enabled'.format(hostname))

        kdump_files = duthost.command('show kdump files')

        reboot(duthost, localhost, reboot_type=REBOOT_TYPE_WATCHDOG)

        # Wait until all critical processes are healthy.
        check_interfaces_and_services(duthost, conn_graph_facts["device_conn"][hostname],
                                      xcvr_skip_list, reboot_type=REBOOT_TYPE_WATCHDOG)

        new_kdump_files = duthost.command('show kdump files')
        assert new_kdump_files != kdump_files, "Kernel core dump file missing"

        self.wait_lc_healthy_if_sup(duthost, duthosts, localhost, conn_graph_facts, xcvr_skip_list)

