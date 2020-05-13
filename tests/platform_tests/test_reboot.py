"""
Check platform status after reboot. Three types of reboot are covered in this script:
* Cold reboot
* Fast reboot
* Warm reboot

This script is to cover the test case 'Reload configuration' in the SONiC platform test plan:
https://github.com/Azure/SONiC/blob/master/doc/pmon/sonic_platform_test_plan.md
"""
import logging
import re
import os
import time
import sys

from datetime import datetime

import pytest

from common.fixtures.conn_graph_facts import conn_graph_facts
from common.utilities import wait_until
from common.reboot import *
from common.platform.interface_utils import check_interface_information
from common.platform.transceiver_utils import check_transceiver_basic
from common.platform.daemon_utils import check_pmon_daemon_status

from check_critical_services import check_critical_services

pytestmark = [pytest.mark.disable_loganalyzer]

MAX_WAIT_TIME_FOR_INTERFACES = 300
MAX_WAIT_TIME_FOR_REBOOT_CAUSE = 120


@pytest.fixture(scope="module", autouse=True)
def teardown_module(duthost, conn_graph_facts):
    yield

    logging.info("Tearing down: to make sure all the critical services, interfaces and transceivers are good")
    interfaces = conn_graph_facts["device_conn"]
    check_critical_services(duthost)
    check_interfaces_and_services(duthost, interfaces)


def reboot_and_check(localhost, dut, interfaces, reboot_type=REBOOT_TYPE_COLD, reboot_helper=None, reboot_kwargs=None):
    """
    Perform the specified type of reboot and check platform status.
    @param localhost: The Localhost object.
    @param dut: The AnsibleHost object of DUT.
    @param interfaces: DUT's interfaces defined by minigraph
    @param reboot_type: The reboot type, pre-defined const that has name convention of REBOOT_TYPE_XXX.
    @param reboot_helper: The helper function used only by power off reboot
    @param reboot_kwargs: The argument used by reboot_helper
    """
    logging.info("Run %s reboot on DUT" % reboot_type)

    reboot(dut, localhost, reboot_type=reboot_type, reboot_helper=reboot_helper, reboot_kwargs=reboot_kwargs)

    check_interfaces_and_services(dut, interfaces, reboot_type)


def check_interfaces_and_services(dut, interfaces, reboot_type = None):
    """
    Perform a further check after reboot-cause, including transceiver status, interface status
    @param localhost: The Localhost object.
    @param dut: The AnsibleHost object of DUT.
    @param interfaces: DUT's interfaces defined by minigraph
    """
    logging.info("Wait until all critical services are fully started")
    check_critical_services(dut)

    if reboot_type is not None:
        logging.info("Check reboot cause")
        assert wait_until(MAX_WAIT_TIME_FOR_REBOOT_CAUSE, 20, check_reboot_cause, dut, reboot_type), \
            "got reboot-cause failed after rebooted by %s" % reboot_type

        if reboot_ctrl_dict[reboot_type]["test_reboot_cause_only"]:
            logging.info("Further checking skipped for %s test which intends to verify reboot-cause only" % reboot_type)
            return

    logging.info("Wait %d seconds for all the transceivers to be detected" % MAX_WAIT_TIME_FOR_INTERFACES)
    assert wait_until(MAX_WAIT_TIME_FOR_INTERFACES, 20, check_interface_information, dut, interfaces), \
        "Not all transceivers are detected or interfaces are up in %d seconds" % MAX_WAIT_TIME_FOR_INTERFACES

    logging.info("Check transceiver status")
    check_transceiver_basic(dut, interfaces)

    logging.info("Check pmon daemon status")
    assert check_pmon_daemon_status(dut), "Not all pmon daemons running."

    if dut.facts["asic_type"] in ["mellanox"]:

        current_file_dir = os.path.dirname(os.path.realpath(__file__))
        sub_folder_dir = os.path.join(current_file_dir, "mellanox")
        if sub_folder_dir not in sys.path:
            sys.path.append(sub_folder_dir)
        from check_hw_mgmt_service import check_hw_management_service
        from check_sysfs import check_sysfs

        logging.info("Check the hw-management service")
        check_hw_management_service(dut)

        logging.info("Check sysfs")
        check_sysfs(dut)


def test_cold_reboot(duthost, testbed_devices, conn_graph_facts):
    """
    @summary: This test case is to perform cold reboot and check platform status
    """
    localhost = testbed_devices["localhost"]

    reboot_and_check(localhost, duthost, conn_graph_facts["device_conn"], reboot_type=REBOOT_TYPE_COLD)


def test_fast_reboot(duthost, testbed_devices, conn_graph_facts):
    """
    @summary: This test case is to perform cold reboot and check platform status
    """
    localhost = testbed_devices["localhost"]

    reboot_and_check(localhost, duthost, conn_graph_facts["device_conn"], reboot_type=REBOOT_TYPE_FAST)


def test_warm_reboot(duthost, testbed_devices, conn_graph_facts):
    """
    @summary: This test case is to perform cold reboot and check platform status
    """
    localhost = testbed_devices["localhost"]
    asic_type = duthost.facts["asic_type"]

    if asic_type in ["mellanox"]:
        issu_capability = duthost.command("show platform mlnx issu")["stdout"]
        if "disabled" in issu_capability:
            pytest.skip("ISSU is not supported on this DUT, skip this test case")

    reboot_and_check(localhost, duthost, conn_graph_facts["device_conn"], reboot_type=REBOOT_TYPE_WARM)


@pytest.fixture(params=[15, 5])
def power_off_delay(request):
    """
    @summary: used to parametrized test cases on power_off_delay
    @param request: pytest request object
    @return: power_off_delay
    """
    return request.param


def _power_off_reboot_helper(kwargs):
    """
    @summary: used to parametrized test cases on power_off_delay
    @param kwargs: the delay time between turning off and on the PSU
    """
    psu_ctrl = kwargs["psu_ctrl"]
    all_psu = kwargs["all_psu"]
    power_on_seq = kwargs["power_on_seq"]
    delay_time = kwargs["delay_time"]

    for psu in all_psu:
        logging.debug("turning off {}".format(psu))
        psu_ctrl.turn_off_psu(psu["psu_id"])
    time.sleep(delay_time)
    logging.info("Power on {}".format(power_on_seq))
    for psu in power_on_seq:
        logging.debug("turning on {}".format(psu))
        psu_ctrl.turn_on_psu(psu["psu_id"])


def test_power_off_reboot(duthost, testbed_devices, conn_graph_facts, psu_controller, power_off_delay):
    """
    @summary: This test case is to perform reboot via powercycle and check platform status
    @param testbed_devices: Fixture initialize devices in testbed
    @param duthost: Fixture for DUT AnsibleHost object
    @param conn_graph_facts: Fixture parse and return lab connection graph
    @param psu_controller: The python object of psu controller
    @param power_off_delay: Pytest fixture. The delay between turning off and on the PSU
    """
    localhost = testbed_devices["localhost"]

    psu_ctrl = psu_controller
    if psu_ctrl is None:
        pytest.skip("No PSU controller for %s, skip rest of the testing in this case" % duthost.hostname)

    all_psu = psu_ctrl.get_psu_status()

    # Purpose of this list is to control sequence of turning on PSUs in power off testing.
    # If there are 2 PSUs, then 3 scenarios would be covered:
    # 1. Turn off all PSUs, turn on PSU1, then check.
    # 2. Turn off all PSUs, turn on PSU2, then check.
    # 3. Turn off all PSUs, turn on one of the PSU, then turn on the other PSU, then check.
    power_on_seq_list = []
    if all_psu:
        power_on_seq_list = [[item] for item in all_psu]
        power_on_seq_list.append(all_psu)

    logging.info("Got all power on sequences {}".format(power_on_seq_list))

    poweroff_reboot_kwargs = {"dut": duthost}

    for power_on_seq in power_on_seq_list:
        poweroff_reboot_kwargs["psu_ctrl"] = psu_ctrl
        poweroff_reboot_kwargs["all_psu"] = all_psu
        poweroff_reboot_kwargs["power_on_seq"] = power_on_seq
        poweroff_reboot_kwargs["delay_time"] = power_off_delay
        reboot_and_check(localhost, duthost, conn_graph_facts["device_conn"], REBOOT_TYPE_POWEROFF,
                         _power_off_reboot_helper, poweroff_reboot_kwargs)


def test_watchdog_reboot(duthost, testbed_devices, conn_graph_facts):
    """
    @summary: This test case is to perform reboot via watchdog and check platform status
    """
    localhost = testbed_devices["localhost"]

    test_watchdog_supported = "python -c \"import sonic_platform.platform as P; P.Platform().get_chassis().get_watchdog(); exit()\""

    watchdog_supported = duthost.command(test_watchdog_supported,module_ignore_errors=True)["stderr"]
    if "" != watchdog_supported:
        pytest.skip("Watchdog is not supported on this DUT, skip this test case")

    reboot_and_check(localhost, duthost, conn_graph_facts["device_conn"], REBOOT_TYPE_WATCHDOG)


def test_continuous_reboot(duthost, testbed_devices, conn_graph_facts):
    """
    @summary: This test case is to perform 3 cold reboot in a row
    """
    localhost = testbed_devices["localhost"]

    for i in range(3):
        reboot_and_check(localhost, duthost, conn_graph_facts["device_conn"], reboot_type=REBOOT_TYPE_COLD)
