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

import pytest

from platform_fixtures import conn_graph_facts
from common.utilities import wait_until
from check_critical_services import check_critical_services
from check_interface_status import check_interface_status
from check_transceiver_status import check_transceiver_basic
from check_transceiver_status import all_transceivers_detected
from psu_controller import psu_controller

def check_reboot_cause(dut, reboot_cause_expected):
    """
    @summary: Check the reboot cause on DUT.
    @param dut: The AnsibleHost object of DUT.
    """
    logging.info("Check the reboot cause")
    output = dut.shell("show reboot-cause")
    reboot_cause_got = output["stdout"]
    logging.debug("show reboot-cause returns {}".format(reboot_cause_got))
    m = re.search(reboot_cause_expected, reboot_cause_got)
    assert m is not None, "got reboot-cause %s after rebooted by %s" % (reboot_cause_got, reboot_cause_expected)


def reboot_and_check(localhost, dut, interfaces, reboot_type="cold", reboot_helper=None, reboot_argu=None):
    """
    Perform the specified type of reboot and check platform status.
    """
    logging.info("Run %s reboot on DUT" % reboot_type)

    if reboot_type == "power off":
        assert reboot_helper is not None, "A reboot function must be provided for hardware reboot"
        reboot_timeout = 300
        reboot_cause = "Power Loss"
        reboot_helper(reboot_argu)

        localhost.wait_for(host=dut.hostname, port=22, state="stopped", delay=10, timeout=120)
    else:
        if reboot_type == "cold":
            reboot_cmd = "reboot"
            reboot_cause = reboot_cmd
            reboot_timeout = 300
        elif reboot_type == "fast":
            reboot_cmd = "fast-reboot"
            reboot_cause = reboot_cmd
            reboot_timeout = 180
        elif reboot_type == "warm":
            reboot_cmd = "warm-reboot"
            reboot_cause = reboot_cmd
            reboot_timeout = 180
        elif reboot_type == "watchdog":
            reboot_timeout = 300
            reboot_cmd = "python -c \"import sonic_platform.platform as P; P.Platform().get_chassis().get_watchdog().arm(5); exit()\""
            reboot_cause = "Watchdog"
        else:
            assert False, "Reboot type %s is not supported" % reboot_type

        process, queue = dut.command(reboot_cmd, module_async=True)

        logging.info("Wait for DUT to go down")
        res = localhost.wait_for(host=dut.hostname, port=22, state="stopped", delay=10, timeout=120,
            module_ignore_errors=True)
        if "failed" in res:
            if process.is_alive():
                logging.error("Command '%s' is not completed" % reboot_cmd)
                process.terminate()
            logging.error("reboot result %s" % str(queue.get()))
            assert False, "DUT did not go down"

    logging.info("Wait for DUT to come back")
    localhost.wait_for(host=dut.hostname, port=22, state="started", delay=10, timeout=reboot_timeout)

    logging.info("Wait until all critical services are fully started")
    check_critical_services(dut)

    logging.info("Check reboot cause")
    check_reboot_cause(dut, reboot_cause)

    logging.info("Wait some time for all the transceivers to be detected")
    assert wait_until(300, 20, all_transceivers_detected, dut, interfaces), \
        "Not all transceivers are detected in 300 seconds"

    logging.info("Check interface status")
    check_interface_status(dut, interfaces)

    logging.info("Check transceiver status")
    check_transceiver_basic(dut, interfaces)

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


def test_cold_reboot(testbed_devices, conn_graph_facts):
    """
    @summary: This test case is to perform cold reboot and check platform status
    """
    ans_host = testbed_devices["dut"]
    localhost = testbed_devices["localhost"]

    reboot_and_check(localhost, ans_host, conn_graph_facts["device_conn"], reboot_type="cold")


def test_fast_reboot(testbed_devices, conn_graph_facts):
    """
    @summary: This test case is to perform cold reboot and check platform status
    """
    ans_host = testbed_devices["dut"]
    localhost = testbed_devices["localhost"]

    reboot_and_check(localhost, ans_host, conn_graph_facts["device_conn"], reboot_type="fast")


def test_warm_reboot(testbed_devices, conn_graph_facts):
    """
    @summary: This test case is to perform cold reboot and check platform status
    """
    ans_host = testbed_devices["dut"]
    localhost = testbed_devices["localhost"]
    asic_type = ans_host.facts["asic_type"]

    if asic_type in ["mellanox"]:
        issu_capability = ans_host.command("show platform mlnx issu")["stdout"]
        if "disabled" in issu_capability:
            pytest.skip("ISSU is not supported on this DUT, skip this test case")

    reboot_and_check(localhost, ans_host, conn_graph_facts["device_conn"], reboot_type="warm")


@pytest.fixture(params=[15, 5])
def power_off_delay(request):
    """
    used to parametrized test cases on power_off_delay
    :param request: pytest request object
    :return: power_off_delay
    """
    return request.param


def _power_off_reboot_helper(args):
    psu_ctrl = args["psu_ctrl"]
    all_psu = args["all_psu"]
    power_on_seq = args["power_on_seq"]
    delay_time = args["delay_time"]

    for psu in all_psu:
        logging.debug("turning off {}".format(psu))
        psu_ctrl.turn_off_psu(psu["psu_id"])
    time.sleep(delay_time)
    logging.info("Power on {}".format(power_on_seq))
    for psu in power_on_seq:
        logging.debug("turning on {}".format(psu))
        psu_ctrl.turn_on_psu(psu["psu_id"])


def test_power_off_reboot(testbed_devices, conn_graph_facts, psu_controller, power_off_delay):
    ans_host = testbed_devices["dut"]
    localhost = testbed_devices["localhost"]

    psu_ctrl = psu_controller(ans_host.hostname, ans_host.facts["asic_type"])
    if psu_ctrl is None:
        pytest.skip("No PSU controller for %s, skip rest of the testing in this case" % ans_host.hostname)

    all_psu = psu_ctrl.get_psu_status()
    if all_psu:
        power_on_seq_list = [[item] for item in all_psu]
        power_on_seq_list.append(all_psu)

    logging.info("Got all power on sequences {}".format(power_on_seq_list))

    delay_time_list = [15, 5]
    poweroff_reboot_argu = {}
    poweroff_reboot_argu["dut"] = ans_host

    for power_on_seq in power_on_seq_list:
        poweroff_reboot_argu["psu_ctrl"] = psu_ctrl
        poweroff_reboot_argu["all_psu"] = all_psu
        poweroff_reboot_argu["power_on_seq"] = power_on_seq
        poweroff_reboot_argu["delay_time"] = power_off_delay
        reboot_and_check(localhost, ans_host, conn_graph_facts["device_conn"], "power off", _power_off_reboot_helper, poweroff_reboot_argu)

def test_watchdog_reboot(testbed_devices, conn_graph_facts):
    ans_host = testbed_devices["dut"]
    localhost = testbed_devices["localhost"]

    watchdog_reboot_command = "python -c \"import sonic_platform.platform as P; P.Platform().get_chassis().get_watchdog().arm(5); exit()\""
    test_watchdog_supported = "python -c \"import sonic_platform.platform as P; P.Platform().get_chassis().get_watchdog(); exit()\""

    watchdog_supported = ans_host.command(test_watchdog_supported)["stderr"]
    if "" != watchdog_supported:
        pytest.skip("Watchdog is not supported on this DUT, skip this test case")

    watchdog_reboot_argu = {}
    watchdog_reboot_argu["dut"] = ans_host
    watchdog_reboot_argu["cause"] = "Watchdog"
    watchdog_reboot_argu["command"] = watchdog_reboot_command
    reboot_and_check(localhost, ans_host, conn_graph_facts["device_conn"], "watchdog")
