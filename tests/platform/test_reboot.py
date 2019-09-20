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
from check_transceiver_status import check_transceiver_basic
from check_daemon_status import check_pmon_daemon_status
from check_all_interface_info import check_interface_information
pytestmark = [pytest.mark.disable_loganalyzer]

REBOOT_TYPE_WARM = "warm"
REBOOT_TYPE_COLD = "cold"
REBOOT_TYPE_FAST = "fast"
REBOOT_TYPE_POWEROFF = "power off"
REBOOT_TYPE_WATCHDOG = "watchdog"

reboot_ctrl_dict = {
    REBOOT_TYPE_POWEROFF : {
        "timeout" : 300,
        "cause" : "Power Loss"
    },
    REBOOT_TYPE_COLD : {
        "command" : "reboot",
        "timeout" : 300,
        "cause" : "reboot"
    },
    REBOOT_TYPE_FAST : {
        "command" : "fast-reboot",
        "timeout" : 180,
        "cause" : "fast-reboot"
    },
    REBOOT_TYPE_WARM : {
        "command" : "warm-reboot",
        "timeout" : 180,
        "cause" : "warm-reboot"
    },
    REBOOT_TYPE_WATCHDOG : {
        "command" : "python -c \"import sonic_platform.platform as P; P.Platform().get_chassis().get_watchdog().arm(5); exit()\"",
        "timeout" : 300,
        "cause" : "Watchdog"
    }
}

def check_reboot_cause(dut, reboot_cause_expected):
    """
    @summary: Check the reboot cause on DUT.
    @param dut: The AnsibleHost object of DUT.
    @param reboot_cause_expected: The expected reboot cause.
    """
    logging.info("Check the reboot cause")
    output = dut.shell("show reboot-cause")
    reboot_cause_got = output["stdout"]
    logging.debug("show reboot-cause returns {}".format(reboot_cause_got))
    m = re.search(reboot_cause_expected, reboot_cause_got)
    assert m is not None, "got reboot-cause %s after rebooted by %s" % (reboot_cause_got, reboot_cause_expected)


def reboot_and_check(localhost, dut, interfaces, reboot_type=REBOOT_TYPE_COLD, reboot_helper=None, reboot_kwargs=None):
    """
    Perform the specified type of reboot and check platform status.
    @param dut: The AnsibleHost object of DUT.
    @param interfaces: DUT's interfaces defined by minigraph
    @param reboot_type: The reboot type, pre-defined const that has name convention of REBOOT_TYPE_XXX.
    @param reboot_helper: The helper function used only by power off reboot
    @param reboot_kwargs: The argument used by reboot_helper
    """
    logging.info("Run %s reboot on DUT" % reboot_type)

    assert reboot_type in reboot_ctrl_dict.keys(), "Unknown reboot type %s" % reboot_type

    reboot_timeout = reboot_ctrl_dict[reboot_type]["timeout"]
    reboot_cause = reboot_ctrl_dict[reboot_type]["cause"]
    if reboot_type == REBOOT_TYPE_POWEROFF:
        assert reboot_helper is not None, "A reboot function must be provided for power off reboot"

        reboot_helper(reboot_kwargs)

        localhost.wait_for(host=dut.hostname, port=22, state="stopped", delay=10, timeout=120)
    else:
        reboot_cmd = reboot_ctrl_dict[reboot_type]["command"]

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
    assert wait_until(300, 20, check_interface_information, dut, interfaces), \
        "Not all transceivers are detected or interfaces are up in 300 seconds"

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


def test_cold_reboot(testbed_devices, conn_graph_facts):
    """
    @summary: This test case is to perform cold reboot and check platform status
    """
    ans_host = testbed_devices["dut"]
    localhost = testbed_devices["localhost"]

    reboot_and_check(localhost, ans_host, conn_graph_facts["device_conn"], reboot_type=REBOOT_TYPE_COLD)


def test_fast_reboot(testbed_devices, conn_graph_facts):
    """
    @summary: This test case is to perform cold reboot and check platform status
    """
    ans_host = testbed_devices["dut"]
    localhost = testbed_devices["localhost"]

    reboot_and_check(localhost, ans_host, conn_graph_facts["device_conn"], reboot_type=REBOOT_TYPE_FAST)


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

    reboot_and_check(localhost, ans_host, conn_graph_facts["device_conn"], reboot_type=REBOOT_TYPE_WARM)


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


def test_power_off_reboot(testbed_devices, conn_graph_facts, psu_controller, power_off_delay):
    """
    @summary: This test case is to perform reboot via powercycle and check platform status
    @param psu_controller: The python object of psu controller
    @param power_off_delay: Pytest fixture. The delay between turning off and on the PSU
    """
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
    poweroff_reboot_kwargs = {}
    poweroff_reboot_kwargs["dut"] = ans_host

    for power_on_seq in power_on_seq_list:
        poweroff_reboot_kwargs["psu_ctrl"] = psu_ctrl
        poweroff_reboot_kwargs["all_psu"] = all_psu
        poweroff_reboot_kwargs["power_on_seq"] = power_on_seq
        poweroff_reboot_kwargs["delay_time"] = power_off_delay
        reboot_and_check(localhost, ans_host, conn_graph_facts["device_conn"], REBOOT_TYPE_POWEROFF, _power_off_reboot_helper, poweroff_reboot_kwargs)


def test_watchdog_reboot(testbed_devices, conn_graph_facts):
    """
    @summary: This test case is to perform reboot via watchdog and check platform status
    """
    ans_host = testbed_devices["dut"]
    localhost = testbed_devices["localhost"]

    test_watchdog_supported = "python -c \"import sonic_platform.platform as P; P.Platform().get_chassis().get_watchdog(); exit()\""

    watchdog_supported = ans_host.command(test_watchdog_supported)["stderr"]
    if "" != watchdog_supported:
        pytest.skip("Watchdog is not supported on this DUT, skip this test case")

    reboot_and_check(localhost, ans_host, conn_graph_facts["device_conn"], REBOOT_TYPE_WATCHDOG)
