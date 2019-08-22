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


def reboot_and_check(localhost, dut, interfaces, reboot_type="cold"):
    """
    Perform the specified type of reboot and check platform status.
    """
    logging.info("Run %s reboot on DUT" % reboot_type)
    if reboot_type == "cold":
        reboot_cmd = "reboot"
        reboot_timeout = 300
    elif reboot_type == "fast":
        reboot_cmd = "fast-reboot"
        reboot_timeout = 180
    elif reboot_type == "warm":
        reboot_cmd = "warm-reboot"
        reboot_timeout = 180
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
