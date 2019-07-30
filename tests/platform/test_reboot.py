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

from ansible_host import ansible_host
from utilities import wait_until
from check_critical_services import check_critical_services
from check_interface_status import check_interface_status
from check_transceiver_status import check_transceiver_basic
from check_transceiver_status import all_transceivers_detected


def reboot_and_check(localhost, dut, reboot_type="cold"):
    """
    Perform the specified type of reboot and check platform status.
    """
    dut.command("show platform summary")
    lab_conn_graph_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), \
        "../../ansible/files/lab_connection_graph.xml")
    conn_graph_facts = localhost.conn_graph_facts(host=dut.hostname, filename=lab_conn_graph_file).\
        contacted['localhost']['ansible_facts']
    interfaces = conn_graph_facts["device_conn"]
    asic_type = dut.shell("show platform summary | awk '/ASIC: / {print$2}'")["stdout"].strip()

    logging.info("Run %s reboot on DUT" % reboot_type)
    if reboot_type == "cold":
        reboot_cmd = "sudo reboot &"
        reboot_timeout = 300
    elif reboot_type == "fast":
        reboot_cmd = "sudo fast-reboot &"
        reboot_timeout = 180
    elif reboot_type == "warm":
        reboot_cmd = "sudo warm-reboot &"
        reboot_timeout = 180
    else:
        assert False, "Reboot type %s is not supported" % reboot_type
    dut.shell(reboot_cmd)

    logging.info("Wait for DUT to go down")
    localhost.wait_for(host=dut.hostname, port=22, state="stopped", delay=10, timeout=120)

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

    if asic_type in ["mellanox"]:

        current_file_dir = os.path.dirname(os.path.realpath(__file__))
        sub_folder_dir = os.path.join(current_file_dir, "mellanox")
        if sub_folder_dir not in sys.path:
            sys.path.append(sub_folder_dir)
        from check_hw_mgmt_service import check_hw_management_service
        from check_hw_mgmt_service import wait_until_fan_speed_set_to_default
        from check_sysfs import check_sysfs

        logging.info("Wait until fan speed is set to default")
        wait_until_fan_speed_set_to_default(dut)

        logging.info("Check the hw-management service")
        check_hw_management_service(dut)

        logging.info("Check sysfs")
        check_sysfs(dut)


def test_cold_reboot(localhost, ansible_adhoc, testbed):
    """
    @summary: This test case is to perform cold reboot and check platform status
    """
    hostname = testbed['dut']
    ans_host = ansible_host(ansible_adhoc, hostname)

    reboot_and_check(localhost, ans_host, reboot_type="cold")


def test_fast_reboot(localhost, ansible_adhoc, testbed):
    """
    @summary: This test case is to perform cold reboot and check platform status
    """
    hostname = testbed['dut']
    ans_host = ansible_host(ansible_adhoc, hostname)

    reboot_and_check(localhost, ans_host, reboot_type="fast")


def test_warm_reboot(localhost, ansible_adhoc, testbed):
    """
    @summary: This test case is to perform cold reboot and check platform status
    """
    hostname = testbed['dut']
    ans_host = ansible_host(ansible_adhoc, hostname)
    asic_type = ans_host.shell("show platform summary | awk '/ASIC: / {print$2}'")["stdout"].strip()

    if asic_type in ["mellanox"]:
        issu_capability = ans_host.command("show platform mlnx issu")["stdout"]
        if "disabled" in issu_capability:
            pytest.skip("ISSU is not supported on this DUT, skip this test case")

    reboot_and_check(localhost, ans_host, reboot_type="warm")
