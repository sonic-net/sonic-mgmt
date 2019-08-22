"""
Check platform status after service is restarted

This script is to cover the test case 'Sequential syncd/swss restart' in the SONiC platform test plan:
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


def restart_service_and_check(localhost, dut, service, interfaces):
    """
    Restart specified service and check platform status
    """

    logging.info("Restart the %s service" % service)
    dut.command("sudo systemctl restart %s" % service)

    logging.info("Wait until all critical services are fully started")
    check_critical_services(dut)

    logging.info("Wait some time for all the transceivers to be detected")
    assert wait_until(300, 20, all_transceivers_detected, dut, interfaces), \
        "Not all transceivers are detected in 300 seconds"

    logging.info("Check interface status")
    time.sleep(60)
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


def test_restart_swss(testbed_devices, conn_graph_facts):
    """
    @summary: This test case is to restart the swss service and check platform status
    """
    dut = testbed_devices["dut"]
    localhost = testbed_devices["localhost"]
    restart_service_and_check(localhost, dut, "swss", conn_graph_facts["device_conn"])


@pytest.mark.skip(reason="Restarting syncd is not supported yet")
def test_restart_syncd(testbed_devices, conn_graph_facts):
    """
    @summary: This test case is to restart the syncd service and check platform status
    """
    dut = testbed_devices["dut"]
    localhost = testbed_devices["localhost"]
    restart_service_and_check(localhost, dut, "syncd", conn_graph_facts["device_conn"])
