"""
Check platform status after config is reloaded

This script is to cover the test case 'Reload configuration' in the SONiC platform test plan:
https://github.com/Azure/SONiC/blob/master/doc/pmon/sonic_platform_test_plan.md
"""
import logging
import os
import sys

import pytest

from common.fixtures.conn_graph_facts import conn_graph_facts
from common.utilities import wait_until
from check_critical_services import check_critical_services
from check_transceiver_status import check_transceiver_basic
from check_all_interface_info import check_interface_information

pytestmark = [pytest.mark.disable_loganalyzer]


def test_reload_configuration(duthost, conn_graph_facts):
    """
    @summary: This test case is to reload the configuration and check platform status
    """
    interfaces = conn_graph_facts["device_conn"]
    asic_type = duthost.facts["asic_type"]

    logging.info("Reload configuration")
    duthost.shell("sudo config reload -y &>/dev/null", executable="/bin/bash")

    logging.info("Wait until all critical services are fully started")
    check_critical_services(duthost)

    logging.info("Wait some time for all the transceivers to be detected")
    assert wait_until(300, 20, check_interface_information, duthost, interfaces), \
        "Not all transceivers are detected in 300 seconds"

    logging.info("Check transceiver status")
    check_transceiver_basic(duthost, interfaces)

    if asic_type in ["mellanox"]:

        current_file_dir = os.path.dirname(os.path.realpath(__file__))
        sub_folder_dir = os.path.join(current_file_dir, "mellanox")
        if sub_folder_dir not in sys.path:
            sys.path.append(sub_folder_dir)
        from check_hw_mgmt_service import check_hw_management_service
        from check_sysfs import check_sysfs

        logging.info("Check the hw-management service")
        check_hw_management_service(duthost)

        logging.info("Check sysfs")
        check_sysfs(duthost)
