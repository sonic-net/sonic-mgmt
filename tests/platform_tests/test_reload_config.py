"""
Check platform status after config is reloaded

This script is to cover the test case 'Reload configuration' in the SONiC platform test plan:
https://github.com/Azure/SONiC/blob/master/doc/pmon/sonic_platform_test_plan.md
"""
import logging

import pytest

from tests.common.fixtures.conn_graph_facts import conn_graph_facts
from tests.common.utilities import wait_until
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.platform.transceiver_utils import check_transceiver_basic
from tests.common.platform.interface_utils import check_all_interface_information, get_port_map

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]


def test_reload_configuration(duthosts, rand_one_dut_hostname, conn_graph_facts, xcvr_skip_list):
    """
    @summary: This test case is to reload the configuration and check platform status
    """
    duthost = duthosts[rand_one_dut_hostname]
    interfaces = conn_graph_facts["device_conn"][duthost.hostname]
    asic_type = duthost.facts["asic_type"]

    logging.info("Reload configuration")
    duthost.shell("sudo config reload -y &>/dev/null", executable="/bin/bash")

    logging.info("Wait until all critical services are fully started")
    wait_critical_processes(duthost)

    logging.info("Wait some time for all the transceivers to be detected")
    assert wait_until(300, 20, check_all_interface_information, duthost, interfaces, xcvr_skip_list), \
        "Not all transceivers are detected in 300 seconds"

    logging.info("Check transceiver status")
    for asic_index in duthost.get_frontend_asic_ids():
        # Get the interfaces pertaining to that asic
        interface_list = get_port_map(duthost, asic_index)
        interfaces_per_asic = {k:v for k, v in interface_list.items() if k in interfaces}
        check_transceiver_basic(duthost, asic_index, interfaces_per_asic, xcvr_skip_list)

    if asic_type in ["mellanox"]:

        from .mellanox.check_hw_mgmt_service import check_hw_management_service
        from .mellanox.check_sysfs import check_sysfs

        logging.info("Check the hw-management service")
        check_hw_management_service(duthost)

        logging.info("Check sysfs")
        check_sysfs(duthost)
