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
from tests.common.platform.interface_utils import check_interface_information

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]


def test_reload_configuration(duthost, conn_graph_facts):
    """
    @summary: This test case is to reload the configuration and check platform status
    """
    interfaces = conn_graph_facts["device_conn"]
    asic_type = duthost.facts["asic_type"]

    logging.info("Reload configuration")
    duthost.shell("sudo config reload -y &>/dev/null", executable="/bin/bash")

    logging.info("Wait until all critical services are fully started")
    wait_critical_processes(duthost)

    logging.info("Wait some time for all the transceivers to be detected")
    assert wait_until(300, 20, check_interface_information, duthost, interfaces), \
        "Not all transceivers are detected in 300 seconds"

    logging.info("Check transceiver status")
    check_transceiver_basic(duthost, interfaces)

    if asic_type in ["mellanox"]:

        from .mellanox.check_hw_mgmt_service import check_hw_management_service
        from .mellanox.check_sysfs import check_sysfs

        logging.info("Check the hw-management service")
        check_hw_management_service(duthost)

        logging.info("Check sysfs")
        check_sysfs(duthost)
