"""
Check platform status after service is restarted

This script is to cover the test case 'Sequential syncd/swss restart' in the SONiC platform test plan:
https://github.com/Azure/SONiC/blob/master/doc/pmon/sonic_platform_test_plan.md
"""
import logging

import pytest

from tests.common import config_reload
from tests.common.fixtures.conn_graph_facts import conn_graph_facts
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.platform.processes_utils import check_critical_processes
from tests.common.platform.processes_utils import get_critical_processes_status
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.platform.transceiver_utils import check_transceiver_basic
from tests.common.platform.interface_utils import check_interface_information

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]


@pytest.fixture(autouse=True, scope="function")
def heal_testbed(duthost):
    # Nothing to do before test
    yield
    status, details = get_critical_processes_status(duthost)
    if not status:
        logging.info("Restoring dut with critical process failure: {}".format(details))
        config_reload(duthost, config_source='config_db', wait=120)

def restart_service_and_check(localhost, dut, service, interfaces):
    """
    Restart specified service and check platform status
    """

    logging.info("Restart the %s service" % service)
    dut.command("sudo systemctl restart %s" % service)

    logging.info("Wait until all critical services are fully started")
    wait_critical_processes(dut)

    logging.info("Wait some time for all the transceivers to be detected")
    pytest_assert(wait_until(300, 20, check_interface_information, dut, interfaces),
                  "Not all interface information are detected within 300 seconds")

    logging.info("Check transceiver status")
    check_transceiver_basic(dut, interfaces)

    if dut.facts["asic_type"] in ["mellanox"]:

        from .mellanox.check_hw_mgmt_service import check_hw_management_service
        from .mellanox.check_sysfs import check_sysfs

        logging.info("Check the hw-management service")
        check_hw_management_service(dut)

        logging.info("Check sysfs")
        check_sysfs(dut)

    logging.info("Check that critical processes are healthy for 60 seconds")
    check_critical_processes(dut, 60)


def test_restart_swss(duthost, localhost, conn_graph_facts):
    """
    @summary: This test case is to restart the swss service and check platform status
    """
    restart_service_and_check(localhost, duthost, "swss", conn_graph_facts["device_conn"])


@pytest.mark.skip(reason="Restarting syncd is not supported yet")
def test_restart_syncd(duthost, localhost, conn_graph_facts):
    """
    @summary: This test case is to restart the syncd service and check platform status
    """
    restart_service_and_check(localhost, duthost, "syncd", conn_graph_facts["device_conn"])
