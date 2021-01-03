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
from tests.common.platform.interface_utils import check_interface_information, get_port_map

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]


@pytest.fixture(autouse=True, scope="function")
def heal_testbed(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    # Nothing to do before test
    yield
    status, details = get_critical_processes_status(duthost)
    if not status:
        logging.info("Restoring dut with critical process failure: {}".format(details))
        config_reload(duthost, config_source='config_db', wait=120)

def is_service_hiting_start_limit(duthost, container_name):
    """
    @summary: Determine whether the container can not be restarted is due to
              start-limit-hit or not
    """
    service_status = duthost.shell("sudo systemctl status {}.service | grep 'Active'".format(container_name))
    for line in service_status["stdout_lines"]:
        if "start-limit-hit" in line:
            return True

    return False

def restart_service_and_check(localhost, dut, service, interfaces):
    """
    Restart specified service and check platform status
    """

    logging.info("Restart the %s service" % service)
    for asic_index in dut.get_asic_ids():
        service_name = dut.get_service_name(service, asic_index)
        dut.command("sudo systemctl restart {}".format(service_name))

    for container in dut.get_host_critical_services_list():
        if is_service_hiting_start_limit(dut, container) is True:
            logging.info("{} hits start limit and clear reset-failed flag".format(container))
            dut.shell("sudo systemctl reset-failed {}.service".format(container))
            dut.shell("sudo systemctl start {}.service".format(container))

    logging.info("Wait until all critical services are fully started")
    wait_critical_processes(dut)

    logging.info("Wait some time for all the transceivers to be detected")
    pytest_assert(wait_until(300, 20, check_interface_information, dut, interfaces),
                  "Not all interface information are detected within 300 seconds")

    logging.info("Check transceiver status")
    for asic_index in dut.get_frontend_asic_ids():
        # Get the interfaces pertaining to that asic
        interface_list = get_port_map(dut, asic_index)
        interfaces_per_asic = {k:v for k, v in interface_list.items() if k in interfaces}
        check_transceiver_basic(dut, asic_index, interfaces_per_asic)

    if dut.facts["asic_type"] in ["mellanox"]:

        from .mellanox.check_hw_mgmt_service import check_hw_management_service
        from .mellanox.check_sysfs import check_sysfs

        logging.info("Check the hw-management service")
        check_hw_management_service(dut)

        logging.info("Check sysfs")
        check_sysfs(dut)

    logging.info("Check that critical processes are healthy for 60 seconds")
    check_critical_processes(dut, 60)


def test_restart_swss(duthosts, rand_one_dut_hostname, localhost, conn_graph_facts):
    """
    @summary: This test case is to restart the swss service and check platform status
    """
    duthost = duthosts[rand_one_dut_hostname]
    restart_service_and_check(localhost, duthost, "swss", conn_graph_facts["device_conn"][duthost.hostname])


@pytest.mark.skip(reason="Restarting syncd is not supported yet")
def test_restart_syncd(duthosts, rand_one_dut_hostname, localhost, conn_graph_facts):
    """
    @summary: This test case is to restart the syncd service and check platform status
    """
    duthost = duthosts[rand_one_dut_hostname]
    restart_service_and_check(localhost, duthost, "syncd", conn_graph_facts["device_conn"][duthost.hostname])
