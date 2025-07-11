"""
Check platform status after service is restarted

This script is to cover the test case 'Sequential syncd/swss restart' in the SONiC platform test plan:
https://github.com/sonic-net/SONiC/blob/master/doc/pmon/sonic_platform_test_plan.md
"""
import logging

import pytest

from tests.common import config_reload  # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts  # noqa: F401
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
        logging.info("One or more critical process failed: Details - {}".format(details))
    # After this test run, rsyslogd is going down if all BGP session established and routes populated
    # restarting syslog to over come this issue, so that subsequent test run will not have errors/failures
    duthost.shell("sudo systemctl restart syslog")


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


def restart_service_and_check(localhost, dut, enum_frontend_asic_index, service, interfaces, xcvr_skip_list):
    """
    Restart specified service and check platform status
    """
    logging.info("Restart the %s service on asic %s" % (service, enum_frontend_asic_index))

    asichost = dut.asic_instance(enum_frontend_asic_index)
    service_name = asichost.get_service_name(service)
    if dut.facts["platform"] == "x86_64-cel_e1031-r0":
        dut.shell("sudo systemctl stop {} && sleep 30 && sudo systemctl start {}".format(service_name, service_name))
    else:
        dut.command("sudo systemctl restart {}".format(service_name))

    for container in dut.get_default_critical_services_list():
        if is_service_hiting_start_limit(dut, container) is True:
            logging.info("{} hits start limit and clear reset-failed flag".format(container))
            dut.shell("sudo systemctl reset-failed {}.service".format(container))
            dut.shell("sudo systemctl start {}.service".format(container))

    logging.info("Wait until all critical services are fully started")
    wait_critical_processes(dut)

    logging.info("Wait some time for all the transceivers to be detected")
    interface_wait_time = 300
    if dut.facts["platform"] == "x86_64-cel_e1031-r0":
        interface_wait_time = 900
    pytest_assert(wait_until(interface_wait_time, 20, 0, check_interface_information, dut,
                  enum_frontend_asic_index, interfaces, xcvr_skip_list),
                  "Not all interface information are detected within {} seconds".format(interface_wait_time))

    logging.info("Check transceiver status on asic %s" % enum_frontend_asic_index)
    check_transceiver_basic(dut, enum_frontend_asic_index, interfaces, xcvr_skip_list)

    if dut.facts["asic_type"] in ["mellanox"]:

        from .mellanox.check_hw_mgmt_service import check_hw_management_service
        from .mellanox.check_sysfs import check_sysfs

        logging.info("Check the hw-management service")
        check_hw_management_service(dut)

        logging.info("Check sysfs")
        check_sysfs(dut)

    logging.info("Check that critical processes are healthy for 60 seconds")
    check_critical_processes(dut, 60)


def test_restart_swss(duthosts, enum_rand_one_per_hwsku_hostname, enum_frontend_asic_index,
                      localhost, conn_graph_facts, xcvr_skip_list):            # noqa: F811
    """
    @summary: This test case is to restart the swss service and check platform status
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    all_interfaces = conn_graph_facts.get("device_conn", {}).get(duthost.hostname, {})

    if enum_frontend_asic_index is not None:
        # Get the interface pertaining to that asic
        interface_list = get_port_map(duthost, enum_frontend_asic_index)

        # Check if the interfaces of this AISC is present in conn_graph_facts
        new_intf_dict = {k: v for k, v in list(interface_list.items()) if k in all_interfaces}
        all_interfaces = new_intf_dict
        logging.info("ASIC {} interface_list {}".format(enum_frontend_asic_index, all_interfaces))

    restart_service_and_check(localhost, duthost, enum_frontend_asic_index, "swss", all_interfaces, xcvr_skip_list)


def test_restart_syncd(duthosts, enum_rand_one_per_hwsku_hostname, enum_frontend_asic_index,
                       localhost, conn_graph_facts, xcvr_skip_list):           # noqa: F811
    """
    @summary: This test case is to restart the syncd service and check platform status
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    restart_service_and_check(localhost, duthost, enum_frontend_asic_index, "syncd",
                              conn_graph_facts.get("device_conn", {}).get(duthost.hostname, {}), xcvr_skip_list)
