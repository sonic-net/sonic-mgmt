"""
On SONiC device reboot, tests the link down on fanout switches
This test supports different platforms including:
    1. chassis
    2. single-asic dut
    3. multi-asic dut
    Note that for now we only run this on t2(chassis)

"""
import logging

import pytest

from tests.common import reboot
from tests.common.reboot import wait_for_startup
from tests.platform_tests.test_reboot import check_interfaces_and_services
from tests.platform_tests.utils import get_max_to_reboot, fanout_hosts_and_ports, link_status_on_host

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0', 't1', 't2'),
    pytest.mark.disable_loganalyzer,
]


def single_dut_and_ports(duthost):
    """
    For single host
    Returns:
            dict of {duthost, [ports]}
    """
    duts_and_ports = {}
    ports = duthost.ports_list()
    duts_and_ports[duthost] = ports
    return duts_and_ports


def test_link_status_on_host_reboot(duthosts, localhost, enum_rand_one_per_hwsku_frontend_hostname,
                                    conn_graph_facts, fanouthosts, xcvr_skip_list):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    max_time_to_reboot = get_max_to_reboot(duthost, 'test_link_down.py')
    hostname = duthost.hostname

    # Before test, check all interfaces and services are up
    check_interfaces_and_services(
        duthost, conn_graph_facts.get("device_conn", {}).get("hostname", {}), xcvr_skip_list)

    dut_ports = single_dut_and_ports(duthost)
    fanouts_and_ports = fanout_hosts_and_ports(fanouthosts, dut_ports)

    # Also make sure fanout hosts' links are up
    link_status_on_host(fanouts_and_ports, max_time_to_reboot)

    # Get a dut uptime before reboot
    dut_uptime_before = duthost.get_up_time()

    # Reboot dut, we should detect this host's fanout switches have all links down
    reboot(duthost, localhost, wait_for_ssh=False)

    # After reboot, immediately check if all links on all fanouts are down
    link_status_on_host(fanouts_and_ports, max_time_to_reboot, up=False)

    # Wait for ssh port to open up on the DUT
    wait_for_startup(duthost, localhost, 0, max_time_to_reboot)

    dut_uptime = duthost.get_up_time()
    logger.info('DUT {} up since {}'.format(hostname, dut_uptime))
    rebooted = float(dut_uptime_before.strftime("%s")) != float(dut_uptime.strftime("%s"))
    assert rebooted, "Device {} did not reboot".format(hostname)

    # After test, check all interfaces and services are up
    check_interfaces_and_services(
        duthost, conn_graph_facts.get("device_conn", {}).get("hostname", {}), xcvr_skip_list)

    # Also make sure fanout hosts' links are up
    link_status_on_host(fanouts_and_ports, max_time_to_reboot)
