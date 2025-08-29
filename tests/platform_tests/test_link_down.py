"""
On SONiC device reboot, tests the link down on fanout switches
This test supports different platforms including:
    1. T0
    2. T1
    3. T2 Chassis

"""
import logging

import pytest

from tests.common import reboot
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.multi_thread_utils import SafeThreadPoolExecutor
from tests.common.reboot import wait_for_startup
from tests.conftest import get_hosts_per_hwsku
from tests.platform_tests.test_reboot import check_interfaces_and_services
from tests.platform_tests.utils import get_max_to_reboot, fanout_hosts_and_ports, link_status_on_host


pytestmark = [
    pytest.mark.topology('t0', 't1', 't2'),
    pytest.mark.disable_loganalyzer,
]


logger = logging.getLogger(__name__)

_cached_frontend_nodes = None


def get_frontend_nodes_per_hwsku(duthosts, request):
    global _cached_frontend_nodes
    if _cached_frontend_nodes is None:
        _cached_frontend_nodes = [
            duthosts[hostname] for hostname in get_hosts_per_hwsku(
                request,
                [host.hostname for host in duthosts.frontend_nodes],
            )
        ]

    return _cached_frontend_nodes


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


def test_link_status_on_host_reboot(request, duthosts, localhost, conn_graph_facts, fanouthosts, xcvr_skip_list):
    frontend_nodes_per_hwsku = get_frontend_nodes_per_hwsku(duthosts, request)
    max_time_to_reboot = dict()
    fanouts_and_ports = dict()
    for duthost in frontend_nodes_per_hwsku:
        max_time_to_reboot[duthost] = get_max_to_reboot(duthost, 'test_link_down.py')
        dut_ports = single_dut_and_ports(duthost)
        fanouts_and_ports[duthost] = fanout_hosts_and_ports(fanouthosts, dut_ports)

    def check_interfaces_and_links(dut):
        # Before and after test, check all interfaces and services are up
        check_interfaces_and_services(
            dut, conn_graph_facts.get("device_conn", {}).get(dut.hostname, {}), xcvr_skip_list)
        # Also make sure fanout hosts' links are up
        link_status_on_host(fanouts_and_ports[dut], max_time_to_reboot[dut])

    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for duthost in frontend_nodes_per_hwsku:
            executor.submit(check_interfaces_and_links, duthost)

    def reboot_and_check(dut):
        # Get a dut uptime before reboot
        dut_uptime_before = dut.get_up_time()

        # Reboot dut, we should detect this host's fanout switches have all links down
        reboot(dut, localhost, wait_for_ssh=False)

        # After reboot, immediately check if all links on all fanouts are down
        link_status_on_host(fanouts_and_ports[dut], max_time_to_reboot[dut], up=False)

        # Wait for ssh port to open up on the DUT
        wait_for_startup(dut, localhost, 0, max_time_to_reboot[dut])

        dut_uptime = dut.get_up_time()
        logger.info('DUT {} up since {}'.format(dut.hostname, dut_uptime))
        rebooted = float(dut_uptime_before.strftime("%s")) != float(dut_uptime.strftime("%s"))
        pytest_assert(rebooted, "Device {} did not reboot".format(dut.hostname))

    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for duthost in frontend_nodes_per_hwsku:
            executor.submit(reboot_and_check, duthost)

    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for duthost in frontend_nodes_per_hwsku:
            executor.submit(check_interfaces_and_links, duthost)
