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

from tests.platform_tests.test_reboot import check_interfaces_and_services
from tests.common.platform.device_utils import fanout_switch_port_lookup
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until, get_plt_reboot_ctrl
from tests.common.reboot import reboot, wait_for_startup

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0', 't1', 't2'),
    pytest.mark.disable_loganalyzer,
]

MAX_TIME_TO_REBOOT = 120


@pytest.fixture(scope='function')
def set_max_to_reboot(duthost):
    """
    For chassis testbeds, we need to specify plt_reboot_ctrl in inventory file,
    to let MAX_TIME_TO_REBOOT to be overwritten by specified timeout value
    """
    global MAX_TIME_TO_REBOOT
    plt_reboot_ctrl = get_plt_reboot_ctrl(duthost, 'test_link_down.py', 'cold')
    if plt_reboot_ctrl:
        MAX_TIME_TO_REBOOT = plt_reboot_ctrl.get('timeout', 120)


def multi_duts_and_ports(duthosts):
    """
    For multi-host
    Returns:
            dict of {{duthost1, [ports]}, {duthost2, [ports]}, ...}
    """
    duts_and_ports = {}
    for duthost in duthosts.frontend_nodes:
        ports = duthost.ports_list()
        duts_and_ports[duthost] = ports
    return duts_and_ports


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


def fanout_hosts_and_ports(fanouthosts, duts_and_ports):
    """
    Use cases:
        1 duthost -> 1 fanout host
        1 duthost -> no fanout host
        1 duthost -> multiple fanout hosts
        multiple duthosts -> 1 fanout hosts

    Returns:
            dict of [fanout, {set of its ports}]
    """
    fanout_and_ports = {}
    for duthost in list(duts_and_ports.keys()):
        for port in duts_and_ports[duthost]:
            fanout, fanout_port = fanout_switch_port_lookup(
                fanouthosts, duthost.hostname, port)
            # some ports on dut may not have link to fanout
            if fanout is None and fanout_port is None:
                logger.info("Interface {} on duthost {} doesn't link to any fanout switch"
                            .format(port, duthost.hostname))
                continue
            logger.info("Interface {} on fanout {} (os type {}) map to interface {} on duthost {}"
                        .format(fanout_port, fanout.hostname, fanout.get_fanout_os(), port, duthost.hostname))
            if fanout in list(fanout_and_ports.keys()):
                fanout_and_ports[fanout].add(fanout_port)
            else:
                fanout_and_ports[fanout] = {fanout_port}
    return fanout_and_ports


def links_down(fanout, ports):
    """
    Input:
        ports: set of ports on this fanout
    Returns:
        True: if all ports are down
        False: if any port is up
    """
    return fanout.links_status_down(ports)


def links_up(fanout, ports):
    """
    Returns:
        True: if all ports are up
        False: if any port is down
    """
    return fanout.links_status_up(ports)


def link_status_on_host(fanouts_and_ports, up=True):
    for fanout, ports in list(fanouts_and_ports.items()):
        hostname = fanout.hostname
        # Assumption here is all fanouts are healthy.
        # If fanout is not healthy, or links not in expected state, following errors will be thrown
        if up:
            # Make sure interfaces are up on fanout hosts
            pytest_assert(wait_until(MAX_TIME_TO_REBOOT, 5, 0, links_up, fanout, ports),
                          "Interface(s) on {} is still down after {}sec".format(hostname, MAX_TIME_TO_REBOOT))
        else:
            # Check every interfaces are down on this host every 5 sec until device boots up
            pytest_assert(wait_until(MAX_TIME_TO_REBOOT, 5, 0, links_down, fanout, ports),
                          "Interface(s) on {} is still up after {}sec".format(hostname, MAX_TIME_TO_REBOOT))
    return True


def link_status_on_all_fanouts(fanouts_and_ports, up=True):
    """
    Return:
        True: if up=True, and all links on all fanout hosts are up
              or
              if up=False, and all link on all fanout hosts are down
    """
    link_status_on_host(fanouts_and_ports, up)
    logger.info("All interfaces on all fanouts are {}!".format('up' if up else 'down'))
    return True


def check_interfaces_and_services_all_LCs(duthosts, conn_graph_facts, xcvr_skip_list):
    for LC in duthosts.frontend_nodes:
        check_interfaces_and_services(
            LC, conn_graph_facts["device_conn"][LC.hostname], xcvr_skip_list)


def test_link_down_on_sup_reboot(duthosts, localhost, enum_supervisor_dut_hostname,
                                 conn_graph_facts, set_max_to_reboot,
                                 fanouthosts, xcvr_skip_list):
    if len(duthosts.nodes) == 1:
        pytest.skip("Skip single-host dut for this test")

    duthost = duthosts[enum_supervisor_dut_hostname]

    # There are some errors due to reboot happened before this test file for some reason,
    # and SUP may not have enough time to recover all dockers and the wait for process wait for 300 secs in
    # pytest_assert(wait_until(300, 20, 0, _all_critical_processes_healthy, dut),
    # would not be enough. _all_critical_processes_healthy only validates processes are started
    # Wait for ssh port to open up on the DUT
    wait_for_startup(duthost, localhost, 0, MAX_TIME_TO_REBOOT)

    hostname = duthost.hostname
    # Before test, check all interfaces and services are up on all linecards
    check_interfaces_and_services_all_LCs(
        duthosts, conn_graph_facts, xcvr_skip_list)

    duts_and_ports = multi_duts_and_ports(duthosts)
    fanouts_and_ports = fanout_hosts_and_ports(fanouthosts, duts_and_ports)

    # Also make sure fanout hosts' links are up
    link_status_on_all_fanouts(fanouts_and_ports)

    # Get a dut uptime before reboot
    dut_uptime_before = duthost.get_up_time()

    # Reboot RP should reboot both RP&LC, should detect all links on all linecards go down
    reboot(duthost, localhost, wait_for_ssh=False)

    # Also make sure fanout hosts' links are down
    link_status_on_all_fanouts(fanouts_and_ports, up=False)

    # Wait for ssh port to open up on the SUP
    wait_for_startup(duthost, localhost, 0, MAX_TIME_TO_REBOOT)
    # Wait for ssh port to open up on the linecards
    for linecard in duthosts.frontend_nodes:
        wait_for_startup(linecard, localhost, 0, MAX_TIME_TO_REBOOT)

    dut_uptime = duthost.get_up_time()
    logger.info('DUT {} up since {}'.format(hostname, dut_uptime))
    rebooted = float(dut_uptime_before.strftime(
        "%s")) != float(dut_uptime.strftime("%s"))
    assert rebooted, "Device {} did not reboot".format(hostname)

    # Verify that the links are all LCs are up
    check_interfaces_and_services_all_LCs(
        duthosts, conn_graph_facts, xcvr_skip_list)

    # Also make sure fanout hosts' links are up
    link_status_on_all_fanouts(fanouts_and_ports)


def test_link_status_on_host_reboot(duthosts, localhost, enum_rand_one_per_hwsku_frontend_hostname,
                                    conn_graph_facts, set_max_to_reboot,
                                    fanouthosts, xcvr_skip_list):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    hostname = duthost.hostname

    # Before test, check all interfaces and services are up
    check_interfaces_and_services(
        duthost, conn_graph_facts.get("device_conn", {}).get("hostname", {}), xcvr_skip_list)

    dut_ports = single_dut_and_ports(duthost)
    fanouts_and_ports = fanout_hosts_and_ports(fanouthosts, dut_ports)

    # Also make sure fanout hosts' links are up
    link_status_on_host(fanouts_and_ports)

    # Get a dut uptime before reboot
    dut_uptime_before = duthost.get_up_time()

    # Reboot dut, we should detect this host's fanout switches have all links down
    reboot(duthost, localhost, wait_for_ssh=False)

    # After reboot, immediately check if all links on all fanouts are down
    link_status_on_host(fanouts_and_ports, up=False)

    # Wait for ssh port to open up on the DUT
    wait_for_startup(duthost, localhost, 0, MAX_TIME_TO_REBOOT)

    dut_uptime = duthost.get_up_time()
    logger.info('DUT {} up since {}'.format(hostname, dut_uptime))
    rebooted = float(dut_uptime_before.strftime(
        "%s")) != float(dut_uptime.strftime("%s"))
    assert rebooted, "Device {} did not reboot".format(hostname)

    # After test, check all interfaces and services are up
    check_interfaces_and_services(
        duthost, conn_graph_facts.get("device_conn", {}).get("hostname", {}), xcvr_skip_list)

    # Also make sure fanout hosts' links are up
    link_status_on_host(fanouts_and_ports)
