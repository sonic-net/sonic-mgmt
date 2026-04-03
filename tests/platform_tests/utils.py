import logging

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.multi_thread_utils import SafeThreadPoolExecutor
from tests.common.platform.device_utils import fanout_switch_port_lookup
from tests.common.utilities import get_plt_reboot_ctrl, wait_until
from tests.platform_tests.test_reboot import check_interfaces_and_services


logger = logging.getLogger(__name__)


def get_max_to_reboot(duthost, test_name):
    """
    For chassis testbeds, we need to specify plt_reboot_ctrl in inventory file,
    to let MAX_TIME_TO_REBOOT to be overwritten by specified timeout value
    """
    max_time_to_reboot = 300
    plt_reboot_ctrl = get_plt_reboot_ctrl(duthost, test_name, 'cold')
    if plt_reboot_ctrl:
        max_time_to_reboot = plt_reboot_ctrl.get('timeout', 120)

    return max_time_to_reboot


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
            fanout, fanout_port = fanout_switch_port_lookup(fanouthosts, duthost.hostname, port)
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


def link_status_on_host(fanouts_and_ports, max_time_to_reboot, up=True):
    for fanout, ports in list(fanouts_and_ports.items()):
        hostname = fanout.hostname
        # Assumption here is all fanouts are healthy.
        # If fanout is not healthy, or links not in expected state, following errors will be thrown
        if up:
            # Make sure interfaces are up on fanout hosts
            pytest_assert(wait_until(max_time_to_reboot, 5, 0, links_up, fanout, ports),
                          "Interface(s) on {} is still down after {}sec".format(hostname, max_time_to_reboot))
        else:
            # Check every interface is down on this host every 5 sec until device boots up
            pytest_assert(wait_until(max_time_to_reboot, 5, 0, links_down, fanout, ports),
                          "Interface(s) on {} is still up after {}sec".format(hostname, max_time_to_reboot))
    return True


def check_interfaces_and_services_all_lcs(duthosts, conn_graph_facts, xcvr_skip_list):
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(
                check_interfaces_and_services,
                linecard, conn_graph_facts["device_conn"][linecard.hostname], xcvr_skip_list,
            )
