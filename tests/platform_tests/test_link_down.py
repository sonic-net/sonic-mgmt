"""
On SONiC device reboot, tests the link down on fanout switches
This test supports different platforms including:
    1. chassis     
    2. single-asic dut
    3. multi-asic dut
    Note that for now we only run this on t2(chassis), which need more time to boot back up, 
    thus have more buffer to check for links
    e.g. for single-asic dut, device boot up takes ~40sec, check for all links takes ~73sec, 
    which means some latter links that are checked may already booted up.
    Even though for current test result, it's still fine on single-asic dut, 
    because when device went back up, links are still delayed to went up :)
    
"""
import logging
import time
import pytest

from tests.platform_tests.test_reboot import check_interfaces_and_services
from tests.common.platform.device_utils import fanout_switch_port_lookup
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.reboot import *

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t2'),
]

MAX_TIME_TO_REBOOT = 120


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
            dict of {[fanout1, [fanout_ports]], [fanout2, [fanout_ports]] ...}
            example:
            {{ os: 'eos', hostname: 'str2-z9332f-02', device_type: 'FanoutLeaf' }: 
            ['Ethernet160', 'Ethernet168', 'Ethernet200', 'Ethernet192']}
    """
    fanout_and_ports = {}
    for duthost in duts_and_ports.keys():
        for port in duts_and_ports[duthost]:
            fanout, fanout_port = fanout_switch_port_lookup(fanouthosts, duthost.hostname, port)
            # some ports on dut may not have link to fanout
            if fanout is None and fanout_port is None:
                logger.info("Interface {} on duthost {} doesn't link to any fanout switch"
                            .format(port, duthost.hostname))
                continue
            logger.info("Interface {} on fanout {} (os type {}) map to interface {} on duthost {}"
                        .format(fanout_port, fanout.hostname, fanout.get_fanout_os(), port, duthost.hostname))
            if fanout in fanout_and_ports.keys():
                fanout_and_ports[fanout].append(fanout_port)
            else:
                fanout_and_ports[fanout] = [fanout_port]
    return fanout_and_ports
    

def is_link_down(fanout, port):
    """
        Either oper/admin status is down meaning link is down
    """
    logger.info("Checking interface {} down status on fanout host {}".format(port, fanout.hostname))
    return fanout.is_intf_status_down(port)


def is_link_up(fanout, port):
    logger.info("Checking interface {} up status on fanout host {}".format(port, fanout.hostname))
    return not fanout.is_intf_status_down(port)


def link_status_on_host(duthost, localhost, fanouts_and_ports, up=True):
    for fanout, ports in fanouts_and_ports.items():
        hostname = fanout.hostname
        for port in ports:
            # Assumption here is all fanouts are healthy.
            # If fanout is not healthy, or links not in expected state, following errors will be thrown
            if up:
                # Make sure interfaces are up on fanout hosts
                pytest_assert(wait_until(MAX_TIME_TO_REBOOT, 5, 0, is_link_up, fanout, port),
                              "Interface {} on {} is still down after {}sec".format(port, hostname, MAX_TIME_TO_REBOOT))
            else:
                # Check every interfaces are down on this host every 5 sec until device boots up
                pytest_assert(wait_until(MAX_TIME_TO_REBOOT, 5, 0, is_link_down, fanout, port),
                              "Interface {} on {} is still up after {}sec".format(port, hostname, MAX_TIME_TO_REBOOT))
                             
        logger.info("All interfaces on {} are {}".format(fanout.hostname, "up" if up else "down"))
    return True


def link_status_on_all_LC(duthosts, localhost, fanouts_and_ports, up=True):
    """
    Return:
        True: all links on all LCs are down
    """
    for LC in duthosts.frontend_nodes:
        link_status_on_host(LC, localhost, fanouts_and_ports, up)
    logger.info("All interfaces on all linecards are down!")
    return True    


def check_interfaces_and_services_all_LCs(duthosts, conn_graph_facts, xcvr_skip_list):
    for LC in duthosts.frontend_nodes:
        check_interfaces_and_services(LC, conn_graph_facts["device_conn"][LC.hostname], xcvr_skip_list)


def test_link_down_on_sup_reboot(duthosts, localhost, enum_supervisor_dut_hostname, 
                                 conn_graph_facts, duts_running_config_facts, 
                                 fanouthosts, tbinfo, xcvr_skip_list):
    if len(duthosts.nodes) == 1:
        pytest.skip("Skip single-host dut for this test")

    duthost = duthosts[enum_supervisor_dut_hostname]
    hostname = duthost.hostname
    # Before test, check all interfaces and services are up on all linecards
    check_interfaces_and_services_all_LCs(duthosts, conn_graph_facts, xcvr_skip_list)

    duts_and_ports = multi_duts_and_ports(duthosts)
    fanouts_and_ports = fanout_hosts_and_ports(fanouthosts, duts_and_ports)

    # Also make sure fanout hosts' links are up
    link_status_on_all_LC(duthosts, localhost, fanouts_and_ports)
    
    # Get a dut uptime before reboot
    dut_uptime_before = duthost.get_up_time()
    
    # Reboot RP should reboot both RP&LC, should detect all links on all linecards go down
    reboot(duthost, localhost, wait_for_ssh=False)

    # RP doesn't have any interfaces, check all LCs' interfaces
    link_status_on_all_LC(duthosts, localhost, fanouts_and_ports, up=False)

    time.sleep(MAX_TIME_TO_REBOOT)

    dut_uptime = duthost.get_up_time()
    logger.info('DUT {} up since {}'.format(hostname, dut_uptime))
    assert float(dut_uptime_before.strftime("%s")) != float(dut_uptime.strftime("%s")), "Device {} did not reboot".format(hostname)


def test_link_status_on_host_reboot(duthosts, localhost, enum_frontend_dut_hostname, 
                                    duts_running_config_facts, conn_graph_facts, 
                                    fanouthosts, xcvr_skip_list, tbinfo):
    duthost = duthosts[enum_frontend_dut_hostname]
    hostname = duthost.hostname

    # Before test, check all interfaces and services are up
    check_interfaces_and_services(duthost, conn_graph_facts["device_conn"][hostname], xcvr_skip_list)
    
    dut_ports = single_dut_and_ports(duthost)
    fanouts_and_ports = fanout_hosts_and_ports(fanouthosts, dut_ports)

    # Also make sure fanout hosts' links are up
    link_status_on_host(duthost, localhost, fanouts_and_ports)

    # Get a dut uptime before reboot
    dut_uptime_before = duthost.get_up_time()
    
    # Reboot dut, we should detect this host's fanout switches have all links down
    reboot(duthost, localhost, wait_for_ssh=False)

    # After reboot, immediately check for links 'down' status
    link_status_on_host(duthost, localhost, fanouts_and_ports, up=False)

    time.sleep(MAX_TIME_TO_REBOOT)

    dut_uptime = duthost.get_up_time()
    logger.info('DUT {} up since {}'.format(hostname, dut_uptime))
    assert float(dut_uptime_before.strftime("%s")) != float(dut_uptime.strftime("%s")), "Device {} did not reboot".format(hostname)
