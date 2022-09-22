"""
On SONiC device reboot, tests the link down on fanout switches
This test supports different platforms including:
    1. chassis
    2. single-asic dut
    3. multi-asic dut
"""
import logging

import pytest
import random

import tests.platform_tests.link_flap.link_flap_utils

from tests.platform_tests.test_reboot import check_interfaces_and_services
from tests.common.platform.device_utils import fanout_switch_port_lookup
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any'),
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
            {{ os: 'eos', hostname: 'str2-z9332f-02', device_type: 'FanoutLeaf' }: ['Ethernet160', 'Ethernet168', 'Ethernet200', 'Ethernet192']}
    """
    fanout_and_ports = {}
    for duthost in duts_and_ports.keys():
        for port in duts_and_ports[duthost]:
            fanout, fanout_port = fanout_switch_port_lookup(fanouthosts, duthost.hostname, port)
            # some ports on dut may not have link to fanout
            if fanout is None and fanout_port is None:
                logger.info("Interface {} on duthost {} doesn't link to any fanout switch".format(fanout_port, fanout.hostname, port, duthost.hostname))
                continue
            logger.info("Interface {} on fanout {} map to interface {} on duthost {}".format(fanout_port, fanout.hostname, port, duthost.hostname))
            if fanout in fanout_and_ports.keys():
                fanout_and_ports[fanout].append(fanout_port)
            else:
                fanout_and_ports[fanout] = [fanout_port]
    return fanout_and_ports

def reboot_duthost(duthost):
    duthost.command("reboot")

def is_link_down(fanout, port):
    """
        Either oper/admin status is down meaning link is down
    """
    logger.info("Checking interface {} status on fanout host {}".format(port, fanout.hostname))
    return fanout.is_intf_status_down(port)

def link_down_on_host(duthost, fanouts_and_ports):
    for fanout in fanouts_and_ports.keys():
        for fanout_port in fanouts_and_ports[fanout]:
            # Check every interfaces are down on this host every 5 sec until device boots up
            pytest_assert(wait_until(MAX_TIME_TO_REBOOT, 5, 0, is_link_down, fanout, fanout_port),
                    "Interface {} on {} is still up after {}sec".format(fanout_port, fanout.hostname, MAX_TIME_TO_REBOOT))
        logger.info("All interfaces on {} are down".format(fanout.hostname))
    return True

def links_down_on_all_LC(duthosts, fanouts_and_ports):
    """
    Return:
        True: all links on all LCs are down
    """
    for LC in duthosts.frontend_nodes:
        link_down_on_host(LC, fanouts_and_ports)
    logger.info("All interfaces on all linecards are down!")
    return True    

def check_interfaces_and_services_all_LCs(duthosts, conn_graph_facts, xcvr_skip_list):
    for LC in duthosts.frontend_nodes:
        check_interfaces_and_services(LC, conn_graph_facts["device_conn"][LC.hostname], xcvr_skip_list)

def test_link_down_on_sup_reboot(duthosts, enum_supervisor_dut_hostname, 
                                conn_graph_facts, duts_running_config_facts, 
                                fanouthosts, tbinfo, xcvr_skip_list):
    if len(duthosts.nodes) == 1:
        pytest.skip("Skip single-host dut for this test")
        
    sup = duthosts[enum_supervisor_dut_hostname]

    if 't2' not in tbinfo['topo']['name']:
        pytest.skip("Skip for non-t2 supervisor card")
   
    # Before test, check all interfaces and services are up on all linecards
    check_interfaces_and_services_all_LCs(duthosts, conn_graph_facts, xcvr_skip_list)
    
    duts_and_ports = multi_duts_and_ports(duthosts)
    fanouts_and_ports = fanout_hosts_and_ports(fanouthosts, duts_and_ports)
    # Reboot RP should reboot both RP&LC, should detect all links on all linecards go down
    logger.info("Rebooting RP {} and checking all linecards' interfaces".format(sup.hostname))

    reboot_duthost(sup)
    # RP doesn't have any interfaces, check all LCs' interfaces
    links_down_on_all_LC(duthosts, fanouts_and_ports)

    # After test, ensure all interfaces and services are up on all linecards before jumping to next test
    # Note that test might issue 'ERROR: AnsibleConnectionFailure: Host unreachable' 
    # if dut hasn't booted up yet, but it's alright because there will be retry
    check_interfaces_and_services_all_LCs(duthosts, conn_graph_facts, xcvr_skip_list)


def test_link_down_on_host_reboot(duthosts, enum_rand_one_per_hwsku_frontend_hostname, 
                                 duts_running_config_facts, conn_graph_facts, 
                                 fanouthosts, xcvr_skip_list, tbinfo):
    
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
   
    # Before test, check all interfaces and services are up
    check_interfaces_and_services(duthost, conn_graph_facts["device_conn"][duthost.hostname], xcvr_skip_list)

    dut_ports = single_dut_and_ports(duthost)
    fanouts_and_ports = fanout_hosts_and_ports(fanouthosts, dut_ports)

    # Reboot dut, we should detect this host's fanout switches have all links down
    # Note that there is case if image has issue that cause 'monit status' to fail, reboot will hang
    logger.info("Rebooting duthost {} and checking its interfaces".format(duthost.hostname))
    reboot_duthost(duthost)

    link_down_on_host(duthost, fanouts_and_ports)

    # After test, ensure all interfaces and services are up
    # Note that test might issue 'ERROR: AnsibleConnectionFailure: Host unreachable' 
    # if dut hasn't booted up yet, but it's alright because there will be retry
    check_interfaces_and_services(duthost, conn_graph_facts["device_conn"][duthost.hostname], xcvr_skip_list)

