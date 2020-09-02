import logging
import pytest

from tests.common.fixtures.conn_graph_facts import conn_graph_facts
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # lgtm[py/unused-import]
from .files.pfcwd_helper import TrafficPorts, set_pfc_timers, select_test_ports

logger = logging.getLogger(__name__)


def pytest_addoption(parser):
    """
    Command line args specific for the pfcwd test

    Args:
        parser: pytest parser object

    Returns:
        None

    """
    parser.addoption('--warm-reboot', action='store', type=bool, default=False,
                     help='Warm reboot needs to be enabled or not')
    parser.addoption('--restore-time', action='store', type=int, default=3000,
                     help='PFC WD storm restore interval')
    parser.addoption('--fake-storm', action='store', type=bool, default=True,
                     help='Fake storm for most ports instead of using pfc gen')

@pytest.fixture(scope="module")
def setup_pfc_test(duthost, ptfhost, conn_graph_facts):
    """
    Sets up all the parameters needed for the PFC Watchdog tests

    Args:
        duthost: AnsibleHost instance for DUT
        ptfhost: AnsibleHost instance for PTF
        conn_graph_facts: fixture that contains the parsed topology info

    Yields:
        setup_info: dictionary containing pfc timers, generated test ports and selected test ports
    """
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    port_list = mg_facts['minigraph_ports'].keys()
    ports = (' ').join(port_list)
    neighbors = conn_graph_facts['device_conn']
    dut_facts = duthost.setup()['ansible_facts']
    dut_eth0_ip = dut_facts['ansible_eth0']['ipv4']['address']
    dut_eth0_mac = dut_facts['ansible_eth0']['macaddress']
    vlan_nw = None

    if mg_facts['minigraph_vlans']:
        # gather all vlan specific info
        vlan_addr = mg_facts['minigraph_vlan_interfaces'][0]['addr']
        vlan_prefix = mg_facts['minigraph_vlan_interfaces'][0]['prefixlen']
        vlan_dev = mg_facts['minigraph_vlan_interfaces'][0]['attachto']
        vlan_ips = duthost.get_ip_in_range(num=1, prefix="{}/{}".format(vlan_addr, vlan_prefix), exclude_ips=[vlan_addr])['ansible_facts']['generated_ips']
        vlan_nw = vlan_ips[0].split('/')[0]

    # build the port list for the test
    tp_handle = TrafficPorts(mg_facts, neighbors, vlan_nw)
    test_ports = tp_handle.build_port_list()
    # select a subset of ports from the generated port list
    selected_ports = select_test_ports(test_ports)

    setup_info = { 'test_ports': test_ports,
                   'port_list': port_list,
                   'selected_test_ports': selected_ports,
                   'pfc_timers' : set_pfc_timers(),
                   'neighbors': neighbors,
                   'eth0_ip': dut_eth0_ip
                  }

    if mg_facts['minigraph_vlans']:
        setup_info['vlan'] = {'addr': vlan_addr,
                              'prefix': vlan_prefix,
                              'dev': vlan_dev
                             }
    else:
        setup_info['vlan'] = None

    # stop pfcwd
    logger.info("--- Stopping Pfcwd ---")
    duthost.command("pfcwd stop")

    # set poll interval
    duthost.command("pfcwd interval {}".format(setup_info['pfc_timers']['pfc_wd_poll_time']))

    yield setup_info

    logger.info("--- Starting Pfcwd ---")
    duthost.command("pfcwd start_default")
