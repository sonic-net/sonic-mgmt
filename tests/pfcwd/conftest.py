import logging
import pytest

from tests.common.fixtures.conn_graph_facts import conn_graph_facts
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory     # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import set_ptf_port_mapping_mode   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import change_mac_addresses        # lgtm[py/unused-import]
from tests.common.mellanox_data import is_mellanox_device as isMellanoxDevice
from .files.pfcwd_helper import TrafficPorts, set_pfc_timers, select_test_ports
from tests.common.utilities import str2bool

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
    parser.addoption('--fake-storm', action='store', type=str2bool, default=True,
                     help='Fake storm for most ports instead of using pfc gen')
    parser.addoption('--two-queues', action='store_true', default=True,
                     help='Run test with sending traffic to both queues [3, 4]')

@pytest.fixture(scope="module")
def two_queues(request):
    """
    Enable/Disable sending traffic to queues [4, 3]
    By default send to queue 4

    Args:
        request: pytest request object
        duthosts: AnsibleHost instance for multi DUT
        rand_one_dut_hostname: hostname of DUT

    Returns:
        two_queues: False/True
    """
    return request.config.getoption('--two-queues')


@pytest.fixture(scope="module")
def fake_storm(request, duthosts, rand_one_dut_hostname):
    """
    Enable/disable fake storm based on platform and input parameters

    Args:
        request: pytest request object
        duthosts: AnsibleHost instance for multi DUT
        rand_one_dut_hostname: hostname of DUT

    Returns:
        fake_storm: False/True
    """
    duthost = duthosts[rand_one_dut_hostname]
    return request.config.getoption('--fake-storm') if not isMellanoxDevice(duthost) else False


def update_t1_test_ports(duthost, mg_facts, test_ports, asic_index, tbinfo):
    """
    Find out active IP interfaces and use the list to
    remove inactive ports from test_ports
    """
    ip_ifaces = duthost.asic_instance(asic_index).get_active_ip_interfaces(tbinfo)
    port_list = []
    for iface in ip_ifaces.keys():
        if iface.startswith("PortChannel"):
            port_list.extend(
                mg_facts["minigraph_portchannels"][iface]["members"]
            )
        else:
            port_list.append(iface)
    port_list_set = set(port_list)
    for port in test_ports.keys():
        if port not in port_list_set:
            del test_ports[port]
    return test_ports


@pytest.fixture(scope="module")
def setup_pfc_test(
    duthosts, rand_one_dut_hostname, ptfhost, conn_graph_facts, tbinfo,
    enum_frontend_asic_index
):
    """
    Sets up all the parameters needed for the PFC Watchdog tests

    Args:
        duthost: AnsibleHost instance for DUT
        ptfhost: AnsibleHost instance for PTF
        conn_graph_facts: fixture that contains the parsed topology info

    Yields:
        setup_info: dictionary containing pfc timers, generated test ports and selected test ports
    """
    SUPPORTED_T1_TOPOS = {"t1-lag", "t1-64-lag"}
    duthost = duthosts[rand_one_dut_hostname]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    port_list = mg_facts['minigraph_ports'].keys()
    ports = (' ').join(port_list)
    neighbors = conn_graph_facts['device_conn'][duthost.hostname]
    dut_eth0_ip = duthost.mgmt_ip
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

    # In T1 topology update test ports by removing inactive ports
    topo = tbinfo["topo"]["name"]
    if topo in SUPPORTED_T1_TOPOS:
        test_ports = update_t1_test_ports(
            duthost, mg_facts, test_ports, enum_frontend_asic_index, tbinfo
        )

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
