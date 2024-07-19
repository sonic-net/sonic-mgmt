import logging
import pytest

from tests.common.fixtures.conn_graph_facts import conn_graph_facts         # noqa F401
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory     # noqa F401
from tests.common.fixtures.ptfhost_utils import set_ptf_port_mapping_mode   # noqa F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses        # noqa F401
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
        enum_rand_one_per_hwsku_frontend_hostname: hostname of DUT

    Returns:
        two_queues: False/True
    """
    return request.config.getoption('--two-queues')


@pytest.fixture(scope="module")
def fake_storm(request, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    Enable/disable fake storm based on platform and input parameters

    Args:
        request: pytest request object
        duthosts: AnsibleHost instance for multi DUT
        enum_rand_one_per_hwsku_frontend_hostname: hostname of DUT

    Returns:
        fake_storm: False/True
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    return request.config.getoption('--fake-storm') if not isMellanoxDevice(duthost) else False


def update_t1_test_ports(duthost, mg_facts, test_ports, tbinfo):
    """
    Find out active IP interfaces and use the list to
    remove inactive ports from test_ports
    """
    ip_ifaces = duthost.get_active_ip_interfaces(tbinfo, asic_index=0)
    port_list = []
    for iface in list(ip_ifaces.keys()):
        if iface.startswith("PortChannel"):
            port_list.extend(
                mg_facts["minigraph_portchannels"][iface]["members"]
            )
        else:
            port_list.append(iface)
    port_list_set = set(port_list)
    for port in list(test_ports.keys()):
        if port not in port_list_set:
            del test_ports[port]
    return test_ports


@pytest.fixture(scope="module")
def setup_pfc_test(
    duthosts, enum_rand_one_per_hwsku_frontend_hostname, ptfhost, conn_graph_facts, tbinfo,     # noqa F811
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
    SUPPORTED_T1_TOPOS = {"t1-lag", "t1-64-lag", "t1-56-lag", "t1-28-lag"}
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    port_list = list(mg_facts['minigraph_ports'].keys())
    neighbors = conn_graph_facts['device_conn'].get(duthost.hostname, {})
    dut_eth0_ip = duthost.mgmt_ip
    vlan_nw = None

    if mg_facts['minigraph_vlans']:
        # Filter VLANs with one interface inside only(PortChannel interface in case of t0-56-po2vlan topo)
        unexpected_vlans = []
        for vlan, vlan_data in list(mg_facts['minigraph_vlans'].items()):
            if len(vlan_data['members']) < 2:
                unexpected_vlans.append(vlan)

        # Update minigraph_vlan_interfaces with only expected VLAN interfaces
        expected_vlan_ifaces = []
        for vlan in unexpected_vlans:
            for mg_vl_iface in mg_facts['minigraph_vlan_interfaces']:
                if vlan != mg_vl_iface['attachto']:
                    expected_vlan_ifaces.append(mg_vl_iface)
        if expected_vlan_ifaces:
            mg_facts['minigraph_vlan_interfaces'] = expected_vlan_ifaces

        # gather all vlan specific info
        vlan_addr = mg_facts['minigraph_vlan_interfaces'][0]['addr']
        vlan_prefix = mg_facts['minigraph_vlan_interfaces'][0]['prefixlen']
        vlan_dev = mg_facts['minigraph_vlan_interfaces'][0]['attachto']
        vlan_ips = duthost.get_ip_in_range(
            num=1, prefix="{}/{}".format(vlan_addr, vlan_prefix),
            exclude_ips=[vlan_addr])['ansible_facts']['generated_ips']
        vlan_nw = vlan_ips[0].split('/')[0]

    # build the port list for the test
    tp_handle = TrafficPorts(mg_facts, neighbors, vlan_nw)
    test_ports = tp_handle.build_port_list()

    # In T1 topology update test ports by removing inactive ports
    topo = tbinfo["topo"]["name"]
    if topo in SUPPORTED_T1_TOPOS:
        test_ports = update_t1_test_ports(
            duthost, mg_facts, test_ports, tbinfo
        )
    # select a subset of ports from the generated port list
    selected_ports = select_test_ports(test_ports)

    setup_info = {'test_ports': test_ports,
                  'port_list': port_list,
                  'selected_test_ports': selected_ports,
                  'pfc_timers': set_pfc_timers(),
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

    logger.info("setup_info : {}".format(setup_info))
    yield setup_info


@pytest.fixture(scope="module")
def setup_dut_test_params(
    duthosts, enum_rand_one_per_hwsku_frontend_hostname, ptfhost, conn_graph_facts, tbinfo,     # noqa F811
):
    """
    Sets up all the parameters needed for the PFCWD tests

    Args:
        duthost: AnsibleHost instance for DUT
        ptfhost: AnsibleHost instance for PTF
        conn_graph_facts: fixture that contains the parsed topology info

    Yields:
        dut_info: dictionary containing dut information
    """
    dut_test_params = {'basicParams': {'is_dualtor': False}}
    if "dualtor" in tbinfo["topo"]["name"]:
        dut_test_params["basicParams"]["is_dualtor"] = True
        vlan_cfgs = tbinfo['topo']['properties']['topology']['DUT']['vlan_configs']
        if vlan_cfgs and 'default_vlan_config' in vlan_cfgs:
            default_vlan_name = vlan_cfgs['default_vlan_config']
            if default_vlan_name:
                for vlan in list(vlan_cfgs[default_vlan_name].values()):
                    if 'mac' in vlan and vlan['mac']:
                        dut_test_params["basicParams"]["def_vlan_mac"] = vlan['mac']
                        break

    logger.info("dut_test_params : {}".format(dut_test_params))
    yield dut_test_params


# icmp_responder need to be paused during the test because the test case
# configures static IP address on ptf host and sends ICMP reply to DUT.
@pytest.fixture(scope="module")
def pause_icmp_responder(ptfhost):
    icmp_responder_status = ptfhost.shell("supervisorctl status icmp_responder", module_ignore_errors=True)["stdout"]
    if "RUNNING" not in icmp_responder_status:
        yield
        return
    ptfhost.shell("supervisorctl stop icmp_responder", module_ignore_errors=True)

    yield

    ptfhost.shell("supervisorctl restart icmp_responder", module_ignore_errors=True)
