import pytest
import ipaddress
import logging

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert as py_assert
from tests.common.dhcp_relay_utils import check_routes_to_dhcp_server
from tests.common.fixtures.vlan_config_swap import load_topo_vlan_configs

logger = logging.getLogger(__name__)

SINGLE_TOR_MODE = 'single'
DUAL_TOR_MODE = 'dual'


def pytest_addoption(parser):
    """
    Adds options to pytest that are used by the COPP tests.
    """
    parser.addoption(
        "--stress_restart_round",
        action="store",
        type=int,
        default=10,
        help="Set custom restart rounds",
    )
    parser.addoption(
        "--stress_restart_duration",
        action="store",
        type=int,
        default=90,
        help="Set custom restart rounds",
    )
    parser.addoption(
        "--stress_restart_pps",
        action="store",
        type=int,
        default=100,
        help="Set custom restart rounds",
    )
    parser.addoption(
        "--max_packets_per_sec",
        action="store",
        type=int,
        help="Set maximum packets per second for stress test",
    )


@pytest.fixture(scope="module", autouse=True)
def check_dhcp_feature_status(duthost):
    feature_status_output = duthost.show_and_parse("show feature status")
    for feature in feature_status_output:
        if feature["feature"] == "dhcp_relay" and feature["state"] != "enabled":
            pytest.skip("dhcp_relay is not enabled")


def _resolve_plan_to_vlan_list(tbinfo, mg_facts, vlan_plan):
    topo_name = tbinfo['topo']['name']
    vlan_configs = load_topo_vlan_configs(topo_name)
    py_assert(
        vlan_configs is not None,
        "Topo {} does not define DUT.vlan_configs".format(topo_name),
    )

    resolved_plan_name = vlan_plan
    if resolved_plan_name is None:
        resolved_plan_name = vlan_configs.get('default_vlan_config')

    py_assert(
        resolved_plan_name in vlan_configs,
        "VLAN plan {!r} not defined in topo {}; available plans: {}".format(
            resolved_plan_name,
            topo_name,
            [k for k in vlan_configs.keys() if k != 'default_vlan_config'],
        ),
    )

    ptf_idx_to_dut_port = {v: k for k, v in mg_facts['minigraph_ptf_indices'].items()}
    vlan_list = []
    for vlan_iface_name, vlan_params in list(vlan_configs[resolved_plan_name].items()):
        prefix = vlan_params.get('prefix')
        vlan_addr = None
        vlan_mask = None
        if prefix:
            vlan_iface = ipaddress.IPv4Interface(prefix)
            vlan_addr = str(vlan_iface.ip)
            vlan_mask = str(vlan_iface.netmask)

        vlan_members = []
        for ptf_idx in vlan_params.get('intfs', []) or []:
            dut_port = ptf_idx_to_dut_port.get(ptf_idx)
            if dut_port is not None and 'PortChannel' not in dut_port:
                vlan_members.append(dut_port)

        vlan_list.append((vlan_iface_name, vlan_members, vlan_addr, vlan_mask))

    return resolved_plan_name, vlan_list


def _build_dhcp_relay_entry_for_vlan(duthost, duthosts, rand_one_dut_hostname, ptfhost, tbinfo,
                                     mg_facts, vlan_iface_name, vlan_members, vlan_addr,
                                     vlan_mask, vlan_plan):
    switch_loopback_ip = mg_facts['minigraph_lo_interfaces'][0]['addr']

    downlink_vlan_iface = {}
    downlink_vlan_iface['name'] = vlan_iface_name
    downlink_vlan_iface['addr'] = vlan_addr
    downlink_vlan_iface['mask'] = vlan_mask
    if vlan_addr and vlan_mask:
        subnet = ipaddress.IPv4Interface("{}/{}".format(vlan_addr, vlan_mask)).network
        downlink_vlan_iface['link_selection_ip'] = str(subnet.network_address)

    res = duthost.shell('cat /sys/class/net/{}/address'.format(vlan_iface_name))
    downlink_vlan_iface['mac'] = res['stdout']
    downlink_vlan_iface['dhcp_server_addrs'] = mg_facts['dhcp_servers']

    client_iface = {}
    for port in vlan_members:
        if port in mg_facts['minigraph_port_name_to_alias_map']:
            break
    else:
        return None
    client_iface['name'] = port
    client_iface['alias'] = mg_facts['minigraph_port_name_to_alias_map'][client_iface['name']]
    client_iface['port_idx'] = mg_facts['minigraph_ptf_indices'][client_iface['name']]

    uplink_interfaces, uplink_port_indices = calculate_uplink_interfaces_and_port_indices(mg_facts)
    other_client_ports_indices = []
    for iface_name in vlan_members:
        if mg_facts['minigraph_ptf_indices'][iface_name] == client_iface['port_idx']:
            pass
        else:
            other_client_ports_indices.append(mg_facts['minigraph_ptf_indices'][iface_name])

    dhcp_relay_data = {}
    dhcp_relay_data['downlink_vlan_iface'] = downlink_vlan_iface
    dhcp_relay_data['client_iface'] = client_iface
    dhcp_relay_data['other_client_ports'] = other_client_ports_indices
    dhcp_relay_data['uplink_interfaces'] = uplink_interfaces
    dhcp_relay_data['uplink_port_indices'] = uplink_port_indices
    dhcp_relay_data['switch_loopback_ip'] = str(switch_loopback_ip)
    dhcp_relay_data['portchannels'] = mg_facts['minigraph_portchannels']
    dhcp_relay_data['vlan_members'] = vlan_members
    dhcp_relay_data['vlan_plan'] = vlan_plan

    loopback_iface = mg_facts['minigraph_lo_interfaces'][0]['name']
    dhcp_relay_data['loopback_iface'] = loopback_iface
    portchannels_with_ips = {}
    portchannels_ip_list = []

    for portchannel_name, portchannel_info in mg_facts['minigraph_portchannels'].items():
        for pc_interface in mg_facts['minigraph_portchannel_interfaces']:
            if pc_interface['attachto'] == portchannel_name:
                ip_with_mask = f"{pc_interface['addr']}/{pc_interface['mask']}"
                ip_obj = ipaddress.ip_interface(ip_with_mask)
                if ip_obj.version != 4:
                    continue
                hosts = list(ip_obj.network.hosts())
                if len(hosts) < 2:
                    logger.warning(f"Not enough hosts for nexthop in {ip_with_mask}")
                    continue

                nexthop = str(hosts[1]) if str(ip_obj.ip) == str(hosts[0]) else str(hosts[0])
                if portchannel_name not in portchannels_with_ips:
                    portchannels_with_ips[portchannel_name] = []
                portchannels_with_ips[portchannel_name] = {
                    "ip": str(ip_obj),
                    "nexthop": nexthop
                }
                portchannels_ip_list.append(str(ip_obj))

    dhcp_relay_data['portchannels_with_ips'] = portchannels_with_ips
    dhcp_relay_data['portchannels_ip_list'] = portchannels_ip_list

    res = duthost.shell('cat /sys/class/net/{}/address'.format(uplink_interfaces[0]))
    dhcp_relay_data['uplink_mac'] = res['stdout']
    if 'dualtor' in tbinfo['topo']['name']:
        standby_duthost = [duthost for duthost in duthosts if duthost != duthosts[rand_one_dut_hostname]][0]
        res = standby_duthost.shell('cat /sys/class/net/{}/address'.format(uplink_interfaces[0]))
        dhcp_relay_data['standby_uplink_mac'] = res['stdout']
        dhcp_relay_data['standby_dut_lo_addr'] = \
            mg_facts["minigraph_devices"][standby_duthost.sonichost.hostname]['lo_addr']
        standby_mg_facts = standby_duthost.get_extended_minigraph_facts(tbinfo)
        standby_uplink_interfaces, standby_uplink_port_indices = \
            calculate_uplink_interfaces_and_port_indices(standby_mg_facts)
        dhcp_relay_data['standby_uplink_port_indices'] = standby_uplink_port_indices
    dhcp_relay_data['default_gw_ip'] = mg_facts['minigraph_mgmt_interface']['gwaddr']

    return dhcp_relay_data


def _build_dhcp_relay_data_list(duthosts, rand_one_dut_hostname, ptfhost, tbinfo, vlan_plan=None):
    duthost = duthosts[rand_one_dut_hostname]
    dhcp_relay_data_list = []

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    resolved_plan_name, vlan_list = _resolve_plan_to_vlan_list(tbinfo, mg_facts, vlan_plan)

    for vlan_iface_name, vlan_members, vlan_addr, vlan_mask in vlan_list:
        dhcp_relay_data = _build_dhcp_relay_entry_for_vlan(
            duthost, duthosts, rand_one_dut_hostname, ptfhost, tbinfo,
            mg_facts, vlan_iface_name, vlan_members, vlan_addr, vlan_mask,
            resolved_plan_name,
        )
        if dhcp_relay_data is not None:
            dhcp_relay_data_list.append(dhcp_relay_data)

    return dhcp_relay_data_list


@pytest.fixture(scope="module")
def dut_dhcp_relay_data_multivlan(duthosts, rand_one_dut_hostname, ptfhost, tbinfo,
                                  parametrize_vlan_config_from_topo):
    """Same shape as `dut_dhcp_relay_data`, but for whichever vlan_config
    variant is currently active. The variant is supplied by
    `parametrize_vlan_config_from_topo` (which also applies the config
    patch). We read its `vlan_plan` and build the matching dhcp_relay_data
    entries."""
    vlan_plan = parametrize_vlan_config_from_topo[0]["vlan_plan"]
    return _build_dhcp_relay_data_list(
        duthosts, rand_one_dut_hostname, ptfhost, tbinfo, vlan_plan,
    )


@pytest.fixture(scope="module")
def dut_dhcp_relay_data(duthosts, rand_one_dut_hostname, ptfhost, tbinfo):
    """ Fixture which returns a list of dictionaries where each dictionary contains
        data necessary to test one instance of a DHCP relay agent running on the DuT.
        This fixture is scoped to the module, as the data it gathers can be used by
        all tests in this module. It does not need to be run before each test.
    """
    return _build_dhcp_relay_data_list(duthosts, rand_one_dut_hostname, ptfhost, tbinfo, vlan_plan=None)


def calculate_uplink_interfaces_and_port_indices(mg_facts):
    uplink_interfaces = []
    uplink_port_indices = []
    for iface_name, neighbor_info_dict in list(mg_facts['minigraph_neighbors'].items()):
        if neighbor_info_dict['name'] in mg_facts['minigraph_devices']:
            neighbor_device_info_dict = mg_facts['minigraph_devices'][neighbor_info_dict['name']]
            if 'type' in neighbor_device_info_dict and neighbor_device_info_dict['type'] in \
                    ['LeafRouter', 'MgmtLeafRouter', 'BackEndLeafRouter']:
                # If this uplink's physical interface is a member of a portchannel interface,
                # we record the name of the portchannel interface here, as this is the actual
                # interface the DHCP relay will listen on.
                iface_is_portchannel_member = False
                for portchannel_name, portchannel_info_dict in list(mg_facts['minigraph_portchannels'].items()):
                    if 'members' in portchannel_info_dict and iface_name in portchannel_info_dict['members']:
                        iface_is_portchannel_member = True
                        if portchannel_name not in uplink_interfaces:
                            uplink_interfaces.append(portchannel_name)
                        break
                    # If the uplink's physical interface is not a member of a portchannel,
                    # add it to our uplink interfaces list
                if not iface_is_portchannel_member:
                    uplink_interfaces.append(iface_name)

                uplink_port_indices.append(mg_facts['minigraph_ptf_indices'][iface_name])
    return uplink_interfaces, uplink_port_indices


@pytest.fixture(scope="module")
def validate_dut_routes_exist(duthosts, rand_one_dut_hostname, dut_dhcp_relay_data):
    """Fixture to valid a route to each DHCP server exist
    """
    py_assert(wait_until(360, 5, 0, check_routes_to_dhcp_server, duthosts[rand_one_dut_hostname],
                         dut_dhcp_relay_data),
              "Packets relayed to DHCP server should go through default route via upstream neighbor, but now it's" +
              " going through mgmt interface, which means device is in an unhealthy status")


@pytest.fixture(scope="module")
def testing_config(duthosts, rand_one_dut_hostname, tbinfo):
    duthost = duthosts[rand_one_dut_hostname]

    if 'dualtor' in tbinfo['topo']['name']:
        yield DUAL_TOR_MODE, duthost
    else:
        yield SINGLE_TOR_MODE, duthost


@pytest.fixture(scope="function")
def clean_processes_after_stress_test(ptfhost):
    yield
    ptfhost.shell("kill -9 $(ps aux | grep  dhcp_relay_stress_test | grep -v 'grep' | awk '{print $2}')",
                  module_ignore_errors=True)
