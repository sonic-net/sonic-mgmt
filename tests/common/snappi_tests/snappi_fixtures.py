"""
This module contains the snappi fixture in the snappi_tests directory.
"""
import pytest
import time
import logging
import snappi
import sys
import random
import subprocess
import csv
import json
import os
from copy import copy
from tests.common.errors import RunAnsibleModuleFail
from ipaddress import ip_address, IPv4Address, IPv6Address
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts     # noqa: F401
from tests.common.snappi_tests.common_helpers import get_addrs_in_subnet, get_peer_snappi_chassis, \
    get_ipv6_addrs_in_subnet, parse_override
from tests.common.snappi_tests.snappi_helpers import SnappiFanoutManager, get_snappi_port_location, \
    get_macs, get_ip_addresses, subnet_mask_from_hosts   # noqa: F401
from tests.common.snappi_tests.port import SnappiPortConfig, SnappiPortType
from tests.common.helpers.assertions import pytest_assert, pytest_require   # noqa: F811
from tests.common.snappi_tests.variables import pfcQueueGroupSize, pfcQueueValueDict, dut_ip_start, snappi_ip_start, \
    prefix_length, dut_ipv6_start, snappi_ipv6_start, v6_prefix_length, dut_ip_for_non_macsec_port
from tests.common.macsec.macsec_config_helper import set_macsec_profile, enable_macsec_port, disable_macsec_port, \
    delete_macsec_profile
from tests.common.snappi_tests.uhd.uhd_helpers import NetworkConfigSettings, create_front_panel_ports, \
    create_connections, create_uhdIp_list, create_arp_bypass, create_profiles
logger = logging.getLogger(__name__)

macsec_enabled_port = {}
macsec_profile_name = ""


@pytest.fixture(scope="module")
def snappi_api_serv_ip(tbinfo):
    """
    In a Snappi testbed, there is no PTF docker.
    Hence, we use ptf_ip field to store snappi API server.
    This fixture returns the IP address of the snappi API server.
    Args:
       tbinfo (pytest fixture): fixture provides information about testbed
    Returns:
        snappi API server IP
    """
    return tbinfo['ptf_ip']


@pytest.fixture(scope="module")
def snappi_api_serv_port(tbinfo, duthosts, rand_one_dut_hostname):
    """
    This fixture returns the TCP Port of the Snappi API server.
    Args:
        duthost (pytest fixture): The duthost fixture.
    Returns:
        snappi API server port.
    """
    if "tg_api_server" in tbinfo:
        return tbinfo['tg_api_server'].split(':')[1]

    duthost = duthosts[rand_one_dut_hostname]
    return (duthost.host.options['variable_manager'].
            _hostvars[duthost.hostname]['snappi_api_server']['rest_port'])


@pytest.fixture(scope='module')
def snappi_api(snappi_api_serv_ip,
               snappi_api_serv_port):
    """
    Fixture for session handle,
    for creating snappi objects and making API calls.
    Args:
        snappi_api_serv_ip (pytest fixture): snappi_api_serv_ip fixture
        snappi_api_serv_port (pytest fixture): snappi_api_serv_port fixture.
    """
    location = "https://" + snappi_api_serv_ip + ":" + str(snappi_api_serv_port)
    # TODO: Currently extension is defaulted to ixnetwork.
    # Going forward, we should be able to specify extension
    # from command line while running pytest.
    api = snappi.api(location=location, ext="ixnetwork")
    # TODO - Uncomment to use. Prefer to use environment vars to retrieve this information
    # api._username = "<please mention the username if other than default username>"
    # api._password = "<please mention the password if other than default password>"
    yield api

    if getattr(api, 'assistant', None) is not None:
        api.assistant.Session.remove()


def __gen_mac(id):
    """
    Generate a MAC address
    Args:
        id (int): Snappi port ID
    Returns:
        MAC address (string)
    """
    return '00:{:02d}:22:33:44:01'.format(id)


def __gen_pc_mac(id):
    """
    Generate a MAC address for a portchannel interface

    Args:
        id (int): portchannel ID
    Returns:
        MAC address (string)
    """
    return '10:22:33:44:55:{:02d}'.format(id)


def __valid_ipv4_addr(ip):
    """
    Determine if a input string is a valid IPv4 address
    Args:
        ip (unicode str): input IP address
    Returns:
        True if the input is a valid IPv4 adress or False otherwise
    """
    try:
        return True if type(ip_address(ip)) is IPv4Address else False
    except ValueError:
        return False


def __valid_ipv6_addr(ip):
    """
    Determine if an input string is a valid IPv6 address
    Args:
        ip (unicode str): input IP address
    Returns:
        True if the input is a valid IPv6 address or False otherwise
    """
    try:
        return True if type(ip_address(ip)) is IPv6Address else False
    except ValueError:
        return False


def __l3_intf_config(config, port_config_list, duthost, snappi_ports, setup=True):
    """
    Generate Snappi configuration of layer 3 interfaces (IPv4 + IPv6).
    """
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    if 'minigraph_interfaces' not in mg_facts:
        return True
    l3_intf_facts = mg_facts['minigraph_interfaces']
    if not l3_intf_facts:
        return True

    # Group all (v4/v6) entries per physical interface
    grouped = {}
    for entry in l3_intf_facts:
        grouped.setdefault(entry['attachto'], []).append(entry)

    for intf, entries in grouped.items():
        port_ids = [i for i, sp in enumerate(snappi_ports) if sp['peer_port'] == intf]
        if len(port_ids) != 1:
            continue
        port_id = port_ids[0]
        mac = __gen_mac(port_id)
        device = config.devices.device(name='Device Port {}'.format(port_id))[-1]
        ethernet = device.ethernets.add()
        ethernet.name = 'Ethernet Port {}'.format(port_id)
        ethernet.connection.port_name = config.ports[port_id].name
        ethernet.mac = mac

        v4_addr = v4_gw = v4_prefix = None
        v6_addr = v6_gw = v6_prefix = None

        for e in entries:
            addr = e['addr']
            peer = e.get('peer_addr')
            if not peer:
                continue
            prefix = int(e['prefixlen'])
            try:
                ip_obj = ip_address(addr)
            except ValueError:
                continue

            asic_inst = duthost.get_port_asic_instance(intf)
            namespace = duthost.get_namespace_from_asic_id(asic_inst.asic_index) if asic_inst else None
            gen_data_flow_dest_ip(peer, duthost, intf, namespace=namespace, setup=setup)

            if ip_obj.version == 4:
                ip_stack = ethernet.ipv4_addresses.add()
                ip_stack.name = 'Ipv4 Port {}'.format(port_id)
                ip_stack.address = peer
                ip_stack.prefix = prefix
                ip_stack.gateway = addr
                v4_addr, v4_gw, v4_prefix = peer, addr, prefix
            else:
                ip6_stack = ethernet.ipv6_addresses.add()
                ip6_stack.name = 'Ipv6 Port {}'.format(port_id)
                ip6_stack.address = peer
                ip6_stack.prefix = prefix
                ip6_stack.gateway = addr
                v6_addr, v6_gw, v6_prefix = peer, addr, prefix

        if any([v4_addr, v6_addr]):
            port_config = SnappiPortConfig(
                id=port_id,
                ip=v4_addr,
                mac=mac,
                gw=v4_gw,
                gw_mac=duthost.get_dut_iface_mac(intf),
                prefix_len=str(v4_prefix) if v4_prefix is not None else None,
                ipv6=v6_addr,
                gw_ipv6=v6_gw,
                prefix_len_v6=str(v6_prefix) if v6_prefix is not None else None,
                port_type=SnappiPortType.IPInterface,
                peer_port=intf
            )
            port_config_list.append(port_config)

    return True


def __vlan_intf_config(config, port_config_list, duthost, snappi_ports):
    """
    Generate Snappi configuration of VLAN member interfaces (IPv4 + IPv6).
    """
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    if 'minigraph_vlans' not in mg_facts:
        return True
    vlan_facts = mg_facts['minigraph_vlans']
    if not vlan_facts:
        return True

    vlan_members = {k: v['members'] for k, v in vlan_facts.items()}
    vlan_intf_facts = mg_facts.get('minigraph_vlan_interfaces', [])
    vlan_entries = {}
    for v in vlan_intf_facts:
        vlan_entries.setdefault(v['attachto'], []).append(v)

    for vlan, members in vlan_members.items():
        if vlan not in vlan_entries:
            continue
        entries = vlan_entries[vlan]
        v4_entry = next((e for e in entries if __valid_ipv4_addr(e['addr'])), None)
        v6_entry = next((e for e in entries if __valid_ipv6_addr(e['addr'])), None)

        if v4_entry:
            gw4 = v4_entry['addr']
            pfx4 = v4_entry['prefixlen']
            subnet4 = f"{gw4}/{pfx4}"
            member_ipv4s = get_addrs_in_subnet(subnet4, len(members))
        else:
            gw4 = pfx4 = None
            member_ipv4s = [None] * len(members)

        if v6_entry:
            gw6 = v6_entry['addr']
            pfx6 = v6_entry['prefixlen']
            subnet6 = f"{gw6}/{pfx6}"
            member_ipv6s = get_ipv6_addrs_in_subnet(subnet6, len(members))
        else:
            gw6 = pfx6 = None
            member_ipv6s = [None] * len(members)

        for idx, phy in enumerate(members):
            port_ids = [i for i, sp in enumerate(snappi_ports) if sp['peer_port'] == phy]
            if len(port_ids) != 1:
                continue
            port_id = port_ids[0]
            mac = __gen_mac(port_id)
            device = config.devices.device(name='Device Port {}'.format(port_id))[-1]
            ethernet = device.ethernets.add()
            ethernet.name = 'Ethernet Port {}'.format(port_id)
            ethernet.connection.port_name = config.ports[port_id].name
            ethernet.mac = mac

            v4_addr = v4_prefix = None
            v6_addr = v6_prefix = None

            if member_ipv4s[idx]:
                ip4 = member_ipv4s[idx]
                ip4_stack = ethernet.ipv4_addresses.add()
                ip4_stack.name = 'Ipv4 Port {}'.format(port_id)
                ip4_stack.address = ip4
                ip4_stack.prefix = int(pfx4)
                ip4_stack.gateway = gw4
                v4_addr, v4_prefix = ip4, pfx4

            if member_ipv6s[idx]:
                ip6 = member_ipv6s[idx]
                ip6_stack = ethernet.ipv6_addresses.add()
                ip6_stack.name = 'Ipv6 Port {}'.format(port_id)
                ip6_stack.address = ip6
                ip6_stack.prefix = int(pfx6)
                ip6_stack.gateway = gw6
                v6_addr, v6_prefix = ip6, pfx6

            if v4_addr or v6_addr:
                port_config = SnappiPortConfig(
                    id=port_id,
                    ip=v4_addr if v4_addr is not None else None,
                    mac=mac,
                    gw=gw4 if v4_addr is not None else None,
                    gw_mac=duthost.get_dut_iface_mac(phy),
                    prefix_len=str(v4_prefix) if v4_addr is not None else None,
                    ipv6=v6_addr,
                    gw_ipv6=gw6,
                    prefix_len_v6=str(v6_prefix) if v6_prefix is not None else None,
                    port_type=SnappiPortType.VlanMember,
                    peer_port=phy)
                port_config_list.append(port_config)

    return True


def __portchannel_intf_config(config, port_config_list, duthost, snappi_ports):
    """
    Generate Snappi configuration of PortChannel (LAG) member and LAG interfaces (IPv4 + IPv6).
    """
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    if 'minigraph_portchannels' not in mg_facts:
        return True
    pc_facts = mg_facts['minigraph_portchannels']
    if not pc_facts:
        return True

    pc_members = {k: v['members'] for k, v in pc_facts.items()}
    pc_intf_facts = mg_facts.get('minigraph_portchannel_interfaces', [])
    pc_entries = {}
    for v in pc_intf_facts:
        pc_entries.setdefault(v['attachto'], []).append(v)

    pc_id = 0
    for pc, members in pc_members.items():
        if pc not in pc_entries:
            continue
        entries = pc_entries[pc]
        v4_entry = next((e for e in entries if __valid_ipv4_addr(e['addr'])), None)
        v6_entry = next((e for e in entries if not __valid_ipv4_addr(e['addr'])), None)

        member_port_ids = [i for i, sp in enumerate(snappi_ports) for m in members if sp['peer_port'] == m]
        if not member_port_ids:
            continue

        lag = config.lags.lag(name='Lag {}'.format(pc))[-1]
        lag.protocol.lacp.actor_system_id = '00:00:00:00:00:01'
        lag.protocol.lacp.actor_system_priority = 1
        lag.protocol.lacp.actor_key = 1

        for phy in members:
            port_ids = [i for i, sp in enumerate(snappi_ports) if sp['peer_port'] == phy]
            if len(port_ids) != 1:
                continue
            port_id = port_ids[0]
            mac = __gen_mac(port_id)
            lp = lag.ports.port(port_name=config.ports[port_id].name)[-1]
            lp.lacp.actor_port_number = 1
            lp.lacp.actor_port_priority = 1
            lp.ethernet.name = 'Ethernet Port {}'.format(port_id)
            lp.ethernet.mac = mac

            # IPv4 base attributes
            base_ip = base_gw = base_prefix = None
            if v4_entry:
                base_ip = v4_entry['peer_addr']
                base_gw = v4_entry['addr']
                base_prefix = v4_entry['prefixlen']

            v6_ip = v6_gw = v6_prefix = None
            if v6_entry:
                v6_ip = v6_entry['peer_addr']
                v6_gw = v6_entry['addr']
                v6_prefix = v6_entry['prefixlen']

            if base_ip is not None or v6_ip is not None:
                port_config = SnappiPortConfig(
                    id=port_id,
                    ip=base_ip,
                    mac=mac,
                    gw=base_gw,
                    gw_mac=duthost.get_dut_iface_mac(phy),
                    prefix_len=str(base_prefix) if base_prefix is not None else None,
                    ipv6=v6_ip,
                    gw_ipv6=v6_gw,
                    prefix_len_v6=str(v6_prefix) if v6_prefix is not None else None,
                    port_type=SnappiPortType.PortChannelMember,
                    peer_port=phy)
                port_config_list.append(port_config)

        device = config.devices.device(name='Device {}'.format(pc))[-1]
        ethernet = device.ethernets.add()
        ethernet.connection.port_name = lag.name
        ethernet.name = 'Ethernet {}'.format(pc)
        ethernet.mac = __gen_pc_mac(pc_id)

        if v4_entry:
            ip_stack = ethernet.ipv4_addresses.add()
            ip_stack.name = 'Ipv4 {}'.format(pc)
            ip_stack.address = v4_entry['peer_addr']
            ip_stack.prefix = int(v4_entry['prefixlen'])
            ip_stack.gateway = v4_entry['addr']
        if v6_entry:
            ip6_stack = ethernet.ipv6_addresses.add()
            ip6_stack.name = 'Ipv6 {}'.format(pc)
            ip6_stack.address = v6_entry['peer_addr']
            ip6_stack.prefix = int(v6_entry['prefixlen'])
            ip6_stack.gateway = v6_entry['addr']

        pc_id += 1

    return True


@pytest.fixture(scope="module")
def is_pfc_enabled(duthosts, rand_one_dut_front_end_hostname):
    """
    This fixture checks if Priority Flow Control (PFC) is enabled on the SONiC DUT.

    Args:
        duthosts (pytest fixture): List of DUT hosts.
        rand_one_dut_front_end_hostname (pytest fixture): Hostname of a randomly selected front-end DUT.

    Returns:
        bool: True if PFC is enabled on at least one port, False otherwise.
    """
    duthost = duthosts[rand_one_dut_front_end_hostname]
    config_facts = duthost.config_facts(host=duthost.hostname, asic_index=0,
                                        source="running")['ansible_facts']

    if "PORT_QOS_MAP" not in list(config_facts.keys()):
        return False

    port_qos_map = config_facts["PORT_QOS_MAP"]
    if len(list(port_qos_map.keys())) == 0:
        return False

    # Here we assume all the ports have the same lossless priorities
    intf = list(port_qos_map.keys())[0]
    pfc_enable = port_qos_map[intf].get('pfc_enable')
    if pfc_enable:
        return True

    return False


@pytest.fixture(scope="function")
def snappi_testbed_config(conn_graph_facts, fanout_graph_facts,     # noqa: F811
                          duthosts, rand_one_dut_hostname, is_pfc_enabled,
                          snappi_api):
    """
    Geenrate snappi API config and port config information for the testbed
    Args:
        conn_graph_facts (pytest fixture)
        fanout_graph_facts (pytest fixture)
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (pytest fixture): DUT hostname
        snappi_api(pytest fixture): Snappi API fixture
    Returns:
        - config (obj): Snappi API config of the testbed
        - port_config_list (list): list of port configuration information
    """
    # As of now both single dut and multidut fixtures are being called from the same test,
    # When this function is called for T2 testbed, just return empty.
    '''
    if is_snappi_multidut(duthosts):
        return None, []
        '''

    duthost = duthosts[rand_one_dut_hostname]

    """ Generate L1 config """
    snappi_fanout = get_peer_snappi_chassis(conn_data=conn_graph_facts,
                                            dut_hostname=duthost.hostname)

    pytest_assert(snappi_fanout is not None, 'Fail to get snappi_fanout')
    snappi_fanout = snappi_fanout[0]
    snappi_fanout_id = list(fanout_graph_facts.keys()).index(snappi_fanout)
    snappi_fanout_list = SnappiFanoutManager(fanout_graph_facts)
    snappi_fanout_list.get_fanout_device_details(device_number=snappi_fanout_id)

    snappi_ports = snappi_fanout_list.get_ports(peer_device=duthost.hostname)

    port_speed = None

    """ L1 config """
    config = snappi_api.config()
    for i in range(len(snappi_ports)):
        config.ports.port(name='Port {}'.format(i),
                          location=get_snappi_port_location(snappi_ports[i]))

        if port_speed is None:
            port_speed = int(snappi_ports[i]['speed'])

        pytest_assert(port_speed == int(snappi_ports[i]['speed']),
                      'Ports have different link speeds')

    speed_gbps = int(port_speed/1000)

    config.options.port_options.location_preemption = True
    l1_config = config.layer1.layer1()[-1]
    l1_config.name = 'L1 config'
    l1_config.port_names = [port.name for port in config.ports]
    l1_config.speed = 'speed_{}_gbps'.format(speed_gbps)
    l1_config.ieee_media_defaults = False
    l1_config.auto_negotiate = False

    # Determine link training and RS-FEC settings from DUT before applying to TGEN
    try:
        run_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
        port_table = run_facts.get('PORT', {})
    except Exception as e:
        logger.warning(f"Failed to read DUT PORT table for link training/FEC detection: {e}")
        port_table = {}

    def _is_enabled(val):
        return str(val).lower() in ['on', 'true', 'yes', '1']

    lt_values = []
    rs_fec_values = []
    for sp in snappi_ports:
        p = sp.get('peer_port')
        attrs = port_table.get(p, {})
        if 'link_training' in attrs:
            lt_values.append(_is_enabled(attrs.get('link_training')))
        if 'fec' in attrs:
            fec_val = str(attrs.get('fec', '')).lower()
            rs_fec_values.append(fec_val.startswith('rs'))

    # Enable only if ALL ports have it enabled
    lt_enable = all(lt_values) if lt_values else False
    rs_fec_enable = all(rs_fec_values) if rs_fec_values else False

    logger.info(f"Configuring TGEN L1: link_training={lt_enable}, rs_fec={rs_fec_enable} (DUT derived)")

    l1_config.auto_negotiation.link_training = lt_enable
    l1_config.auto_negotiation.rs_fec = rs_fec_enable

    if is_pfc_enabled:
        pfc = l1_config.flow_control.ieee_802_1qbb
        pfc.pfc_delay = 0
        if pfcQueueGroupSize == 8:
            pfc.pfc_class_0 = 0
            pfc.pfc_class_1 = 1
            pfc.pfc_class_2 = 2
            pfc.pfc_class_3 = 3
            pfc.pfc_class_4 = 4
            pfc.pfc_class_5 = 5
            pfc.pfc_class_6 = 6
            pfc.pfc_class_7 = 7
        elif pfcQueueGroupSize == 4:
            pfc.pfc_class_0 = pfcQueueValueDict[0]
            pfc.pfc_class_1 = pfcQueueValueDict[1]
            pfc.pfc_class_2 = pfcQueueValueDict[2]
            pfc.pfc_class_3 = pfcQueueValueDict[3]
            pfc.pfc_class_4 = pfcQueueValueDict[4]
            pfc.pfc_class_5 = pfcQueueValueDict[5]
            pfc.pfc_class_6 = pfcQueueValueDict[6]
            pfc.pfc_class_7 = pfcQueueValueDict[7]
        else:
            pytest_assert(False, 'pfcQueueGroupSize value is not 4 or 8')
    else:
        logger.info('PFC is not enabled on the DUT, skipping PFC configuration on TGEN')

    port_config_list = []

    config_result = __vlan_intf_config(config=config,
                                       port_config_list=port_config_list,
                                       duthost=duthost,
                                       snappi_ports=snappi_ports)
    pytest_assert(config_result is True, 'Fail to configure Vlan interfaces')

    config_result = __portchannel_intf_config(config=config,
                                              port_config_list=port_config_list,
                                              duthost=duthost,
                                              snappi_ports=snappi_ports)
    pytest_assert(config_result is True, 'Fail to configure portchannel interfaces')

    config_result = __l3_intf_config(config=config,
                                     port_config_list=port_config_list,
                                     duthost=duthost,
                                     snappi_ports=snappi_ports)
    pytest_assert(config_result is True, 'Fail to configure L3 interfaces')

    return config, port_config_list


@pytest.fixture(scope="module")
def tgen_ports(duthost, conn_graph_facts, fanout_graph_facts):      # noqa: F811
    """
    Populate tgen ports info of T0 testbed and returns as a list
    Args:
        duthost (pytest fixture): duthost fixture
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
    Return:
        [{'card_id': '1',
        'ip': '22.1.1.2',
        'ipv6': '3001::2',
        'ipv6_prefix': u'64',
        'location': '10.36.78.238;1;2',
        'peer_device': 'sonic-s6100-dut',
        'peer_ip': u'22.1.1.1',
        'peer_ipv6': u'3001::1',
        'peer_port': 'Ethernet8',
        'port_id': '2',
        'prefix': u'24',
        'speed': 'speed_400_gbps'},
        {'card_id': '1',
        'ip': '21.1.1.2',
        'ipv6': '2001::2',
        'ipv6_prefix': u'64',
        'location': '10.36.78.238;1;1',
        'peer_device': 'sonic-s6100-dut',
        'peer_ip': u'21.1.1.1',
        'peer_ipv6': u'2001::1',
        'peer_port': 'Ethernet0',
        'port_id': '1',
        'prefix': u'24',
        'speed': 'speed_400_gbps'}]
    """
    speed_type = {
                  '10000': 'speed_10_gbps',
                  '25000': 'speed_25_gbps',
                  '40000': 'speed_40_gbps',
                  '50000': 'speed_50_gbps',
                  '100000': 'speed_100_gbps',
                  '200000': 'speed_200_gbps',
                  '400000': 'speed_400_gbps',
                  '800000': 'speed_800_gbps'}
    config_facts = duthost.config_facts(host=duthost.hostname,
                                        source="running")['ansible_facts']
    snappi_fanouts = get_peer_snappi_chassis(conn_data=conn_graph_facts,
                                             dut_hostname=duthost.hostname)
    pytest_assert(snappi_fanouts is not None, 'Fail to get snappi_fanout')
    snappi_fanout_list = SnappiFanoutManager(fanout_graph_facts)
    for snappi_fanout in snappi_fanouts:
        snappi_fanout_id = list(fanout_graph_facts.keys()).index(snappi_fanout)
        snappi_fanout_list.get_fanout_device_details(device_number=snappi_fanout_id)
        snappi_ports = snappi_fanout_list.get_ports(peer_device=duthost.hostname)
        port_speeds = {int(p['speed']) for p in snappi_ports}
        if len(port_speeds) != 1:
            """ All the ports should have the same bandwidth """
            return None
        port_speed = port_speeds.pop()
        dutIps = create_ip_list(dut_ip_start, len(snappi_ports), mask=prefix_length)
        tgenIps = create_ip_list(snappi_ip_start, len(snappi_ports), mask=prefix_length)
        dutv6Ips = create_ip_list(dut_ipv6_start, len(snappi_ports), mask=v6_prefix_length)
        tgenv6Ips = create_ip_list(snappi_ipv6_start, len(snappi_ports), mask=v6_prefix_length)
        for port_id, port in enumerate(snappi_ports):
            port['speed'] = speed_type.get(str(port_speed), port['speed'])
            peer_port = port['peer_port']
            int_addrs = list(config_facts['INTERFACE'][peer_port].keys())
            for ipver, addr_type in (("ipv4", "IPv4"), ("ipv6", "IPv6")):
                entry = next((a for a in int_addrs if (":" in a) == (ipver == "ipv6")), None)
                if ipver == "ipv4":
                    dut_list, tgen_list, mask = dutIps, tgenIps, prefix_length
                    peer_ip_key, prefix_key, ip_key = "peer_ip", "prefix", "ip"
                else:
                    dut_list, tgen_list, mask = dutv6Ips, tgenv6Ips, v6_prefix_length
                    peer_ip_key, prefix_key, ip_key = "peer_ipv6", "ipv6_prefix", "ipv6"
                if entry:
                    # Already configured on DUT
                    port[peer_ip_key], port[prefix_key] = entry.split("/")
                    port[ip_key] = get_addrs_in_subnet(entry, 1, exclude_ips=[entry.split("/")[0]])[0]
                else:
                    # Assign and configure new IPs
                    port[peer_ip_key] = dut_list[port_id]
                    port[prefix_key] = mask
                    port[ip_key] = tgen_list[port_id]
                    try:
                        logger.info(
                            f"Pre-configuring {addr_type}: {duthost.hostname} "
                            f"port {peer_port} -> {dut_list[port_id]}/{mask}"
                        )
                        duthost.command(
                            f"sudo config interface ip add {peer_port} {dut_list[port_id]}/{mask}"
                        )
                    except Exception as e:
                        pytest.fail(
                            f"Unable to configure {addr_type} on {peer_port}: {e}",
                            pytrace=False,
                        )
    return snappi_ports


def snappi_multi_base_config(duthost_list,
                             snappi_ports,
                             snappi_api,
                             setup=True):
    """
    Generate snappi API config and port config information for the testbed
    This function takes care of mixed-speed interfaces by removing assert and printing info log.
    l1_config is added to both the snappi_ports instead of just one.

    Args:
        duthost_list (pytest fixture): list of DUTs
        snappi_ports: list of snappi ports
        snappi_api(pytest fixture): Snappi API fixture
        setup (bool): Indicates if functionality is called to create or clear the setup.
    Returns:
        - config (obj): Snappi API config of the testbed
        - port_config_list (list): list of port configuration information
        - snappi_ports (list): list of snappi_ports selected for the test.
    """

    """ Generate L1 config """

    config = snappi_api.config()
    tgen_ports = [port['location'] for port in snappi_ports]

    new_snappi_ports = [dict(list(sp.items()) + [('port_id', i)])
                        for i, sp in enumerate(snappi_ports) if sp['location'] in tgen_ports]

    # Printing info level if ingress and egress interfaces are of different speeds.
    if (len(set([sp['speed'] for sp in new_snappi_ports])) > 1):
        logger.info('Rx and  Tx ports have different link speeds')
    [config.ports.port(name='Port {}'.format(sp['port_id']), location=sp['location']) for sp in new_snappi_ports]

    # Generating L1 config for both the snappi_ports.
    for port in config.ports:
        for index, snappi_port in enumerate(new_snappi_ports):
            if snappi_port['location'] == port.location:
                l1_config = config.layer1.layer1()[-1]
                l1_config.name = 'L1 config {}'.format(index)
                l1_config.port_names = [port.name]
                l1_config.speed = 'speed_'+str(int(int(snappi_port['speed'])/1000))+'_gbps'
                l1_config.ieee_media_defaults = False
                l1_config.auto_negotiate = False
                l1_config.auto_negotiation.link_training = False
                l1_config.auto_negotiation.rs_fec = True
                pfc = l1_config.flow_control.ieee_802_1qbb
                pfc.pfc_delay = 0
            if pfcQueueGroupSize == 8:
                pfc.pfc_class_0 = 0
                pfc.pfc_class_1 = 1
                pfc.pfc_class_2 = 2
                pfc.pfc_class_3 = 3
                pfc.pfc_class_4 = 4
                pfc.pfc_class_5 = 5
                pfc.pfc_class_6 = 6
                pfc.pfc_class_7 = 7
            elif pfcQueueGroupSize == 4:
                pfc.pfc_class_0 = pfcQueueValueDict[0]
                pfc.pfc_class_1 = pfcQueueValueDict[1]
                pfc.pfc_class_2 = pfcQueueValueDict[2]
                pfc.pfc_class_3 = pfcQueueValueDict[3]
                pfc.pfc_class_4 = pfcQueueValueDict[4]
                pfc.pfc_class_5 = pfcQueueValueDict[5]
                pfc.pfc_class_6 = pfcQueueValueDict[6]
                pfc.pfc_class_7 = pfcQueueValueDict[7]
            else:
                pytest_assert(False, 'pfcQueueGroupSize value is not 4 or 8')

    port_config_list = []

    return (setup_dut_ports(
        setup=setup,
        duthost_list=duthost_list,
        config=config,
        port_config_list=port_config_list,
        snappi_ports=new_snappi_ports))


def snappi_dut_base_config(duthost_list,
                           snappi_ports,
                           snappi_api,
                           setup=True):
    """
    Generate snappi API config and port config information for the testbed
    Args:
        duthost_list (pytest fixture): list of DUTs
        snappi_ports: list of snappi ports
        snappi_api(pytest fixture): Snappi API fixture
    Returns:
        - config (obj): Snappi API config of the testbed
        - port_config_list (list): list of port configuration information
    """

    """ Generate L1 config """

    config = snappi_api.config()
    tgen_ports = [port['location'] for port in snappi_ports]

    new_snappi_ports = [dict(list(sp.items()) + [('port_id', i)])
                        for i, sp in enumerate(snappi_ports) if sp['location'] in tgen_ports]
    pytest_assert(len(set([sp['speed'] for sp in new_snappi_ports])) == 1, 'Ports have different link speeds')
    [config.ports.port(name='Port {}'.format(sp['port_id']), location=sp['location']) for sp in new_snappi_ports]
    speed_gbps = int(int(new_snappi_ports[0]['speed'])/1000)

    config.options.port_options.location_preemption = True
    l1_config = config.layer1.layer1()[-1]
    l1_config.name = 'L1 config'
    l1_config.port_names = [port.name for port in config.ports]
    l1_config.speed = 'speed_{}_gbps'.format(speed_gbps)
    l1_config.ieee_media_defaults = False
    l1_config.auto_negotiate = False
    if is_snappi_multidut(duthost_list):
        l1_config.auto_negotiation.link_training = False
    else:
        l1_config.auto_negotiation.link_training = True
    l1_config.auto_negotiation.rs_fec = True

    pfc = l1_config.flow_control.ieee_802_1qbb
    pfc.pfc_delay = 0
    if pfcQueueGroupSize == 8:
        pfc.pfc_class_0 = 0
        pfc.pfc_class_1 = 1
        pfc.pfc_class_2 = 2
        pfc.pfc_class_3 = 3
        pfc.pfc_class_4 = 4
        pfc.pfc_class_5 = 5
        pfc.pfc_class_6 = 6
        pfc.pfc_class_7 = 7
    elif pfcQueueGroupSize == 4:
        pfc.pfc_class_0 = pfcQueueValueDict[0]
        pfc.pfc_class_1 = pfcQueueValueDict[1]
        pfc.pfc_class_2 = pfcQueueValueDict[2]
        pfc.pfc_class_3 = pfcQueueValueDict[3]
        pfc.pfc_class_4 = pfcQueueValueDict[4]
        pfc.pfc_class_5 = pfcQueueValueDict[5]
        pfc.pfc_class_6 = pfcQueueValueDict[6]
        pfc.pfc_class_7 = pfcQueueValueDict[7]
    else:
        pytest_assert(False, 'pfcQueueGroupSize value is not 4 or 8')

    port_config_list = []

    return (setup_dut_ports(
        setup=setup,
        duthost_list=duthost_list,
        config=config,
        port_config_list=port_config_list,
        snappi_ports=new_snappi_ports))


def setup_dut_ports(
        setup,
        duthost_list,
        config,
        port_config_list,
        snappi_ports):

    ptype = "--snappi_macsec" in sys.argv
    if not ptype:
        for index, duthost in enumerate(duthost_list):
            config_result = __vlan_intf_config(config=config,
                                               port_config_list=port_config_list,
                                               duthost=duthost,
                                               snappi_ports=snappi_ports)
            pytest_assert(config_result is True, 'Fail to configure Vlan interfaces')

        for index, duthost in enumerate(duthost_list):
            config_result = __portchannel_intf_config(config=config,
                                                      port_config_list=port_config_list,
                                                      duthost=duthost,
                                                      snappi_ports=snappi_ports)
            pytest_assert(config_result is True, 'Fail to configure portchannel interfaces')

        if is_snappi_multidut(duthost_list):
            for index, duthost in enumerate(duthost_list):
                config_result = __intf_config_multidut(
                                                        config=config,
                                                        port_config_list=port_config_list,
                                                        duthost=duthost,
                                                        snappi_ports=snappi_ports,
                                                        setup=setup)
                pytest_assert(config_result is True, 'Fail to configure multidut L3 interfaces')
        else:
            for index, duthost in enumerate(duthost_list):
                config_result = __l3_intf_config(config=config,
                                                 port_config_list=port_config_list,
                                                 duthost=duthost,
                                                 snappi_ports=snappi_ports,
                                                 setup=setup)
                pytest_assert(config_result is True, 'Fail to configure L3 interfaces')
    else:
        for index, duthost in enumerate(duthost_list):
            config_result = __intf_config_macsec(config=config,
                                                 port_config_list=port_config_list,
                                                 duthost=duthost,
                                                 snappi_ports=snappi_ports,
                                                 setup=setup)
            pytest_assert(config_result is True, 'Fail to configure macsec on snappi ports')
    return config, port_config_list, snappi_ports


def get_tgen_peer_ports(snappi_ports, hostname):
    ports = [(port['location'], port['peer_port']) for port in snappi_ports if port['peer_device'] == hostname]
    return ports


def __intf_config(config, port_config_list, duthost, snappi_ports):
    """
    Generate Snappi configuration of Vlan interfaces
    Args:
        config (obj): Snappi API config of the testbed
        port_config_list (list): list of Snappi port configuration information
        duthost (object): device under test
        snappi_ports (list): list of Snappi port information
    Returns:
        True if we successfully generate configuration or False
    """
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    if 'minigraph_vlans' in mg_facts:
        vlan_facts = mg_facts['minigraph_vlans']
    else:
        return True

    if len(vlan_facts) == 0:
        return True

    vlan_member = {}
    for k, v in vlan_facts.items():
        vlan_member[k] = v['members']

    vlan_intf_facts = mg_facts['minigraph_vlan_interfaces']
    vlan_intf = {}
    for v in vlan_intf_facts:
        if __valid_ipv4_addr(v['addr']):
            vlan_intf[v['attachto']] = v

    """ For each Vlan """
    for vlan in vlan_member:
        phy_intfs = vlan_member[vlan]
        gw_addr = str(vlan_intf[vlan]['addr'])
        prefix = str(vlan_intf[vlan]['prefixlen'])
        vlan_subnet = '{}/{}'.format(gw_addr, prefix)
        vlan_ip_addrs = get_addrs_in_subnet(vlan_subnet, len(phy_intfs))

        """ For each physical interface attached to this Vlan """
        for i in range(len(phy_intfs)):
            phy_intf = phy_intfs[i]
            vlan_ip_addr = vlan_ip_addrs[i]

            port_ids = [id for id, snappi_port in enumerate(snappi_ports)
                        if snappi_port['peer_port'] == phy_intf]
            if len(port_ids) != 1:
                return False

            port_id = port_ids[0]
            mac = __gen_mac(port_id)
            device = config.devices.device(
                name='Device Port {}'.format(port_id))[-1]

            ethernet = device.ethernets.add()
            ethernet.name = 'Ethernet Port {}'.format(port_id)
            ethernet.connection.port_name = config.ports[port_id].name
            ethernet.mac = mac

            ip_stack = ethernet.ipv4_addresses.add()
            ip_stack.name = 'Ipv4 Port {}'.format(port_id)
            ip_stack.address = vlan_ip_addr
            ip_stack.prefix = int(prefix)
            ip_stack.gateway = gw_addr

            port_config = SnappiPortConfig(id=port_id,
                                           ip=vlan_ip_addr,
                                           mac=mac,
                                           gw=gw_addr,
                                           gw_mac=duthost.get_dut_iface_mac(phy_intf),
                                           prefix_len=prefix,
                                           port_type=SnappiPortType.VlanMember,
                                           peer_port=phy_intf)

            port_config_list.append(port_config)

    return True


def __intf_config_multidut(config, port_config_list, duthost, snappi_ports, setup=True):
    """
    Configures interfaces of the DUT
    Args:
        config (obj): Snappi API config of the testbed
        port_config_list (list): list of Snappi port configuration information
        duthost (object): device under test
        snappi_ports (list): list of Snappi port information
        setup: Setting up or teardown? True or False
    Returns:
        True if we successfully configure the interfaces or False
    """
    dutIps = create_ip_list(dut_ip_start, len(snappi_ports), mask=prefix_length)
    tgenIps = create_ip_list(snappi_ip_start, len(snappi_ports), mask=prefix_length)
    ports = [port for port in snappi_ports if port['peer_device'] == duthost.hostname]

    for port in ports:
        port_id = port['port_id']
        dutIp = dutIps[port_id]
        tgenIp = tgenIps[port_id]
        mac = __gen_mac(port_id)
        logger.info('Configuring Dut: {} with port {} with IP {}/{}'.format(
                                                                            duthost.hostname,
                                                                            port['peer_port'],
                                                                            dutIp,
                                                                            prefix_length))
        if setup:
            cmd = "add"
        else:
            cmd = "remove"
        if not setup:
            gen_data_flow_dest_ip(tgenIp, duthost, port['peer_port'], port['asic_value'], setup)

        if port['asic_value'] is None:
            duthost.command('sudo config interface ip {} {} {}/{} \n' .format(
                                                                                cmd,
                                                                                port['peer_port'],
                                                                                dutIp,
                                                                                prefix_length))
        else:
            duthost.command('sudo config interface -n {} ip {} {} {}/{} \n' .format(
                                                                                    port['asic_value'],
                                                                                    cmd,
                                                                                    port['peer_port'],
                                                                                    dutIp,
                                                                                    prefix_length))
        if setup:
            gen_data_flow_dest_ip(tgenIp, duthost, port['peer_port'], port['asic_value'], setup)
        if setup is False:
            continue
        port['intf_config_changed'] = True
        device = config.devices.device(name='Device Port {}'.format(port_id))[-1]
        ethernet = device.ethernets.add()
        ethernet.name = 'Ethernet Port {}'.format(port_id)
        ethernet.connection.port_name = config.ports[port_id].name
        ethernet.mac = mac
        ip_stack = ethernet.ipv4_addresses.add()
        ip_stack.name = 'Ipv4 Port {}'.format(port_id)
        ip_stack.address = tgenIp
        ip_stack.prefix = prefix_length
        ip_stack.gateway = dutIp
        port_config = SnappiPortConfig(
                                        id=port_id,
                                        ip=tgenIp,
                                        mac=mac,
                                        gw=dutIp,
                                        gw_mac=duthost.get_dut_iface_mac(port['peer_port']),
                                        prefix_len=prefix_length,
                                        port_type=SnappiPortType.IPInterface,
                                        peer_port=port['peer_port']
                                      )
        port_config_list.append(port_config)

    return True


reconfigure_port = {}


def __intf_config_macsec(config, port_config_list, duthost, snappi_ports, setup=True):
    """
    Configures macsec on snappi interfaces
    Args:
        config (obj): Snappi API config of the testbed
        port_config_list (list): list of Snappi port configuration information
        duthost (object): device under test
        snappi_ports (list): list of Snappi port information
        setup: Setting up or teardown? True or False
    Returns:
        True if we successfully configure the interfaces or False
    """
    global macsec_enabled_port, macsec_profile_name, reconfigure_port
    ptype = "--snappi_macsec" in sys.argv
    num_of_non_macsec_snappi_devices = 7
    static_prefix_length = str(subnet_mask_from_hosts(num_of_non_macsec_snappi_devices))
    for index, port in enumerate(snappi_ports):
        if port['duthost'] == duthost:
            peer_port = port['peer_port']
            asic_inst = duthost.get_port_asic_instance(peer_port)
            namespace = duthost.get_namespace_from_asic_id(asic_inst.asic_index) if asic_inst else None
            facts = duthost.config_facts(host=duthost.hostname,
                                         source="running", namespace=namespace)
            config_facts = facts['ansible_facts']
            int_addrs = list(config_facts['INTERFACE'][peer_port].keys())
            subnet = [ele for ele in int_addrs if "." in ele]
            if port['port_id'] == 0 and int(subnet[0].split("/")[1]) > int(static_prefix_length):
                logger.info('Removing existing IP {} from interface {}'.format(subnet[0], port['peer_port']))
                reconfigure_port = port
                reconfigure_port['original_subnet'] = subnet[0]
                if port['asic_value'] is None:
                    duthost.command('sudo config interface ip remove {} {}/{} \n'.
                                    format(port['peer_port'], subnet[0].split("/")[0], subnet[0].split("/")[1]))
                else:
                    duthost.command('sudo config interface -n {} ip remove {} {}/{} \n' .
                                    format(port['asic_value'], port['peer_port'],
                                           subnet[0].split("/")[0], subnet[0].split("/")[1]))
                logger.info('Adding IP {}/28 to interface {}'.format(dut_ip_for_non_macsec_port, port['peer_port']))
                if port['asic_value'] is None:
                    duthost.command('sudo config interface ip add {} {}/{} \n'.
                                    format(port['peer_port'], dut_ip_for_non_macsec_port, static_prefix_length))
                else:
                    duthost.command('sudo config interface -n {} ip add {} {}/{} \n' .
                                    format(port['asic_value'], port['peer_port'],
                                           dut_ip_for_non_macsec_port, static_prefix_length))
                subnet = [dut_ip_for_non_macsec_port + '/' + str(static_prefix_length)]
            port['ipAddress'] = get_addrs_in_subnet(subnet[0], 1, exclude_ips=[subnet[0].split("/")[0]])[0]
            if not subnet:
                pytest_assert(False, "No IP address found for peer port {}".format(peer_port))
            port['ipGateway'], port['prefix'] = subnet[0].split("/")
            port['subnet'] = subnet[0]
    ports = []
    for port in snappi_ports:
        if port['peer_device'] == duthost.hostname:
            ports.append(port)
    if ptype:
        macsec_var_file = os.path.expanduser("../tests/snappi_tests/macsec_profile.json")
        with open(macsec_var_file, "r") as f:
            all_values = json.load(f)
    for port in ports:
        port_id = port['port_id']
        dutIp = port['ipGateway']
        tgenIp = port['ipAddress']
        prefix_length = int(port['prefix'])
        mac = __gen_mac(port_id+num_of_non_macsec_snappi_devices)
        if not setup:
            gen_data_flow_dest_ip(tgenIp, duthost, port['peer_port'], port['asic_value'], setup)
        if setup:
            gen_data_flow_dest_ip(tgenIp, duthost, port['peer_port'], port['asic_value'], setup)
        if setup is False:
            continue
        port['intf_config_changed'] = True
        if ptype and port_id == 1:
            device = config.devices.device(name='Device Port {}'.format(port_id))[-1]
            ethernet = device.ethernets.add()
            ethernet.name = 'Ethernet Port {}'.format(port_id)
            ethernet.connection.port_name = config.ports[port_id].name
            ethernet.mac = mac
            # Configure MACsec on DUT
            rawout = port['duthost'].command('show macsec {}'.format(port['peer_port']))['stdout']
            for line in rawout.split('\n'):
                if 'profile' in line:
                    profile_name = line.split()[1]
                    logger.info('Removing already configured Macsec profile {}'.format(profile_name))
                    delete_macsec_profile(port['duthost'], port['peer_port'], profile_name)
            macsec_enabled_port = port
            macsec_profile_name = '256_XPN_SCI'
            cipher = all_values[macsec_profile_name]['cipher_suite']
            primary_cak = all_values[macsec_profile_name]['primary_cak']
            primary_ckn = all_values[macsec_profile_name]['primary_ckn']
            priority = all_values[macsec_profile_name]['priority']
            policy = all_values[macsec_profile_name]['policy']
            rekey_period = all_values[macsec_profile_name]['rekey_period']
            send_sci = all_values[macsec_profile_name]['send_sci']
            logger.info('Configuring DUTHOST:{}'.format(port['duthost'].hostname))
            logger.info('Configuring MACSEC on DUT Interfaces: {}'.format(port['peer_port']))
            set_macsec_profile(port['duthost'], port['peer_port'], macsec_profile_name, priority,
                               cipher, primary_cak, primary_ckn, policy, send_sci, rekey_period)
            enable_macsec_port(port['duthost'], port['peer_port'], macsec_profile_name)
            if port['asic_value'] is None:
                duthost.command("sudo arp -i {} -s {} {} \n".
                                format(port['peer_port'], tgenIp, mac))
                logger.info("sudo arp -i {} -s {} {}".
                            format(port['peer_port'], tgenIp, mac))
            else:
                duthost.command("sudo ip netns exec {} arp -i {} -s {} {} \n".
                                format(port['asic_value'], port['peer_port'], tgenIp, mac))
                logger.info("sudo ip netns exec {} arp -i {} -s {} {}".
                            format(port['asic_value'], port['peer_port'], tgenIp, mac))
            # Tx Port
            ip1 = ethernet.ipv4_addresses.add()
            ip1.name = "ip2"
            ip1.address = tgenIp
            ip1.prefix = int(prefix_length)
            ip1.gateway = dutIp
            ip1.gateway_mac.choice = "value"
            ip1.gateway_mac.value = duthost.get_dut_iface_mac(port['peer_port'])
            ####################
            # MACsec
            ####################
            macsec1 = device.macsec
            macsec1_int = macsec1.ethernet_interfaces.add()
            macsec1_int.eth_name = ethernet.name
            secy1 = macsec1_int.secure_entity
            secy1.name = "macsec1"

            # Data plane and crypto engine
            secy1.data_plane.choice = "encapsulation"
            secy1.data_plane.encapsulation.crypto_engine.choice = "encrypt_only"

            # Data plane and crypto engine
            secy1.data_plane.choice = "encapsulation"
            secy1.data_plane.encapsulation.tx.include_sci = True
            secy1.data_plane.encapsulation.crypto_engine.choice = "encrypt_only"
            secy1_crypto_engine_enc_only = secy1.data_plane.encapsulation.crypto_engine.encrypt_only

            # Data plane Tx SC PN
            secy1_dataplane_txsc1 = secy1_crypto_engine_enc_only.secure_channels.add()
            secy1_dataplane_txsc1.tx_pn.choice = all_values['snappi']['tx_pn_choice']

            ####################
            # MKA
            ####################
            secy1_key_gen_proto = secy1.key_generation_protocol
            secy1_key_gen_proto.choice = "mka"
            kay1 = secy1_key_gen_proto.mka
            kay1.name = "mka1"
            # Basic properties
            kay1.basic.key_derivation_function = all_values['snappi']['key_derivation_function']
            kay1.basic.actor_priority = all_values['snappi']['actor_priority']
            # Key source: PSK
            kay1_key_src = kay1.basic.key_source
            kay1_key_src.choice = "psk"
            kay1_psk_chain = kay1_key_src.psks

            # PSK 1
            kay1_psk1 = kay1_psk_chain.add()
            kay1_psk1.cak_name = all_values['snappi']['cak_name']
            kay1_psk1.cak_value = all_values['snappi']['cak_value']

            kay1_psk1.start_offset_time.hh = 0
            kay1_psk1.start_offset_time.mm = 22

            kay1_psk1.end_offset_time.hh = 0
            kay1_psk1.end_offset_time.hh = 0

            # Rekey mode
            kay_rekey_mode = kay1.basic.rekey_mode
            kay_rekey_mode.choice = all_values['snappi']['mka_rekey_mode_choice']
            kay_rekey_timer_based = kay_rekey_mode.timer_based
            kay_rekey_timer_based.choice = all_values['snappi']['mka_rekey_timer_choice']
            kay_rekey_timer_based.interval = all_values['snappi']['mka_rekey_timer_interval']

            # Remaining basic properties autofilled
            # Key server
            kay1_key_server = kay1.key_server
            kay1_key_server.cipher_suite = all_values['snappi']['cipher_suite']
            kay1_key_server.confidentialty_offset = all_values['snappi']['confidentiality_offset']

            # Tx SC
            kay1_tx = kay1.tx
            kay1_txsc1 = kay1_tx.secure_channels.add()
            kay1_txsc1.name = "txsc1"
            kay1_txsc1.system_id = mac
            # Remaining Tx SC settings autofilled
            eotr = config.egress_only_tracking
            eotr1 = eotr.add()
            eotr1.port_name = config.ports[port_id].name

            # eotr filter
            eotr1_filter1 = eotr1.filters.add()
            eotr1_filter1.choice = "auto_macsec"

            # eotr metric tag for destination MAC 3rd byte from MSB: LS 4 bits
            eotr1_mt1 = eotr1.metric_tags.add()
            eotr1_mt1.name = "pause traffic"
            eotr1_mt1.rx_offset = 0
            eotr1_mt1.length = 8
            eotr1_mt1.tx_offset.choice = "custom"
            eotr1_mt1.tx_offset.custom.value = 0
            port_config = SnappiPortConfig(
                                id=port_id,
                                ip=tgenIp,
                                mac=mac,
                                gw=dutIp,
                                gw_mac=duthost.get_dut_iface_mac(port['peer_port']),
                                prefix_len=prefix_length,
                                port_type=SnappiPortType.IPInterface,
                                peer_port=port['peer_port']
                            )
            port_config_list.append(port_config)
        elif ptype and port_id == 0:
            ip_values = get_ip_addresses(tgenIp, num_of_non_macsec_snappi_devices)
            for nd in range(0, num_of_non_macsec_snappi_devices):
                device = config.devices.device(name='Device Port {}_{}'.format(port_id, nd))[-1]
                ethernet = device.ethernets.add()
                ethernet.name = 'Ethernet Port {}_{}'.format(port_id, nd)
                ethernet.connection.port_name = config.ports[port_id].name
                ethernet.mac = __gen_mac(nd)
                ip_stack = ethernet.ipv4_addresses.add()
                ip_stack.name = 'Ipv4 Port {}_{}'.format(port_id, nd)
                ip_stack.address = ip_values[nd]
                ip_stack.prefix = int(prefix_length)
                ip_stack.gateway = dutIp
                port_config = SnappiPortConfig(
                    id=port_id,
                    ip=ip_values[nd],
                    mac=__gen_mac(nd),
                    gw=dutIp,
                    gw_mac=duthost.get_dut_iface_mac(port['peer_port']),
                    prefix_len=prefix_length,
                    port_type=SnappiPortType.IPInterface,
                    peer_port=port['peer_port']
                )
                port_config_list.append(port_config)
            # ip_stack.gateway_mac.choice = "value"
            # ip_stack.gateway_mac.value = "4c:71:0d:26:61:27"    # get this mac address from the dut.
            # Rx Port
            # egress only tracking(eotr)
            eotr = config.egress_only_tracking
            eotr1 = eotr.add()
            eotr1.port_name = config.ports[port_id].name

            # eotr filter
            eotr1_filter1 = eotr1.filters.add()
            eotr1_filter1.choice = "auto_macsec"
            # eotr metric tag for destination MAC 3rd byte from MSB: LS 4 bits
            eotr1_mt1 = eotr1.metric_tags.add()
            eotr1_mt1.name = "ipv4_dscp"
            eotr1_mt1.rx_offset = 0
            eotr1_mt1.length = 8
            eotr1_mt1.tx_offset.choice = "custom"
            eotr1_mt1.tx_offset.custom.value = 0
    return True


def create_ip_list(value, count, mask=32, incr=0):
    '''
        Create a list of ips based on the count provided
        Parameters:
            value: start value of the list
            count: number of ips required
            mask: subnet mask for the ips to be created
            incr: increment value of the ip
    '''
    if sys.version_info.major == 2:
        value = unicode(value)          # noqa: F405, F821

    ip_list = [value]
    for i in range(1, count):
        if ip_address(value).version == 4:
            incr1 = pow(2, (32 - int(mask))) + incr
            value = (IPv4Address(value) + incr1).compressed
        elif ip_address(value).version == 6:
            if mask == 32:
                mask = 64
            incr1 = pow(2, (128 - int(mask))) + incr
            value = (IPv6Address(value) + incr1).compressed
        ip_list.append(value)

    return ip_list


def cleanup_config(duthost_list, snappi_ports):
    ptype = "--snappi_macsec" in sys.argv
    if not ptype:
        if (duthost_list[0].facts['asic_type'] == "cisco-8000" and
                duthost_list[0].get_facts().get("modular_chassis", None)):
            global DEST_TO_GATEWAY_MAP  # noqa: F824
            copy_DEST_TO_GATEWAY_MAP = copy(DEST_TO_GATEWAY_MAP)
            for addr in copy_DEST_TO_GATEWAY_MAP:
                gen_data_flow_dest_ip(
                    addr,
                    dut=DEST_TO_GATEWAY_MAP[addr]['dut'],
                    intf=None,
                    namespace=DEST_TO_GATEWAY_MAP[addr]['asic'],
                    setup=False)

            time.sleep(4)

        for index, duthost in enumerate(duthost_list):
            port_count = len(snappi_ports)
            dutIps = create_ip_list(dut_ip_start, port_count, mask=prefix_length)
            for port in snappi_ports:
                if port['peer_device'] == duthost.hostname and port['intf_config_changed']:
                    port_id = port['port_id']
                    dutIp = dutIps[port_id]
                    logger.info('Removing Configuration on Dut: {} with port {} with ip :{}/{}'.
                                format(duthost.hostname,
                                       port['peer_port'],
                                       dutIp,
                                       prefix_length))
                    if port['asic_value'] is None:
                        duthost.command('sudo config interface ip remove {} {}/{} \n'.
                                        format(port['peer_port'],
                                               dutIp,
                                               prefix_length))
                    else:
                        duthost.command('sudo config interface -n {} ip remove {} {}/{} \n'.
                                        format(port['asic_value'],
                                               port['peer_port'],
                                               dutIp,
                                               prefix_length))
                    port['intf_config_changed'] = False
    else:
        if reconfigure_port:
            dut_obj = reconfigure_port['duthost']
            logger.info('Removing modified IP {} from interface {}'.
                        format(reconfigure_port['subnet'], reconfigure_port['peer_port']))
            if reconfigure_port['asic_value'] is None:
                dut_obj.command('sudo config interface ip remove {} {}/{} \n'.
                                format(reconfigure_port['peer_port'],
                                       dut_ip_for_non_macsec_port, 28))
            else:
                dut_obj.command('sudo config interface -n {} ip remove {} {}/{} \n' .
                                format(reconfigure_port['asic_value'],
                                       reconfigure_port['peer_port'], dut_ip_for_non_macsec_port, 28))
            logger.info('Adding back the original IP {} to interface {}'.
                        format(reconfigure_port['original_subnet'], reconfigure_port['peer_port']))
            if reconfigure_port['asic_value'] is None:
                dut_obj.command('sudo config interface ip add {} {}/{} \n'.
                                format(reconfigure_port['peer_port'],
                                       reconfigure_port['original_subnet'].split('/')[0],
                                       reconfigure_port['original_subnet'].split('/')[1]))
            else:
                dut_obj.command('sudo config interface -n {} ip add {} {}/{} \n'.
                                format(reconfigure_port['asic_value'], reconfigure_port['peer_port'],
                                       reconfigure_port['original_subnet'].split('/')[0],
                                       reconfigure_port['original_subnet'].split('/')[1]))
            logger.info('Disabling MACsec on {} port {}'.
                        format(macsec_enabled_port['duthost'].hostname,
                               macsec_enabled_port['peer_port']))
        logger.info('Disabling MACsec on {} port {}'.
                    format(macsec_enabled_port['duthost'].hostname,
                           macsec_enabled_port['peer_port']))
        disable_macsec_port(macsec_enabled_port['duthost'],  macsec_enabled_port['peer_port'])
        logger.info('Deleting macsec profile {} on {} port {}'.format(macsec_profile_name,
                                                                      macsec_enabled_port['duthost'].hostname,
                                                                      macsec_enabled_port['peer_port']))
        delete_macsec_profile(macsec_enabled_port['duthost'], macsec_enabled_port['peer_port'], macsec_profile_name)


@pytest.fixture(scope="module")
def multidut_snappi_ports_for_bgp(duthosts,                                # noqa: F811
                                  tbinfo,                                  # noqa: F811
                                  conn_graph_facts,                        # noqa: F811
                                  fanout_graph_facts_multidut):            # noqa: F811
    """
    Populate snappi ports and connected DUT ports info of T1 and T2 testbed and returns as a list
    Args:
        duthost (pytest fixture): duthost fixture
        tbinfo (pytest fixture): fixture provides information about testbed
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
    Return:
        return tuple of duts and snappi ports
    """
    speed_type = {'50000': 'speed_50_gbps',
                  '100000': 'speed_100_gbps',
                  '200000': 'speed_200_gbps',
                  '400000': 'speed_400_gbps'}
    multidut_snappi_ports = []

    for duthost in duthosts:
        snappi_fanout = get_peer_snappi_chassis(conn_data=conn_graph_facts,
                                                dut_hostname=duthost.hostname)
        if snappi_fanout is None:
            continue
        snappi_fanout = snappi_fanout[0]
        snappi_fanout_id = list(fanout_graph_facts_multidut.keys()).index(snappi_fanout)
        snappi_fanout_list = SnappiFanoutManager(fanout_graph_facts_multidut)
        snappi_fanout_list.get_fanout_device_details(device_number=snappi_fanout_id)
        snappi_ports = snappi_fanout_list.get_ports(peer_device=duthost.hostname)
        port_speed = None
        for i in range(len(snappi_ports)):
            if port_speed is None:
                port_speed = int(snappi_ports[i]['speed'])

            elif port_speed != int(snappi_ports[i]['speed']):
                """ All the ports should have the same bandwidth """
                return None

        for port in snappi_ports:
            port['location'] = get_snappi_port_location(port)
            port['speed'] = speed_type[port['speed']]
            port['api_server_ip'] = tbinfo['ptf_ip']
        multidut_snappi_ports = multidut_snappi_ports + snappi_ports
    return multidut_snappi_ports


@pytest.fixture(scope="module")
def get_snappi_ports_single_dut(duthosts,  # noqa: F811
                                conn_graph_facts,  # noqa: F811
                                fanout_graph_facts,  # noqa: F811
                                tbinfo,
                                snappi_api_serv_ip,
                                rand_one_dut_hostname,
                                rand_one_dut_portname_oper_up
                                ):  # noqa: F811
    speed_type = {
                  '10000': 'speed_10_gbps',
                  '25000': 'speed_25_gbps',
                  '40000': 'speed_40_gbps',
                  '50000': 'speed_50_gbps',
                  '100000': 'speed_100_gbps',
                  '200000': 'speed_200_gbps',
                  '400000': 'speed_400_gbps',
                  '800000': 'speed_800_gbps'}

    if is_snappi_multidut(duthosts):
        return []

    duthost = duthosts[rand_one_dut_hostname]

    """ Generate L1 config """
    snappi_fanouts = get_peer_snappi_chassis(conn_data=conn_graph_facts,
                                             dut_hostname=duthost.hostname)

    pytest_assert(snappi_fanouts is not None, 'Fail to get snappi_fanout')
    snappi_fanout_list = SnappiFanoutManager(fanout_graph_facts)
    snappi_ports_all = []
    for snappi_fanout in snappi_fanouts:
        snappi_fanout_id = list(fanout_graph_facts.keys()).index(snappi_fanout)
        snappi_fanout_list.get_fanout_device_details(device_number=snappi_fanout_id)
        snappi_ports = snappi_fanout_list.get_ports(peer_device=duthost.hostname)
        # Add snappi ports for each chassis connetion
        for sp in snappi_ports:
            snappi_ports_all.append(sp)

        for port in snappi_ports_all:
            port['intf_config_changed'] = False
            port['api_server_ip'] = tbinfo['ptf_ip']
            port['asic_type'] = duthost.facts["asic_type"]
            port['duthost'] = duthost
            port['snappi_speed_type'] = speed_type[port['speed']]
            if duthost.facts["num_asic"] > 1:
                port['asic_value'] = duthost.get_port_asic_instance(port['peer_port']).namespace
            else:
                port['asic_value'] = None
    for index, port in enumerate(snappi_ports_all):
        port['port_id'] = str(index + 1)
    return snappi_ports_all


@pytest.fixture(scope="module")
def get_snappi_ports_multi_dut(duthosts,  # noqa: F811
                               tbinfo,  # noqa: F811
                               conn_graph_facts,  # noqa: F811
                               fanout_graph_facts_multidut,
                               ):  # noqa: F811
    """
    Populate snappi ports and connected DUT ports info of T1 and T2 testbed and returns as a list
    Args:
        duthost (pytest fixture): duthost fixture
        tbinfo (pytest fixture): fixture provides information about testbed
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
    Return: (list)
        [{  'api_server_ip': '10.36.78.59',
            'asic_type': 'broadcom',
            'asic_value': None,
            'card_id': '4',
            'duthost': <MultiAsicSonicHost sonic-s6100-dut2>,
            'ip': '10.36.78.53',
            'location': '10.36.78.53;4;7',
            'peer_device': 'sonic-s6100-dut1',
            'peer_port': 'Ethernet72',
            'port_id': '7',
            'snappi_speed_type': 'speed_100_gbps',
            'speed': '100000'
        },
        {   'api_server_ip': '10.36.78.59',
            'asic_type': 'broadcom',
            'asic_value': 'asic0',
            'card_id': '4',
            'duthost': <MultiAsicSonicHost sonic-s6100-dut2>,
            'ip': '10.36.78.53',
            'location': '10.36.78.53;4;8',
            'peer_device': 'sonic-s6100-dut2',
            'peer_port': 'Ethernet76',
            'port_id': '8',
            'snappi_speed_type': 'speed_100_gbps',
            'speed': '100000'
        }]
    """
    speed_type = {
                  '10000': 'speed_10_gbps',
                  '25000': 'speed_25_gbps',
                  '40000': 'speed_40_gbps',
                  '50000': 'speed_50_gbps',
                  '100000': 'speed_100_gbps',
                  '200000': 'speed_200_gbps',
                  '400000': 'speed_400_gbps',
                  '800000': 'speed_800_gbps'}
    multidut_snappi_ports = []

    if not is_snappi_multidut(duthosts):
        return []

    for duthost in duthosts:
        snappi_fanouts = get_peer_snappi_chassis(conn_data=conn_graph_facts,
                                                 dut_hostname=duthost.hostname)
        if snappi_fanouts is None:
            continue
        snappi_fanout_list = SnappiFanoutManager(fanout_graph_facts_multidut)
        for snappi_fanout in snappi_fanouts:
            snappi_fanout_id = list(fanout_graph_facts_multidut.keys()).index(snappi_fanout)
            snappi_fanout_list.get_fanout_device_details(device_number=snappi_fanout_id)
            snappi_ports = snappi_fanout_list.get_ports(peer_device=duthost.hostname)

            for port in snappi_ports:
                port['intf_config_changed'] = False
                port['api_server_ip'] = tbinfo['ptf_ip']
                port['asic_type'] = duthost.facts["asic_type"]
                port['duthost'] = duthost
                port['snappi_speed_type'] = speed_type[port['speed']]
                if duthost.facts["num_asic"] > 1:
                    port['asic_value'] = duthost.get_port_asic_instance(port['peer_port']).namespace
                else:
                    port['asic_value'] = None
            multidut_snappi_ports = multidut_snappi_ports + snappi_ports
    for index, port in enumerate(multidut_snappi_ports):
        port['port_id'] = str(index + 1)
    return multidut_snappi_ports


def is_snappi_multidut(duthosts):
    if duthosts is None or len(duthosts) == 0:
        return False
    if len(duthosts) == 1:
        return False
    if len(duthosts) > 1:
        return True
    return duthosts[0].get_facts().get("modular_chassis")


@pytest.fixture(scope="module")
def get_snappi_ports(duthosts, request):
    """
    Returns the snappi port info based on the testbed type
    Args:
        duthosts (pytest fixture): list of DUTs
        request (pytest fixture): request fixture
    Return: (list)
    """
    # call the fixture based on the testbed type for minimize the impact
    # use the same fixture for different testbeds in the future if possible?
    if is_snappi_multidut(duthosts):
        snappi_ports = request.getfixturevalue("get_snappi_ports_multi_dut")
    else:
        snappi_ports = request.getfixturevalue("get_snappi_ports_single_dut")
    return snappi_ports


def get_snappi_ports_for_rdma(snappi_port_list, rdma_ports, tx_port_count, rx_port_count, testbed):
    """
    Returns the required tx and rx ports for the rdma test
    Args:
        snappi_port_list (list): List of snappi ports and connected DUT ports info of T1 and T2 testbed
        rdma_ports (dict): RDMA port info for testbed subtype defined in variables.py
        tx_port_count (int): Number of Tx ports required for the test
        rx_port_count (int): Number of Rx ports required for the test
    Return: (list)
    """
    tx_snappi_ports = []
    rx_snappi_ports = []
    var_tx_ports = random.sample(rdma_ports['tx_ports'], tx_port_count)
    var_rx_ports = random.sample(rdma_ports['rx_ports'], rx_port_count)
    for port in snappi_port_list:
        for var_rx_port in var_rx_ports:
            if port['peer_port'] == var_rx_port['port_name'] and port['peer_device'] == var_rx_port['hostname']:
                rx_snappi_ports.append(port)
        for var_tx_port in var_tx_ports:
            if port['peer_port'] == var_tx_port['port_name'] and port['peer_device'] == var_tx_port['hostname']:
                tx_snappi_ports.append(port)

    pytest_require(
        len(rx_snappi_ports) == rx_port_count,
        f"Rx Ports for {testbed} in MULTIDUT_PORT_INFO doesn't match with "
        f"ansible/files/*links.csv: rx_snappi_ports: {rx_snappi_ports}, and "
        f"wanted: {rx_port_count}")
    pytest_require(
        len(tx_snappi_ports) == tx_port_count,
        f"Tx Ports for {testbed} in MULTIDUT_PORT_INFO doesn\'t match with "
        f"ansible/files/*links.csv: tx_snappi_ports: {tx_snappi_ports}, and "
        f"wanted: {tx_port_count}")

    multidut_snappi_ports = rx_snappi_ports + tx_snappi_ports
    return multidut_snappi_ports


def clear_fabric_counters(duthost):
    """
    Clears the fabric counters for the duthost based on broadcom-DNX platform.
    Args:
        duthost(obj): dut host object
    Returns:
        None
    """
    if "platform_asic" in duthost.facts and duthost.facts["platform_asic"] == "broadcom-dnx":
        logger.info('Clearing fabric counters for DUT:{}'.format(duthost.hostname))
        duthost.shell('sonic-clear fabriccountersport \n')
        time.sleep(1)


def check_fabric_counters(duthost):
    """
    Check for the fabric counters for the duthost based on broadcom-DNX platform.
    Test assert if the value of CRC, and FEC_UNCORRECTABLE.
    Args:
        duthost(obj): dut host object
    Returns:
        None
    """
    if "platform_asic" in duthost.facts and duthost.facts["platform_asic"] == "broadcom-dnx":
        raw_out = duthost.shell("show fabric counters port | grep -Ev 'ASIC|---|down'")['stdout']
        logger.info('Verifying fabric counters for DUT:{}'.format(duthost.hostname))
        for line in raw_out.split('\n'):
            # Checking if the port is UP.
            if 'up' in line:
                val_list = line.split()
                crc_errors = int(val_list[7].replace(',', ''))
                fec_uncor_err = int(val_list[9].replace(',', ''))
                # Assert if CRC or FEC uncorrected errors are non-zero.
                pytest_assert(crc_errors == 0, 'CRC errors:{} for DUT:{}, ASIC:{}, Port:{}'.
                              format(crc_errors, duthost.hostname, val_list[0], val_list[1]))
                pytest_assert(fec_uncor_err == 0, 'Forward Uncorrectable errors:{} for DUT:{}, ASIC:{}, Port:{}'.
                              format(fec_uncor_err, duthost.hostname, val_list[0], val_list[1]))


def setup_config_uhd_connect(request, tbinfo, ha_test_case=None):
    """
    Standalone function for UHD connect configuration that can be called in threads
    """
    def read_links_from_csv(file_path):
        with open(file_path, 'r') as f:
            return list(csv.DictReader(f))

    uhd_enabled = request.config.getoption("--uhd_config")
    save_uhd_config = request.config.getoption("--save_uhd_config")

    if uhd_enabled:
        # Load UHD-specific config file
        logger.info(f"Loading UHD-specific config file for test case: {ha_test_case}")

        logger.info("Configuring UHD connect")
        csv_data = read_links_from_csv(uhd_enabled)
        dpu_ports = [row for row in csv_data if row['OutPort'] == 'True']
        l47_ports = [row for row in csv_data if row['OutPort'] == 'False']
        ethpass_ports = [row for row in csv_data if row['EthernetPass'] == 'True']
        has_switchover = any(dpu.get('SwitchOverPort') == 'True' for dpu in dpu_ports)

        uhdConnect_ip = tbinfo['uhd_ip']
        num_cps_cards = tbinfo['num_cps_cards']
        num_tcpbg_cards = tbinfo['num_tcpbg_cards']
        num_udpbg_cards = tbinfo['num_udpbg_cards']
        num_dpu_ports = len(dpu_ports)

        cards_dict = {
            'num_cps_cards': num_cps_cards,
            'num_tcpbg_cards': num_tcpbg_cards,
            'num_udpbg_cards': num_udpbg_cards,
            'num_dpus_ports': num_dpu_ports,
            'l47_ports': l47_ports,
            'dpu_ports': dpu_ports,
            'ethpass_ports': ethpass_ports,
            'switchover_port': has_switchover
        }

        uhdSettings = NetworkConfigSettings()  # noqa: F405
        uhdSettings.set_mac_addresses(tbinfo['l47_tg_clientmac'], tbinfo['l47_tg_servermac'], tbinfo['dut_mac'])
        total_cards = num_cps_cards + num_tcpbg_cards + num_udpbg_cards
        subnet_mask = uhdSettings.subnet_mask

        logger.info(f"Configuring UHD connect for {uhdSettings.ENI_COUNT} ENIs")
        ip_list = create_uhdIp_list(subnet_mask, uhdSettings, cards_dict)  # noqa: F405
        fp_ports_list = create_front_panel_ports(int(total_cards * 2), uhdSettings, cards_dict)  # noqa: F405
        arp_bypass_list = create_arp_bypass(fp_ports_list, ip_list, uhdSettings, cards_dict, subnet_mask)  # noqa: F405
        connections_list = create_connections(fp_ports_list, ip_list, subnet_mask, uhdSettings,  # noqa: F405
                                              cards_dict, arp_bypass_list)

        config = {
            "profiles": create_profiles(uhdSettings),  # noqa: F405
            "front_panel_ports": fp_ports_list,
            "connections": connections_list
        }

        headers = {  # noqa: F841
            'Content-Type': 'application/json'
        }

        file_name = "tempUhdConfig.json"
        file_location = os.getcwd()
        uhd_post_url = uhdSettings.uhd_post_url
        url = "https://{}/{}".format(uhdConnect_ip, uhd_post_url)  # noqa: F841
        json.dump(config, open("{}/{}".format(file_location, file_name), "w"), indent=1)

        logger.info(f"Pushing created UHD configuration file {file_name} to UHD Connect")
        uhdConf_cmd = ('curl -k -X POST -H \"Content-Type: application/json\" -d @\"{}/{}\"   '
                       '{}').format(file_location, file_name, url)
        subprocess.run(uhdConf_cmd, shell=True, capture_output=True, text=True)

        if not save_uhd_config:
            logger.info("Removing UHD config file")
            rm_cmd_uhdconf = 'rm {}/{}'.format(file_location, file_name)
            subprocess.run(rm_cmd_uhdconf, shell=True, capture_output=True, text=True)  # noqa: F841
        else:
            logger.info(f"Saving UHD config to {file_location}")
        logger.info("UHD configuration completed")
    else:
        logger.info("UHD config not enabled, skipping config")

    return


@pytest.fixture(scope="module")
def config_uhd_connect(request, tbinfo):
    """
    Fixture configures UHD connect
    """
    return setup_config_uhd_connect(request, tbinfo)


DEST_TO_GATEWAY_MAP = {}  # noqa: F824


# Add static routes using CLI WAY.
def gen_data_flow_dest_ip(addr, dut=None, intf=None, namespace=None, setup=True):
    '''
        Return a static route-d IP address for the given IP gateway(Ixia port address).
        Also configure the same in the DUT.
    '''
    if dut is None:
        if addr not in DEST_TO_GATEWAY_MAP:
            return addr
        return DEST_TO_GATEWAY_MAP[addr]['dest']

    if dut.facts['asic_type'] != "cisco-8000":
        DEST_TO_GATEWAY_MAP[addr] = {}
        DEST_TO_GATEWAY_MAP[addr]['dest'] = addr
        return addr

    if setup:
        if addr in DEST_TO_GATEWAY_MAP:
            return DEST_TO_GATEWAY_MAP[addr]['dest']

    '''
        Create a new IP address, which is computed from
        (given addr + 3.0.0.0) addresses later.
        So the dest for 200.0.0.1 will be 203.0.0.1/32
    '''
    ip_addr = ip_address(addr)
    if (ip_addr.version == 6):
        logger.info("Skip arp setting up for ipv6 since ipv6 does not support arp")
        return

    DEST_TO_GATEWAY_MAP[addr] = {}
    DEST_TO_GATEWAY_MAP[addr]['dest'] = str(ip_addr + 3*256*256*256)
    DEST_TO_GATEWAY_MAP[addr]['intf'] = intf
    DEST_TO_GATEWAY_MAP[addr]['dut'] = dut
    DEST_TO_GATEWAY_MAP[addr]['asic'] = namespace
    cmd = "del"
    if setup:
        cmd = "add"
    asic_arg = ""
    if namespace is not None:
        asic_arg = f"ip netns exec {namespace}"
    int_arg = ""
    if intf:
        int_arg = f"-i {intf}"
    if setup:
        arp_opt = f"-s {addr} aa:bb:cc:dd:ee:ff"  # noqa: E231
    else:
        arp_opt = f"-d {addr}"

    try:
        dut.shell(f"sudo {asic_arg} arp {int_arg} {arp_opt}")
        dut.shell(
            "{} config route {} prefix {}/32 nexthop {} {}".format(
                asic_arg, cmd, DEST_TO_GATEWAY_MAP[addr]['dest'], addr,
                DEST_TO_GATEWAY_MAP[addr]['intf']))
    except RunAnsibleModuleFail:
        if setup:
            raise
        else:
            # Its already removed by reboot
            pass

    if setup:
        return DEST_TO_GATEWAY_MAP[addr]['dest']
    else:
        del DEST_TO_GATEWAY_MAP[addr]


@pytest.fixture(scope="module")
def snappi_port_selection(get_snappi_ports, number_of_tx_rx_ports, mixed_speed=None):
    '''
    Dynamic selection of the DUT ports for the test.
    Selects ports for three test combinations:
            - Single line-card single asic
            - Single line-card multiple asic
            - Multiple line-card.
    Args:
        get_snappi_ports(fixture): returns list of the ports available in test.
        number_of_tx_rx_ports(fixture): count of tx and rx ports available from the test.
    Returns:
        snappi_ports(dict): Dictionary with interface-speed and line-card-combo being primary keys.
        Example: {'100':{'single-linecard-single-asic':{ports}, 'single-linecard-multiple-asic':{ports}}}

    '''
    # Reverse this here since this is more like on the DUT perspective
    rx_port_count, tx_port_count = number_of_tx_rx_ports
    tmp_snappi_port_list = get_snappi_ports

    if (not mixed_speed):
        # Creating list of all interface speeds from selected ports.
        port_speed_list = []
        for item in tmp_snappi_port_list:
            if (int(item['speed'])/1000) not in port_speed_list:
                port_speed_list.append(int(item['speed'])/1000)

        port_list = {}
        # Repeating loop for speed_types
        for port_speed in port_speed_list:
            new_list = []
            # Selecting ports matching the port_speed
            for item in tmp_snappi_port_list:
                if (int(item['speed']) == (port_speed * 1000)):
                    new_list.append(item)

            # Creating dictionary f{hostname}{asic_val}
            # f[hostname]['asic'] should contain associated elements.
            f = {}
            for item in new_list:
                hostname = item['peer_device']
                asic = item['asic_value']
                if hostname not in f:
                    f[hostname] = {}
                if asic not in f[hostname]:
                    f[hostname][asic] = []
                f[hostname][asic].append(item)

            total_ports = tx_port_count + rx_port_count

            # Initializing dictionary port_list{speed}{line-card-asic-combo}
            # example port_list['100']['single_linecard_single_asic']

            # for 'single-linecard-single-asic'
            for device, asic in f.items():
                for asic_val in asic.keys():
                    if len(f[device][asic_val]) >= (total_ports):
                        if port_speed not in port_list:
                            port_list[port_speed] = {}
                        if 'single_linecard_single_asic' not in port_list[port_speed]:
                            port_list[port_speed]['single_linecard_single_asic'] = []
                        if len(port_list[port_speed]['single_linecard_single_asic']) == total_ports:
                            break
                        else:
                            port_list[port_speed]['single_linecard_single_asic'] = f[device][asic_val][0:total_ports]

            # for 'single_linecard_multiple_asic'
            egress_done = False
            ingress_done = False
            tmp_ing_list = []
            for device, asic in f.items():
                # Execute ONLY if the number of asics is more than one.
                if len(asic.keys()) < 2:
                    continue
                else:
                    for asic_val in asic.keys():
                        asic_port_len = len(f[device][asic_val])
                        if ((asic_port_len >= tx_port_count) or (asic_port_len >= rx_port_count)):
                            # Initializing the dictionary
                            if port_speed not in port_list:
                                port_list[port_speed] = {}
                            if 'single_linecard_multiple_asic' not in port_list[port_speed]:
                                port_list[port_speed]['single_linecard_multiple_asic'] = []

                            # If the dictionary is complete, no need to add further ports.
                            if len(port_list[port_speed]['single_linecard_multiple_asic']) == total_ports:
                                break

                            # Accomodating ingress ports first if more ports are available.
                            if ((asic_port_len - tx_port_count) > (asic_port_len - rx_port_count)
                                    and not ingress_done
                                    and not tmp_ing_list
                                    and (asic_port_len >= rx_port_count)):
                                tmp_ing_list = f[device][asic_val][0:rx_port_count]
                                ingress_done = True
                            elif (not egress_done and (asic_port_len >= tx_port_count)):
                                tx_list = f[device][asic_val][0:tx_port_count]
                                port_list[port_speed]['single_linecard_multiple_asic'] = tx_list
                                egress_done = True
                                tmp_len = len(port_list[port_speed]['single_linecard_multiple_asic'])
                                if (tmp_ing_list
                                        and (tmp_len < total_ports)):
                                    port_list[port_speed]['single_linecard_multiple_asic'].append(tmp_ing_list)
                            elif (not ingress_done and (asic_port_len >= rx_port_count)):
                                rx_list = f[device][asic_val][0:rx_port_count]
                                port_list[port_speed]['single_linecard_multiple_asic'].append(rx_list)
                                tmp_ing_list = f[device][asic_val][0:rx_port_count]
                                ingress_done = True

            if (ingress_done
                    and egress_done
                    and (len(flatten_list(port_list[port_speed]['single_linecard_multiple_asic'])) < total_ports)):
                port_list[port_speed]['single_linecard_multiple_asic'].append(tmp_ing_list)

            # Flatten the dictionary if the dictionary is created.
            if (port_speed in port_list) and ('single_linecard_multiple_asic' in port_list[port_speed]):
                port_list[port_speed]['single_linecard_multiple_asic'] = flatten_list(
                    port_list[port_speed]['single_linecard_multiple_asic'])
                # If egress or ingress ports are not found, delete the dictionary key-value.
                if (not egress_done or not ingress_done):
                    del port_list[port_speed]['single_linecard_multiple_asic']

            # for 'multiple linecard, multiple ASIC'
            egress_done = False
            ingress_done = False
            tmp_ing_list = []

            for device, asic in f.items():
                # Creating list for a given device for all ASIC combinations.
                all_asic_ports = []
                for asic_val in asic.keys():
                    all_asic_ports.append(f[device][asic_val])
                all_asic_ports = flatten_list(all_asic_ports)

                # Initializing the dictionary, if it does not exist.
                if port_speed not in port_list:
                    port_list[port_speed] = {}
                if 'multiple_linecard_multiple_asic' not in port_list[port_speed]:
                    port_list[port_speed]['multiple_linecard_multiple_asic'] = []

                asic_port_len = len(all_asic_ports)
                if ((asic_port_len - tx_port_count) > (asic_port_len - rx_port_count)
                        and not ingress_done
                        and not tmp_ing_list
                        and (asic_port_len >= rx_port_count)):
                    tmp_ing_list = all_asic_ports[0:rx_port_count]
                    ingress_done = True
                # Identifying egress ports first
                elif (len(port_list[port_speed]['multiple_linecard_multiple_asic']) <= tx_port_count
                        and not egress_done and len(all_asic_ports) >= tx_port_count):
                    port_list[port_speed]['multiple_linecard_multiple_asic'].append(all_asic_ports[0:tx_port_count])
                    # egress ports identified, move to next device.
                    # No need to select egress ports now.
                    egress_done = True
                    continue
                # Identifying ingress ports
                elif (len(port_list[port_speed]['multiple_linecard_multiple_asic']) <= rx_port_count
                        and not ingress_done and len(all_asic_ports) >= rx_port_count):
                    port_list[port_speed]['multiple_linecard_multiple_asic'].append(all_asic_ports[0:rx_port_count])
                    # ingress ports identified, move to next device.
                    # No need to select ingress ports now.
                    ingress_done = True
                    continue

            if (ingress_done
                    and egress_done
                    and (len(port_list[port_speed]['multiple_linecard_multiple_asic']) < total_ports)):
                port_list[port_speed]['multiple_linecard_multiple_asic'].append(tmp_ing_list)

            # Flatten the dictionary, if the dictionary is created.
            if (port_speed in port_list) and ('multiple_linecard_multiple_asic' in port_list[port_speed]):
                # Flattening the list.
                port_list[port_speed]['multiple_linecard_multiple_asic'] = flatten_list(
                        port_list[port_speed]['multiple_linecard_multiple_asic'])

                # If the dictionary does not select either ingress or egress ports, then dictionary is deleted.
                if (not egress_done or not ingress_done):
                    del port_list[port_speed]['multiple_linecard_multiple_asic']

        pytest_assert(port_list is not None, 'snappi ports are not available for required Rx and Tx port counts')
        return port_list


@pytest.fixture(scope="function")
def tgen_port_info(request: pytest.FixtureRequest, snappi_port_selection, get_snappi_ports,
                   number_of_tx_rx_ports, duthosts, snappi_api):
    testbed = request.config.getoption("--testbed")

    is_override, _ = parse_override(
        testbed,
        'multidut_port_info'
    )

    if is_override:
        testbed_subtype, rdma_ports = next(iter(request.param.items()))
        tx_port_count, rx_port_count = number_of_tx_rx_ports

        if len(get_snappi_ports) < tx_port_count + rx_port_count:
            pytest.skip(
                "Need Minimum of 2 ports defined in ansible/files/*links.csv"
                " file, got:{}".format(len(get_snappi_ports)))

        if len(rdma_ports['tx_ports']) < tx_port_count:
            pytest.skip(
                "Doesn't have the required Tx ports defined for "
                "testbed {}, subtype {} in variables.override.yml".format(
                    testbed, testbed_subtype))

        if len(rdma_ports['rx_ports']) < rx_port_count:
            pytest.skip(
                "Doesn't have the required Rx ports defined for "
                "testbed {}, subtype {} in variables.override.yml".format(
                    testbed, testbed_subtype))

        snappi_ports = get_snappi_ports
        if is_snappi_multidut(duthosts):
            snappi_ports = get_snappi_ports_for_rdma(
                get_snappi_ports,
                rdma_ports,
                tx_port_count,
                rx_port_count,
                testbed
            )
        return snappi_dut_base_config(duthosts, snappi_ports, snappi_api, setup=True)

    flatten_skeleton_parameter = request.param
    speed, category = flatten_skeleton_parameter.split("-")

    if float(speed) not in snappi_port_selection or category not in snappi_port_selection[float(speed)]:
        pytest.skip(f"Unsupported combination for {flatten_skeleton_parameter}")

    snappi_ports = snappi_port_selection[float(speed)][category]

    if not snappi_ports:
        pytest.skip(f"Unsupported combination for {flatten_skeleton_parameter}")

    return snappi_dut_base_config(duthosts, snappi_ports, snappi_api, setup=True)


def flatten_list(lst):
    '''
    Function to flatten the list
    Args:
        lst(list): list that needs to be flattened
    Retuns:
        flattened(list): flattened list
    '''
    flattened = []
    for item in lst:
        if isinstance(item, list):
            flattened.extend(flatten_list(item))
        else:
            flattened.append(item)
    return flattened
