"""
This module contains the snappi fixture in the snappi_tests directory.
"""
import pytest
import time
import logging
import os
import snappi
import sys
import random
from copy import copy
from tests.common.helpers.assertions import pytest_require
from tests.common.errors import RunAnsibleModuleFail
from ipaddress import ip_address, IPv4Address, IPv6Address
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts     # noqa: F401
from tests.common.snappi_tests.common_helpers import get_addrs_in_subnet, get_peer_snappi_chassis, \
    get_ipv6_addrs_in_subnet, parse_override
from tests.common.snappi_tests.snappi_helpers import SnappiFanoutManager, get_snappi_port_location
from tests.common.snappi_tests.port import SnappiPortConfig, SnappiPortType
from tests.common.helpers.assertions import pytest_assert
from tests.common.snappi_tests.variables import pfcQueueGroupSize, pfcQueueValueDict, dut_ip_start, snappi_ip_start, \
    prefix_length, dut_ipv6_start, snappi_ipv6_start, v6_prefix_length


logger = logging.getLogger(__name__)


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
    USERNAME_ENV = "TGEN_USERNAME"
    PASSWORD_ENV = "TGEN_PASSWORD"
    pytest_assert(USERNAME_ENV in os.environ,
                  "Please specify the TGEN username in the environment variable {}".format(USERNAME_ENV))
    pytest_assert(PASSWORD_ENV in os.environ,
                  "Please specify the TGEN password in the environment variable {}".format(PASSWORD_ENV))
    api._username = os.environ.get(USERNAME_ENV)
    api._password = os.environ.get(PASSWORD_ENV)
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
    return '00:11:22:33:44:{:02d}'.format(id)


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

    speed_type = {'50000': 'speed_50_gbps',
                  '100000': 'speed_100_gbps',
                  '200000': 'speed_200_gbps',
                  '400000': 'speed_400_gbps'}

    snappi_fanout = get_peer_snappi_chassis(conn_data=conn_graph_facts,
                                            dut_hostname=duthost.hostname)
    snappi_fanout_id = list(fanout_graph_facts.keys()).index(snappi_fanout)
    snappi_fanout_list = SnappiFanoutManager(fanout_graph_facts)
    snappi_fanout_list.get_fanout_device_details(device_number=snappi_fanout_id)
    snappi_ports = snappi_fanout_list.get_ports(peer_device=duthost.hostname)
    port_speed = None

    for i in range(len(snappi_ports)):
        if port_speed is None:
            port_speed = int(snappi_ports[i]['speed'])

        elif port_speed != int(snappi_ports[i]['speed']):
            """ All the ports should have the same bandwidth """
            return None

    config_facts = duthost.config_facts(host=duthost.hostname,
                                        source="running")['ansible_facts']
    for port in snappi_ports:
        port['location'] = get_snappi_port_location(port)
        port['speed'] = speed_type[port['speed']]
    try:
        for port in snappi_ports:
            peer_port = port['peer_port']
            asic_instance = duthost.get_port_asic_instance(peer_port)
            config_facts = asic_instance.config_facts(
                host=duthost.hostname,
                source="running")['ansible_facts']
            int_addrs = list(config_facts['INTERFACE'][peer_port].keys())
            ipv4_subnet = [ele for ele in int_addrs if "." in ele][0]
            if not ipv4_subnet:
                raise Exception("IPv4 is not configured on the interface {}".format(peer_port))
            port['peer_ip'], port['prefix'] = ipv4_subnet.split("/")
            port['ip'] = get_addrs_in_subnet(ipv4_subnet, 1)[0]
            ipv6_subnet = [ele for ele in int_addrs if ":" in ele][0]
            if not ipv6_subnet:
                raise Exception("IPv6 is not configured on the interface {}".format(peer_port))
            port['peer_ipv6'], port['ipv6_prefix'] = ipv6_subnet.split("/")
            port['ipv6'] = get_ipv6_addrs_in_subnet(ipv6_subnet, 1)[0]
    except Exception:
        snappi_ports = pre_configure_dut_interface(duthost, snappi_ports)
        logger.info(snappi_ports)

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

    pytest_assert(len(port_config_list) == len(snappi_ports), 'Failed to configure DUT ports')

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
        value = unicode(value)          # noqa: F821

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

    if (duthost_list[0].facts['asic_type'] == "cisco-8000" and
            duthost_list[0].get_facts().get("modular_chassis", None)):
        global DEST_TO_GATEWAY_MAP
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
                logger.info('Removing Configuration on Dut: {} with port {} with ip :{}/{}'.format(
                                                                                                   duthost.hostname,
                                                                                                   port['peer_port'],
                                                                                                   dutIp,
                                                                                                   prefix_length))
                if port['asic_value'] is None:
                    duthost.command('sudo config interface ip remove {} {}/{} \n' .format(
                                                                                          port['peer_port'],
                                                                                          dutIp,
                                                                                          prefix_length))
                else:
                    duthost.command('sudo config interface -n {} ip remove {} {}/{} \n' .format(
                                                                                                port['asic_value'],
                                                                                                port['peer_port'],
                                                                                                dutIp,
                                                                                                prefix_length))
                port['intf_config_changed'] = False


def pre_configure_dut_interface(duthost, snappi_ports):
    """
    Populate tgen ports info of T0 testbed and returns as a list
    Args:
        duthost (pytest fixture): duthost fixture
        snappi_ports: list of snappi ports
    """

    dutIps = create_ip_list(dut_ip_start, len(snappi_ports), mask=prefix_length)
    tgenIps = create_ip_list(snappi_ip_start, len(snappi_ports), mask=prefix_length)
    dutv6Ips = create_ip_list(dut_ipv6_start, len(snappi_ports), mask=v6_prefix_length)
    tgenv6Ips = create_ip_list(snappi_ipv6_start, len(snappi_ports), mask=v6_prefix_length)
    snappi_ports_dut = []
    for port in snappi_ports:
        if port['peer_device'] == duthost.hostname:
            snappi_ports_dut.append(port)

    for port in snappi_ports_dut:
        port_id = int(port['port_id'])-1
        port['peer_ip'] = dutIps[port_id]
        port['prefix'] = prefix_length
        port['ip'] = tgenIps[port_id]
        port['peer_ipv6'] = dutv6Ips[port_id]
        port['ipv6_prefix'] = v6_prefix_length
        port['ipv6'] = tgenv6Ips[port_id]
        port['asic_value'] = duthost.get_port_asic_instance(port['peer_port'])
        asic_cmd = ""
        if port['asic_value'] is not None:
            asic_cmd = " -n {} ".format(port['asic_value'])
        try:
            logger.info('Pre-Configuring Dut: {} with port {} with IP {}/{}'.format(
                                                                                duthost.hostname,
                                                                                port['peer_port'],
                                                                                dutIps[port_id],
                                                                                prefix_length))
            duthost.command('sudo config interface {} ip add {} {}/{} \n' .format(
                                                                                asic_cmd,
                                                                                port['peer_port'],
                                                                                dutIps[port_id],
                                                                                prefix_length))
            logger.info('Pre-Configuring Dut: {} with port {} with IPv6 {}/{}'.format(
                                                                                duthost.hostname,
                                                                                port['peer_port'],
                                                                                dutv6Ips[port_id],
                                                                                v6_prefix_length))
            duthost.command('sudo config interface {} ip add {} {}/{} \n' .format(
                                                                                asic_cmd,
                                                                                port['peer_port'],
                                                                                dutv6Ips[port_id],
                                                                                v6_prefix_length))
            gen_data_flow_dest_ip(tgenIps[port_id], duthost, port['peer_port'], port['asic_value'], setup=True)
            gen_data_flow_dest_ip(tgenv6Ips[port_id], duthost, port['peer_port'], port['asic_value'], setup=True)
        except Exception:
            pytest_assert(False, "Unable to configure ip on the interface {}".format(port['peer_port']))
    return snappi_ports_dut


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

    dut_hostname, dut_port = rand_one_dut_portname_oper_up.split('|')
    pytest_require(rand_one_dut_hostname == dut_hostname,
                   "{} Port is not mapped to the expected DUT".format(rand_one_dut_portname_oper_up))

    """ Generate L1 config """
    snappi_fanout = get_peer_snappi_chassis(conn_data=conn_graph_facts,
                                            dut_hostname=duthost.hostname)

    pytest_assert(snappi_fanout is not None, 'Fail to get snappi_fanout')

    snappi_fanout_id = list(fanout_graph_facts.keys()).index(snappi_fanout)
    snappi_fanout_list = SnappiFanoutManager(fanout_graph_facts)
    snappi_fanout_list.get_fanout_device_details(device_number=snappi_fanout_id)

    snappi_ports = snappi_fanout_list.get_ports(peer_device=duthost.hostname)

    rx_ports = []
    tx_ports = []
    for port in snappi_ports:
        port['intf_config_changed'] = False
        port['location'] = get_snappi_port_location(port)
        port['speed'] = port['speed']
        port['api_server_ip'] = tbinfo['ptf_ip']
        port['asic_type'] = duthost.facts["asic_type"]
        port['duthost'] = duthost
        port['snappi_speed_type'] = speed_type[port['speed']]
        if duthost.facts["num_asic"] > 1:
            port['asic_value'] = duthost.get_port_asic_instance(port['peer_port']).namespace
        else:
            port['asic_value'] = None
        # convert to RX ports first, tx ports later to be consistent with multi-dut
        if port['peer_port'] == dut_port:
            rx_ports.append(port)
        else:
            tx_ports.append(port)
    return rx_ports + tx_ports


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
        snappi_fanout = get_peer_snappi_chassis(conn_data=conn_graph_facts,
                                                dut_hostname=duthost.hostname)
        if snappi_fanout is None:
            continue
        snappi_fanout_id = list(fanout_graph_facts_multidut.keys()).index(snappi_fanout)
        snappi_fanout_list = SnappiFanoutManager(fanout_graph_facts_multidut)
        snappi_fanout_list.get_fanout_device_details(device_number=snappi_fanout_id)
        snappi_ports = snappi_fanout_list.get_ports(peer_device=duthost.hostname)

        for port in snappi_ports:
            port['intf_config_changed'] = False
            port['location'] = get_snappi_port_location(port)
            port['speed'] = port['speed']
            port['api_server_ip'] = tbinfo['ptf_ip']
            port['asic_type'] = duthost.facts["asic_type"]
            port['duthost'] = duthost
            port['snappi_speed_type'] = speed_type[port['speed']]
            if duthost.facts["num_asic"] > 1:
                port['asic_value'] = duthost.get_port_asic_instance(port['peer_port']).namespace
            else:
                port['asic_value'] = None
        multidut_snappi_ports = multidut_snappi_ports + snappi_ports
    return multidut_snappi_ports


def is_snappi_multidut(duthosts):
    if duthosts is None or len(duthosts) == 0:
        return False

    if len(duthosts) == 1:
        return duthosts[0].get_facts().get("modular_chassis")
    return len(duthosts) > 1


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

    pytest_assert(len(rx_snappi_ports) == rx_port_count,
                  'Rx Ports for {} in MULTIDUT_PORT_INFO doesn\'t match with ansible/files/*links.csv'.format(testbed))
    pytest_assert(len(tx_snappi_ports) == tx_port_count,
                  'Tx Ports for {} in MULTIDUT_PORT_INFO doesn\'t match with ansible/files/*links.csv'.format(testbed))

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


DEST_TO_GATEWAY_MAP = {}


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
    try:
        dut.shell("{} arp -i {} -s {} aa:bb:cc:dd:ee:ff".format(
            asic_arg, intf, addr))
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
