"""
This module contains the snappi fixture in the snappi_tests directory.
"""
import pytest
import logging
import snappi
import sys
import random
import snappi_convergence
from ipaddress import ip_address, IPv4Address, IPv6Address
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts     # noqa: F401
from tests.common.snappi_tests.common_helpers import get_addrs_in_subnet, get_peer_snappi_chassis, \
    get_ipv6_addrs_in_subnet
from tests.common.snappi_tests.snappi_helpers import SnappiFanoutManager, get_snappi_port_location
from tests.common.snappi_tests.port import SnappiPortConfig, SnappiPortType
from tests.common.helpers.assertions import pytest_assert
from tests.snappi_tests.variables import dut_ip_start, snappi_ip_start, prefix_length, \
    dut_ipv6_start, snappi_ipv6_start, v6_prefix_length, pfcQueueGroupSize, \
    pfcQueueValueDict
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
def snappi_api_serv_port(duthosts, rand_one_dut_hostname):
    """
    This fixture returns the TCP Port of the Snappi API server.
    Args:
        duthost (pytest fixture): The duthost fixture.
    Returns:
        snappi API server port.
    """
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


def __l3_intf_config(config, port_config_list, duthost, snappi_ports):
    """
    Generate Snappi configuration of layer 3 interfaces
    Args:
        config (obj): Snappi API config of the testbed
        port_config_list (list): list of Snappi port configuration information
        duthost (object): device under test
        snappi_ports (list): list of Snappi port information
    Returns:
        True if we successfully generate configuration or False
    """
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    if 'minigraph_interfaces' in mg_facts:
        l3_intf_facts = mg_facts['minigraph_interfaces']
    else:
        return True

    if len(l3_intf_facts) == 0:
        return True

    l3_intf = {}
    for v in l3_intf_facts:
        if __valid_ipv4_addr(v['addr']):
            l3_intf[v['attachto']] = v

    dut_mac = str(duthost.facts['router_mac'])

    for k, v in list(l3_intf.items()):
        intf = str(k)
        gw_addr = str(v['addr'])
        prefix = str(v['prefixlen'])
        ip = str(v['peer_addr'])

        port_ids = [id for id, snappi_port in enumerate(snappi_ports)
                    if snappi_port['peer_port'] == intf]
        if len(port_ids) != 1:
            return False

        port_id = port_ids[0]
        mac = __gen_mac(port_id)

        device = config.devices.device(
            name='Device Port {}'.format(port_id))[-1]

        ethernet = device.ethernets.add()
        ethernet.name = 'Ethernet Port {}'.format(port_id)
        ethernet.port_name = config.ports[port_id].name
        ethernet.mac = mac

        ip_stack = ethernet.ipv4_addresses.add()
        ip_stack.name = 'Ipv4 Port {}'.format(port_id)
        ip_stack.address = ip
        ip_stack.prefix = int(prefix)
        ip_stack.gateway = gw_addr

        port_config = SnappiPortConfig(id=port_id,
                                       ip=ip,
                                       mac=mac,
                                       gw=gw_addr,
                                       gw_mac=dut_mac,
                                       prefix_len=prefix,
                                       port_type=SnappiPortType.IPInterface,
                                       peer_port=intf)

        port_config_list.append(port_config)

    return True


def __vlan_intf_config(config, port_config_list, duthost, snappi_ports):
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
    for k, v in list(vlan_facts.items()):
        vlan_member[k] = v['members']

    vlan_intf_facts = mg_facts['minigraph_vlan_interfaces']
    vlan_intf = {}
    for v in vlan_intf_facts:
        if __valid_ipv4_addr(v['addr']):
            vlan_intf[v['attachto']] = v

    dut_mac = str(duthost.facts['router_mac'])

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
            ethernet.port_name = config.ports[port_id].name
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
                                           gw_mac=dut_mac,
                                           prefix_len=prefix,
                                           port_type=SnappiPortType.VlanMember,
                                           peer_port=phy_intf)

            port_config_list.append(port_config)

    return True


def __portchannel_intf_config(config, port_config_list, duthost, snappi_ports):
    """
    Generate Snappi configuration of portchannel interfaces
    Args:
        config (obj): Snappi API config of the testbed
        port_config_list (list): list of Snappi port configuration information
        duthost (object): device under test
        snappi_ports (list): list of Snappi port information
    Returns:
        True if we successfully generate configuration or False
    """
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    if 'minigraph_portchannels' in mg_facts:
        pc_facts = mg_facts['minigraph_portchannels']
    else:
        return True

    if len(pc_facts) == 0:
        return True

    pc_member = {}
    for k, v in list(pc_facts.items()):
        pc_member[k] = v['members']

    pc_intf_facts = mg_facts['minigraph_portchannel_interfaces']
    pc_intf = {}
    for v in pc_intf_facts:
        if __valid_ipv4_addr(v['addr']):
            pc_intf[v['attachto']] = v

    dut_mac = str(duthost.facts['router_mac'])

    """ For each port channel """
    pc_id = 0
    for pc in pc_member:
        phy_intfs = pc_member[pc]
        gw_addr = str(pc_intf[pc]['addr'])
        prefix = str(pc_intf[pc]['prefixlen'])
        pc_ip_addr = str(pc_intf[pc]['peer_addr'])

        lag = config.lags.lag(name='Lag {}'.format(pc))[-1]
        lag.protocol.lacp.actor_system_id = '00:00:00:00:00:01'
        lag.protocol.lacp.actor_system_priority = 1
        lag.protocol.lacp.actor_key = 1

        for i in range(len(phy_intfs)):
            phy_intf = phy_intfs[i]

            port_ids = [id for id, snappi_port in enumerate(snappi_ports)
                        if snappi_port['peer_port'] == phy_intf]
            if len(port_ids) != 1:
                return False

            port_id = port_ids[0]
            mac = __gen_mac(port_id)

            lp = lag.ports.port(port_name=config.ports[port_id].name)[-1]
            lp.lacp.actor_port_number = 1
            lp.lacp.actor_port_priority = 1

            lp.ethernet.name = 'Ethernet Port {}'.format(port_id)
            lp.ethernet.mac = mac

            port_config = SnappiPortConfig(id=port_id,
                                           ip=pc_ip_addr,
                                           mac=mac,
                                           gw=gw_addr,
                                           gw_mac=dut_mac,
                                           prefix_len=prefix,
                                           port_type=SnappiPortType.PortChannelMember,
                                           peer_port=phy_intf)

            port_config_list.append(port_config)

        device = config.devices.device(name='Device {}'.format(pc))[-1]

        ethernet = device.ethernets.add()
        ethernet.port_name = lag.name
        ethernet.name = 'Ethernet {}'.format(pc)
        ethernet.mac = __gen_pc_mac(pc_id)

        ip_stack = ethernet.ipv4_addresses.add()
        ip_stack.name = 'Ipv4 {}'.format(pc)
        ip_stack.address = pc_ip_addr
        ip_stack.prefix = int(prefix)
        ip_stack.gateway = gw_addr

        pc_id = pc_id + 1

    return True


@pytest.fixture(scope="function")
def snappi_testbed_config(conn_graph_facts, fanout_graph_facts,     # noqa F811
                          duthosts, rand_one_dut_hostname, snappi_api):
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
def tgen_ports(duthost, conn_graph_facts, fanout_graph_facts):      # noqa F811

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


@pytest.fixture(scope='module')
def cvg_api(snappi_api_serv_ip,
            snappi_api_serv_port):
    api = snappi_convergence.api(location=snappi_api_serv_ip + ':' + str(snappi_api_serv_port), ext='ixnetwork')
    yield api
    if getattr(api, 'assistant', None) is not None:
        api.assistant.Session.remove()


def snappi_dut_base_config(duthost_list,
                           snappi_ports,
                           snappi_api):
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

    for index, duthost in enumerate(duthost_list):
        config_result = __intf_config_multidut(
                                                config=config,
                                                port_config_list=port_config_list,
                                                duthost=duthost,
                                                snappi_ports=new_snappi_ports)
        pytest_assert(config_result is True, 'Fail to configure Vlan interfaces')

    return config, port_config_list, new_snappi_ports


@pytest.fixture(scope="function")
def get_multidut_snappi_ports(duthosts, conn_graph_facts, fanout_graph_facts):            # noqa: F811
    """
    Populate tgen ports and connected DUT ports info of T0 testbed and returns as a list
    Args:
        duthost (pytest fixture): duthost fixture
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
    Return:
        return tuple of duts and tgen ports
    """
    def _get_multidut_snappi_ports(line_card_choice, line_card_info):
        host_names = line_card_info['hostname']
        asic_info = line_card_info['asic']
        asic_port_map = {
            "asic0": ['Ethernet%d' % i for i in range(0, 72, 4)],
            "asic1": ['Ethernet%d' % i for i in range(72, 144, 4)],
            None: ['Ethernet%d' % i for i in range(0, 144, 4)],
        }
        ports = []
        for index, host in enumerate(duthosts):
            snappi_fanout_list = SnappiFanoutManager(fanout_graph_facts)
            for i in range(len(snappi_fanout_list.fanout_list)):
                try:
                    snappi_fanout_list.get_fanout_device_details(i)
                except Exception:
                    pass
            snappi_ports = snappi_fanout_list.get_ports(peer_device=host.hostname)
            for port in snappi_ports:
                port['location'] = get_snappi_port_location(port)
                for hostname in host_names:
                    for asic in asic_info:
                        if port["peer_port"] in asic_port_map[asic] and hostname in port['peer_device']:
                            port['asic_value'] = asic
                            port['asic_type'] = host.facts["asic_type"]
                            port['duthost'] = host
                            ports.append(port)
        return ports
    return _get_multidut_snappi_ports


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

    dut_mac = str(duthost.facts['router_mac'])

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
            ethernet.port_name = config.ports[port_id].name
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
                                           gw_mac=dut_mac,
                                           prefix_len=prefix,
                                           port_type=SnappiPortType.VlanMember,
                                           peer_port=phy_intf)

            port_config_list.append(port_config)

    return True


def __intf_config_multidut(config, port_config_list, duthost, snappi_ports):
    """
    Configures interfaces of the DUT
    Args:
        config (obj): Snappi API config of the testbed
        port_config_list (list): list of Snappi port configuration information
        duthost (object): device under test
        snappi_ports (list): list of Snappi port information
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
        if port['asic_value'] is None:
            duthost.command('sudo config interface ip add {} {}/{} \n' .format(
                                                                                port['peer_port'],
                                                                                dutIp,
                                                                                prefix_length))
        else:
            duthost.command('sudo config interface -n {} ip add {} {}/{} \n' .format(
                                                                                    port['asic_value'],
                                                                                    port['peer_port'],
                                                                                    dutIp,
                                                                                    prefix_length))
        device = config.devices.device(name='Device Port {}'.format(port_id))[-1]
        ethernet = device.ethernets.add()
        ethernet.name = 'Ethernet Port {}'.format(port_id)
        ethernet.port_name = config.ports[port_id].name
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


def get_multidut_tgen_peer_port_set(line_card_choice, ports, config_set, number_of_tgen_peer_ports=2):
    """
    Configures interfaces of the DUT
    Args:
        line_card_choice (obj): Line card type defined by the variable file
        ports (list): list of Snappi port configuration information
        config_set: Comprises of linecard configuration type and asic values
        number_of_tgen_peer_ports: number of ports needed for the test
    Returns:
        The ports for the respective line card choice from the testbed file
    """
    linecards = {}
    try:
        from itertools import product
        from itertools import izip_longest as zip_longest
    except ImportError:
        from itertools import zip_longest

    for port in ports:
        if port['peer_device'] in linecards:
            if port['asic_value'] not in linecards[port['peer_device']]:
                linecards[port['peer_device']][port['asic_value']] = []
        else:
            linecards[port['peer_device']] = {}
            linecards[port['peer_device']][port['asic_value']] = []
        linecards[port['peer_device']][port['asic_value']].append(port)

    if len(ports) < number_of_tgen_peer_ports or not linecards:
        raise Exception("Not Enough ports ")
    peer_ports = []
    if line_card_choice in ['chassis_single_line_card_single_asic', 'non_chassis_single_line_card']:
        # same asic ports required
        for line_card, asics in linecards.items():
            for asic, asic_info in asics.items():
                if config_set[line_card_choice]['asic'][0] == asic:
                    if len(asic_info) >= number_of_tgen_peer_ports:
                        peer_ports = list(random.sample(asic_info, number_of_tgen_peer_ports))
                        return peer_ports
                    else:
                        raise Exception(
                            'Error: Not enough ports for line card "%s" and asic "%s"' % (line_card_choice, asic))
    elif line_card_choice in ['chassis_single_line_card_multi_asic']:
        # need 2 asic  minimum one port from each asic
        for line_card, asics in linecards.items():
            if len(asics.keys()) >= 2:
                peer_ports = list(zip_longest(*asics.values()))
                peer_ports = [item for sublist in peer_ports for item in sublist]
                peer_ports = list(filter(None, peer_ports))
                return peer_ports[:number_of_tgen_peer_ports]
            else:
                raise Exception('Error: Invalid line_card_choice or Not enough ports')

    elif line_card_choice in ['chassis_multi_line_card_single_asic', 'non_chassis_multi_line_card']:
        # DIfferent line card and minimum one port from same same asic number
        if len(linecards.keys()) >= 2:
            common_asic_across_line_cards = set(linecards[next(iter(linecards))].keys())
            for d in linecards.values():
                common_asic_across_line_cards.intersection_update(set(d.keys()))
            for asic in common_asic_across_line_cards:
                peer_ports = [linecards[line_card][asic] for line_card in linecards.keys()]
                peer_ports = list(zip(*peer_ports))
                peer_ports = [item for sublist in peer_ports for item in sublist]
                return peer_ports[:number_of_tgen_peer_ports]
        else:
            raise Exception('Error: Not enough line_card_choice')

    elif line_card_choice in ['chassis_multi_line_card_multi_asic']:
        # Different line card and minimum one port from different asic number
        if len(linecards.keys()) >= 2:
            host_asic = list(product(config_set[line_card_choice]['hostname'], config_set[line_card_choice]['asic']))
            peer_ports = list(zip_longest(*[linecards[host][asic]
                              for host, asic in host_asic if asic in linecards[host]]))
            peer_ports = [item for sublist in peer_ports for item in sublist]
            peer_ports = list(filter(None, peer_ports))
            return peer_ports[:number_of_tgen_peer_ports]
        else:
            raise Exception('Error: Not enough line_card_choice')


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
    for index, duthost in enumerate(duthost_list):
        port_count = len(snappi_ports)
        dutIps = create_ip_list(dut_ip_start, port_count, mask=prefix_length)
        for port in snappi_ports:
            if port['peer_device'] == duthost.hostname:
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
        try:
            logger.info('Pre-Configuring Dut: {} with port {} with IP {}/{}'.format(
                                                                                duthost.hostname,
                                                                                port['peer_port'],
                                                                                dutIps[port_id],
                                                                                prefix_length))
            duthost.command('sudo config interface ip add {} {}/{} \n' .format(
                                                                                port['peer_port'],
                                                                                dutIps[port_id],
                                                                                prefix_length))
            logger.info('Pre-Configuring Dut: {} with port {} with IPv6 {}/{}'.format(
                                                                                duthost.hostname,
                                                                                port['peer_port'],
                                                                                dutv6Ips[port_id],
                                                                                v6_prefix_length))
            duthost.command('sudo config interface ip add {} {}/{} \n' .format(
                                                                                port['peer_port'],
                                                                                dutv6Ips[port_id],
                                                                                v6_prefix_length))
        except Exception:
            pytest_assert(False, "Unable to configure ip on the interface {}".format(port['peer_port']))
    return snappi_ports_dut
