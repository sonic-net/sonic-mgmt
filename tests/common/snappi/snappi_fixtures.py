"""
This module contains the snappi fixture
"""
import pytest
import logging
import snappi
import snappi_convergence
from ipaddress import ip_address, IPv4Address, IPv6Address
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts
from tests.common.snappi.common_helpers import get_addrs_in_subnet,get_peer_snappi_chassis, get_ipv6_addrs_in_subnet, get_asic_count
from tests.common.snappi.snappi_helpers import SnappiFanoutManager, get_snappi_port_location
from tests.common.snappi.port import SnappiPortConfig, SnappiPortType
from tests.common.helpers.assertions import pytest_assert
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
            _hostvars[duthost.hostname]['secret_group_vars']
            ['snappi_api_server']['rest_port'])


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
    return '11:22:33:44:55:{:02d}'.format(id)

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

def create_ip_list(value, count, mask=32, incr=0):
    '''
        Create a list of ips based on the count provided
        Parameters:
            value: start value of the list
            count: number of ips required
            mask: subnet mask for the ips to be created
            incr: increment value of the ip
    '''
    ip_list = [value]
    for i in range(1, count):
        if ip_address(unicode(value)).version == 4:
            incr1 = pow(2, (32 - int(mask))) + incr
            value = (IPv4Address(unicode(value)) + incr1).compressed
        elif ip_address(unicode(value)).version == 6:
            if mask == 32:
                mask = 64
            incr1 = pow(2, (128 - int(mask))) + incr
            value = (IPv6Address(unicode(value)) + incr1).compressed
        ip_list.append(value)

    return ip_list

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

    for k, v in l3_intf.items():
        intf = str(k)
        gw_addr = str(v['addr'])
        prefix = str(v['prefixlen'])
        ip = str(v['peer_addr'])

        port_ids = [id for id, snappi_port in enumerate(snappi_ports) \
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

            port_ids = [id for id, snappi_port in enumerate(snappi_ports) \
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

            port_ids = [id for id, snappi_port in enumerate(snappi_ports) \
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
    for k, v in pc_facts.items():
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
        for i in range(len(phy_intfs)):
            phy_intf = phy_intfs[i]

            port_ids = [id for id, snappi_port in enumerate(snappi_ports) \
                        if snappi_port['peer_port'] == phy_intf]
            if len(port_ids) != 1:
                return False

            port_id = port_ids[0]
            mac = __gen_mac(port_id)

            lp = lag.ports.port(port_name=config.ports[port_id].name)[-1]
            lp.protocol.lacp.actor_system_id = '00:00:00:00:00:01'
            lp.protocol.lacp.actor_system_priority = 1
            lp.protocol.lacp.actor_port_priority = 1
            lp.protocol.lacp.actor_port_number = 1
            lp.protocol.lacp.actor_key = 1

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
def snappi_testbed_config(conn_graph_facts,
                          fanout_graph_facts,
                          duthosts,
                          rand_one_dut_hostname,
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
    pfc.pfc_class_0 = 0
    pfc.pfc_class_1 = 1
    pfc.pfc_class_2 = 2
    pfc.pfc_class_3 = 3
    pfc.pfc_class_4 = 4
    pfc.pfc_class_5 = 5
    pfc.pfc_class_6 = 6
    pfc.pfc_class_7 = 7

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
def tgen_ports(duthost,
               conn_graph_facts,
               fanout_graph_facts):

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
    snappi_fanout_list.get_fanout_device_details(device_number = snappi_fanout_id)
    snappi_ports = snappi_fanout_list.get_ports(peer_device = duthost.hostname)
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
    #try:
    for port in snappi_ports:
        peer_port = port['peer_port']
        int_addrs = config_facts['INTERFACE'][peer_port].keys()
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
    #except:
    #    raise Exception('Configure IPv4 and IPv6 on DUT interfaces')

    return snappi_ports


@pytest.fixture(scope='module')
def cvg_api(snappi_api_serv_ip,
            snappi_api_serv_port):
    api = snappi_convergence.api(location=snappi_api_serv_ip + ':' + str(snappi_api_serv_port),ext='ixnetwork')
    yield api
    if getattr(api, 'assistant', None) is not None:
        api.assistant.Session.remove()

def snappi_dut_base_config(duthost_list,
                           tgen_ports,
                           snappi_ports,
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

    """ Generate L1 config """


    port_speed = None

    new_snappi_ports = []
    """ L1 config """
    config = snappi_api.config()
    j=0
    for i in range(len(snappi_ports)):
        if snappi_ports[i]['location'] in tgen_ports:
            config.ports.port(name='Port {}'.format(i),
                          location=snappi_ports[i]['location'])
            snappi_ports[i]['port_id'] = j

            new_snappi_ports.append(snappi_ports[i])
            if port_speed is None:
                port_speed = int(snappi_ports[i]['speed'])

            pytest_assert(port_speed == int(snappi_ports[i]['speed']),
                      'Ports have different link speeds')
            j +=1

    speed_gbps = int(port_speed/1000)

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
    pfc.pfc_class_0 = 0
    pfc.pfc_class_1 = 1
    pfc.pfc_class_2 = 2
    pfc.pfc_class_3 = 3
    pfc.pfc_class_4 = 4
    pfc.pfc_class_5 = 5
    pfc.pfc_class_6 = 6
    pfc.pfc_class_7 = 7

    port_config_list = []

    for index,duthost in enumerate(duthost_list):
        config_result = __intf_config_multidut(config=config,
                                       port_config_list=port_config_list,
                                       duthost=duthost,
                                       snappi_port=new_snappi_ports[index],
                                       snappi_ports=new_snappi_ports)
        pytest_assert(config_result is True, 'Fail to configure Vlan interfaces')

    return config, port_config_list, new_snappi_ports

def cleanup_config(duthost_list,snappi_ports):
    for index,duthost in enumerate(duthost_list):
        port_count=len(snappi_ports)
        prefix=24
        dutIps = create_ip_list("20.0.1.1", port_count, mask=prefix)
        tgenIps = create_ip_list("20.0.1.2", port_count, mask=prefix)
        for port in snappi_ports:
            if port['peer_device']==duthost.hostname:
                port_id=port['port_id']
                dutIp = dutIps[port_id]
                tgenIp = tgenIps[port_id]
                logger.info('Removing Configuration on Dut: {} with port {} with ip :{}/{}'.format(duthost.hostname,port['peer_port'],dutIp,prefix))
                if port['asic_value'] == 'None':
                    duthost.command('sudo config interface ip remove {} {}/{} \n' .format(port['peer_port'],dutIp,prefix))
                else:
                    duthost.command('sudo config interface -n {} ip remove {} {}/{} \n' .format(port['asic_value'],port['peer_port'],dutIp,prefix))

@pytest.fixture(scope="function")
def get_multidut_snappi_ports(duthosts,
                               conn_graph_facts,
                               fanout_graph_facts,):

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
            "asic0": [
                "Ethernet0",  
                "Ethernet4",  
                "Ethernet8",  
                "Ethernet12", 
                "Ethernet16", 
                "Ethernet20", 
                "Ethernet24", 
                "Ethernet28", 
                "Ethernet32", 
                "Ethernet36", 
                "Ethernet40", 
                "Ethernet44", 
                "Ethernet48", 
                "Ethernet52", 
                "Ethernet56", 
                "Ethernet60", 
                "Ethernet64", 
                "Ethernet68",
            ],
            "asic1": [
                "Ethernet72", 
                "Ethernet76", 
                "Ethernet80", 
                "Ethernet84", 
                "Ethernet88", 
                "Ethernet92", 
                "Ethernet96", 
                "Ethernet100",
                "Ethernet104",
                "Ethernet108",
                "Ethernet112",
                "Ethernet116",
                "Ethernet120",
                "Ethernet124",
                "Ethernet128",
                "Ethernet132",
                "Ethernet136",
                "Ethernet140",
            ],
            "None": [
                "Ethernet0",  
                "Ethernet4",  
                "Ethernet8",  
                "Ethernet12", 
                "Ethernet16", 
                "Ethernet20", 
                "Ethernet24", 
                "Ethernet28", 
                "Ethernet32", 
                "Ethernet36", 
                "Ethernet40", 
                "Ethernet44", 
                "Ethernet48", 
                "Ethernet52", 
                "Ethernet56", 
                "Ethernet60", 
                "Ethernet64", 
                "Ethernet68",
                "Ethernet72", 
                "Ethernet76", 
                "Ethernet80", 
                "Ethernet84", 
                "Ethernet88", 
                "Ethernet92", 
                "Ethernet96", 
                "Ethernet100",
                "Ethernet104",
                "Ethernet108",
                "Ethernet112",
                "Ethernet116",
                "Ethernet120",
                "Ethernet124",
                "Ethernet128",
                "Ethernet132",
                "Ethernet136",
                "Ethernet140",
            ]
        }
        ports=[]
        for index,host in enumerate(duthosts):
            snappi_fanout = get_peer_snappi_chassis(conn_data=conn_graph_facts,
                                                dut_hostname=host.hostname)
            snappi_fanout_list = SnappiFanoutManager(fanout_graph_facts)
            for i in range(0,3):
                try :
                    snappi_fanout_list.get_fanout_device_details(i)
                except:
                    pass
            snappi_ports = snappi_fanout_list.get_ports(peer_device = host.hostname)
            for port in snappi_ports:
                port['location'] = get_snappi_port_location(port)
                for hostname in host_names:
                    for asic in asic_info:
                        if port["peer_port"] in asic_port_map[asic] and hostname in port['peer_device']:
                            port['asic_value'] = asic
                            ports.append(port)         
        return ports
    return _get_multidut_snappi_ports

def get_tgen_peer_ports(snappi_ports, hostname):
    ports = []
    for port in snappi_ports:
        if port['peer_device'] == hostname:
            ports.append((port['location'], port['peer_port']))
    return ports

def __vlan_intf_config_multidut(config, port_config_list, duthost, snappi_ports):
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
    hostname = duthost.hostname
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

            port_ids = [snappi_port["port_id"] for snappi_port in snappi_ports \
                        if (snappi_port['peer_port'] == phy_intf and snappi_port['peer_device'] == hostname)]

            if len(port_ids) != 1:
                continue

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


def __intf_config_multidut(config, port_config_list, duthost, snappi_port, snappi_ports):
    dut_mac = str(duthost.facts['router_mac'])
    prefix=24
    count=0
    temp=[]
    port_count=len(snappi_ports)
    dutIps = create_ip_list("20.0.1.1", port_count, mask=prefix)
    tgenIps = create_ip_list("20.0.1.2", port_count, mask=prefix)
    for port in snappi_ports:
        if port['peer_device']==duthost.hostname:
            port_id=port['port_id']
            dutIp = dutIps[port_id]
            tgenIp = tgenIps[port_id]
            mac = __gen_mac(port_id)
            logger.info('Configuring Dut: {} with port {} with IP {}/{}'.format(duthost.hostname,port['peer_port'],dutIp,prefix))
            if port['asic_value'] == 'None':
                duthost.command('sudo config interface ip add {} {}/{} \n' .format(port['peer_port'],dutIp,prefix))
            else:
                duthost.command('sudo config interface -n {} ip add {} {}/{} \n' .format(port['asic_value'],port['peer_port'],dutIp,prefix))
            device = config.devices.device(
                name='Device Port {}'.format(port_id))[-1]

            ethernet = device.ethernets.add()
            ethernet.name = 'Ethernet Port {}'.format(port_id)
            ethernet.port_name = config.ports[port_id].name
            ethernet.mac = mac

            ip_stack = ethernet.ipv4_addresses.add()
            ip_stack.name = 'Ipv4 Port {}'.format(port_id)
            ip_stack.address = tgenIp
            ip_stack.prefix = int(prefix)
            ip_stack.gateway = dutIp
            port_config = SnappiPortConfig(id=port_id,
                                            ip=tgenIp,
                                            mac=mac,
                                            gw=dutIp,
                                            gw_mac=dut_mac,
                                            prefix_len=prefix,
                                            port_type=SnappiPortType.IPInterface,
                                            peer_port=port['peer_port'])

            port_config_list.append(port_config)
        else:
            pass


    return True

def __portchannel_intf_config_multidut(config, port_config_list, duthost, snappi_ports):
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
    hostname = duthost.hostname
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    if 'minigraph_portchannels' in mg_facts:
        pc_facts = mg_facts['minigraph_portchannels']
    else:
        return True

    if len(pc_facts) == 0:
        return True

    pc_member = {}
    for k, v in pc_facts.items():
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
        for i in range(len(phy_intfs)):
            phy_intf = phy_intfs[i]

            # port_ids = [id for id, snappi_port in enumerate(snappi_ports) \
            #             if snappi_port['peer_port'] == phy_intf]
            port_ids = [snappi_port["port_id"] for snappi_port in snappi_ports \
                        if (snappi_port['peer_port'] == phy_intf and snappi_port['peer_device'] == hostname)]
            if len(port_ids) != 1:
                continue

            port_id = port_ids[0]
            mac = __gen_mac(port_id)

            lp = lag.ports.port(port_name=config.ports[port_id].name)[-1]
            lp.protocol.lacp.actor_system_id = '00:00:00:00:00:01'
            lp.protocol.lacp.actor_system_priority = 1
            lp.protocol.lacp.actor_port_priority = 1
            lp.protocol.lacp.actor_port_number = 1
            lp.protocol.lacp.actor_key = 1

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
    hostname = duthost.hostname
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
    for k, v in l3_intf.items():

        intf = str(k)
        gw_addr = str(v['addr'])
        prefix = str(v['prefixlen'])
        ip = str(v['peer_addr'])

        port_ids = [id for id, snappi_port in enumerate(snappi_ports) \
                    if snappi_port['peer_port'] == intf]
        if len(port_ids) != 1:
            continue

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

def get_dut_interconnected_ports(conn_graph_facts, src_host, dst_host):
    ports = []
    for key, value in conn_graph_facts['device_conn'][src_host].items():
        if value['peerdevice'] == dst_host:
            ports.append((key, value['peerport']))
    return ports

def get_multidut_tgen_peer_port_set(line_card_choice,ports,config_set):
    asic1_ports, asic2_ports=[],[]
    try:
        if line_card_choice == 'chassis_single_line_card_single_asic' or line_card_choice =='non_chassis_single_line_card':
            port1=random.sample(ports,1)[0]
            for port in ports:
                if port!=port1:
                    port2 = port
                    port_set1 = (port1['location'],port1['peer_port'])
                    port_set2 = (port2['location'],port2['peer_port'])
                else:
                    continue
        elif line_card_choice == 'chassis_single_line_card_multi_asic':
            for port in ports:
                if port['asic_value'] == config_set[line_card_choice]['asic'][0]:
                    asic1_ports.append(port)
                elif port['asic_value'] == config_set[line_card_choice]['asic'][1]:
                    asic2_ports.append(port)
            port1=random.sample(asic1_ports,1)[0]
            port2=random.sample(asic2_ports,1)[0]
            port_set1 = (port1['location'],port1['peer_port'])
            port_set2 = (port2['location'],port2['peer_port'])
        elif line_card_choice == 'chassis_multi_line_card_single_asic' or line_card_choice =='non_chassis_multi_line_card':
            for port in ports:
                if port['peer_device'] == config_set[line_card_choice]['hostname'][0]:
                    asic1_ports.append(port)
                elif port['peer_device'] == config_set[line_card_choice]['hostname'][1]:
                    asic2_ports.append(port)
            port1=random.sample(asic1_ports,1)[0]
            port2=random.sample(asic2_ports,1)[0]
            port_set1 = (port1['location'],port1['peer_port'])
            port_set2 = (port2['location'],port2['peer_port'])
        elif line_card_choice == 'chassis_multi_line_card_multi_asic':
            for port in ports:
                if port['asic_value'] == config_set[line_card_choice]['asic'][0] and port['peer_device'] == config_set[line_card_choice]['hostname'][0]:
                    asic1_ports.append(port)
                elif port['asic_value'] == config_set[line_card_choice]['asic'][1] and port['peer_device'] == config_set[line_card_choice]['hostname'][1]:
                    asic2_ports.append(port)
            port1=random.sample(asic1_ports,1)[0]
            port2=random.sample(asic2_ports,1)[0]
            port_set1 = (port1['location'],port1['peer_port'])
            port_set2 = (port2['location'],port2['peer_port'])
        else:
            pass
        return [(port_set1,port_set2),[port1,port2]]
    except Exception as e:
        raise Exception(e,'Error: Invalid line_card_choice or Not enough ports')

def get_multidut_3_tgen_peer_port_set(line_card_choice,ports,config_set):
    asic1_ports, asic2_ports=[],[]
    try:
        if line_card_choice == 'chassis_single_line_card_single_asic' or line_card_choice =='non_chassis_single_line_card':
            port1=ports[0]
            port2=ports[1]
            port3=ports[2]
            port_set1 = (port1['location'],port1['peer_port'])
            port_set2 = (port2['location'],port2['peer_port'])
            port_set3 = (port3['location'],port3['peer_port'])
        elif line_card_choice == 'chassis_single_line_card_multi_asic':
            for port in ports:
                if port['asic_value'] == config_set[line_card_choice]['asic'][0]:
                    asic1_ports.append(port)
                elif port['asic_value'] == config_set[line_card_choice]['asic'][1]:
                    asic2_ports.append(port)
            port1=random.sample(asic1_ports,1)[0]
            port2=random.sample(asic2_ports,1)[0]
            for port in asic2_ports:
                if port!=port2:
                    port3 = port
                else:
                    continue
            port_set1 = (port1['location'],port1['peer_port'])
            port_set2 = (port2['location'],port2['peer_port'])
            port_set3 = (port3['location'],port3['peer_port'])
        elif line_card_choice == 'chassis_multi_line_card_single_asic' or line_card_choice =='non_chassis_multi_line_card':
            for port in ports:
                if port['peer_device'] == config_set[line_card_choice]['hostname'][0]:
                    asic1_ports.append(port)
                elif port['peer_device'] == config_set[line_card_choice]['hostname'][1]:
                    asic2_ports.append(port)
            port1=random.sample(asic1_ports,1)[0]
            port2=random.sample(asic2_ports,1)[0]
            for port in asic2_ports:
                if port!=port2:
                    port3 = port
                else:
                    continue
            port_set1 = (port1['location'],port1['peer_port'])
            port_set2 = (port2['location'],port2['peer_port'])
            port_set3 = (port3['location'],port3['peer_port'])
        elif line_card_choice == 'chassis_multi_line_card_multi_asic':
            for port in ports:
                if port['asic_value'] == config_set[line_card_choice]['asic'][0] and port['peer_device'] == config_set[line_card_choice]['hostname'][0]:
                    asic1_ports.append(port)
                elif port['asic_value'] == config_set[line_card_choice]['asic'][1] and port['peer_device'] == config_set[line_card_choice]['hostname'][1]:
                    asic2_ports.append(port)
            port1=random.sample(asic1_ports,1)[0]
            port2=random.sample(asic2_ports,1)[0]
            for port in asic2_ports:
                if port!=port2:
                    port3 = port
                else:
                    continue
            port_set1 = (port1['location'],port1['peer_port'])
            port_set2 = (port2['location'],port2['peer_port'])
            port_set3 = (port3['location'],port3['peer_port'])
        else:
            pass
        return [(port_set1,port_set2,port_set3),[port1,port2,port3]]
    except Exception as e:
        raise Exception(e,'Error: Invalid line_card_choice or Not enough ports')
