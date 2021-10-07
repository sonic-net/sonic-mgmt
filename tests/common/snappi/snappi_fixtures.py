"""
This module contains the snappi fixture
"""
import pytest
import snappi
from ipaddress import ip_address, IPv4Address
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts
from tests.common.snappi.common_helpers import get_addrs_in_subnet,\
    get_peer_snappi_chassis
from tests.common.snappi.snappi_helpers import SnappiFanoutManager, get_snappi_port_location
from tests.common.snappi.port import SnappiPortConfig, SnappiPortType
from tests.common.helpers.assertions import pytest_assert


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
            name='Device Port {}'.format(port_id),
            container_name=config.ports[port_id].name)[-1]

        ethernet = device.ethernet
        ethernet.name = 'Ethernet Port {}'.format(port_id)
        ethernet.mac = mac

        ip_stack = ethernet.ipv4
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
                name='Device Port {}'.format(port_id),
                container_name=config.ports[port_id].name)[-1]

            ethernet = device.ethernet
            ethernet.name = 'Ethernet Port {}'.format(port_id)
            ethernet.mac = mac

            ip_stack = ethernet.ipv4
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

        device = config.devices.device(name='Device {}'.format(pc),
                                       container_name=lag.name)[-1]

        ethernet = device.ethernet
        ethernet.name = 'Ethernet {}'.format(pc)
        ethernet.mac = __gen_pc_mac(pc_id)

        ip_stack = device.ethernet.ipv4
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