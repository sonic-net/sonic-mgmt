"""
This module contains the necessary fixtures for running test cases with
Ixia devices and IxNetwork. If more fixtures are required, they should be
included in this file.
"""

import pytest
from ipaddress import ip_address, IPv4Address
from ixnetwork_restpy import SessionAssistant
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts
from tests.common.ixia.common_helpers import get_vlan_subnet, get_addrs_in_subnet,\
    get_peer_ixia_chassis
from tests.common.ixia.ixia_helpers import IxiaFanoutManager, get_tgen_location
from tests.common.ixia.port import IxiaPortConfig, IxiaPortType
from tests.common.helpers.assertions import pytest_assert

try:
    from abstract_open_traffic_generator.port import Port
    from abstract_open_traffic_generator.config import Options, Config
    from abstract_open_traffic_generator.layer1 import Layer1, FlowControl,\
        Ieee8021qbb, AutoNegotiation
    from abstract_open_traffic_generator.device import Device, Ethernet, Ipv4,\
        Pattern
    from ixnetwork_open_traffic_generator.ixnetworkapi import IxNetworkApi
    from abstract_open_traffic_generator.port import Options as PortOptions
    import abstract_open_traffic_generator.lag as lag

except ImportError as e:
    raise pytest.skip.Exception("Test case is skipped: " + repr(e), allow_module_level=True)

@pytest.fixture(scope = "module")
def ixia_api_serv_ip(tbinfo):
    """
    In an Ixia testbed, there is no PTF docker.
    Hence, we use ptf_ip field to store Ixia API server.
    This fixture returns the IP address of the Ixia API server.

    Args:
       tbinfo (pytest fixture): fixture provides information about testbed

    Returns:
        Ixia API server IP
    """
    return tbinfo['ptf_ip']


@pytest.fixture(scope = "module")
def ixia_api_serv_user(duthosts, rand_one_dut_hostname):
    """
    Return the username of Ixia API server.

    Args:
        duthost (pytest fixture): The duthost fixture.

    Returns:
        Ixia API server username.
    """
    duthost = duthosts[rand_one_dut_hostname]
    return duthost.host.options['variable_manager']._hostvars[duthost.hostname]['ixia_api_server']['user']


@pytest.fixture(scope = "module")
def ixia_api_serv_passwd(duthosts, rand_one_dut_hostname):
    """
    Return the password of Ixia API server.

    Args:
        duthost (pytest fixture): The duthost fixture.

    Returns:
        Ixia API server password.
    """
    duthost = duthosts[rand_one_dut_hostname]
    return duthost.host.options['variable_manager']._hostvars[duthost.hostname]['ixia_api_server']['password']


@pytest.fixture(scope = "module")
def ixia_api_serv_port(duthosts, rand_one_dut_hostname):
    """
    This fixture returns the TCP port for REST API of the ixia API server.

    Args:
        duthost (pytest fixture): The duthost fixture.

    Returns:
        Ixia API server REST port.
    """
    duthost = duthosts[rand_one_dut_hostname]
    return duthost.host.options['variable_manager']._hostvars[duthost.hostname]['ixia_api_server']['rest_port']


@pytest.fixture(scope = "module")
def ixia_api_serv_session_id(duthosts, rand_one_dut_hostname):
    """
    Ixia API server can spawn multiple session on the same REST port.
    Optional for LINUX, required for windows return the session ID.

    Args:
        duthost (pytest fixture): The duthost fixture.

    Returns:
        Ixia API server session id.
    """
    duthost = duthosts[rand_one_dut_hostname]
    return duthost.host.options['variable_manager']._hostvars[duthost.hostname]['ixia_api_server']['session_id']


@pytest.fixture(scope = "module")
def ixia_dev(duthosts, rand_one_dut_hostname, fanouthosts):
    """
    Returns the Ixia chassis IP. This fixture can return multiple IPs if
    multiple Ixia chassis are present in the test topology.

    Args:
        duthost (pytest fixture): The duthost fixture.
        fanouthosts (pytest fixture): The fanouthosts fixture.

    Returns:
        Dictionary of Ixia Chassis IP/IPs.
    """
    duthost = duthosts[rand_one_dut_hostname]
    result = dict()
    ixia_dev_hostnames = fanouthosts.keys()
    for hostname in ixia_dev_hostnames:
        result[hostname] = duthost.host.options['inventory_manager'].get_host(hostname).get_vars()['ansible_host']
    return result


@pytest.fixture(scope = "function")
def ixia_api_server_session(
        ixia_api_serv_ip,
        ixia_api_serv_user,
        ixia_api_serv_passwd,
        ixia_api_serv_port,
        ixia_api_serv_session_id) :
    """
    Ixia session manager fixture.

    Args:
        ixia_api_serv_ip (pytest fixture): ixia_api_serv_ip fixture
        ixia_api_serv_user (pytest fixture): ixia_api_serv_user fixture.
        ixia_api_serv_passwd (pytest fixture): ixia_api_serv_passwd fixture.
        ixia_api_serv_port (pytest fixture): ixia_api_serv_port fixture.
        ixia_api_serv_session_id (pytest fixture): ixia_api_serv_session_id
            fixture.

    Returns:
        IxNetwork Session
    """

    if (ixia_api_serv_session_id.lower() != 'none') :
        session = SessionAssistant(IpAddress=ixia_api_serv_ip,
                                   UserName=ixia_api_serv_user,
                                   Password=ixia_api_serv_passwd,
                                   RestPort=ixia_api_serv_port,
                                   SessionId=ixia_api_serv_session_id)
    else :
        session = SessionAssistant(IpAddress=ixia_api_serv_ip,
                                   UserName=ixia_api_serv_user,
                                   Password=ixia_api_serv_passwd,
                                   RestPort=ixia_api_serv_port)
    ixNetwork = session.Ixnetwork
    ixNetwork.NewConfig()

    yield session

    ixNetwork.NewConfig()
    session.Session.remove()

@pytest.fixture(scope = "module")
def ixia_api(ixia_api_serv_ip,
             ixia_api_serv_port,
             ixia_api_serv_user,
             ixia_api_serv_passwd):

    """
    Ixia session fixture for Tgen API

    Args:
        ixia_api_serv_ip (pytest fixture): ixia_api_serv_ip fixture
        ixia_api_serv_port (pytest fixture): ixia_api_serv_port fixture.
        ixia_api_serv_user (pytest fixture): ixia_api_serv_user fixture.
        ixia_api_serv_passwd (pytest fixture): ixia_api_serv_passwd fixture.

    Returns:
        IxNetwork Session

    """
    api_session = IxNetworkApi(address=ixia_api_serv_ip,
                               port=ixia_api_serv_port,
                               username=ixia_api_serv_user,
                               password=ixia_api_serv_passwd)

    yield api_session

    if api_session and api_session.assistant and api_session.assistant.Session:
        api_session.assistant.Session.remove()

@pytest.fixture(scope = "function")
def ixia_testbed(conn_graph_facts,
                 fanout_graph_facts,
                 duthosts,
                 rand_one_dut_hostname):

    """
    L2/L3 Tgen API config for the T0 testbed

    Args:
        conn_graph_facts (pytest fixture)
        fanout_graph_facts (pytest fixture)
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (pytest fixture): DUT hostname

    Returns:
        L2/L3 config for the T0 testbed
    """
    duthost = duthosts[rand_one_dut_hostname]
    ixia_fanout = get_peer_ixia_chassis(conn_data=conn_graph_facts,
                                        dut_hostname=duthost.hostname)

    if ixia_fanout is None:
        return None

    ixia_fanout_id = list(fanout_graph_facts.keys()).index(ixia_fanout)
    ixia_fanout_list = IxiaFanoutManager(fanout_graph_facts)
    ixia_fanout_list.get_fanout_device_details(device_number=ixia_fanout_id)

    ixia_ports = ixia_fanout_list.get_ports(peer_device=duthost.hostname)

    ports = list()
    port_names = list()
    port_speed = None

    """ L1 config """
    for i in range(len(ixia_ports)):
        port = Port(name='Port {}'.format(i),
                    location=get_tgen_location(ixia_ports[i]))

        ports.append(port)
        port_names.append(port.name)

        if port_speed is None:
            port_speed = int(ixia_ports[i]['speed'])

        elif port_speed != int(ixia_ports[i]['speed']):
            """ All the ports should have the same bandwidth """
            return None

    pfc = Ieee8021qbb(pfc_delay=0,
                      pfc_class_0=0,
                      pfc_class_1=1,
                      pfc_class_2=2,
                      pfc_class_3=3,
                      pfc_class_4=4,
                      pfc_class_5=5,
                      pfc_class_6=6,
                      pfc_class_7=7)

    flow_ctl = FlowControl(choice=pfc)

    auto_negotiation = AutoNegotiation(link_training=True,
                                       rs_fec=True)

    l1_config = Layer1(name='L1 config',
                       speed='speed_%d_gbps' % int(port_speed/1000),
                       auto_negotiate=False,
                       auto_negotiation=auto_negotiation,
                       ieee_media_defaults=False,
                       flow_control=flow_ctl,
                       port_names=port_names)

    config = Config(ports=ports,
                    layer1=[l1_config],
                    options=Options(PortOptions(location_preemption=True)))

    """ L2/L3 config """
    vlan_subnet = get_vlan_subnet(duthost)
    if vlan_subnet is None:
        return None

    vlan_ip_addrs = get_addrs_in_subnet(vlan_subnet, len(ixia_ports))
    gw_addr = vlan_subnet.split('/')[0]
    prefix = vlan_subnet.split('/')[1]

    for i in range(len(ixia_ports)):
        ip_stack = Ipv4(name='Ipv4 {}'.format(i),
                        address=Pattern(vlan_ip_addrs[i]),
                        prefix=Pattern(prefix),
                        gateway=Pattern(gw_addr),
                        ethernet=Ethernet(name='Ethernet {}'.format(i)))

        device = Device(name='Device {}'.format(i),
                        device_count=1,
                        container_name=port_names[i],
                        choice=ip_stack)

        config.devices.append(device)

    return config

def __gen_mac(id):
    """
    Generate a MAC address

    Args:
        id (int): IXIA port ID

    Returns:
        MAC address (string)
    """
    return '00:11:22:33:44:{:02d}'.format(id)

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

def __l3_intf_config(config, port_config_list, duthost, ixia_ports):
    """
    Generate Tgen configuration of layer 3 interfaces

    Args:
        config (obj): Tgen API config of the testbed
        port_config_list (list): list of IXIA port configuration information
        duthost (object): device under test
        ixia_ports (list): list of IXIA port information

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

        port_ids = [id for id, ixia_pot in enumerate(ixia_ports) \
                    if ixia_pot['peer_port'] == intf]
        if len(port_ids) != 1:
            return False

        port_id = port_ids[0]
        mac = __gen_mac(port_id)
        ethernet = Ethernet(name='Ethernet Port {}'.format(port_id),
                            mac=Pattern(mac))

        ip_stack = Ipv4(name='Ipv4 Port {}'.format(port_id),
                        address=Pattern(ip),
                        prefix=Pattern(prefix),
                        gateway=Pattern(gw_addr),
                        ethernet=ethernet)

        device = Device(name='Device Port {}'.format(port_id),
                        device_count=1,
                        container_name=config.ports[port_id].name,
                        choice=ip_stack)

        config.devices.append(device)

        port_config = IxiaPortConfig(id=port_id,
                                     ip=ip,
                                     mac=mac,
                                     gw=gw_addr,
                                     gw_mac=dut_mac,
                                     prefix_len=prefix,
                                     port_type=IxiaPortType.IPInterface,
                                     peer_port=intf)

        port_config_list.append(port_config)

    return True

def __vlan_intf_config(config, port_config_list, duthost, ixia_ports):
    """
    Generate Tgen configuration of Vlan interfaces

    Args:
        config (obj): Tgen API config of the testbed
        port_config_list (list): list of IXIA port configuration information
        duthost (object): device under test
        ixia_ports (list): list of IXIA port information

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

            port_ids = [id for id, ixia_pot in enumerate(ixia_ports) \
                        if ixia_pot['peer_port'] == phy_intf]
            if len(port_ids) != 1:
                return False

            port_id = port_ids[0]
            mac = __gen_mac(port_id)
            ethernet = Ethernet(name='Ethernet Port {}'.format(port_id),
                                mac=Pattern(mac))

            ip_stack = Ipv4(name='Ipv4 Port {}'.format(port_id),
                            address=Pattern(vlan_ip_addr),
                            prefix=Pattern(prefix),
                            gateway=Pattern(gw_addr),
                            ethernet=ethernet)

            device = Device(name='Device Port {}'.format(port_id),
                            device_count=1,
                            container_name=config.ports[port_id].name,
                            choice=ip_stack)

            config.devices.append(device)

            port_config = IxiaPortConfig(id=port_id,
                                         ip=vlan_ip_addr,
                                         mac=mac,
                                         gw=gw_addr,
                                         gw_mac=dut_mac,
                                         prefix_len=prefix,
                                         port_type=IxiaPortType.VlanMember,
                                         peer_port=phy_intf)

            port_config_list.append(port_config)

    return True

def __portchannel_intf_config(config, port_config_list, duthost, ixia_ports):
    """
    Generate Tgen configuration of portchannel interfaces

    Args:
        config (obj): Tgen API config of the testbed
        port_config_list (list): list of IXIA port configuration information
        duthost (object): device under test
        ixia_ports (list): list of IXIA port information

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
    for pc in pc_member:
        phy_intfs = pc_member[pc]
        gw_addr = str(pc_intf[pc]['addr'])
        prefix = str(pc_intf[pc]['prefixlen'])
        pc_ip_addr = str(pc_intf[pc]['peer_addr'])

        lag_ports = []

        for i in range(len(phy_intfs)):
            phy_intf = phy_intfs[i]

            port_ids = [id for id, ixia_pot in enumerate(ixia_ports) \
                        if ixia_pot['peer_port'] == phy_intf]
            if len(port_ids) != 1:
                return False

            port_id = port_ids[0]
            mac = __gen_mac(port_id)

            proto = lag.Protocol(choice=lag.Lacp(
                actor_system_id='00:00:00:00:00:01',
                actor_system_priority=1,
                actor_port_priority=1,
                actor_port_number=1,
                actor_key=1))

            ethernet = lag.Ethernet(name='Ethernet Port {}'.format(port_id),
                                    mac=mac)

            lag_port = lag.Port(port_name=config.ports[port_id].name,
                                protocol=proto,
                                ethernet=ethernet)

            lag_ports.append(lag_port)

            port_config = IxiaPortConfig(id=port_id,
                                         ip=pc_ip_addr,
                                         mac=mac,
                                         gw=gw_addr,
                                         gw_mac=dut_mac,
                                         prefix_len=prefix,
                                         port_type=IxiaPortType.PortChannelMember,
                                         peer_port=phy_intf)

            port_config_list.append(port_config)

        lag_intf = lag.Lag(name='Lag {}'.format(pc), ports=lag_ports)
        config.lags.append(lag_intf)

        ip_stack = Ipv4(name='Ipv4 {}'.format(pc),
                        address=Pattern(pc_ip_addr),
                        prefix=Pattern(prefix),
                        gateway=Pattern(gw_addr),
                        ethernet=Ethernet(name='Ethernet {}'.format(pc)))

        device = Device(name='Device {}'.format(pc),
                        device_count=1,
                        container_name=lag_intf.name,
                        choice=ip_stack)

        config.devices.append(device)

    return True

@pytest.fixture(scope = "function")
def ixia_testbed_config(conn_graph_facts,
                        fanout_graph_facts,
                        duthosts,
                        rand_one_dut_hostname):
    """
    Geenrate Tgen API config and port config information for the testbed

    Args:
        conn_graph_facts (pytest fixture)
        fanout_graph_facts (pytest fixture)
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (pytest fixture): DUT hostname

    Returns:
        - config (obj): Tgen API config of the testbed
        - port_config_list (list): list of port configuration information
    """
    duthost = duthosts[rand_one_dut_hostname]

    """ Generate L1 config """
    ixia_fanout = get_peer_ixia_chassis(conn_data=conn_graph_facts,
                                        dut_hostname=duthost.hostname)

    pytest_assert(ixia_fanout is not None, 'Fail to get ixia_fanout')

    ixia_fanout_id = list(fanout_graph_facts.keys()).index(ixia_fanout)
    ixia_fanout_list = IxiaFanoutManager(fanout_graph_facts)
    ixia_fanout_list.get_fanout_device_details(device_number=ixia_fanout_id)

    ixia_ports = ixia_fanout_list.get_ports(peer_device=duthost.hostname)

    ports = []
    port_names = []
    port_speed = None

    for i in range(len(ixia_ports)):
        port = Port(name='Port {}'.format(i),
                    location=get_tgen_location(ixia_ports[i]))

        ports.append(port)
        port_names.append(port.name)

        if port_speed is None:
            port_speed = int(ixia_ports[i]['speed'])

        pytest_assert(port_speed == int(ixia_ports[i]['speed']),
                      'Ports have different link speeds')

    pfc = Ieee8021qbb(pfc_delay=0,
                      pfc_class_0=0,
                      pfc_class_1=1,
                      pfc_class_2=2,
                      pfc_class_3=3,
                      pfc_class_4=4,
                      pfc_class_5=5,
                      pfc_class_6=6,
                      pfc_class_7=7)

    flow_ctl = FlowControl(choice=pfc)

    auto_negotiation = AutoNegotiation(link_training=True,
                                       rs_fec=True)

    speed_gbps = int(port_speed/1000)

    l1_config = Layer1(name='L1 config',
                       speed='speed_{}_gbps'.format(speed_gbps),
                       auto_negotiate=False,
                       auto_negotiation=auto_negotiation,
                       ieee_media_defaults=False,
                       flow_control=flow_ctl,
                       port_names=port_names)

    config = Config(ports=ports,
                    layer1=[l1_config],
                    options=Options(PortOptions(location_preemption=True)))

    port_config_list = []

    config_result = __vlan_intf_config(config=config,
                                       port_config_list=port_config_list,
                                       duthost=duthost,
                                       ixia_ports=ixia_ports)
    pytest_assert(config_result is True, 'Fail to configure Vlan interfaces')

    config_result = __portchannel_intf_config(config=config,
                                              port_config_list=port_config_list,
                                              duthost=duthost,
                                              ixia_ports=ixia_ports)
    pytest_assert(config_result is True, 'Fail to configure portchannel interfaces')

    config_result = __l3_intf_config(config=config,
                                     port_config_list=port_config_list,
                                     duthost=duthost,
                                     ixia_ports=ixia_ports)
    pytest_assert(config_result is True, 'Fail to configure L3 interfaces')

    return config, port_config_list
