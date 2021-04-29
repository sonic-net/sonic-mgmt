"""
This module contains the necessary fixtures for running test cases with
Ixia devices and IxNetwork. If more fixtures are required, they should be
included in this file.
"""

import pytest
from ixnetwork_restpy import SessionAssistant
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts
from tests.common.ixia.common_helpers import get_vlan_subnet, get_addrs_in_subnet,\
    get_peer_ixia_chassis, get_ipv6_addrs_in_subnet
from tests.common.ixia.ixia_helpers import IxiaFanoutManager, get_tgen_location
import snappi

try:
    from abstract_open_traffic_generator.port import Port
    from abstract_open_traffic_generator.config import Options, Config
    from abstract_open_traffic_generator.layer1 import Layer1, FlowControl,\
        Ieee8021qbb, AutoNegotiation
    from abstract_open_traffic_generator.device import Device, Ethernet, Ipv4,\
        Pattern
    from ixnetwork_open_traffic_generator.ixnetworkapi import IxNetworkApi
    from abstract_open_traffic_generator.port import Options as PortOptions

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
    return duthost.host.options['variable_manager']._hostvars[duthost.hostname]['secret_group_vars']['ixia_api_server']['user']


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
    return duthost.host.options['variable_manager']._hostvars[duthost.hostname]['secret_group_vars']['ixia_api_server']['password']


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
    return duthost.host.options['variable_manager']._hostvars[duthost.hostname]['secret_group_vars']['ixia_api_server']['rest_port']


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
    return duthost.host.options['variable_manager']._hostvars[duthost.hostname]['secret_group_vars']['ixia_api_server']['session_id']


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

    if api_session:
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


@pytest.fixture(scope='module')
def snappi_api(ixia_api_serv_ip,
               ixia_api_serv_port):
    """
    Snappi session fixture for snappi Tgen API

    Args:
        ixia_api_serv_ip (pytest fixture): ixia_api_serv_ip fixture
        ixia_api_serv_port (pytest fixture): ixia_api_serv_port fixture.
    """
    host = "https://" + ixia_api_serv_ip + ":" + str(ixia_api_serv_port)
    api = snappi.api(host=host, ext="ixnetwork")

    yield api

    if api.assistant is not None:
        api.assistant.Session.remove()


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

    ixia_fanout = get_peer_ixia_chassis(conn_data=conn_graph_facts,
                                        dut_hostname=duthost.hostname)
    ixia_fanout_id = list(fanout_graph_facts.keys()).index(ixia_fanout)
    ixia_fanout_list = IxiaFanoutManager(fanout_graph_facts)
    ixia_fanout_list.get_fanout_device_details(device_number=ixia_fanout_id)
    ixia_ports = ixia_fanout_list.get_ports(peer_device=duthost.hostname)
    port_speed = None

    for i in range(len(ixia_ports)):
        if port_speed is None:
            port_speed = int(ixia_ports[i]['speed'])

        elif port_speed != int(ixia_ports[i]['speed']):
            """ All the ports should have the same bandwidth """
            return None

    config_facts = duthost.config_facts(host=duthost.hostname,
                                        source="running")['ansible_facts']

    for port in ixia_ports:
        port['location'] = get_tgen_location(port)
        port['speed'] = speed_type[port['speed']]

    for port in ixia_ports:

        peer_port = port['peer_port']
        int_addrs = config_facts['INTERFACE'][peer_port].keys()
        ipv4_subnet = [ele for ele in int_addrs if "." in ele][0]
        ipv6_subnet = [ele for ele in int_addrs if ":" in ele][0]
        if not ipv4_subnet:
            raise Exception("IPv4 is not configured on the interface {}"
                            .format(peer_port))
        port['peer_ip'], port['prefix'] = ipv4_subnet.split("/")
        port['ip'] = get_addrs_in_subnet(ipv4_subnet, 1)[0]

        if not ipv6_subnet:
            raise Exception("IPv6 is not configured on the interface {}"
                            .format(peer_port))
        port['peer_ipv6'], port['ipv6_prefix'] = ipv6_subnet.split("/")
        port['ipv6'] = get_ipv6_addrs_in_subnet(ipv6_subnet, 1)[0]

    return ixia_ports
