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
    get_peer_ixia_chassis
from tests.common.ixia.ixia_helpers import IxiaFanoutManager, get_tgen_location

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
def ixia_api_serv_user(pre_selected_dut):
    """
    Return the username of Ixia API server.

    Args:
        pre_selected_dut (pytest fixture): The pre_selected_dut fixture.

    Returns:
        Ixia API server username.
    """
    return pre_selected_dut.host.options['variable_manager']._hostvars[pre_selected_dut.hostname]['secret_group_vars']['ixia_api_server']['user']


@pytest.fixture(scope = "module")
def ixia_api_serv_passwd(pre_selected_dut):
    """
    Return the password of Ixia API server.

    Args:
        pre_selected_dut (pytest fixture): The pre_selected_dut fixture.

    Returns:
        Ixia API server password.
    """
    return pre_selected_dut.host.options['variable_manager']._hostvars[pre_selected_dut.hostname]['secret_group_vars']['ixia_api_server']['password']


@pytest.fixture(scope = "module")
def ixia_api_serv_port(pre_selected_dut):
    """
    This fixture returns the TCP port for REST API of the ixia API server.

    Args:
        pre_selected_dut (pytest fixture): The pre_selected_dut fixture.

    Returns:
        Ixia API server REST port.
    """
    return pre_selected_dut.host.options['variable_manager']._hostvars[pre_selected_dut.hostname]['secret_group_vars']['ixia_api_server']['rest_port']


@pytest.fixture(scope = "module")
def ixia_api_serv_session_id(pre_selected_dut):
    """
    Ixia API server can spawn multiple session on the same REST port.
    Optional for LINUX, required for windows return the session ID.

    Args:
        pre_selected_dut (pytest fixture): The pre_selected_dut fixture.

    Returns:
        Ixia API server session id.
    """
    return pre_selected_dut.host.options['variable_manager']._hostvars[pre_selected_dut.hostname]['secret_group_vars']['ixia_api_server']['session_id']


@pytest.fixture(scope = "module")
def ixia_dev(pre_selected_dut, fanouthosts):
    """
    Returns the Ixia chassis IP. This fixture can return multiple IPs if
    multiple Ixia chassis are present in the test topology.

    Args:
        pre_selected_dut (pytest fixture): The pre_selected_dut fixture.
        fanouthosts (pytest fixture): The fanouthosts fixture.

    Returns:
        Dictionary of Ixia Chassis IP/IPs.
    """
    result = dict()
    ixia_dev_hostnames = fanouthosts.keys()
    for hostname in ixia_dev_hostnames:
        result[hostname] = pre_selected_dut.host.options['inventory_manager'].get_host(hostname).get_vars()['ansible_host']
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
    api_session.assistant.Session.remove()

@pytest.fixture(scope = "function")
def ixia_testbed(conn_graph_facts,
                    fanout_graph_facts,
                    pre_selected_dut):

    """
    L2/L3 Tgen API config for the T0 testbed

    Args:
        conn_graph_facts (pytest fixture)
        fanout_graph_facts (pytest fixture)
        pre_selected_dut (pytest fixture): The pre selected DUT

    Returns:
        L2/L3 config for the T0 testbed
    """
    duthost = pre_selected_dut
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
