"""
This module contains the snappi fixture
"""
import pytest
import snappi_convergence
#from ipaddress import ip_address, IPv4Address
from tests.common.fixtures.conn_graph_facts import (
    conn_graph_facts, fanout_graph_facts)
from tests.common.snappi.common_helpers import (
    get_vlan_subnet, get_addrs_in_subnet,get_peer_snappi_chassis)
from tests.common.snappi.snappi_helpers import SnappiFanoutManager, get_snappi_port_location

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


@pytest.fixture(scope="function")
def tgen_ports(duthost,conn_graph_facts,fanout_graph_facts):
    """
    Populate tgen ports info of T0 testbed and returns as a list
    Args:
        duthost (pytest fixture): duthost fixture
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
    Return:
    [{'card_id': '1',
        'ip': '21.1.1.2',
        'location': '10.36.78.238;1;2',
        'prefix': u'24',
        'peer_ip': u'21.1.1.1',
        'peer_device': 'example-s6100-dut-1',
        'peer_port': 'Ethernet0',
        'port_id': '2',
        'speed': '400000'},
        {'card_id': '1',
        'ip': '22.1.1.2',
        'location': '10.36.78.238;1;1',
        'prefix': u'24',
        'peer_ip': u'22.1.1.1',
        'peer_device': 'example-s6100-dut-1',
        'peer_port': 'Ethernet8',
        'port_id': '1',
        'speed': '400000'}]
    """
    speed_type = {'50000': 'speed_50_gbps',
                  '100000': 'speed_100_gbps',
                  '200000': 'speed_200_gbps',
                  '400000': 'speed_400_gbps'}
    snappi_fanout = get_peer_snappi_chassis(conn_data=conn_graph_facts,dut_hostname=duthost.hostname)
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
    config_facts = duthost.config_facts(host=duthost.hostname,source="running")['ansible_facts']
    for port in snappi_ports:
        port['location'] = get_snappi_port_location(port)
        port['speed'] = speed_type[port['speed']]
    for port in snappi_ports:
        peer_port = port['peer_port']
        subnet = config_facts['INTERFACE'][peer_port].keys()[0]
        if not subnet:
            raise Exception("IP is not configured on the interface {}".format(peer_port))
        port['peer_ip'], port['prefix'] = subnet.split("/")
        port['ip'] = get_addrs_in_subnet(subnet, 1)[0]
    return snappi_ports

@pytest.fixture(scope='module')
def cvg_api(snappi_api_serv_ip,
               snappi_api_serv_port):
    #api = snappi_convergence.api(location=snappi_api_serv_ip + ':' + str(snappi_api_serv_port),ext='ixnetwork')
    api = snappi_convergence.api(location='10.36.77.53' + ':' + '11009',ext='ixnetwork')
    yield api
    if getattr(api, 'assistant', None) is not None:
        api.assistant.Session.remove()