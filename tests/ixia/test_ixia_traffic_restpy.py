###############################################################################
# This test cases demonstrates: 
#   * All the fixtures required for running ixia script (please see the 
#     arguments of the test function)
#   * How Ixia chassis card/ports are addressed
#   * How you can configure/control ixia devices, start traffic and collect 
#     statistics using REST API
#   * This simple sanity test cases can be used to check if testbed setup
#     is correct or not - since it prints a lot of testbed data
###############################################################################

import logging
import time
import pytest
import ipaddr
from common.utilities import wait_until
from common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts 
from common.reboot import *
from ixnetwork_restpy import SessionAssistant, Files

from common.ixia.ixia_fixtures import ixia_api_serv_ip, ixia_api_serv_user,\
     ixia_api_serv_passwd, ixia_api_serv_port, ixia_api_serv_session_id, \
     ixia_api_server_session  

from common.ixia.ixia_helpers import get_neigh_ixia_mgmt_ip, get_neigh_ixia_card,\
     get_neigh_ixia_port, IxiaFanoutManager

import time

def create_ipv4_traffic_end_points (
    src_start_port,
    src_port_count,
    src_first_route_index,
    src_route_count,
    dst_start_port,
    dst_port_count,
    dst_first_route_index,
    dst_route_count) :

    src = [{'arg1': '/api/v1/sessions/1/ixnetwork/topology/1/deviceGroup/1/ethernet/1/ipv4/1',
             'arg2': src_start_port, 
             'arg3': src_port_count, 
             'arg4': src_first_route_index, 
             'arg5': dst_route_count}
    ]

    dst = [{'arg1': '/api/v1/sessions/1/ixnetwork/topology/1/deviceGroup/1/ethernet/1/ipv4/1', 
             'arg2': dst_start_port, 
             'arg3': dst_port_count, 
             'arg4': dst_first_route_index,
             'arg5': dst_route_count}
    ]

    return (src, dst)


def test_testbed(testbed, conn_graph_facts, duthost, fanout_graph_facts,
    ixia_api_server_session, fanouthosts):

    logger.info("Connection Graph Facts = %s " %(conn_graph_facts))
    logger.info("Fanout Graph facts = %s" %(fanout_graph_facts))
    logger.info("DUT hostname = %s" %(duthost.hostname))
 
    mg_facts  = duthost.minigraph_facts(host=duthost.hostname)
    gatewayIp = mg_facts['ansible_facts']['minigraph_vlan_interfaces'][0]['addr']

    ixiaFanoutHostList = IxiaFanoutManager(fanout_graph_facts) 
    ixiaFanoutHostList.get_fanout_device_details(device_number = 0)

    # Build gateway valuelist. Same gateway IP for all interface
    gateway_value_list = []
    for i in ixiaFanoutHostList.ports() :
        gateway_value_list.append(gatewayIp)

    # Create ixNetwork interface IP address list 
    interface_ip_list = []
    ipaddress = ipaddr.IPv4Address(gatewayIp)
    for i in ixiaFanoutHostList.ports() :
        ipaddress = ipaddress + 1
        interface_ip_list.append(ipaddress._string_from_ip_int(ipaddress._ip))

    session   = ixia_api_server_session
    ixNetwork = session.Ixnetwork
    portMap   = session.PortMapAssistant()

    vport_list = []
    for i in ixiaFanoutHostList.ports() :
        (chassisIp, cardId, portId) = ixiaFanoutHostList.getCardPort(i)
        vport_list.append(portMap.Map(chassisIp, cardId, portId))
       
    t1 = time.time()
    portMap.Connect(ChassisTimeout=1200, ForceOwnership=True)
    t2 = time.time()

    time_taken = t2 - t1
    logger.info("time-taken to connect = %s" %(time_taken))

    for vport in vport_list :
        vport.L1Config.NovusHundredGigLan.IeeeL1Defaults        = False         
        vport.L1Config.NovusHundredGigLan.EnableAutoNegotiation = False
        vport.L1Config.NovusHundredGigLan.EnableRsFec           = True
        vport.L1Config.NovusHundredGigLan.EnableRsFecStats      = True

    topology1    = ixNetwork.Topology.add(Name='Topo1', Ports=vport_list)
    deviceGroup1 = topology1.DeviceGroup.add(Name='DG1', Multiplier='1')
    ethernet1    = deviceGroup1.Ethernet.add(Name='Eth1')
    ipv4         = ethernet1.Ipv4.add(Name='Ipv4')

    ipv4.GatewayIp.ValueList(gateway_value_list)
    ipv4.Address.ValueList(interface_ip_list)

    ixNetwork.StartAllProtocols()
    logger.info("Wait for 5 seconds for iv4 sessions to up")
    time.sleep(5) 

    # Create a traffic item 
    traffic_item = ixNetwork.Traffic.TrafficItem.add(
                   Name        = 'Traffic Test',
                   TrafficType = 'ipv4')

    # Create a ipv4 source and destination for the endpoint of traffic item.
    src_dst_ep = create_ipv4_traffic_end_points (
                 src_start_port        = 1,
                 src_port_count        = 1,
                 src_first_route_index = 1,
                 src_route_count       = 1,
                 dst_start_port        = 2,
                 dst_port_count        = 3,
                 dst_first_route_index = 1,
                 dst_route_count       = 1
    )

    # Create endpoint set and set source and destination.
    endPoint                      = traffic_item.EndpointSet.add()
    endPoint.ScalableSources      = src_dst_ep[0]
    endPoint.ScalableDestinations = src_dst_ep[1]

    # Enable tracking.
    traffic_item.Tracking.find().TrackBy = ['trackingenabled0']

    # Generate, apply and start traffic.
    traffic_item.Generate()
    ixNetwork.Traffic.Apply()
    ixNetwork.Traffic.Start()

    logger.info("run traffic for 5 seconds")
    time.sleep(5)

    # Fetch statistics.
    logger.info(session.StatViewAssistant('Traffic Item Statistics'))
    ixNetwork.Traffic.Stop()
    assert 1

