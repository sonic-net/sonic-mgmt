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
import pprint
from common.utilities import wait_until
from common.fixtures.conn_graph_facts import conn_graph_facts
from common.platform.interface_utils import check_interface_information
from common.platform.daemon_utils import check_pmon_daemon_status
from common.reboot import *
from common.platform.device_utils import fanout_switch_port_lookup
from common.helpers import assertions
from ixnetwork_restpy import SessionAssistant, Files

from lib.ixia_fixtures import ixia_api_serv_ip, ixia_api_serv_user,\
     ixia_api_serv_passwd, ixia_dev, ixia_api_serv_port, ixia_api_serv_session_id

from lib.ixia_helpers import get_neigh_ixia_mgmt_ip, get_neigh_ixia_card,\
     get_neigh_ixia_port 


import time

#pytestmark = [pytest.mark.disable_loganalyzer]

def returnIxiaChassisIp (chassisDict, no) :
    chList = []
    for key in chassisDict.keys():
        chList.append(chassisDict[key])

    return (chList[no - 1])

def parseDeviceConn (device_conn) :
    retval = []
    dive_con_dict = device_conn['device_conn']
    for key in dive_con_dict.keys() :
        pp =  dive_con_dict[key]['peerport']
        string = pp + '/' + key
        retval.append(string)
    retval.sort()
    return(retval)

def getCard(ixiaCardPortList, num) :
    card = ixiaCardPortList[num].split('/')[0]
    cardNo = int(card.replace('Card', ''))
    return(cardNo)

def getPort(ixiaCardPortList, num) :
    port = ixiaCardPortList[num].split('/')[1]
    portNo = int(port.replace('Port', ''))
    return(portNo)

def test_testbed(testbed, conn_graph_facts, duthost, ixia_dev, ixia_api_serv_ip,
                 ixia_api_serv_user, ixia_api_serv_passwd, ixia_api_serv_port,
                 ixia_api_serv_session_id):
    print("conn_graph_fact          ==============")
    pprint.pprint(conn_graph_facts)
    print("DUT hostname             ==============")
    print(duthost.hostname)
    print(dir(duthost))
    print("ixia ports               ==============")
    ixiaports = parseDeviceConn(conn_graph_facts)
    print(ixiaports)
    print("IXIA CHASSIS IP          ==============")
    print(ixia_dev)
    print("IXIA API SERVER IP       ==============")
    print(ixia_api_serv_ip)
    print("IXIA API SERVER USER     ==============")
    print(ixia_api_serv_user)
    print("IXIA API SERVER PASSWORD ==============")
    print(ixia_api_serv_passwd)
    print("IXIA API REST PORT       ==============")
    print(ixia_api_serv_port)
    print("IXIA API SESSION ID      ==============")
    print(ixia_api_serv_session_id)
    print("=======================================")

    clientIp  = ixia_api_serv_ip
    UserName  = ixia_api_serv_user
    Password  = ixia_api_serv_passwd
    RestPort  = ixia_api_serv_passwd
    SessionId = ixia_api_serv_session_id
    chassisIp = returnIxiaChassisIp(ixia_dev, 1)

    cardId    = getCard(ixiaports, 0)
    PortId1   = getPort(ixiaports, 0)
    PortId2   = getPort(ixiaports, 1)
    PortId3   = getPort(ixiaports, 2)
    PortId4   = getPort(ixiaports, 3)
    PortId5   = getPort(ixiaports, 4)
    PortId6   = getPort(ixiaports, 5)

    if (SessionId != "None") :
        session = SessionAssistant(IpAddress = clientIp,
                               UserName = UserName,
                               Password = Password,
                               RestPort = RestPort,
                               SessionId = SessionId)
    else :
        session = SessionAssistant(IpAddress = clientIp,
                               UserName = UserName,
                               Password = Password,
                               RestPort = RestPort)
   
    sessionData = session.Session
    ixNetwork   = session.Ixnetwork
    ixNetwork.NewConfig()
    portMap = session.PortMapAssistant()

    vPort1 = portMap.Map(chassisIp, cardId, PortId1)
    vPort2 = portMap.Map(chassisIp, cardId, PortId2)
    vPort3 = portMap.Map(chassisIp, cardId, PortId3)
    vPort4 = portMap.Map(chassisIp, cardId, PortId4)
    vPort5 = portMap.Map(chassisIp, cardId, PortId5)
    vPort6 = portMap.Map(chassisIp, cardId, PortId6)
    #print ('connecting to chassis %s' %(chassisIp))

    t1 = time.time()
    portMap.Connect(ChassisTimeout=1200, ForceOwnership=True)
    t2 = time.time()

    time_taken = t2 - t1
    print("time-taken to connect == %s" %(time_taken))

    vPort1.L1Config.NovusHundredGigLan.IeeeL1Defaults  =  False
    vPort1.L1Config.NovusHundredGigLan.EnableAutoNegotiation =False
    vPort1.L1Config.NovusHundredGigLan.EnableRsFec = True
    vPort1.L1Config.NovusHundredGigLan.EnableRsFecStats = True

    vPort2.L1Config.NovusHundredGigLan.IeeeL1Defaults  =  False
    vPort2.L1Config.NovusHundredGigLan.EnableAutoNegotiation =False
    vPort2.L1Config.NovusHundredGigLan.EnableRsFec = True
    vPort2.L1Config.NovusHundredGigLan.EnableRsFecStats = True 

    vPort3.L1Config.NovusHundredGigLan.IeeeL1Defaults  =  False
    vPort3.L1Config.NovusHundredGigLan.EnableAutoNegotiation =False
    vPort3.L1Config.NovusHundredGigLan.EnableRsFec = True
    vPort3.L1Config.NovusHundredGigLan.EnableRsFecStats = True 

    vPort4.L1Config.NovusHundredGigLan.IeeeL1Defaults  =  False
    vPort4.L1Config.NovusHundredGigLan.EnableAutoNegotiation =False
    vPort4.L1Config.NovusHundredGigLan.EnableRsFec = True
    vPort4.L1Config.NovusHundredGigLan.EnableRsFecStats = True 

    vPort5.L1Config.NovusHundredGigLan.IeeeL1Defaults  =  False
    vPort5.L1Config.NovusHundredGigLan.EnableAutoNegotiation =False
    vPort5.L1Config.NovusHundredGigLan.EnableRsFec = True
    vPort5.L1Config.NovusHundredGigLan.EnableRsFecStats = True 

    vPort6.L1Config.NovusHundredGigLan.IeeeL1Defaults  =  False
    vPort6.L1Config.NovusHundredGigLan.EnableAutoNegotiation =False
    vPort6.L1Config.NovusHundredGigLan.EnableRsFec = True
    vPort6.L1Config.NovusHundredGigLan.EnableRsFecStats = True 

    vPort1.Name = 'Tx1'
    vPort4.Name = 'Rx1'
    state = vPort1.State
    print ('creating topology')

    topology1    = ixNetwork.Topology.add(Name='Topo1', Ports=[vPort1, vPort2, vPort3, vPort4, vPort5, vPort6])
    deviceGroup1 = topology1.DeviceGroup.add(Name='DG1', Multiplier='1')
    ethernet1    = deviceGroup1.Ethernet.add(Name='Eth1')
    ipv4         = ethernet1.Ipv4.add(Name='Ipv4')

    ipv4.GatewayIp.ValueList(['192.168.1.1','192.168.1.1','192.168.1.1','192.168.1.1', '192.168.1.1', '192.168.1.1'])
    ipv4.Address.ValueList(['192.168.1.2','192.168.1.3','192.168.1.4','192.168.1.5', '192.168.1.6', '192.168.1.7'])

    ixNetwork.StartAllProtocols()
    time.sleep(60) 

    # Traffic
    traffic_item = ixNetwork.Traffic.TrafficItem.add(Name='Traffic Test', TrafficType='ipv4')
    dest = [{'arg1': '/api/v1/sessions/1/ixnetwork/topology/1/deviceGroup/1/ethernet/1/ipv4/1', 'arg2': 1, 'arg3': 4, 'arg4': 1 ,'arg5': 1}]
    src  = [{'arg1': '/api/v1/sessions/1/ixnetwork/topology/1/deviceGroup/1/ethernet/1/ipv4/1', 'arg2': 1, 'arg3': 1, 'arg4': 1, 'arg5': 1}]
    endPoint = traffic_item.EndpointSet.add()
    traffic_item.Tracking.find().TrackBy = ['trackingenabled0']
    endPoint.ScalableSources = src
    endPoint.ScalableDestinations = dest
    traffic_item.Generate()
    ixNetwork.Traffic.Apply()
    ixNetwork.Traffic.Start()
    time.sleep(10)
    print(session.StatViewAssistant('Traffic Item Statistics'))

    print('passed')

    assert 1

