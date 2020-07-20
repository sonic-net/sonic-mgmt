import logging
import time
import pytest
from common.utilities import wait_until

from common.reboot import logger

from common.fixtures.conn_graph_facts import conn_graph_facts, \
     fanout_graph_facts

from common.ixia.ixia_fixtures import ixia_api_serv_ip, ixia_api_serv_user,\
     ixia_api_serv_passwd, ixia_api_serv_port, ixia_api_serv_session_id, \
     ixia_api_server_session

from common.ixia.ixia_helpers import IxiaFanoutManager
from common.ixia.common_helpers import incriment_ip_address

from common.tgen_api.tgenfixtures import TgenApi

"""
Import Tgen Data Models
    Related to protocol configuration:
        Port -> Port configuration (name and location)
        Layer1 -> Layer1 configuration 
        Topology -> Topology configuration.
    Related to traffic configuration:
        Ethernet-> Ethernet layer configuration of data packet
        IP -> IP layer configuration of data packet.
        PfcPause -> PFC pause configuration
        Flow -> Flow configuration
    Repository all the above config:
        Config -> Repository all the above config   
"""
from common.tgen_api.tgenmodels import Port, Layer1, Topology, Ethernet,\
     Ipv4, PfcPause, Flow, Config

def test_testbed(testbed, conn_graph_facts, duthost, fanout_graph_facts,
    fanouthosts, TgenApi):

    """
    This test module demonstrates capability of the tgen fixture.
     
    Note: All the below fixture in the argument must be available in the
        test case. They cannot me hidden inside other fixture.

    Args: 
        testbed (pytest fixture): Pytest fixture to get the testbed 
            information.

        conn_graph_facts (pytest fixture): Pytest fixture to get the connection
            graph.

        duthost (pytest fixture): Pytest fixture to get the DUT details. 

        fanout_graph_facts (pytest fixture): Details of the fanout devices.

        fanouthosts (pytest fixture):  Details of the fanout hosts.

        TgenApi (pytest fixture) : Ixia defined pytest fixture.
    """

    # Extract the Gateway IP from dut host fixture. 
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)
    gateway_ip = mg_facts['ansible_facts']['minigraph_vlan_interfaces'][0]['addr']
    start_interface_ip = incriment_ip_address(gateway_ip)

    # extract the ports from fanout_graph_facts fixture.
    ixiaFanoutHostList = IxiaFanoutManager(fanout_graph_facts) 
    ixiaFanoutHostList.get_fanout_device_details(device_number = 0)

    logger.info("Configuring ports.")
    config = Config(ports=Port(ixiaFanoutHostList.get_ports()),
                    topo=Topology({'topo_name':'T1', 'if_ip': start_interface_ip, 'if_ip_step': '0.0.0.1', 'gw_ip': gateway_ip, 'gw_ip_step': '0.0.0.0'}))

    TgenApi.init_tgen(config)
    TgenApi.configure()
    TgenApi.start()
    
    logger.info("wait for two seconds")
    time.sleep(2)

    TgenApi.stop()
 
