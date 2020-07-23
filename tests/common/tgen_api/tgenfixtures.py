""" 
A SONIC pytest fixture returning a TgenApi implementation
"""

import pytest
from common.reboot import logger

from common.fixtures.conn_graph_facts import conn_graph_facts, \
     fanout_graph_facts

from common.ixia.ixia_helpers import IxiaFanoutManager
from common.ixia.common_helpers import incriment_ip_address

from common.ixia.ixia_fixtures import ixia_api_serv_ip, ixia_api_serv_user,\
    ixia_api_serv_passwd, ixia_api_serv_port, ixia_api_serv_session_id


from tgenmodels import Config, Port
from tgenapi import TgenApi
from keystgenapi import KeysTgenApi
import common.tgen_api

from common.tgen_api.tgenmodels import Port, Layer1, Topology, Ethernet,\
     Ipv4, PfcPause, Flow, Config

@pytest.fixture
def TgenApi(testbed, 
            conn_graph_facts, 
            duthost, 
            fanout_graph_facts,
            fanouthosts,
            ixia_api_serv_ip,
            ixia_api_serv_user,
            ixia_api_serv_passwd,
            ixia_api_serv_port,
            ixia_api_serv_session_id):

    mg_facts = duthost.minigraph_facts(host=duthost.hostname)
   
    gateway_ip = mg_facts['ansible_facts']['minigraph_vlan_interfaces'][0]['addr']
    start_interface_ip = incriment_ip_address(gateway_ip)

    # extract the ports from fanout_graph_facts fixture.
    ixiaFanoutHostList = IxiaFanoutManager(fanout_graph_facts)
    ixiaFanoutHostList.get_fanout_device_details(device_number = 0)

    logger.info("Configuring ports.")
    config = Config(ports=Port(ixiaFanoutHostList.get_ports()),
                    topo=Topology({'topo_name':'T1', 'if_ip': start_interface_ip, 'if_ip_step': '0.0.0.1', 'gw_ip': gateway_ip, 'gw_ip_step': '0.0.0.0'}))

    tgen = KeysTgenApi(config)
    session = tgen.connect(
        host=ixia_api_serv_ip,
        port=ixia_api_serv_port,
        username=ixia_api_serv_user,
        password=ixia_api_serv_passwd
    )

    ixNetwork = session.Ixnetwork
    ixNetwork.NewConfig()
    
    yield tgen

    ixNetwork.NewConfig()
    session.Session.remove()

