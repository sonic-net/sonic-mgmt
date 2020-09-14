import logging
import time
import pytest
import json

from ixnetwork_open_traffic_generator.ixnetworkapi import IxNetworkApi

from tests.common.reboot import logger
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts 

from tests.common.helpers.assertions import pytest_assert

from tests.common.ixia.ixia_fixtures import ixia_api_serv_ip, \
    ixia_api_serv_user, ixia_api_serv_passwd, ixia_dev, ixia_api_serv_port,\
    ixia_api_serv_session_id, api

from tests.common.ixia.ixia_helpers import IxiaFanoutManager, get_location

from tests.common.ixia.common_helpers import get_vlan_subnet, \
    get_addrs_in_subnet

from files.qos_fixtures import lossless_prio_dscp_map
from files.configs.pfc import configure_pfc_lossy
from abstract_open_traffic_generator.control import FlowTransmit

START_DELAY = 1
TRAFFIC_DURATION = 5

def run_pfc_pause_lossy_traffic_test(api, dut, exp_dur) :
    """
    This test case checks the behaviour of the SONiC DUT when it receives 
    a PFC pause frame on lossy priorities.

                                +-----------+
    [Keysight Chassis Tx Port]  |           | [Keysight Chassis Rx Port]
    --------------------------->| SONiC DUT |<---------------------------
    Test Data Traffic +         |           |  PFC pause frame on 
    Background Dada Traffic     +-----------+  "lossy" priorities.

    1. Configure SONiC DUT with multipul lossless priorities. 
    2. On SONiC DUT enable PFC on several priorities e.g priority 3 and 4.
    3. On the Keysight chassis Tx port create two flows - a) 'Test Data Traffic'
       and b) 'Background Data traffic'.
    4. Configure 'Test Data Traffic' such that it contains traffic items
       with all lossy priorities.
    5. Configure 'Background Data Traffic' it contains traffic items with
       all lossless priorities.
    6. From Rx port send pause frames on all lossless priorities. Then
       start 'Test Data Traffic' and 'Background Data Traffic'.
    7. Verify the following: 
       (a) When Pause Storm are running, Keysight Rx port is receiving
       both 'Test Data Traffic' and 'Background Data traffic'.
       (b) When Pause Storm are stoped, then also Keysight Rx port is receiving
       both 'Test Data Traffic' and 'Background Data traffic'.
    """
    
    dut.shell('sudo pfcwd stop')

    # start all flows
    api.set_flow_transmit(FlowTransmit('start'))

    logger.info("Traffic is running for %s seconds" %(exp_dur))
    time.sleep(exp_dur)

    # stop all flows
    api.set_flow_transmit(FlowTransmit('stop'))

    # Get statistics
    test_stat = api.get_flow_results('Test Data')

    for rows in test_stat['rows'] :
        tx_frame_index = test_stat['columns'].index('frames_tx')
        rx_frame_index = test_stat['columns'].index('frames_rx')
        caption_index = test_stat['columns'].index('name')   
        if ((rows[caption_index] == 'Test Data') or
            (rows[caption_index] == 'Background Data')):
            if rows[tx_frame_index] != rows[rx_frame_index] :
                pytest_assert(False,
                    "Not all %s reached Rx End" %(rows[caption_index]))


def test_pfc_pause_for_lossy_traffic(testbed,
                                     conn_graph_facts,
                                     duthost,
                                     api,
                                     fanout_graph_facts,
                                     lossless_prio_dscp_map) :

    fanout_devices = IxiaFanoutManager(fanout_graph_facts)
    fanout_devices.get_fanout_device_details(device_number=0)
    device_conn = conn_graph_facts['device_conn']

    # The number of ports should be at least two for this test
    available_phy_port = fanout_devices.get_ports()
    pytest_assert(len(available_phy_port) > 2,
                  "Number of physical ports must be at least 2")

    # Get interface speed of peer port
    for intf in available_phy_port:
        peer_port = intf['peer_port']
        intf['speed'] = int(device_conn[peer_port]['speed'])


    for i in range(len(available_phy_port)):
        rx_id = i
        tx_id = (i + 1) % len(available_phy_port)
        
        tx_location = get_location(available_phy_port[tx_id])
        rx_location = get_location(available_phy_port[rx_id])

        tx_speed = available_phy_port[tx_id]['speed']
        rx_speed = available_phy_port[rx_id]['speed']

        pytest_assert(tx_speed == rx_speed,
            "Tx bandwidth must be equal to Rx bandwidth") 
       
        vlan_subnet = get_vlan_subnet(duthost)
        pytest_assert(vlan_subnet is not None,
                      "Fail to get Vlan subnet information")
        vlan_ip_addrs = get_addrs_in_subnet(vlan_subnet, 2)

        gw_addr = vlan_subnet.split('/')[0]
        interface_ip_addr = vlan_ip_addrs[0]

        bg_dscp_list = [prio for prio in lossless_prio_dscp_map]
        test_dscp_list = [x for x in range(64) if x not in bg_dscp_list]

        config = configure_pfc_lossy(
            api = api,
            phy_tx_port=tx_location,
            phy_rx_port=rx_location,
            port_speed=tx_speed,
            tx_port_ip=vlan_ip_addrs[1],
            rx_port_ip=vlan_ip_addrs[0],
            tx_gateway_ip=gw_addr,
            rx_gateway_ip=gw_addr,
            test_data_priority=test_dscp_list,
            background_data_priority=bg_dscp_list,
            test_flow_name='Test Data',
            background_flow_name='Background Data',
            start_delay=START_DELAY)

        run_pfc_pause_lossy_traffic_test(
            api=api, 
            dut=duthost, 
            exp_dur=(START_DELAY + TRAFFIC_DURATION))

