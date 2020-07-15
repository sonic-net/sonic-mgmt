from common.reboot import logger
import logging
import time
import pytest
from common.fixtures.conn_graph_facts import conn_graph_facts

from common.helpers.assertions import pytest_assert

from common.ixia.ixia_fixtures import ixia_api_serv_ip, ixia_api_serv_user,\
     ixia_api_serv_passwd, ixia_dev,  ixia_api_serv_port,\
     ixia_api_serv_session_id, ixia_api_server_session

from common.ixia.ixia_helpers import configure_ports,\
     create_topology, start_protocols, create_ipv4_traffic, create_pause_traffic, \
     start_traffc, stop_traffic, get_statistics, IxiaFanoutManager

from common.ixia.common_helpers import get_vlan_subnet, get_addrs_in_subnet

from common.ixia.qos_fixtures import lossless_prio_dscp_map

pytestmark = [pytest.mark.disable_loganalyzer]

""" Data packet size in bytes """
DATA_PKT_SIZE = 1024

"""
Run a PFC experiment
                     _________
                    |         |
IXIA tx_port ------ |   DUT   |------ IXIA rx_port
                    |_________|
IXIA sends test traffic and background traffic from tx_port
IXIA sends PFC pause frames from rx_port to pause priorities 
                    
@param session: IXIA session
@param dut: Ansible instance of SONiC device under test (DUT)
@param tx_port: IXIA port to transmit traffic
@param rx_port: IXIA port to receive traffic
@param port_bw: bandwidth (in Mbps) of tx_port and rx_port
@param test_prio_list: PFC priorities of test traffic and PFC pause frames
@param test_dscp_list: DSCP values of test traffic
@param bg_dscp_list: DSCP values of background traffic
@param exp_dur: experiment duration in second
@param paused: if test traffic should be paused
"""
def run_pfc_exp(session, dut, tx_port, rx_port, port_bw, test_prio_list, test_dscp_list, bg_dscp_list,\
                exp_dur, paused):
    
    """ Disable DUT's PFC watchdog """
    dut.shell('sudo pfcwd stop')
    
    vlan_subnet = get_vlan_subnet(dut)
    pytest_assert(vlan_subnet is not None, "Fail to get Vlan subnet information")
    
    gw_addr = vlan_subnet.split('/')[0]
    """ One for sender and the other one for receiver """
    vlan_ip_addrs = get_addrs_in_subnet(vlan_subnet, 2)
       
    topo_receiver = create_topology(session=session,
                                    name="Receiver", 
                                    ports=list(rx_port),
                                    ip_start=vlan_ip_addrs[0],
                                    ip_incr_step='0.0.0.1',
                                    gw_start=gw_addr, 
                                    gw_incr_step='0.0.0.0')

    topo_sender = create_topology(session=session, 
                                  name="Sender", 
                                  ports=list(tx_port), 
                                  ip_start=vlan_ip_addrs[1], 
                                  ip_incr_step='0.0.0.1', 
                                  gw_start=gw_addr, 
                                  gw_incr_step='0.0.0.0')

    start_protocols(session)
    
    test_traffic = create_ipv4_traffic(session=session,
                                       name='Test Data Traffic',
                                       source=topo_sender,
                                       destination=topo_receiver,
                                       pkt_size=DATA_PKT_SIZE,
                                       duration=exp_dur,
                                       rate_percent=50,
                                       start_delay=1,
                                       dscp_list=test_dscp_list,
                                       lossless_prio_list=test_prio_list)

    background_traffic = create_ipv4_traffic(session=session,
                                             name='Background Data Traffic',
                                             source=topo_sender,
                                             destination=topo_receiver,
                                             pkt_size=DATA_PKT_SIZE,
                                             duration=exp_dur,
                                             rate_percent=50,
                                             start_delay=1,
                                             dscp_list=bg_dscp_list,
                                             lossless_prio_list=None)
    
    """ Pause time duration (in second) for each PFC pause frame """ 
    pause_dur_per_pkt = 65535 * 64 * 8.0 / (port_bw * 1000000) 
    
    """ Do not specify duration here as we want it keep running """
    pfc_traffic = create_pause_traffic(session=session,
                                       name='PFC Pause Storm',
                                       source=rx_port,
                                       pkt_per_sec=1.1/pause_dur_per_pkt,
                                       start_delay=0,
                                       global_pause=False,
                                       pause_prio_list=test_prio_list)
    
    start_traffc(session)
    
    """ Wait for test and background traffic to finish """
    time.sleep(exp_dur+1.5)
    
    """ Capture traffic statistics  """
    
    flow_statistics = get_statistics(session)
    logger.info(flow_statistics)
        
    for row_number, flow_stat in enumerate(flow_statistics.Rows):
        tx_frames = int(flow_stat['Tx Frames'])
        rx_frames = int(flow_stat['Rx Frames'])       
        
        if 'Test' in flow_stat['Traffic Item']:
            if paused:          
                pytest_assert(tx_frames>0 and rx_frames==0, "Test traffic should be fully paused")
            else:
                pytest_assert(tx_frames>0 and tx_frames==rx_frames, "Test traffic should not be impacted")
                       
        elif 'PFC' in flow_stat['Traffic Item']:
            pytest_assert(tx_frames>0 and rx_frames==0, "PFC packets should be dropped")
        else:         
            pytest_assert(tx_frames>0 and tx_frames==rx_frames, "Background traffic should not be impacted")
        
    stop_traffic(session)

def test_pfc_pause_lossless(testbed, conn_graph_facts, lossless_prio_dscp_map, duthost, ixia_dev, \
                            ixia_api_server_session, fanout_graph_facts):
    
    port_list = list()
    fanout_devices = IxiaFanoutManager(fanout_graph_facts)
    fanout_devices.get_fanout_device_details(device_number = 0)

    device_conn = conn_graph_facts['device_conn']
    for intf in fanout_devices.get_ports():
        peer_port = intf['peer_port'] 
        intf['speed'] = int(device_conn[peer_port]['speed']) * 100 
        port_list.append(intf)

                
    """ The topology should have at least two interfaces """
    pytest_assert(len(device_conn)>=2, "The topology should have at least two interfaces")
                
    """ Test pausing each lossless priority individually """

    session = ixia_api_server_session
    for prio in lossless_prio_dscp_map:
        for i in range(len(port_list)): 
            vports = configure_ports(session, port_list)
 
            rx_id = i
            tx_id = (i+1) % len(port_list)
            
            rx_port = vports[rx_id]
            tx_port = vports[tx_id]
            rx_port_bw = port_list[rx_id]['speed']
            tx_port_bw = port_list[tx_id]['speed']
            
            pytest_assert(rx_port_bw == tx_port_bw)
            
            """ All the DSCP values mapped to this priority """
            test_dscp_list = lossless_prio_dscp_map[prio]
            """ The other DSCP values """
            bg_dscp_list = [x for x in range(64) if x not in test_dscp_list]
            
            exp_dur = 2
                
            run_pfc_exp(session=session, 
                        dut=duthost, 
                        tx_port=tx_port, 
                        rx_port=rx_port,
                        port_bw=tx_port_bw,
                        test_prio_list=[prio],
                        test_dscp_list=test_dscp_list, 
                        bg_dscp_list=bg_dscp_list,
                        exp_dur=exp_dur,
                        paused=True)

            ixNetwork = session.Ixnetwork
            ixNetwork.NewConfig()

