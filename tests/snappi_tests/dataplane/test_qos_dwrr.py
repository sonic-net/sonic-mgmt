import logging
import pytest

from tests.snappi_tests.qos.files.qos_priority_helper import read_dut_configs, create_snappi_flows, run_traffic, get_flow_statistics, delete_flows
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts, fanout_graph_facts_multidut                      # noqa F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
     snappi_api,  get_snappi_ports, get_snappi_ports_single_dut, get_snappi_ports_multi_dut, snappi_testbed_config     # noqa F401

from tests.snappi_tests.dataplane.files.helper import get_duthost_vlan_details, set_primary_chassis, create_snappi_l1config, create_snappi_config

from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.common.snappi_tests.snappi_helpers import wait_for_arp

logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology('tgen')]

"""
Requirements:
   - The DUT's config file must have correct SCHEDULER weight settings that maps
     to interface QUEUE IDs
   - Other QoS settings are: BUFFER_POOL, BUFFER_PG,  SCHEDULER, TC_TO_QUEUE_MAP,
                             DSCP_TO_TC_MAP, TC_TO_PRIORITY_GROUP_MAP, QUEUE, WRED_PROFILE
                             
This script performs two different types of test:
   1> Inter-port testing
   2> Intra-port testing
   
- Every port is tested as a Rx-Port. 
- This script reads the dut config file and ...
- Calculates the expected loss% based on interface's Queue ID mapping to the scheduler's weight

Flow examples:
    Ethernet1 SrcIp:192.168.1.2 QID:0 TC:0 DSCP:0 scheduler.0 WT:1  TTl_WT:91 Expected_Loss%:98.9
    Ethernet2 SrcIp:192.168.1.4 QID:1 TC:1 DSCP:1 scheduler.1 WT:10 TTl_WT:91 Expected_Loss%:89.0
    Ethernet3 SrcIp:192.168.1.5 QID:2 TC:2 DSCP:2 scheduler.2 WT:20 TTl_WT:91 Expected_Loss%:78.0
    Ethernet4 SrcIp:192.168.1.6 QID:3 TC:3 DSCP:3 scheduler.3 WT:30 TTl_WT:91 Expected_Loss%:67.0
    Ethernet5 SrcIp:192.168.1.7 QID:4 TC:4 DSCP:4 scheduler.1 WT:10 TTl_WT:91 Expected_Loss%:89.0
    Ethernet6 SrcIp:192.168.1.8 QID:5 TC:5 DSCP:5 scheduler.1 WT:10 TTl_WT:91 Expected_Loss%:89.0
    Ethernet7 SrcIp:192.168.1.9 QID:6 TC:6 DSCP:6 scheduler.1 WT:10 TTl_WT:91 Expected_Loss%:89.0
"""

class Common_vars:
    ports_per_group = 1
    total_tx_ports = 7
    traffic_flows = []
    snappi_port_groups = {}
    dut_qos_configs = {}
    frame_size = 4096
    line_rate_percentage = 100
    flow_duration_seconds = 10
    pass_threshold_pct = 0.01
    snappi_vports = None 
    
    # For inter-port and intra-port testing 8x100G ports per per group. 
    # For quick test, set to 1. 
    # Otherwise, set to 8 for production testing (testing port-group of 8 to rotate the Rx-Port) 
    total_rx_port_rotation = 8
          
    # For inter-port testing
    total_port_groups = 0
    
    
@pytest.mark.parametrize("subnet_type", ["IPv4"])
def test_qos_traffic_priorities(snappi_api,                 # noqa F811
                                conn_graph_facts,           # noqa F811
                                fanout_graph_facts_multidut, # noqa F811
                                duthosts,
                                set_primary_chassis,
                                rand_one_dut_hostname,
                                rand_one_dut_portname_oper_up,
                                get_snappi_ports,
                                subnet_type,
                                create_snappi_l1config
                                ):
    """
    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        setup_snappi_port_configs (pytest fixture): Returns a list of dicts containing all snappi port srcIp, gateways, duthost, etc
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): port to test, e.g., 's6100-1|Ethernet0'

    Returns:
        N/A
    """
    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.interface_type = 'vlan'
    snappi_ports = get_duthost_vlan_details(duthosts, get_snappi_ports)
    tx_ports = [snappi_ports[0]]
    rx_ports = snappi_ports[1:]

    snappi_config = create_snappi_l1config
    
    snappi_extra_params.protocol_config = {
        "Tx": {"protocol_type": "vlan", "is_rdma": True, "ports": tx_ports, "subnet_type": subnet_type},
        "Rx": {"protocol_type": "vlan", "is_rdma": True, "ports": rx_ports, "subnet_type": subnet_type},
    }

    # Add ports and NGPF     
    snappi_config, snappi_obj_handles = create_snappi_config(snappi_config, snappi_extra_params)
    # Execute config ports and NGPF configs
    snappi_api.set_config(snappi_config)

    logger.info('Wait for Arp to Resolve ...')
    wait_for_arp(snappi_api, max_attempts=10, poll_interval_sec=2)
    
    # Intra-Port testing
    #    Test all 64 ports in one single DUT
    #    In groups of 8 ports (1.1, 1.2, 1.3 ...)
    #    Rotate each port to be the rx-port so every port is QoS-tested as a rx-port
    for rx_port_index in range(Common_vars.total_rx_port_rotation):   
        logger.info(f'Intra-port testing: Rx-Port:{rx_port_index}')         
        define_tx_rx_intra_port_testing(snappi_ports, duthosts, rx_port_index)
        read_dut_configs(Common_vars, duthosts, typeOfTest='dwrr')
        snappi_configs = create_snappi_flows(Common_vars, duthosts, snappi_config, snappi_api, snappi_ports)
        run_traffic(Common_vars, api=snappi_api, config=snappi_configs)
        verify_dwrr_pass_criteria(snappi_api)
        delete_flows(snappi_api)
    
    # Inter-Port testing
    for rx_port_index in range(Common_vars.total_rx_port_rotation):
        logger.info(f'Inter-port testing: Rx-Port:{rx_port_index}')  
        define_tx_rx_inter_port_testing(snappi_ports, duthosts, rx_port_index)
        read_dut_configs(Common_vars, duthosts, typeOfTest='dwrr')
        snappi_configs = create_snappi_flows(Common_vars, duthosts, snappi_config, snappi_api, snappi_ports)
        run_traffic(Common_vars, api=snappi_api, config=snappi_configs)
        verify_dwrr_pass_criteria(snappi_api)
        delete_flows(snappi_api)


def define_tx_rx_inter_port_testing(snappi_port_configs, duthosts, rx_port_index):
    """
    For "INTER-PORT" testing
    
    - This function defines the rx/tx ports 
    - Create tx_ports|rx_ports list
    
    snappi_port_configs:
        {'ipAddress': '192.168.1.18',
        'ipGateway': '192.168.1.3',
        'prefix': 24,
        'subnet': '192.168.1.0/24',
        'src_mac_address': 'aa:00:00:00:00:0f',
        'router_mac_address': '9c:69:ed:6f:92:51',
        'speed': '100000',
        'snappi_speed_type': 'speed_100_gbps',
        'peer_port': 'Ethernet23',
        'location': '10.36.84.33/2.8',
        'duthost': <MultiAsicSonicHost sonic-s6100-dut1>,
        'api_server_ip': '10.36.84.33',
        'asic_type': 'broadcom',
        'asic_value': None
        }
    
    Common_vars.snappi_port_groups:
        {
            'sonic-s6100-dut1': {
                1: {
                    'rx_ports': [
                        {
                            'ipAddress': '192.168.1.2',
                            'ipGateway': '192.168.1.3',
                            'prefix': 24,
                            'subnet': '192.168.1.0/24',
                            'src_mac_address': 'aa:00:00:00:00:00',
                            'router_mac_address': '9c:69:ed:6f:92:51',
                            'speed': '100000',
                            'snappi_speed_type': 'speed_100_gbps',
                            'peer_port': 'Ethernet0',
                            'location': '10.36.84.33/1.1',
                            'duthost': <MultiAsicSonicHost sonic-s6100-dut1>,
                            'api_server_ip': '10.36.84.33',
                            'asic_type': 'broadcom',
                            'asic_value': None
                        }
                    ],
                    'tx_ports': [
                        {
                            'ipAddress': '192.168.1.4',
                            'ipGateway': '192.168.1.3',
                            'prefix': 24,
                            'subnet': '192.168.1.0/24',
                            'src_mac_address': 'aa:00:00:00:00:01',
                            'router_mac_address': '9c:69:ed:6f:92:51',
                            'speed': '100000',
                            'snappi_speed_type': 'speed_100_gbps',
                            'peer_port': 'Ethernet1',
                            'location': '10.36.84.33/1.2',
                            'duthost': <MultiAsicSonicHost sonic-s6100-dut1>,
                            'api_server_ip': '10.36.84.33',
                            'asic_type': 'broadcom',
                            'asic_value': None,
                            'total_weight': 0
                        },
                        {
                            'ipAddress': '192.168.1.5',
                            'ipGateway': '192.168.1.3',
                            'prefix': 24,
                            'subnet': '192.168.1.0/24',
                            'src_mac_address': 'aa:00:00:00:00:02',
                            'router_mac_address': '9c:69:ed:6f:92:51',
                            'speed': '100000',
                            'snappi_speed_type': 'speed_100_gbps',
                            'peer_port': 'Ethernet2',
                            'location': '10.36.84.33/1.3',
                            'duthost': <MultiAsicSonicHost sonic-s6100-dut1>,
                            'api_server_ip': '10.36.84.33',
                            'asic_type': 'broadcom',
                            'asic_value': None,
                            'total_weight': 0
                        }
                    ],
                    'port_list': [],
                    'queue_id_list': [],
                    'total_weight': 0,
                    'dscp_tos_generator': {},
                    'traffic_items': [{'traffic_item_name': 'sonic-s6100-dut1:Ethernet1 SrcIp:192.168.1.4 QID:0 TC:0 DSCP:8 scheduler.0 WT:95 TTl_WT:305 Expected_Loss%:5',
                                        'pfc_queue_id': 0,
                                        'dscp_phb_value': 8,
                                        'ip_address': '192.168.1.4',
                                        'router_mac_address': '9c:69:ed:6f:92:51',
                                        'src_mac_address': 'aa:00:00:00:00:01',
                                        'location': '10.36.84.33/1.2',
                                        'dut_hostname': 'sonic-s6100-dut1',
                                        'peer_port': 'Ethernet1'
                                       },
                                       {'traffic_item_name': 'sonic-s6100-dut1:Ethernet2 SrcIp:192.168.1.5 QID:1 TC:1 DSCP:1 scheduler.1 WT:5 TTl_WT:305 Expected_Loss%:95',
                                        'pfc_queue_id': 1,
                                        'dscp_phb_value': 1,
                                        'ip_address': '192.168.1.5',
                                        'router_mac_address': '9c:69:ed:6f:92:51',
                                        'src_mac_address': 'aa:00:00:00:00:02',
                                        'location': '10.36.84.33/1.3',
                                        'dut_hostname': 'sonic-s6100-dut1',
                                        'peer_port': 'Ethernet2'
                                    }]
                }
            }    
    """ 
    # 1> Get all of the dut hosts first
    all_dut_host_names = []
    for snappi_port in snappi_port_configs:
        if snappi_port['duthost'].hostname not in all_dut_host_names:
            all_dut_host_names.append(snappi_port['duthost'].hostname)
        
    # 2> For each dut host, get port-groups.ports
    # Get unique port-group list from snappi port locations
    for dut_hostname in all_dut_host_names:
        # Get all the user defined ports for the test.  Ports are not neccessarily in 
        # the order of 1,2,3,4.  It could be 1,3,5,7
        port_group_range = []
           
        for snappi_port in snappi_port_configs:
            if snappi_port['duthost'].hostname == dut_hostname:
                location = snappi_port['location']
                 # ['10.36.84.33', '1.1'] or ['10.36.78.53;4;5'] -> ['10.36.78.53, '4', '5']
                if '/' in location:
                    port = location.split('/')
                    port_group = port[1].split('.')[0]
                    
                if ';' in location:
                    port = location.split(';')
                    port_group = port[1]
                
                if int(port_group) not in port_group_range:
                    port_group_range.append(int(port_group))
                    
        Common_vars.snappi_port_groups[dut_hostname] = {}

        # Group ports into 8 ports per Resource-Group (1=RxPort 7=TxPort)
        # snappi_port_number = 2 in this example -> 10.36.84.33/2.8
        for snappi_port_group_number in port_group_range:
            Common_vars.snappi_port_groups[dut_hostname][snappi_port_group_number] = {'rx_ports': [],
                                                                                      'tx_ports': [],
                                                                                      'port_list': [],
                                                                                      'queue_id_list': [],
                                                                                      'dscp_tos_generator': {},
                                                                                      'traffic_items': []}
            index = 0

            # The rx-port goes on rotation in the snappi_port_configs list of ports
            for snappi_port in snappi_port_configs:
                if snappi_port['duthost'].hostname == dut_hostname:
                    # As of this writing, the testcase requires 8 AriesOne ports
                    # The port location begins with 1.#
                    # 'location': '10.36.84.33/2.8'
                    if '/' in snappi_port['location']:
                        location_port_group_number = int(snappi_port['location'].split('/')[-1].split('.')[0])
                        
                    if ';' in snappi_port['location']:
                        location_port_group_number = int(snappi_port['location'].split(';')[1])
                                        
                    if location_port_group_number == snappi_port_group_number:
                        Common_vars.snappi_port_groups[dut_hostname][snappi_port_group_number]['port_list'].append(snappi_port)

        # Below will only be processed if the current dut has ports defined in links.csv file
        for snappi_port_group_number in port_group_range:
            if snappi_port_group_number != port_group_range[-1]:
                current_port_group_index = port_group_range.index(snappi_port_group_number)
                inter_port_group_number = port_group_range[current_port_group_index + 1]
            else:
                # The last port-group sends to the first port-group
                inter_port_group_number = port_group_range[0]
            
            # Get the next port-group as rx-port
            rx_port = Common_vars.snappi_port_groups[dut_hostname][inter_port_group_number]['port_list'][rx_port_index]
            Common_vars.snappi_port_groups[dut_hostname][snappi_port_group_number]['rx_ports'].append(rx_port)
               
            # Build the tx-port list            
            for index,tx_port in enumerate(Common_vars.snappi_port_groups[dut_hostname][snappi_port_group_number]['port_list']):
                if index != rx_port_index:
                    Common_vars.snappi_port_groups[dut_hostname][snappi_port_group_number]['tx_ports'].append(tx_port)
                    tx_port.update({'total_weight': 0})

        for snappi_port_group_number in port_group_range:
            # Remove the list. Save memory.
            if snappi_port_group_number in Common_vars.snappi_port_groups[dut_hostname].keys():
                Common_vars.snappi_port_groups[dut_hostname][snappi_port_group_number]['port_list'] = []

def define_tx_rx_intra_port_testing(snappi_port_configs, duthosts, rx_port_index):
    """
    For "INTRA-PORT" testing
    Create tx_ports|rx_ports list
    """
    # 1> Get all of the dut hosts first
    all_dut_host_names = []
    for snappi_port in snappi_port_configs:
        if snappi_port['duthost'].hostname not in all_dut_host_names:
            all_dut_host_names.append(snappi_port['duthost'].hostname)

    # 2> For each dut host, get port-groups.ports
    # Get unique port-group list from snappi port locations
    for dut_hostname in all_dut_host_names: 
        # Get all the user defined ports for the test.  Ports are not neccessarily in 
        # the order of 1,2,3,4.  It could be 1,3,5,7
        port_group_range = []
                   
        # Get unique port-group list from snappi port locations
        for snappi_port in snappi_port_configs:
            if snappi_port['duthost'].hostname == dut_hostname:
                location = snappi_port['location']
                 # ['10.36.84.33', '1.1'] or ['10.36.78.53;4;5'] -> ['10.36.78.53, '4', '5']
                if '/' in location:
                    port = location.split('/')
                    port_group = port[1].split('.')[0]
                    
                if ';' in location:
                    port = location.split(';')
                    port_group = port[1]
                
                if int(port_group) not in port_group_range:
                    port_group_range.append(int(port_group))
    
        Common_vars.snappi_port_groups[dut_hostname] = {}

        # Group ports into 8 ports (1=RxPort 7=TxPort)
        # snappi_port_number = 2 in this example -> 10.36.84.33/2.8
        for snappi_port_group_number in port_group_range:
            Common_vars.snappi_port_groups[dut_hostname][snappi_port_group_number] = {'rx_ports': [],
                                                                                      'tx_ports': [],
                                                                                      'queue_id_list': [],
                                                                                      'dscp_tos_generator': {},
                                                                                      'traffic_items': []}
            index = 0
                    
            # The rx-port goes on rotation in the snappi_port_configs list of ports
            for snappi_port in snappi_port_configs:
                if snappi_port['duthost'].hostname == dut_hostname:
                    # As of this writing, the testcase requires 8 AriesOne ports
                    # The port location begins with 1.#
                    # 'location': '10.36.84.33/2.8'
                    if '/' in snappi_port['location']:
                        location_port_group_number = int(snappi_port['location'].split('/')[-1].split('.')[0])
                        
                    if ';' in snappi_port['location']:
                        location_port_group_number = int(snappi_port['location'].split(';')[1])

                    if location_port_group_number == snappi_port_group_number:
                        if index == rx_port_index:
                            Common_vars.snappi_port_groups[dut_hostname][snappi_port_group_number]['rx_ports'].append(snappi_port)
                        else:
                            # Preset the total_weight with 0. This will get incremented when calculating the tx-port total weight
                            snappi_port.update({'total_weight': 0})
                            Common_vars.snappi_port_groups[dut_hostname][snappi_port_group_number]['tx_ports'].append(snappi_port)
                            
                        index += 1

def verify_dwrr_pass_criteria(snappi_api):
    selected_view_columns = ['Tx Port', 'Rx Port', 'Traffic Item', 'Tx Frames', 'Rx Frames', 'Frames Delta', 'Loss %']

    flow_stats = get_flow_statistics(snappi_api, 
                                     stat_view_name='Flow Statistics', 
                                     stat_view_columns=selected_view_columns,
                                     show_tabulated_table=True)
    
    for flow in flow_stats:     
        # flow: {'Tx Port': 'Port_2', 'Rx Port': 'Port_1', 'Traffic Item': 'sonic-s6100-dut1:Ethernet1 SrcIp:192.168.1.2 QID:0 TC:0 DSCP:0 scheduler.0 WT:1 TTl_WT:91 Expected_Loss%:98.9', 
        #        'Tx Frames': '43143573', 'Rx Frames': '1763514', 'Frames Delta': '41380059', 'Loss %': '95.912'} 
        tx_port = flow['Tx Port']
        rx_port = flow['Rx Port']
        traffic_item = flow['Traffic Item']
        flow_loss_percentage = float(flow['Loss %'])
                     
        # ['sonic-s6100-dut1:Ethernet84', 'SrcIp:192.168.1.47', 'QID:3', 'TC:3', 'DSCP:3', 'scheduler.3', 'WT:30', 'TTl_WT:91', 'Expected_Loss%:67.0']
        expected_loss_pct = round(float(traffic_item.split(' ')[-1].split(':')[1]), 2)
            
        # Allow 1% threshold for passing criteria
        traffic_flow_pass_criteria = round((expected_loss_pct * Common_vars.pass_threshold_pct), 2)
        loss_delta = round(abs(flow_loss_percentage - expected_loss_pct), 2)
        
        logger.info(f'verify_dwrr_pass_criteria: {tx_port} -> {rx_port} Loss%:{flow_loss_percentage}  Expected_Loss:{expected_loss_pct}  Loss_Delta:{loss_delta}  Exceptable {Common_vars.pass_threshold_pct}%  Loss-Threshold:{traffic_flow_pass_criteria}')
        
        failed_message = f'Expecting Loss%:{expected_loss_pct}  Rx-Loss:{flow_loss_percentage}  Loss-Delta:{loss_delta}  Exceptable {Common_vars.pass_threshold_pct}% loss-threshold:{traffic_flow_pass_criteria}'
        pytest_assert(loss_delta < traffic_flow_pass_criteria, failed_message)