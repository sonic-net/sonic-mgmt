import logging
import pytest
from re import match, search

from tests.snappi_tests.qos.files.qos_priority_helper import read_dut_configs, create_snappi_flows, clear_dut_stat_counters, run_traffic, get_flow_statistics

from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts, fanout_graph_facts_multidut                      # noqa F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
     snappi_api,  get_snappi_ports, get_snappi_ports_single_dut, get_snappi_ports_multi_dut, snappi_testbed_config     # noqa F401

from tests.snappi_tests.dataplane.files.helper import get_duthost_vlan_details, set_primary_chassis, create_snappi_l1config, create_snappi_config

from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.common.snappi_tests.snappi_helpers import wait_for_arp
 
from rich import print as pr
       
logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology('tgen')]

class Common_vars:
    ports_per_group = 8
    total_tx_ports = 7
    traffic_flows = []
    snappi_port_groups = {}
    dut_qos_configs = {}
    frame_size = 4096
    line_rate_percentage = 100
    flow_duration_seconds = 10
    pass_threshold_pct = 0.01
    snappi_vports = None        
    # For inter-port testing
    total_port_groups = 0
    
    # Enable dut queue stat counters. WRED testing.
    dut_queue_stat_counters = []
    
    
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
    - 2 TxPorts -> 1 RxPort
    - Dut change the ECN marker bit from 2 to 3
    - Compare dut stats with traffic generator's egress status
    
    +---------+---------+-----------------------------------------------------------------------------------+-----------------+-----------+-----------+--------------+--------+
    | Tx Port | Rx Port | Traffic Item                                                                      | Egress Tracking | Tx Frames | Rx Frames | Frames Delta | Loss % |
    +---------+---------+-----------------------------------------------------------------------------------+-----------------+-----------+-----------+--------------+--------+
    | Port_2  | Port_1  | SrcIp:192.168.1.2 QID:0 TC:0 DSCP:8 scheduler.0 WT:95 TTl_WT:305 Expected_Loss%:5 | Custom:         | 42983931  | 40840326  | 2143605      | 4.987  |
    |         |         |                                                                                   | 2               |           | 5863      |              |        |
    |         |         |                                                                                   | 3               |           | 40834463  |              |        |
    | Port_3  | Port_1  | SrcIp:192.168.1.4 QID:1 TC:1 DSCP:1 scheduler.1 WT:5 TTl_WT:305 Expected_Loss%:95 | Custom:         | 42983931  | 2157751   | 40826180     | 94.980 |
    |         |         |                                                                                   | 2               |           | 299       |              |        |
    |         |         |                                                                                   | 3               |           | 2157452   |              |        |
    +---------+---------+-----------------------------------------------------------------------------------+-----------------+-----------+-----------+--------------+--------+

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
    
    define_rx_tx_dwrr_wred_port_testing(snappi_ports, duthosts)
    read_dut_configs(Common_vars, duthosts, typeOfTest='dwrr+wred')
    
    snappi_configs = create_snappi_flows(Common_vars,
                                         duthosts,
                                         snappi_config,
                                         snappi_api,
                                         snappi_ports)
    
    config_snappi_egress_tracking_wred(snappi_api,
                                       egress_encapsulation='Any: Use Custom Settings',
                                       egress_custom_offset_bits=126,
                                       egress_width_bits=2,
                                       egress_offset="Custom",
                                       egress_stat_view_name='EgressStats')
    
    clear_dut_stat_counters(duthosts)
    run_traffic(Common_vars, api=snappi_api, config=snappi_configs)
    verify_dwrr_wred_pass_criteria(duthosts, snappi_api)


def define_rx_tx_dwrr_wred_port_testing(snappi_port_configs, duthosts):
    """ 
    2 TxPorts - > 1 RxPort
    """
    # 1> Get all of the dut hosts first
    all_dut_host_names = []
    for snappi_port in snappi_port_configs:
        if snappi_port['duthost'].hostname not in all_dut_host_names:
            all_dut_host_names.append(snappi_port['duthost'].hostname)
    
    dut_hostname = all_dut_host_names[0]
    
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
                # 'location': '10.36.84.33/2.8' | 10.36.78.53;4;5
                if '/' in snappi_port['location']:
                    location_port_group_number = int(snappi_port['location'].split('/')[-1].split('.')[0])
                    
                if ';' in snappi_port['location']:
                    location_port_group_number = int(snappi_port['location'].split(';')[1])
                    
                if location_port_group_number == snappi_port_group_number:
                    if index == 0:
                        Common_vars.snappi_port_groups[dut_hostname][snappi_port_group_number]['rx_ports'].append(snappi_port)
                    
                    if index in [1, 2]:
                        # Preset the total_weight with 0. This will get incremented when calculating the tx-port total weight
                        snappi_port.update({'total_weight': 0})
                        Common_vars.snappi_port_groups[dut_hostname][snappi_port_group_number]['tx_ports'].append(snappi_port)
                        
                    index += 1
    
    
def config_snappi_egress_tracking_wred(snappi_api, egress_encapsulation, egress_custom_offset_bits,
                                       egress_width_bits, egress_offset="Custom", egress_stat_view_name='EgressStats'):
    """ 
    Configure Snappi egress tracking to verify dut egress packets
    """
    # Safety check: Apply traffic or else configuring egress tracking won't work.
    snappi_api._ixnetwork.Traffic.Apply()

    for traffic_item_obj in snappi_api._ixnetwork.Traffic.TrafficItem.find():
        tracking                         = traffic_item_obj.Tracking.find()[0]
        tracking.Egress.Encapsulation    = egress_encapsulation
        tracking.Egress.CustomOffsetBits = egress_custom_offset_bits
        tracking.Egress.CustomWidthBits  = egress_width_bits
        tracking.Egress.Offset           = egress_offset
        traffic_item_obj.EgressEnabled   = True
        traffic_item_obj.Generate()
        
    snappi_api._ixnetwork.Traffic.Apply()
    
    egressTrackingOffsetFilter = f'Custom: ({egress_width_bits} bits at offset {egress_custom_offset_bits})'
    
    # Create Egress Stats
    logger.info('\n\nCreating new statview for egress stats...')
    snappi_api._ixnetwork.Statistics.View.add(Caption=egress_stat_view_name,
                                              TreeViewNodeName='Egress Custom Views',
                                              Type='layer23TrafficFlow',
                                              Visible=True)

    egressStatViewObj = snappi_api._ixnetwork.Statistics.View.find(Caption=egress_stat_view_name)

    # Dynamically get the Traffic Items Filter ID
    availableTrafficItemFilterId = []

    for eachTrafficItemFilterId in egressStatViewObj.AvailableTrafficItemFilter.find():
        availableTrafficItemFilterId.append(eachTrafficItemFilterId.href)
            
    if availableTrafficItemFilterId == []:
        lpytest_assert(False, 'config_snappi_egress_tracking_wred: No traffic item filter ID found')

    logger.info(f'\n\navailableTrafficItemFilterId: {availableTrafficItemFilterId}\n')

    # # /api/v1/sessions/1/ixnetwork/statistics/view/12
    layer23TrafficFlowFilter = egressStatViewObj.Layer23TrafficFlowFilter.find()[0]
    layer23TrafficFlowFilter.EgressLatencyBinDisplayOption = 'showEgressRows'
    layer23TrafficFlowFilter.TrafficItemFilterIds = availableTrafficItemFilterId

    # Get the egress tracking filter
    egressTrackingFilter = None
    ingressTrackingFilter = None
    ingressTrackingFilterName = None

    # Show all the avaialable filter names/options
    for eachTrackingFilter in egressStatViewObj.AvailableTrackingFilter.find():
        # eachTrackingFilter.Name = Custom: (2 bits at offset 126)
        logger.info(f'\n\nAvailable tracking filters: {eachTrackingFilter.Name}\n')

        if bool(match('.*[0-9]+ bits at offset *[0-9]+|Flow Group', eachTrackingFilter.Name)):
            egressTrackingFilter = eachTrackingFilter.href

        if egressTrackingFilter is None:
            pytest_assert(False, f'config_snappi_egress_tracking_wred: Failed to locate your defined custom offsets: {egressTrackingOffsetFilter}')
            
        if ingressTrackingFilterName is not None:
            if eachTrackingFilter.Name == ingressTrackingFilterName:
                ingressTrackingFilter = eachTrackingFilter.href

        # # /api/v1/sessions/1/ixnetwork/statistics/view/23/availableTrackingFilter/3
        logger.info(f'Located egressTrackingFilter: {egressTrackingFilter}')
        # egressTrackingFilter: /api/v1/sessions/1/ixnetwork/statistics/view/12/availableTrackingFilter/1
        layer23TrafficFlowFilter.EnumerationFilter.add(SortDirection='ascending', TrackingFilterId=egressTrackingFilter)

        # This will include ingress tracking in the egress statview.
        if ingressTrackingFilterName is not None:
            layer23TrafficFlowFilter.EnumerationFilter.add(SortDirection='ascending', TrackingFilterId=ingressTrackingFilter)

    for eachEgressStatCounter in egressStatViewObj.Statistic.find():
        eachEgressStatCounter.Enabled = True

    egressStatViewObj.Enabled = True
    egressStatViewObj.AutoUpdate = True

def verify_dwrr_wred_pass_criteria(duthosts, snappi_api):
    """ 
    Get DUT egress stats and compare with traffic generator's rx stats
    
    show queue wredcounters Ethernet64
        Port    TxQ    EcnMarked/pkts    EcnMarked/bytes
    ----------  -----  ----------------  -----------------
    Ethernet64    UC0         160510586       295336835072
    Ethernet64    UC1           9884512        15550418104
    """
    dut_stats = {}
    doOnce = True
    current_traffic_item = ''
    selected_view_columns = ['Tx Port', 'Rx Port', 'Traffic Item', 'Egress Tracking', 'Tx Frames', 'Rx Frames', 'Frames Delta', 'Loss %']

    flow_stats = get_flow_statistics(snappi_api,
                                     stat_view_name='EgressStats',
                                     stat_view_columns=selected_view_columns,
                                     show_tabulated_table=True)

    """
    [
        {
            'Tx Port': '10.36.78.53;4;6',
            'Rx Port': '10.36.78.53;4;5',
            'Traffic Item': 'sonic-s6100-dut1:Ethernet68 SrcIp:192.168.1.3 QID:0 TC:0 DSCP:8 scheduler.0 WT:95 TTl_WT:395 Expected_Loss%:5',
            'Egress Tracking': 'Custom: (2 bits at offset 126)',
            'Tx Frames': '44446238',
            'Rx Frames': '42218514',
            'Frames Delta': '2227724',
            'Loss %': '5.012'
        },
        {'Tx Port': '', 'Rx Port': '', 'Traffic Item': '', 'Egress Tracking': '2', 'Tx Frames': '', 'Rx Frames': '5701', 'Frames Delta': '', 'Loss %': ''},
        {'Tx Port': '', 'Rx Port': '', 'Traffic Item': '', 'Egress Tracking': '3', 'Tx Frames': '', 'Rx Frames': '42212813', 'Frames Delta': '', 'Loss %': ''},
        {
            'Tx Port': '10.36.78.53;4;7',
            'Rx Port': '10.36.78.53;4;5',
            'Traffic Item': 'sonic-s6100-dut1:Ethernet72 SrcIp:192.168.1.4 QID:1 TC:1 DSCP:0 scheduler.1 WT:5 TTl_WT:395 Expected_Loss%:95',
            'Egress Tracking': 'Custom: (2 bits at offset 126)',
            'Tx Frames': '72595522',
            'Rx Frames': '3642034',
            'Frames Delta': '68953488',
            'Loss %': '94.983'
        },
        {'Tx Port': '', 'Rx Port': '', 'Traffic Item': '', 'Egress Tracking': '2', 'Tx Frames': '', 'Rx Frames': '456', 'Frames Delta': '', 'Loss %': ''},
        {'Tx Port': '', 'Rx Port': '', 'Traffic Item': '', 'Egress Tracking': '3', 'Tx Frames': '', 'Rx Frames': '3641578', 'Frames Delta': '', 'Loss %': ''}
    ]
    """    
        
    for flow in flow_stats:
        tx_port      = flow['Tx Port']
        rx_port      = flow['Rx Port']
        traffic_item = flow['Traffic Item']
        egress_stats = flow['Egress Tracking']
        tx_frames    = flow['Tx Frames']
        rx_frames    = flow['Rx Frames']
        
        if flow['Loss %'] != '':
            flow_loss_percentage = float(flow['Loss %'])
        else:
            flow_loss_percentage = flow['Loss %']

        if traffic_item != '':
            current_traffic_item = traffic_item
            expected_loss_pct = round(float(traffic_item.split(' ')[-1].split(':')[1]), 2)
                
            # Allow 1% threshold for passing criteria
            traffic_flow_pass_criteria = round((expected_loss_pct * Common_vars.pass_threshold_pct), 2)
            loss_delta = round(abs(flow_loss_percentage - expected_loss_pct), 2)
            
            logger.info(f'Verify Weight Loss%: {tx_port} -> {rx_port} Loss%:{flow_loss_percentage}  Expected_Loss:{expected_loss_pct}  Loss_Delta:{loss_delta}  Exceptable {Common_vars.pass_threshold_pct}%  Loss-Threshold:{traffic_flow_pass_criteria}')
            
            # Verify Scheduler's weight loss percentage
            failed_message = f'Expecting Loss%:{expected_loss_pct}  Rx-Loss:{flow_loss_percentage}  Loss-Delta:{loss_delta}  Exceptable {Common_vars.pass_threshold_pct}% loss-threshold:{traffic_flow_pass_criteria}'
            pytest_assert(loss_delta < traffic_flow_pass_criteria, failed_message)

        # Not every flow stat line has traffic item and traffic item line always come first
        if egress_stats != '' and egress_stats == "3":
            regex_traffic_item = search('.*QID:([0-9]+) +', current_traffic_item)
            queue_id = regex_traffic_item.group(1)
            dut_stats[int(queue_id)] = {'rxPackets': int(rx_frames)}  
                                
    for dut_host in duthosts:                    
        for port_group_num, properties in Common_vars.snappi_port_groups[dut_host.hostname].items():
            rx_port_details = properties['rx_ports'][0]

            #dut_stat_counters_obj = dut_host.shell(f"show queue wredcounters {rx_port_details['peer_port']} --json")['stdout']
            #dut_stat_counters = json.loads(dut_stat_counters_obj)
            dut_stat_counters_obj = dut_host.shell(f"show queue wredcounters {rx_port_details['peer_port']}")['stdout']
                
            # Get the index position of TxQ first
            if doOnce:
                doOnce = False
                  
                for line in dut_stat_counters_obj.split('\n'):
                    regexMatch = search('(.*TxQ.*)', line)
                    if regexMatch:
                        column_names_line = regexMatch.group(0)
                        column_names_line = column_names_line.split(' ')
                        column_names_line2 = [item for item in column_names_line if item != '']
                        txq_index = column_names_line2.index('TxQ')
                        egress_pkt_index = column_names_line2.index('EcnMarked/pkts')
                        logger.info(line)
                        break
            
            for line in dut_stat_counters_obj.split('\n'):
                if rx_port_details['peer_port'] in line:
                    each_line = line.split(' ')
                    # Remove invisible characters in each line
                    each_line2 = [item for item in each_line if item != '']

                    # each_line2: ['Ethernet64', 'UC0', '43,894,549', '179,792,072,704']      
                    tx_queue_stat = each_line2[txq_index]
                    if 'UC' not in tx_queue_stat:
                        break
                    
                    tx_queue = tx_queue_stat.split('UC')[1] 
                    
                    """ 
                    show queue wredcounters Ethernet64
                    Port    TxQ    EcnMarked/pkts    EcnMarked/bytes
                    ----------  -----  ----------------  -----------------
                    Ethernet64    UC0         160510586       295336835072
                    Ethernet64    UC1           9884512        15550418104
                    """
                    for queue in Common_vars.dut_queue_stat_counters:
                        if int(tx_queue) == queue:
                            logger.info(f'{line}')
                            egress_pkts = int(each_line2[egress_pkt_index].replace(',', ''))
                            dut_stats[int(queue)].update({'egressPackets': egress_pkts})                  
    
    # Verify Egress stats 
    for queue in Common_vars.dut_queue_stat_counters:
        logger.info(f'Verifying Egress Queue: {queue}:  EgressPkts: {dut_stats[queue]["egressPackets"]}  RxPkets: {dut_stats[queue]["rxPackets"]}')
        pytest_assert(dut_stats[queue]['egressPackets'] == dut_stats[queue]['rxPackets'],
                      f'QueueId: {queue} egressPkts:{dut_stats[queue]["egressPackets"]}  rxPkts:{dut_stats[queue]["rxPackets"]}'
                     )
    