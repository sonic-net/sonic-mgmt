import logging, time, json
from tabulate import tabulate
from re import search

from tests.common.helpers.assertions import pytest_assert
from tests.common.snappi_tests.traffic_generation import setup_base_traffic_config, generate_test_flows, \
    generate_background_flows, generate_pause_flows, run_traffic, verify_pause_flow, verify_basic_test_flow, \
    verify_background_flow, verify_pause_frame_count_dut, verify_egress_queue_frame_count, \
    verify_in_flight_buffer_pkts, verify_unset_cev_pause_frame_count, verify_tx_frame_count_dut, \
    verify_rx_frame_count_dut
from tests.common.snappi_tests.common_helpers import pfc_class_enable_vector,\
    get_lossless_buffer_size, get_pg_dropped_packets,\
    stop_pfcwd, disable_packet_aging, sec_to_nanosec,\
    get_pfc_frame_count, packet_capture, config_capture_pkt,\
    traffic_flow_mode, calc_pfc_pause_flow_rate      # noqa F401
from tests.common.snappi_tests.snappi_helpers import get_dut_port_id
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.common.snappi_tests.port import select_ports
from tests.common.snappi_tests.variables import pfcQueueGroupSize, pfcQueueValueDict
from tests.common.snappi_tests.snappi_helpers import wait_for_arp

logger = logging.getLogger(__name__)

class qos_settings:
    weight_list = [(5, 'scheduler.0'), 
                   (15, 'scheduler.1'), 
                   (20, 'scheduler.2')]

    dscp_map_priorities = {3: [3], 6: 46, 1: 8}    
    
    traffic_item_names = [('High 3: No drop', 3),
                          ('Medium 6: Weight=20 50% drop', 6),
                          ('Low 1: Weight=5 87.5% drop', 1)]
      
      
def run_qos_priority_test(snappi_api,
                          testbed_config,
                          port_config_list,
                          duthost,
                          dut_port,
                          sonic_ethernet_port_list,
                          conn_graph_facts,
                          fanout_graph_facts):
    
    pytest_assert(testbed_config is not None, 'Fail to get L2/3 testbed config') 

    # Get the ID of the port to test
    port_id = get_dut_port_id(dut_hostname=duthost.hostname,
                              dut_port=dut_port,
                              conn_data=conn_graph_facts,
                              fanout_data=fanout_graph_facts)

    pytest_assert(port_id is not None, f'Fail to get ID for port {dut_port}')
    
    tx_port_id_list, rx_port_id_list = select_ports(port_config_list=port_config_list,
                                                    pattern='many to one',
                                                    rx_port_id=port_id)

    config_dut_qos(duthost, sonic_ethernet_port_list)
     
    snappi_extra_params = SnappiTestParams()

    flows = testbed_config.flows
    all_flow_names = [flow.name for flow in flows]
    data_flow_names = [flow.name for flow in flows if PAUSE_FLOW_NAME not in flow.name]
    
    for index, src_port_id in enumerate(tx_port_id_list):
        flow_name = qos_settings.traffic_item_names [index][0]
        flow_priority = qos_settings.traffic_item_names [index][1]
        
        for dst_port_id in rx_port_id_list:
            if src_port_id == dst_port_id:
                continue

            config_qos_many_to_one(testbed_config= testbed_config,
                                   port_config_list=port_config_list,
                                   src_port_id=src_port_id,
                                   dst_port_id=dst_port_id,
                                   flow_name_prefix=flow_name,
                                   flow_prio=flow_priority,
                                   flow_rate_percent=100,
                                   flow_dur_sec=60,
                                   flow_delay_sec=0,
                                   data_pkt_size=64,
                                   prio_dscp_map=qos_settings.dscp_map_priorities)
    
    run_traffic(api=snappi_api,
                config=testbed_config,
                all_flow_names=all_flow_names,
                exp_dur_sec=10)
        
    flow_statistics_data = get_flow_statistics(snappi_api)

    # Calculating the stream loss % 
    # 15/(5+15+20)*100Gbps = 37.5Gbps is allocated to queue 3, which is lossless
    # queue 1 & queue 6 get the rest 62.5Gbps.
    # queue 1 gets 5/(5+20)*62.5 = 12.5, so its loss rate is 87.5%
    # queue 6 gets 20/(5+20)*62.5 = 50, so its loss rate is 50%
    for index, flowStats in enumerate(flow_statistics_data):
        flow_loss_pct = round(float(flowStats[6]), 1)
        
        if index == 0:
            expected_loss_pct = 0
            pytest_assert(flow_loss_pct == 0, f'High Priority. Expecting no loss. Loss %={flow_loss_pct}')
            logger.info(f'High priority. No loss expected. Passed')
            
        if index == 1:
            expected_loss_pct = calculate_traffic_loss_percentage(weight=20)
            pytest_assert(flow_loss_pct == expected_loss_pct, f'Medium Priority. Expecting {expected_loss_pct}% loss. Loss %={flow_loss_pct}')
            logger.info(f'Medium priority. Expected loss% = {expected_loss_pct}. Passed')
            
        if index == 2:
            expected_loss_pct = calculate_traffic_loss_percentage(weight=5)
            pytest_assert(flow_loss_pct == expected_loss_pct, f'Low Priority. Expecting {expected_loss_pct}% loss. Loss %={flow_loss_pct}')
            logger.info(f'Low priority. Expected loss% = {expected_loss_pct}. Passed')
  
    # Clean up DUT
    remove_dut_interface_ip_addresses(duthost, sonic_ethernet_port_list)

def calculate_traffic_loss_percentage(weight):
    '''
    step 1: Get allocated bandwidth to queue
     
       weight
    ------------  x 100 = allocated bandwidth to queue
    total weight
    
    step 2: Total bandwidth - allocated-bandwidth-to-queue = expected loss %
    
    Example:
        If weight = 15 and total weight = 40 (5, 15, 20)
        
        5/40 = 0.125 x 100 = 12.5 (allocated to queue)
        100 - 12.5 = 87.5% loss
    '''
    total_weight = 0
    for x_weight in qos_settings.weight_list:
        total_weight += int(x_weight[0])
    
    pct_allocated_to_queue = (weight / total_weight) * 100
    expected_loss_pct = 100 - pct_allocated_to_queue
    return expected_loss_pct

def config_dut_qos(duthost, sonic_ethernet_port_list):
    verifyDutSchedulerStr = duthost.shell("show runningconfiguration all")['stdout']
    verifyDutSchedulerObj = json.loads(verifyDutSchedulerStr)

    if 'scheduler.0' in verifyDutSchedulerObj['SCHEDULER']:
        if verifyDutSchedulerObj['SCHEDULER']['scheduler.0']['weight'] != '5':
            scheduler_0_current_weight = verifyDutSchedulerObj['SCHEDULER']['scheduler.0']['weight']
            logger.info(f'config_dut_qos: adding scheduler.0 weight=5')
            duthost.shell("sudo config scheduler update scheduler.0 --sched_type DWRR --weight 5")
    else:
        logger.info(f'config_dut_qos: adding scheduler.0 weight=5')
        duthost.shell("sudo config scheduler add scheduler.0 --sched_type DWRR --weight 5")

    if 'scheduler.1' in verifyDutSchedulerObj['SCHEDULER']:
        if verifyDutSchedulerObj['SCHEDULER']['scheduler.1']['weight'] != '15':
            scheduler_1_current_weight = verifyDutSchedulerObj['SCHEDULER']['scheduler.1']['weight']
            logger.info(f'config_dut_qos: updating scheduler.1 weight=15')
            duthost.shell("sudo config scheduler update scheduler.1 --sched_type DWRR --weight 15")    
    else:
        logger.info(f'config_dut_qos: adding scheduler.1 weight=15')
        duthost.shell("sudo config scheduler add scheduler.1 --sched_type DWRR --weight 15")
                             
    if 'scheduler.2' in verifyDutSchedulerObj['SCHEDULER']:
        if verifyDutSchedulerObj['SCHEDULER']['scheduler.2']['weight'] != '20':
            scheduler_2_current_weight = verifyDutSchedulerObj['SCHEDULER']['scheduler.2']['weight']
            logger.info(f'config_dut_qos: updating scheduler.2 weight=20')
            duthost.shell("sudo config scheduler update scheduler.2 --sched_type DWRR --weight 20")    
    else:
        logger.info(f'config_dut_qos: adding scheduler.2 weight=20')
        duthost.shell("sudo config scheduler add scheduler.2 --sched_type DWRR --weight 20")
        
    for interface in verifyDutSchedulerObj['QUEUE'].keys():
        #     "QUEUE": {
        #         "Ethernet120|0": {
        #             "scheduler": "scheduler.0"
        #         }
        
        # interface = interface:Ethernet120|0
        regexMatch = search(f'(Ethernet[0-9]+)\|([0-9]+)', interface)
        if regexMatch:
            ethernetInterface = regexMatch.group(1)
            pfcQueue = regexMatch.group(2)
            
            if ethernetInterface in sonic_ethernet_port_list:
                if pfcQueue in ['0', '1', '2']:
                    if verifyDutSchedulerObj['QUEUE'][interface]['scheduler'] != 'scheduler.0':
                       duthost.shell(f'sudo config interface scheduler unbind queue {ethernetInterface} {pfcQueue}')
                    else: 
                        logger.info(f'config_dut_qos: {ethernetInterface}  pfcQueue:{pfcQueue} scheduler.0')
                        duthost.shell(f'sudo config interface scheduler bind queue {ethernetInterface} {pfcQueue} scheduler.0')

                if pfcQueue in ['3', '4']:
                    if verifyDutSchedulerObj['QUEUE'][interface]['scheduler'] != 'scheduler.1':
                        duthost.shell(f'sudo config interface scheduler unbind queue {ethernetInterface} {pfcQueue}')
                    else:
                        logger.info(f'config_dut_qos: {ethernetInterface}  pfcQueue:{pfcQueue} scheduler.1')
                        duthost.shell(f'sudo config interface scheduler bind queue {ethernetInterface} {pfcQueue} scheduler.1')
                        
                if pfcQueue in ['5', '6']:
                    if verifyDutSchedulerObj['QUEUE'][interface]['scheduler'] != 'scheduler.2':
                        duthost.shell(f'sudo config interface scheduler unbind queue {ethernetInterface} {pfcQueue}')
                    else:
                        logger.info(f'config_dut_qos: {ethernetInterface}  pfcQueue:{pfcQueue} scheduler.2')
                        duthost.shell(f'sudo config interface scheduler bind queue {ethernetInterface} {pfcQueue} scheduler.2')
    
    # In case the Ethernet interface pfc-queue binding to a scheduler doesn't exists                    
    for ethInterface in sonic_ethernet_port_list:
        for item in [(0, 'scheduler.0'), (1, 'scheduler.0'), (2, 'scheduler.0'), 
                     (3, 'scheduler.1'), (4, 'scheduler.1'), 
                     (5, 'scheduler.2'), (6, 'scheduler.2')]:
            pfcQueueInt = item[0]
            scheduler = item[1]
            if f'{ethInterface}|{pfcQueueInt}' not in verifyDutSchedulerObj['QUEUE']:
                logger.info(f'config_dut_qos: adding {ethInterface}|{pfcQueueInt} {scheduler}')
                duthost.shell(f'sudo config interface scheduler bind queue {ethInterface} {pfcQueueInt} {scheduler}')

def remove_dut_interface_ip_addresses(duthost, sonic_ethernet_port_list):
    ip_int_output = duthost.shell("show ip int")['stdout_lines']
    for line in ip_int_output:
        regexMatch = search(f'(Ethernet[0-9]+) +([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+) .*', line)
        if regexMatch:
            if regexMatch.group(1) in sonic_ethernet_port_list:
                logger.info(f'Removing Sonic DUT IP interface: {regexMatch.group(1)} {regexMatch.group(2)}')
                duthost.shell(f'sudo config interface ip remove {regexMatch.group(1)} {regexMatch.group(2)}')
                        
def config_qos_many_to_one(testbed_config,
                           port_config_list,
                           src_port_id,
                           dst_port_id,
                           flow_name_prefix,
                           flow_prio,
                           flow_rate_percent,
                           flow_dur_sec,
                           flow_delay_sec,
                           data_pkt_size,
                           prio_dscp_map):
    """
    Generate the configuration for a data flow

    Args:
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        src_port_id (int): ID of the source port
        dst_port_id (int): ID of destination port
        flow_name_prefix (str): prefix of flow' name
        flow_prio_list (list): priorities of the flow
        flow_rate_percent (int): rate percentage for the flow
        flow_dur_sec (int): duration of the flow in second
        flow_delay_sec (int): delay before starting flow in second
        data_pkt_size (int): packet size of the flow in byte
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).

    Returns:
        N/A
    """
    tx_port_config = next(
        (x for x in port_config_list if x.id == src_port_id), None)
    rx_port_config = next(
        (x for x in port_config_list if x.id == dst_port_id), None)

    tx_mac = tx_port_config.mac
    if tx_port_config.gateway == rx_port_config.gateway and \
       tx_port_config.prefix_len == rx_port_config.prefix_len:
        """ If soruce and destination port are in the same subnet """
        rx_mac = rx_port_config.mac
    else:
        rx_mac = tx_port_config.gateway_mac

    flow = testbed_config.flows.flow(flow_name_prefix)[-1]
    flow.tx_rx.port.tx_name = testbed_config.ports[src_port_id].name
    flow.tx_rx.port.rx_name = testbed_config.ports[dst_port_id].name

    eth, ipv4 = flow.packet.ethernet().ipv4()
    eth.src.value = tx_mac
    eth.dst.value = rx_mac
    if pfcQueueGroupSize == 8:
        eth.pfc_queue.value = flow_prio
    else:
        eth.pfc_queue.value = pfcQueueValueDict[flow_prio]

    ipv4.src.value = tx_port_config.ip
    ipv4.dst.value = rx_port_config.ip
    ipv4.priority.choice = ipv4.priority.DSCP
    
    if type(prio_dscp_map[flow_prio]) is list:
        ipv4.priority.dscp.phb.values = prio_dscp_map[flow_prio]
    else:
        ipv4.priority.dscp.phb.value = prio_dscp_map[flow_prio]
        
    ipv4.priority.dscp.ecn.value = (
        ipv4.priority.dscp.ecn.CAPABLE_TRANSPORT_1)

    flow.size.fixed = data_pkt_size
    flow.rate.percentage = flow_rate_percent
    flow.duration.fixed_seconds.seconds = flow_dur_sec
    flow.duration.fixed_seconds.delay.nanoseconds = int(
        sec_to_nanosec(flow_delay_sec))

    flow.metrics.enable = True
    flow.metrics.loss = True

def run_traffic(api, config, all_flow_names, exp_dur_sec):
    """
    Run traffic and dump per-flow statistics

    Args:
        api (obj): SNAPPI session
        config (obj): experiment config (testbed config + flow config)
        all_flow_names (list): list of names of all the flows
        exp_dur_sec (int): experiment duration in second

    Returns:
        per-flow statistics (list)
    """
    api.set_config(config)
       
    logger.info('Wait for Arp to Resolve ...')
    wait_for_arp(api, max_attempts=30, poll_interval_sec=2)

    logger.info('Starting transmit on all flows ...')
    ts = api.transmit_state()
    ts.state = ts.START
    api.set_transmit_state(ts)

    time.sleep(exp_dur_sec)

    logger.info('Stop transmit on all flows ...')
    ts = api.transmit_state()
    ts.state = ts.STOP
    api.set_transmit_state(ts)    
    time.sleep(5)

def get_flow_statistics(snappi_api):
    flowStatistics = snappi_api._assistant.StatViewAssistant('Flow Statistics')
    viewSelectedColumns = ['Tx Port', 'Rx Port', 'Traffic Item', 'Tx Frames', 'Rx Frames', 'Frames Delta', 'Loss %']
    columnHeaders = flowStatistics.ColumnHeaders[1:]
    getColumnIndexes = []
    
    for column in viewSelectedColumns:
        index = columnHeaders.index(column)
        getColumnIndexes.append(index)
    
    data = []
    for flowStat in flowStatistics.Rows.RawData:
        currentData = []
        for index in getColumnIndexes:
            currentData.append(flowStat[index])
            
        data.append(currentData)
                                      
    table = tabulate(
        data,
        headers=columnHeaders,
        tablefmt="psql",
        numalign="right",
        stralign="left",
        colalign=("left", "left", "left")
    ) 
      
    logger.info(f'\n{table}') 
    return data