# uncompyle6 version 3.9.0
# Python bytecode version base 2.7 (62211)
# Decompiled from: Python 3.10.4 (tags/v3.10.4:9d38120, Mar 23 2022, 23:13:41) [MSC v.1929 64 bit (AMD64)]
# Embedded file name: /var/johnar/sonic-mgmt/tests/snappi/multi_dut_rdma/files/rdma_helper.py
# Compiled at: 2023-02-10 09:15:26
import time
from math import ceil
import logging
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts
from tests.common.snappi.snappi_helpers import get_dut_port_id
from tests.common.snappi.common_helpers import pfc_class_enable_vector, stop_pfcwd, disable_packet_aging
from tests.common.snappi.port import select_ports
from tests.common.snappi.snappi_helpers import wait_for_arp
logger = logging.getLogger(__name__)
PAUSE_FLOW_NAME = 'Pause Storm'
TEST_FLOW_NAME = 'Test Flow'
TEST_FLOW_AGGR_RATE_PERCENT = 30
BG_FLOW_NAME = 'Background Flow'
BG_FLOW_AGGR_RATE_PERCENT = 25
DATA_PKT_SIZE = 1024
DATA_FLOW_DURATION_SEC = 2
DATA_FLOW_DELAY_SEC = 1
SNAPPI_POLL_DELAY_SEC = 2
TOLERANCE_THRESHOLD = 0.05
PORT_SPEED = 'speed_100_gbps'

def run_pfc_test(api,
                testbed_config,
                port_config_list,
                conn_data,
                fanout_data,
                duthost1,
                rx_port,
                rx_port_id_list,
                duthost2, tx_port,
                tx_port_id_list,
                dut_port,
                pause_prio_list,
                test_prio_list,
                bg_prio_list,
                prio_dscp_map):
    """
    Run PFC watchdog test in a multi-node (>=3) topoology

    Args:
        api (obj): SNAPPI session
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        conn_data (dict): the dictionary returned by conn_graph_fact.
        fanout_data (dict): the dictionary returned by fanout_graph_fact.
        duthost (Ansible host instance): device under test
        dut_port (str): DUT port to test
        pause_prio_list (list): priorities to pause for PFC pause storm
        test_prio_list (list): priorities of test flows
        bg_prio_list (list): priorities of background flows
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).
    Returns:
        N/A
    """
    pytest_assert(testbed_config is not None, 'Fail to get L2/3 testbed config')
    stop_pfcwd(duthost1, rx_port['asic_value'])
    disable_packet_aging(duthost1)
    stop_pfcwd(duthost2, tx_port[0]['asic_value'])
    disable_packet_aging(duthost2)

    #test_flow_rate_percent = int(TEST_FLOW_AGGR_RATE_PERCENT / len(test_prio_list))
    #bg_flow_rate_percent = int(BG_FLOW_AGGR_RATE_PERCENT / len(bg_prio_list))
    test_flow_rate_percent = int(TEST_FLOW_AGGR_RATE_PERCENT)
    bg_flow_rate_percent = int(BG_FLOW_AGGR_RATE_PERCENT)
    exp_dur_sec = 5
    __gen_traffic(testbed_config=testbed_config,
                port_config_list=port_config_list,
                rx_port_id_list=rx_port_id_list,
                tx_port_id_list=tx_port_id_list,
                pause_flow_name=PAUSE_FLOW_NAME,
                pause_prio_list=pause_prio_list,
                test_flow_name=TEST_FLOW_NAME,
                test_flow_prio_list=test_prio_list,
                test_flow_rate_percent=test_flow_rate_percent,
                bg_flow_name=BG_FLOW_NAME,
                bg_flow_prio_list=bg_prio_list,
                bg_flow_rate_percent=bg_flow_rate_percent,
                data_flow_dur_sec=DATA_FLOW_DURATION_SEC,
                data_pkt_size=DATA_PKT_SIZE,
                prio_dscp_map=prio_dscp_map)
    
    flows = testbed_config.flows
    all_flow_names = [ flow.name for flow in flows ]
    flow_stats = __run_traffic(api=api, 
                                config=testbed_config, 
                                all_flow_names=all_flow_names,
                                exp_dur_sec=exp_dur_sec,
                                duthost=duthost1)
    speed_str = testbed_config.layer1[0].speed
    speed_gbps = int(speed_str.split('_')[1])

    __verify_results(rows=flow_stats,
                     test_flow_name=TEST_FLOW_NAME,
                     bg_flow_name=BG_FLOW_NAME,
                     rx_port=rx_port)

def __data_flow_name(name_prefix, src_id, dst_id, prio):
    """
    Generate name for a data flow

    Args:
        name_prefix (str): name prefix
        src_id (int): ID of the source port
        dst_id (int): ID of the destination port
        prio (int): priority of the flow

    Returns:
        Name of the flow (str)
    """
    return ('{} {} -> {} Prio {}').format(name_prefix, src_id, dst_id, prio)


def __gen_traffic(testbed_config,
                port_config_list,
                rx_port_id_list,
                tx_port_id_list,
                pause_flow_name,
                pause_prio_list,
                test_flow_name,
                test_flow_prio_list,
                test_flow_rate_percent,
                bg_flow_name,
                bg_flow_prio_list,
                bg_flow_rate_percent,
                data_flow_dur_sec,
                data_pkt_size,
                prio_dscp_map):
    """
    Generate configurations of flows under all to all traffic pattern, including
    test flows, background flows and pause storm. Test flows and background flows
    are also known as data flows.

    Args:
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        port_id (int): ID of DUT port to test.
        pause_flow_name (str): name of pause storm
        pause_prio_list (list): priorities to pause for PFC frames
        test_flow_name (str): name prefix of test flows
        test_prio_list (list): priorities of test flows
        test_flow_rate_percent (int): rate percentage for each test flow
        bg_flow_name (str): name prefix of background flows
        bg_prio_list (list): priorities of background flows
        bg_flow_rate_percent (int): rate percentage for each background flow
        data_flow_dur_sec (int): duration of data flows in second
        pfc_storm_dur_sec (float): duration of the pause storm in second
        data_pkt_size (int): packet size of data flows in byte
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).

    Returns:
        N/A
    """
    __gen_data_flows(testbed_config=testbed_config,
                    port_config_list=port_config_list,
                    src_port_id_list=tx_port_id_list,
                    dst_port_id_list=rx_port_id_list,
                    flow_name_prefix=TEST_FLOW_NAME,
                    flow_prio_list=test_flow_prio_list,
                    flow_rate_percent=test_flow_rate_percent,
                    flow_dur_sec=data_flow_dur_sec,
                    data_pkt_size=data_pkt_size,
                    prio_dscp_map=prio_dscp_map)

    __gen_data_flows(testbed_config=testbed_config,
                    port_config_list=port_config_list,
                    src_port_id_list=tx_port_id_list,
                    dst_port_id_list=rx_port_id_list,
                    flow_name_prefix=BG_FLOW_NAME,
                    flow_prio_list=bg_flow_prio_list,
                    flow_rate_percent=bg_flow_rate_percent,
                    flow_dur_sec=data_flow_dur_sec,
                    data_pkt_size=data_pkt_size,
                    prio_dscp_map=prio_dscp_map)


def __gen_data_flows(testbed_config, 
                    port_config_list, 
                    src_port_id_list,
                    dst_port_id_list,
                    flow_name_prefix, 
                    flow_prio_list, 
                    flow_rate_percent, 
                    flow_dur_sec, 
                    data_pkt_size,
                    prio_dscp_map):
    """
    Generate the configuration for data flows

    Args:
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        src_port_id_list (list): IDs of source ports
        dst_port_id_list (list): IDs of destination ports
        flow_name_prefix (str): prefix of flows' names
        flow_prio_list (list): priorities of data flows
        flow_rate_percent (int): rate percentage for each flow
        flow_dur_sec (int): duration of each flow in second
        data_pkt_size (int): packet size of data flows in byte
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).

    Returns:
        N/A
    """
    for src_port_id in src_port_id_list:
        for dst_port_id in dst_port_id_list:
            if src_port_id == dst_port_id:
                continue
            __gen_data_flow(testbed_config=testbed_config,
                            port_config_list=port_config_list, 
                            src_port_id=src_port_id, 
                            dst_port_id=dst_port_id,
                            flow_name_prefix=flow_name_prefix,
                            flow_prio=flow_prio_list, 
                            flow_rate_percent=flow_rate_percent,
                            flow_dur_sec=flow_dur_sec, 
                            data_pkt_size=data_pkt_size,
                            prio_dscp_map=prio_dscp_map)


def __gen_data_flow(testbed_config,
                    port_config_list,
                    src_port_id, 
                    dst_port_id, 
                    flow_name_prefix, 
                    flow_prio, 
                    flow_rate_percent, 
                    flow_dur_sec, 
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
        data_pkt_size (int): packet size of the flow in byte
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).

    Returns:
        N/A
    """
    tx_port_config = next((x for x in port_config_list if x.id == src_port_id), None)
    rx_port_config = next((x for x in port_config_list if x.id == dst_port_id), None)
    tx_mac = tx_port_config.mac
    if tx_port_config.gateway == rx_port_config.gateway and tx_port_config.prefix_len == rx_port_config.prefix_len:
        rx_mac = rx_port_config.mac
    else:
        rx_mac = tx_port_config.gateway_mac

    flow = testbed_config.flows.flow(name='{} {} -> {}'.format(flow_name_prefix,src_port_id,dst_port_id))[-1]
    flow.tx_rx.port.tx_name = testbed_config.ports[src_port_id].name
    flow.tx_rx.port.rx_name = testbed_config.ports[dst_port_id].name
    eth, ipv4 = flow.packet.ethernet().ipv4()
    eth.src.value = tx_mac
    eth.dst.value = rx_mac
    ipv4.src.value = tx_port_config.ip
    ipv4.dst.value = rx_port_config.ip
    ipv4.priority.choice = ipv4.priority.DSCP
    flow_prio_dscp_list = []
    for fp in flow_prio:
        for val in prio_dscp_map[fp]:
            flow_prio_dscp_list.append(val)

    ipv4.priority.dscp.phb.values = flow_prio_dscp_list
    ipv4.priority.dscp.ecn.value = ipv4.priority.dscp.ecn.CAPABLE_TRANSPORT_1
    flow.size.fixed = data_pkt_size
    flow.rate.percentage = flow_rate_percent
    flow.duration.choice = flow.duration.CONTINUOUS
    flow.duration.continuous.delay.nanoseconds = 0

    flow.metrics.enable = True
    flow.metrics.loss = True

def start_traffic(api,flow_names):
    logger.info("Starting traffic on :{}".format(flow_names))
    ts = api.transmit_state()
    ts.flow_names = flow_names
    ts.state = ts.START
    api.set_transmit_state(ts)

def stop_traffic(api,flow_names):
    logger.info("Stopping traffic on :{}".format(flow_names))
    ts = api.transmit_state()
    ts.flow_names = flow_names
    ts.state = ts.STOP
    api.set_transmit_state(ts)

def __run_traffic(api, config, all_flow_names, exp_dur_sec, duthost):
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
    test_traffic,bg_traffic=[],[]
    api.set_config(config)

    logger.info('Wait for Arp to Resolve ...')
    wait_for_arp(api, max_attempts=10, poll_interval_sec=2)
    duthost.command("sonic-clear counters \n")
    logger.info('Starting transmit on all flows ...')
    for flow in all_flow_names:
        if 'Test Flow' in flow:
            test_traffic.append(flow)
        else:
            bg_traffic.append(flow)
    logger.info('Start Traffic..')
    start_traffic(api,bg_traffic)
    time.sleep(5)
    start_traffic(api,test_traffic)

    logger.info('Stop Traffic..')
    stop_traffic(api,all_flow_names)
    var = duthost.shell("show interface counters")['stdout']
    """ Dump per-flow statistics """
    request = api.metrics_request()
    request.flow.flow_names = all_flow_names
    rows = api.get_metrics(request).flow_metrics
    file1 = open('myfile.txt', 'w+')
    file1.writelines(var)
    return rows
'''
def is_traffic_stopped(api, flow_names=[]):
    """
    Returns true if traffic in stop state
    """
    fq = api.metrics_request()
    fq.flow.flow_names = flow_names
    metrics = api.get_metrics(fq).flow_metrics
    return all([m.transmit == "stopped" for m in metrics])
'''
def __verify_results(rows,
                     test_flow_name,
                     bg_flow_name,
                     rx_port):
    """
    Verify if we get expected experiment results

    Args:
        rows (list): per-flow statistics
        speed_gbps (int): link speed in Gbps
        pause_flow_name (str): name of pause storm
        test_flow_name (str): name of test flows
        bg_flow_name (str): name of background flows
        test_flow_rate_percent (int): rate percentage for each test flow
        bg_flow_rate_percent (int): rate percentage for each background flow
        data_pkt_size (int): packet size of data flows in byte
        test_flow_pause (bool): if test flows are expected to be paused
        trigger_pfcwd (bool): if PFC watchdog is expected to be triggered
        pause_port_id (int): ID of the port to send PFC pause frames
        tolerance (float): maximum allowable deviation

    Returns:
        N/A
    """
    sum=1
    for row in rows:
        if bg_flow_name in row.name:
            tx_frames = row.frames_tx
            rx_frames = row.frames_rx
            logger.info('{}, TX Frames:{}, RX Frames:{}'.format(row.name, tx_frames, rx_frames))
            pytest_assert(tx_frames == rx_frames,
                        '{} should not have any dropped packet'.format(row.name))
            pytest_assert(row.loss == 0,
                        '{} should not have traffic loss'.format(row.name))
            sum+=int(row.frames_rx)
        else:
            tx_frames = row.frames_tx
            rx_frames = row.frames_rx
            logger.info('{}, TX Frames:{}, RX Frames:{}'.format(row.name, tx_frames, rx_frames))
            pytest_assert(tx_frames != rx_frames,
                        '{} should have dropped packet'.format(row.name))
            pytest_assert(row.loss > 0,
                    '{} should have traffic loss'.format(row.name))
            sum+=int(row.frames_rx)

    logger.info('Total Frames Received on Rx Port : {}'.format(sum))
    with open('myfile.txt') as f:
        while True:
            line = f.readline()
            if not line:
                break
            if rx_port['peer_port'] in line:
                logger.info('DUT Counter for {} : {}'.format(rx_port['peer_port'],line))
                if str(format(sum, ',')) in line.split(' '):
                    logger.info('PASS: DUT counters match with the total frames received on Rx port')
                else:
                    pytest_assert(False,"FAIL: DUT counters doesn't match with the total frames received on Rx port")
