import time
from math import ceil
from itertools import permutations
import logging

from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts
from tests.common.ixia.ixia_fixtures import ixia_api_serv_ip, ixia_api_serv_port
from tests.common.ixia.ixia_helpers import get_dut_port_id
from tests.common.ixia.common_helpers import pfc_class_enable_vector,\
    start_pfcwd, enable_packet_aging, get_pfcwd_poll_interval, get_pfcwd_detect_time

logger = logging.getLogger(__name__)


PAUSE_FLOW_NAME = 'Pause Storm'
TEST_FLOW_NAME = 'Test Flow'
TEST_FLOW_AGGR_RATE_PERCENT = 45
BG_FLOW_NAME = 'Background Flow'
BG_FLOW_AGGR_RATE_PERCENT = 45
DATA_PKT_SIZE = 1024
IXIA_POLL_DELAY_SEC = 2
TOLERANCE_THRESHOLD = 0.05

def run_pfcwd_multi_node_test(api,
                              testbed_config,
                              conn_data,
                              fanout_data,
                              duthost,
                              dut_port,
                              pause_prio_list,
                              test_prio_list,
                              bg_prio_list,
                              prio_dscp_map,
                              trigger_pfcwd,
                              pattern):
    """
    Run PFC watchdog test in a multi-node (>=3) topoology

    Args:
        api (obj): snappi API session
        testbed_config (obj): L2/L3 config of a T0 testbed
        conn_data (dict): the dictionary returned by conn_graph_fact.
        fanout_data (dict): the dictionary returned by fanout_graph_fact.
        duthost (Ansible host instance): device under test
        dut_port (str): DUT port to test
        pause_prio_list (list): priorities to pause for PFC pause storm
        test_prio_list (list): priorities of test flows
        bg_prio_list (list): priorities of background flows
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).
        trigger_pfcwd (bool): if PFC watchdog is expected to be triggered
        pattern (str): traffic pattern
    Returns:
        N/A
    """
    patterns = ['all to all', 'many to one', '2 sender 2 receiver']
    pytest_assert(pattern in patterns,
                  'Unknown pattern {}. We only support {}'.format(pattern, patterns))

    pytest_assert(testbed_config is not None, 'Fail to get L2/3 testbed config')

    num_devices = len(testbed_config.devices)
    pytest_require(num_devices >= 3, "This test requires at least 3 hosts")

    start_pfcwd(duthost)
    enable_packet_aging(duthost)

    """ Get the ID of the port to test """
    port_id = get_dut_port_id(dut_hostname=duthost.hostname,
                              dut_port=dut_port,
                              conn_data=conn_data,
                              fanout_data=fanout_data)

    pytest_assert(port_id is not None,
                  'Fail to get ID for port {}'.format(dut_port))

    poll_interval_sec = get_pfcwd_poll_interval(duthost) / 1000.0
    detect_time_sec = get_pfcwd_detect_time(host_ans=duthost, intf=dut_port) / 1000.0

    if trigger_pfcwd:
        pfc_storm_dur_sec = poll_interval_sec + detect_time_sec
    else:
        pfc_storm_dur_sec = 0.5 * detect_time_sec

    exp_dur_sec = ceil(pfc_storm_dur_sec + 1)

    """ Generate traffic config """
    if pattern == "all to all":
        test_flow_rate_percent = int(TEST_FLOW_AGGR_RATE_PERCENT / \
                                     (num_devices - 1) / \
                                     len(test_prio_list))

        bg_flow_rate_percent = int(BG_FLOW_AGGR_RATE_PERCENT / \
                                   (num_devices - 1) / \
                                   len(bg_prio_list))

        __gen_a2a_traffic(testbed_config=testbed_config,
                          port_id=port_id,
                          pause_flow_name=PAUSE_FLOW_NAME,
                          pause_prio_list=pause_prio_list,
                          test_flow_name=TEST_FLOW_NAME,
                          test_flow_prio_list=test_prio_list,
                          test_flow_rate_percent=test_flow_rate_percent,
                          bg_flow_name=BG_FLOW_NAME,
                          bg_flow_prio_list=bg_prio_list,
                          bg_flow_rate_percent=bg_flow_rate_percent,
                          data_flow_dur_sec=exp_dur_sec,
                          pfc_storm_dur_sec=pfc_storm_dur_sec,
                          data_pkt_size=DATA_PKT_SIZE,
                          prio_dscp_map=prio_dscp_map)

    elif pattern == "many to one":
        test_flow_rate_percent = int(TEST_FLOW_AGGR_RATE_PERCENT / \
                                     (num_devices - 1) / \
                                     len(test_prio_list))

        bg_flow_rate_percent = int(BG_FLOW_AGGR_RATE_PERCENT / \
                                   (num_devices - 1) / \
                                   len(bg_prio_list))

        __gen_m2o_traffic(testbed_config=testbed_config,
                          port_id=port_id,
                          pause_flow_name=PAUSE_FLOW_NAME,
                          pause_prio_list=pause_prio_list,
                          test_flow_name=TEST_FLOW_NAME,
                          test_flow_prio_list=test_prio_list,
                          test_flow_rate_percent=test_flow_rate_percent,
                          bg_flow_name=BG_FLOW_NAME,
                          bg_flow_prio_list=bg_prio_list,
                          bg_flow_rate_percent=bg_flow_rate_percent,
                          data_flow_dur_sec=exp_dur_sec,
                          pfc_storm_dur_sec=pfc_storm_dur_sec,
                          data_pkt_size=DATA_PKT_SIZE,
                          prio_dscp_map=prio_dscp_map)

    elif pattern == "2 sender 2 receiver":
        test_flow_rate_percent = int(TEST_FLOW_AGGR_RATE_PERCENT / \
                                     2.0 / \
                                     len(test_prio_list))
        bg_flow_rate_percent = int(BG_FLOW_AGGR_RATE_PERCENT / \
                                   2.0 / \
                                   len(bg_prio_list))

        __gen_2sender_2receiver_traffic(testbed_config=testbed_config,
                                        port_id=port_id,
                                        pause_flow_name=PAUSE_FLOW_NAME,
                                        pause_prio_list=pause_prio_list,
                                        test_flow_name=TEST_FLOW_NAME,
                                        test_flow_prio_list=test_prio_list,
                                        test_flow_rate_percent=test_flow_rate_percent,
                                        bg_flow_name=BG_FLOW_NAME,
                                        bg_flow_prio_list=bg_prio_list,
                                        bg_flow_rate_percent=bg_flow_rate_percent,
                                        data_flow_dur_sec=exp_dur_sec,
                                        pfc_storm_dur_sec=pfc_storm_dur_sec,
                                        data_pkt_size=DATA_PKT_SIZE,
                                        prio_dscp_map=prio_dscp_map)


    """ Tgen config = testbed config + flow config """
    flows = testbed_config.flows

    all_flow_names = [flow.name for flow in flows]

    flow_stats = __run_traffic(api=api,
                               config=testbed_config,
                               all_flow_names=all_flow_names,
                               exp_dur_sec=exp_dur_sec)

    speed_str = testbed_config.layer1[0].speed
    speed_gbps = int(speed_str.split('_')[1])

    __verify_results(rows=flow_stats,
                     speed_gbps=speed_gbps,
                     pause_flow_name=PAUSE_FLOW_NAME,
                     test_flow_name=TEST_FLOW_NAME,
                     bg_flow_name=BG_FLOW_NAME,
                     test_flow_rate_percent=test_flow_rate_percent,
                     bg_flow_rate_percent=bg_flow_rate_percent,
                     data_flow_dur_sec=exp_dur_sec,
                     data_pkt_size=DATA_PKT_SIZE,
                     trigger_pfcwd=trigger_pfcwd,
                     pause_port_id=port_id,
                     tolerance=TOLERANCE_THRESHOLD)

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
    return "{} {} -> {} Prio {}".format(name_prefix, src_id, dst_id, prio)

def __data_flow_src(flow_name):
    """
    Get the source ID from the data flow's name

    Args:
        flow_name (str): name of the data flow

    Returns:
        ID of the source port (str)
    """
    words = flow_name.split()
    index = words.index('->')
    return int(words[index-1])

def __data_flow_dst(flow_name):
    """
    Get the destination ID from the data flow's name

    Args:
        flow_name (str): name of the data flow

    Returns:
        ID of the destination port (str)
    """
    words = flow_name.split()
    index = words.index('->')
    return int(words[index+1])

def __gen_2sender_2receiver_traffic(testbed_config,
                                    port_id,
                                    pause_flow_name,
                                    pause_prio_list,
                                    test_flow_name,
                                    test_flow_prio_list,
                                    test_flow_rate_percent,
                                    bg_flow_name,
                                    bg_flow_prio_list,
                                    bg_flow_rate_percent,
                                    data_flow_dur_sec,
                                    pfc_storm_dur_sec,
                                    data_pkt_size,
                                    prio_dscp_map):
    """
    Generate configurations of flows under 2 sender 2 receiver traffic pattern,
    including test flows, background flows and pause storm. Test flows and
    background flows are also known as data flows.

    Args:
        testbed_config (obj): L2/L3 config of a T0 testbed
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
    """ Generate a PFC pause storm """
    pause_port_id = port_id
    __gen_pause_flow(testbed_config=testbed_config,
                     src_port_id=pause_port_id,
                     flow_name=pause_flow_name,
                     pause_prio_list=pause_prio_list,
                     flow_dur_sec=pfc_storm_dur_sec)

    """
    Generate bi-birectional data flows between [port_id+2] and
    [port_id, port_id+1]
    """
    one_port_id_list = [(port_id + 2) % len(testbed_config.devices)]
    two_port_id_list = [port_id, (port_id + 1) % len(testbed_config.devices)]

    perm = permutations([one_port_id_list, two_port_id_list])

    for src_port_id_list, dst_port_id_list in list(perm):
        # Generate test flows
        __gen_data_flows(testbed_config=testbed_config,
                         src_port_id_list=src_port_id_list,
                         dst_port_id_list=dst_port_id_list,
                         flow_name_prefix=TEST_FLOW_NAME,
                         flow_prio_list=test_flow_prio_list,
                         flow_rate_percent=test_flow_rate_percent,
                         flow_dur_sec=data_flow_dur_sec,
                         data_pkt_size=data_pkt_size,
                         prio_dscp_map=prio_dscp_map)

        # Generate background flows
        __gen_data_flows(testbed_config=testbed_config,
                         src_port_id_list=src_port_id_list,
                         dst_port_id_list=dst_port_id_list,
                         flow_name_prefix=BG_FLOW_NAME,
                         flow_prio_list=bg_flow_prio_list,
                         flow_rate_percent=bg_flow_rate_percent,
                         flow_dur_sec=data_flow_dur_sec,
                         data_pkt_size=data_pkt_size,
                         prio_dscp_map=prio_dscp_map)


def __gen_a2a_traffic(testbed_config,
                      port_id,
                      pause_flow_name,
                      pause_prio_list,
                      test_flow_name,
                      test_flow_prio_list,
                      test_flow_rate_percent,
                      bg_flow_name,
                      bg_flow_prio_list,
                      bg_flow_rate_percent,
                      data_flow_dur_sec,
                      pfc_storm_dur_sec,
                      data_pkt_size,
                      prio_dscp_map):
    """
    Generate configurations of flows under all to all traffic pattern, including
    test flows, background flows and pause storm. Test flows and background flows
    are also known as data flows.

    Args:
        testbed_config (obj): L2/L3 config of a T0 testbed
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
    """ Generate a PFC pause storm """
    pause_port_id = port_id
    __gen_pause_flow(testbed_config=testbed_config,
                     src_port_id=pause_port_id,
                     flow_name=pause_flow_name,
                     pause_prio_list=pause_prio_list,
                     flow_dur_sec=pfc_storm_dur_sec)

    """ Generate all-to-all traffic pattern """
    num_devices = len(testbed_config.devices)

    for src_port_id in range(num_devices):
        src_port_id_list = [src_port_id]
        dst_port_id_list = [i for i in range(num_devices) if i != src_port_id]

        # Generate test flows
        __gen_data_flows(testbed_config=testbed_config,
                         src_port_id_list=src_port_id_list,
                         dst_port_id_list=dst_port_id_list,
                         flow_name_prefix=TEST_FLOW_NAME,
                         flow_prio_list=test_flow_prio_list,
                         flow_rate_percent=test_flow_rate_percent,
                         flow_dur_sec=data_flow_dur_sec,
                         data_pkt_size=data_pkt_size,
                         prio_dscp_map=prio_dscp_map)
        # Generate background flows
        __gen_data_flows(testbed_config=testbed_config,
                         src_port_id_list=src_port_id_list,
                         dst_port_id_list=dst_port_id_list,
                         flow_name_prefix=BG_FLOW_NAME,
                         flow_prio_list=bg_flow_prio_list,
                         flow_rate_percent=bg_flow_rate_percent,
                         flow_dur_sec=data_flow_dur_sec,
                         data_pkt_size=data_pkt_size,
                         prio_dscp_map=prio_dscp_map)


def __gen_m2o_traffic(testbed_config,
                      port_id,
                      pause_flow_name,
                      pause_prio_list,
                      test_flow_name,
                      test_flow_prio_list,
                      test_flow_rate_percent,
                      bg_flow_name,
                      bg_flow_prio_list,
                      bg_flow_rate_percent,
                      data_flow_dur_sec,
                      pfc_storm_dur_sec,
                      data_pkt_size,
                      prio_dscp_map):
    """
    Generate configurations of flows under many to one traffic pattern, including
    test flows, background flows and pause storm. Test flows and background flows
    are also known as data flows.

    Args:
        testbed_config (obj): L2/L3 config of a T0 testbed
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

    """ Generate a PFC pause storm """
    pause_port_id = port_id
    __gen_pause_flow(testbed_config=testbed_config,
                     src_port_id=pause_port_id,
                     flow_name=pause_flow_name,
                     pause_prio_list=pause_prio_list,
                     flow_dur_sec=pfc_storm_dur_sec)

    """ Generate many-to-one traffic pattern """
    num_devices = len(testbed_config.devices)
    src_port_id_list = [i for i in range(num_devices) if i != port_id]
    dst_port_id_list = [port_id]

    __gen_data_flows(testbed_config=testbed_config,
                     src_port_id_list=src_port_id_list,
                     dst_port_id_list=dst_port_id_list,
                     flow_name_prefix=TEST_FLOW_NAME,
                     flow_prio_list=test_flow_prio_list,
                     flow_rate_percent=test_flow_rate_percent,
                     flow_dur_sec=data_flow_dur_sec,
                     data_pkt_size=data_pkt_size,
                     prio_dscp_map=prio_dscp_map)

    __gen_data_flows(testbed_config=testbed_config,
                     src_port_id_list=src_port_id_list,
                     dst_port_id_list=dst_port_id_list,
                     flow_name_prefix=BG_FLOW_NAME,
                     flow_prio_list=bg_flow_prio_list,
                     flow_rate_percent=bg_flow_rate_percent,
                     flow_dur_sec=data_flow_dur_sec,
                     data_pkt_size=data_pkt_size,
                     prio_dscp_map=prio_dscp_map)


def __gen_data_flows(testbed_config,
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
        testbed_config (obj): L2/L3 config of a T0 testbed
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
            for prio in flow_prio_list:
                __gen_data_flow(testbed_config=testbed_config,
                                src_port_id=src_port_id,
                                dst_port_id=dst_port_id,
                                flow_name_prefix=flow_name_prefix,
                                flow_prio=prio,
                                flow_rate_percent=flow_rate_percent,
                                flow_dur_sec=flow_dur_sec,
                                data_pkt_size=data_pkt_size,
                                prio_dscp_map=prio_dscp_map)


def __gen_data_flow(testbed_config,
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
        testbed_config (obj): L2/L3 config of a T0 testbed
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
    tx_device_names = [testbed_config.devices[src_port_id].name]
    rx_device_names = [testbed_config.devices[dst_port_id].name]

    flow_name = __data_flow_name(name_prefix=flow_name_prefix,
                                 src_id=src_port_id,
                                 dst_id=dst_port_id,
                                 prio=flow_prio)

    data_flow = testbed_config.flows.flow(name=flow_name)[-1]
    data_flow.tx_rx.device.tx_names = tx_device_names
    data_flow.tx_rx.device.rx_names = rx_device_names

    eth, ipv4 = data_flow.packet.ethernet().ipv4()
    eth.pfc_queue.value = flow_prio
    ipv4.priority.choice = ipv4.priority.DSCP
    ipv4.priority.dscp.phb.values = prio_dscp_map[flow_prio]
    ipv4.priority.dscp.ecn.value = (
        ipv4.priority.dscp.ecn.CAPABLE_TRANSPORT_1)

    data_flow.size.fixed = data_pkt_size
    data_flow.rate.percentage = flow_rate_percent
    data_flow.duration.fixed_seconds.seconds = flow_dur_sec


def __gen_pause_flow(testbed_config,
                     src_port_id,
                     flow_name,
                     pause_prio_list,
                     flow_dur_sec):
    """
    Generate the configuration for a PFC pause storm

    Args:
        testbed_config (obj): L2/L3 config of a T0 testbed
        src_port_id (int): ID of the source port
        flow_name (str): flow' name
        pause_prio_list (list): priorities to pause for PFC frames
        flow_dur_sec (float): duration of the flow in second

    Returns:
        N/A
    """
    pause_time = []
    for x in range(8):
        if x in pause_prio_list:
            pause_time.append('ffff')
        else:
            pause_time.append('0000')

    vector = pfc_class_enable_vector(pause_prio_list)

    pause_flow = testbed_config.flows.flow(name=flow_name)[-1]
    dst_port_id = (src_port_id + 1) % len(testbed_config.devices)
    pause_flow.tx_rx.port.tx_name = testbed_config.ports[src_port_id].name
    pause_flow.tx_rx.port.rx_name = testbed_config.ports[dst_port_id].name

    pause_pkt = pause_flow.packet.pfcpause()[-1]

    pause_pkt.src.value = '00:00:fa:ce:fa:ce'
    pause_pkt.dst.value = '01:80:C2:00:00:01'
    pause_pkt.class_enable_vector.value = vector
    pause_pkt.pause_class_0.value = pause_time[0]
    pause_pkt.pause_class_1.value = pause_time[1]
    pause_pkt.pause_class_2.value = pause_time[2]
    pause_pkt.pause_class_3.value = pause_time[3]
    pause_pkt.pause_class_4.value = pause_time[4]
    pause_pkt.pause_class_5.value = pause_time[5]
    pause_pkt.pause_class_6.value = pause_time[6]
    pause_pkt.pause_class_7.value = pause_time[7]

    """
    The minimal fixed time duration in IXIA is 1 second.
    To support smaller durations, we need to use # of packets
    """
    speed_str = testbed_config.layer1[0].speed
    speed_gbps = int(speed_str.split('_')[1])
    pause_dur = 65535 * 64 * 8.0 / (speed_gbps * 1e9)
    pps = int(2 / pause_dur)
    pkt_cnt = pps * flow_dur_sec

    pause_flow.rate.pps = pps
    pause_flow.size.fixed = 64
    pause_flow.duration.fixed_packets.packets = pkt_cnt
    pause_flow.duration.fixed_packets.delay = 0


def __run_traffic(api, config, all_flow_names, exp_dur_sec):
    """
    Run traffic and dump per-flow statistics

    Args:
        api (obj): snappi API session
        config (obj): experiment config (testbed config + flow config)
        all_flow_names (list): list of names of all the flows
        exp_dur_sec (int): experiment duration in second

    Returns:
        per-flow statistics (list)
    """
    response = api.set_config(config)
    pytest_assert(len(response.errors) == 0,
                  'Set Config failed due to errors')
    logger.info('Starting transmit on all flows ...')
    ts = api.transmit_state()
    ts.state = ts.START
    response = api.set_transmit_state(ts)
    pytest_assert(len(response.errors) == 0,
                  'Start traffic failed due to errors')
    time.sleep(exp_dur_sec)

    attempts = 0
    max_attempts = 20

    while attempts < max_attempts:
        request = api.metrics_request()
        request.flow.flow_names = all_flow_names
        rows = api.get_metrics(request).flow_metrics

        """ If all the data flows have stopped """
        transmit_states = [row.transmit for row in rows]
        if len(rows) == len(all_flow_names) and\
           list(set(transmit_states)) == ['stopped']:
            time.sleep(IXIA_POLL_DELAY_SEC)
            break
        else:
            time.sleep(1)
            attempts += 1

    pytest_assert(attempts < max_attempts,
                  "Flows do not stop in {} seconds".format(max_attempts))

    """ Dump per-flow statistics """
    request = api.metrics_request()
    request.flow.flow_names = all_flow_names
    rows = api.get_metrics(request).flow_metrics
    logger.info('Stop transmit on all flows ...')
    ts = api.transmit_state()
    ts.state = ts.STOP
    response = api.set_transmit_state(ts)
    pytest_assert(len(response.errors) == 0,
                  'Stop traffic failed due to errors')
    return rows


def __verify_results(rows,
                     speed_gbps,
                     pause_flow_name,
                     test_flow_name,
                     bg_flow_name,
                     test_flow_rate_percent,
                     bg_flow_rate_percent,
                     data_flow_dur_sec,
                     data_pkt_size,
                     trigger_pfcwd,
                     pause_port_id,
                     tolerance):
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
    for row in rows:
        flow_name = row.name
        tx_frames = row.frames_tx
        rx_frames = row.frames_rx

        if pause_flow_name in flow_name:
            """ PFC pause storm """
            pytest_assert(tx_frames > 0 and rx_frames == 0,
                          "All the PFC packets should be dropped")

        elif bg_flow_name in flow_name:
            """ Background flows """
            pytest_assert(tx_frames == rx_frames,
                          '{} should not have any dropped packet'.format(flow_name))

            exp_bg_flow_rx_pkts =  bg_flow_rate_percent / 100.0 * speed_gbps \
                * 1e9 * data_flow_dur_sec / 8.0 / data_pkt_size
            deviation = (rx_frames - exp_bg_flow_rx_pkts) / float(exp_bg_flow_rx_pkts)
            pytest_assert(abs(deviation) < tolerance,
                          '{} should receive {} packets (actual {})'.\
                          format(flow_name, exp_bg_flow_rx_pkts, rx_frames))

        elif test_flow_name in flow_name:
            """ Test flows """
            src_port_id = __data_flow_src(flow_name)
            dst_port_id = __data_flow_dst(flow_name)

            exp_test_flow_rx_pkts =  test_flow_rate_percent / 100.0 * speed_gbps \
                * 1e9 * data_flow_dur_sec / 8.0 / data_pkt_size

            if trigger_pfcwd and\
               (src_port_id == pause_port_id or dst_port_id == pause_port_id):
                """ Once PFC watchdog is triggered, it will impact bi-directional traffic """
                pytest_assert(tx_frames > rx_frames,
                              '{} should have dropped packets'.format(flow_name))

            elif not trigger_pfcwd and dst_port_id == pause_port_id:
                """ This test flow is delayed by PFC storm """
                pytest_assert(tx_frames == rx_frames,
                              '{} should not have any dropped packet'.format(flow_name))
                pytest_assert(rx_frames < exp_test_flow_rx_pkts,
                              '{} shoudl receive less than {} packets (actual {})'.\
                              format(flow_name, exp_test_flow_rx_pkts, rx_frames))

            else:
                """ Otherwise, the test flow is not impacted by PFC storm """
                pytest_assert(tx_frames == rx_frames,
                              '{} should not have any dropped packet'.format(flow_name))

                deviation = (rx_frames - exp_test_flow_rx_pkts) / float(exp_test_flow_rx_pkts)
                pytest_assert(abs(deviation) < tolerance,
                              '{} should receive {} packets (actual {})'.\
                              format(flow_name, exp_test_flow_rx_pkts, rx_frames))
