import time
from math import ceil
import logging

from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts          # noqa F401
from tests.common.snappi_tests.snappi_helpers import get_dut_port_id
from tests.common.snappi_tests.common_helpers import pfc_class_enable_vector,\
    get_pfcwd_poll_interval, get_pfcwd_detect_time, get_pfcwd_restore_time,\
    enable_packet_aging, start_pfcwd, sec_to_nanosec
from tests.common.snappi_tests.port import select_ports, select_tx_port
from tests.common.snappi_tests.snappi_helpers import wait_for_arp

logger = logging.getLogger(__name__)

PAUSE_FLOW_NAME = "Pause Storm"
WARM_UP_TRAFFIC_NAME = "Warm Up Traffic"
DATA_FLOW1_NAME = "Data Flow 1"
DATA_FLOW2_NAME = "Data Flow 2"
WARM_UP_TRAFFIC_DUR = 1
DATA_PKT_SIZE = 1024
SNAPPI_POLL_DELAY_SEC = 2
DEVIATION = 0.3


def run_pfcwd_basic_test(api,
                         testbed_config,
                         port_config_list,
                         conn_data,
                         fanout_data,
                         duthost,
                         dut_port,
                         prio_list,
                         prio_dscp_map,
                         trigger_pfcwd):
    """
    Run a basic PFC watchdog test

    Args:
        api (obj): SNAPPI session
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        conn_data (dict): the dictionary returned by conn_graph_fact.
        fanout_data (dict): the dictionary returned by fanout_graph_fact.
        duthost (Ansible host instance): device under test
        dut_port (str): DUT port to test
        prio_list (list): priorities of data flows and pause storm
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).
        trigger_pfcwd (bool): if PFC watchdog is expected to be triggered

    Returns:
        N/A
    """

    pytest_assert(testbed_config is not None,
                  'Fail to get L2/3 testbed config')

    start_pfcwd(duthost)
    enable_packet_aging(duthost)

    # Set appropriate pfcwd loss deviation - these values are based on empirical testing
    DEVIATION = 0.35 if duthost.facts['asic_type'] in ["broadcom"] else 0.3

    """ Get the ID of the port to test """
    port_id = get_dut_port_id(dut_hostname=duthost.hostname,
                              dut_port=dut_port,
                              conn_data=conn_data,
                              fanout_data=fanout_data)

    pytest_assert(port_id is not None,
                  'Fail to get ID for port {}'.format(dut_port))

    poll_interval_sec = get_pfcwd_poll_interval(duthost) / 1000.0
    detect_time_sec = get_pfcwd_detect_time(
        host_ans=duthost, intf=dut_port) / 1000.0
    restore_time_sec = get_pfcwd_restore_time(
        host_ans=duthost, intf=dut_port) / 1000.0

    """ Warm up traffic is initially sent before any other traffic to prevent pfcwd
    fake alerts caused by idle links (non-incremented packet counters) during pfcwd detection periods """
    warm_up_traffic_dur_sec = WARM_UP_TRAFFIC_DUR
    warm_up_traffic_delay_sec = 0

    if trigger_pfcwd:
        """ Large enough to trigger PFC watchdog """
        pfc_storm_dur_sec = ceil(detect_time_sec + poll_interval_sec + 0.1)

        flow1_delay_sec = restore_time_sec / 2 + WARM_UP_TRAFFIC_DUR
        flow1_dur_sec = pfc_storm_dur_sec

        """ Start data traffic 2 after PFC is restored """
        flow2_delay_sec = pfc_storm_dur_sec + restore_time_sec + \
            poll_interval_sec + WARM_UP_TRAFFIC_DUR
        flow2_dur_sec = 1

        flow1_max_loss_rate = 1
        flow1_min_loss_rate = 1 - DEVIATION

    else:
        pfc_storm_dur_sec = detect_time_sec * 0.5
        flow1_delay_sec = pfc_storm_dur_sec * 0.1 + WARM_UP_TRAFFIC_DUR
        flow1_dur_sec = ceil(pfc_storm_dur_sec)

        """ Start data traffic 2 after the completion of data traffic 1 """
        flow2_delay_sec = flow1_delay_sec + flow1_dur_sec + WARM_UP_TRAFFIC_DUR + 0.1
        flow2_dur_sec = 1

        flow1_max_loss_rate = 0
        flow1_min_loss_rate = 0

    exp_dur_sec = flow2_delay_sec + flow2_dur_sec + 1

    """ Generate traffic config """
    __gen_traffic(testbed_config=testbed_config,
                  port_config_list=port_config_list,
                  port_id=port_id,
                  pause_flow_name=PAUSE_FLOW_NAME,
                  pause_flow_dur_sec=pfc_storm_dur_sec,
                  data_flow_name_list=[WARM_UP_TRAFFIC_NAME,
                                       DATA_FLOW1_NAME, DATA_FLOW2_NAME],
                  data_flow_delay_sec_list=[
                      warm_up_traffic_delay_sec, flow1_delay_sec, flow2_delay_sec],
                  data_flow_dur_sec_list=[
                      warm_up_traffic_dur_sec, flow1_dur_sec, flow2_dur_sec],
                  data_pkt_size=DATA_PKT_SIZE,
                  prio_list=prio_list,
                  prio_dscp_map=prio_dscp_map)

    flows = testbed_config.flows

    all_flow_names = [flow.name for flow in flows]

    flow_stats = __run_traffic(api=api,
                               config=testbed_config,
                               all_flow_names=all_flow_names,
                               exp_dur_sec=exp_dur_sec)

    __verify_results(rows=flow_stats,
                     data_flow_name_list=[DATA_FLOW1_NAME, DATA_FLOW2_NAME],
                     data_flow_min_loss_rate_list=[flow1_min_loss_rate, 0],
                     data_flow_max_loss_rate_list=[flow1_max_loss_rate, 0])


def __gen_traffic(testbed_config,
                  port_config_list,
                  port_id,
                  pause_flow_name,
                  pause_flow_dur_sec,
                  data_flow_name_list,
                  data_flow_delay_sec_list,
                  data_flow_dur_sec_list,
                  data_pkt_size,
                  prio_list,
                  prio_dscp_map):
    """
    Generate configurations of flows, including data flows and pause storm.

    Args:
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        port_id (int): ID of DUT port to test.
        pause_flow_name (str): name of pause storm
        pause_flow_dur_sec (float): duration of pause storm in second
        data_flow_name_list (list): list of data flow names
        data_flow_delay_sec_list (list): list of data flow start delays in second
        data_flow_dur_sec_list (list): list of data flow durations in second
        data_pkt_size (int): size of data packets in byte
        prio_list (list): priorities of data flows and pause storm
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).

    Returns:
        N/A
    """

    rx_port_id = port_id
    tx_port_id_list, rx_port_id_list = select_ports(port_config_list=port_config_list,
                                                    pattern="many to one",
                                                    rx_port_id=rx_port_id)
    pytest_assert(len(tx_port_id_list) > 0, "Cannot find any TX ports")
    tx_port_id = select_tx_port(tx_port_id_list=tx_port_id_list,
                                rx_port_id=rx_port_id)
    pytest_assert(tx_port_id is not None, "Cannot find a suitable TX port")

    tx_port_config = next(
        (x for x in port_config_list if x.id == tx_port_id), None)
    rx_port_config = next(
        (x for x in port_config_list if x.id == rx_port_id), None)

    tx_mac = tx_port_config.mac
    if tx_port_config.gateway == rx_port_config.gateway and \
       tx_port_config.prefix_len == rx_port_config.prefix_len:
        """ If soruce and destination port are in the same subnet """
        rx_mac = rx_port_config.mac
    else:
        rx_mac = tx_port_config.gateway_mac

    """ PFC storm """
    pause_flow = testbed_config.flows.flow(name=pause_flow_name)[-1]
    pause_flow.tx_rx.port.tx_name = testbed_config.ports[rx_port_id].name
    pause_flow.tx_rx.port.rx_name = testbed_config.ports[tx_port_id].name

    pause_pkt = pause_flow.packet.pfcpause()[-1]

    pause_time = []
    for x in range(8):
        if x in prio_list:
            pause_time.append(int('ffff', 16))
        else:
            pause_time.append(int('0000', 16))

    vector = pfc_class_enable_vector(prio_list)

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

    speed_str = testbed_config.layer1[0].speed
    speed_gbps = int(speed_str.split('_')[1])
    pause_dur = 65535 * 64 * 8.0 / (speed_gbps * 1e9)
    pps = int(2 / pause_dur)
    pause_pkt_cnt = pps * pause_flow_dur_sec

    pause_flow.rate.pps = pps
    pause_flow.size.fixed = 64
    pause_flow.duration.fixed_packets.packets = int(pause_pkt_cnt)
    pause_flow.duration.fixed_packets.delay.nanoseconds = int(
        sec_to_nanosec(WARM_UP_TRAFFIC_DUR))

    pause_flow.metrics.enable = True
    pause_flow.metrics.loss = True

    tx_port_name = testbed_config.ports[tx_port_id].name
    rx_port_name = testbed_config.ports[rx_port_id].name
    data_flow_rate_percent = int(100 / len(prio_list))

    """ For each data flow """
    for i in range(len(data_flow_name_list)):

        """ For each priority """
        for prio in prio_list:
            data_flow = testbed_config.flows.flow(
                name='{} Prio {}'.format(data_flow_name_list[i], prio))[-1]
            data_flow.tx_rx.port.tx_name = tx_port_name
            data_flow.tx_rx.port.rx_name = rx_port_name

            eth, ipv4 = data_flow.packet.ethernet().ipv4()
            eth.src.value = tx_mac
            eth.dst.value = rx_mac
            eth.pfc_queue.value = prio

            ipv4.src.value = tx_port_config.ip
            ipv4.dst.value = rx_port_config.ip
            ipv4.priority.choice = ipv4.priority.DSCP
            ipv4.priority.dscp.phb.values = prio_dscp_map[prio]
            ipv4.priority.dscp.ecn.value = (
                ipv4.priority.dscp.ecn.CAPABLE_TRANSPORT_1)

            data_flow.size.fixed = data_pkt_size
            data_flow.rate.percentage = data_flow_rate_percent
            data_flow.duration.fixed_seconds.seconds = (
                data_flow_dur_sec_list[i])
            data_flow.duration.fixed_seconds.delay.nanoseconds = int(
                sec_to_nanosec(data_flow_delay_sec_list[i]))

            data_flow.metrics.enable = True
            data_flow.metrics.loss = True


def __run_traffic(api, config, all_flow_names, exp_dur_sec):
    """
    Run traffic and dump per-flow statistics

    Args:
        api (obj): SNAPPI session
        config (obj): experiment config (testbed config + flow config)
        all_flow_names (list): list of names of all the flows
        exp_dur_sec (float): experiment duration in second

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

    attempts = 0
    max_attempts = 20
    while attempts < max_attempts:
        request = api.metrics_request()
        request.flow.flow_names = all_flow_names
        rows = api.get_metrics(request).flow_metrics

        """ If all the flows have stopped """
        transmit_states = [row.transmit for row in rows]
        if len(rows) == len(all_flow_names) and\
           list(set(transmit_states)) == ['stopped']:
            time.sleep(SNAPPI_POLL_DELAY_SEC)
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
    api.set_transmit_state(ts)

    return rows


def __verify_results(rows,
                     data_flow_name_list,
                     data_flow_min_loss_rate_list,
                     data_flow_max_loss_rate_list):
    """
    Verify if we get expected experiment results

    Args:
        rows (list): per-flow statistics
        data_flow_name_list (list): list of data flow names
        data_flow_min_loss_rate_list (list): list of data flow min loss rates
        data_flow_max_loss_rate_list (list): list of data flow max loss rates

    Returns:
        N/A
    """
    num_data_flows = len(data_flow_name_list)
    data_flow_tx_frames_list = num_data_flows * [0]
    data_flow_rx_frames_list = num_data_flows * [0]

    for row in rows:
        flow_name = row.name
        tx_frames = row.frames_tx
        rx_frames = row.frames_rx

        for i in range(num_data_flows):
            if data_flow_name_list[i] in flow_name:
                data_flow_tx_frames_list[i] += tx_frames
                data_flow_rx_frames_list[i] += rx_frames

    for i in range(num_data_flows):
        loss_rate = 1 - \
            float(data_flow_rx_frames_list[i]) / data_flow_tx_frames_list[i]
        min_loss_rate = data_flow_min_loss_rate_list[i]
        max_loss_rate = data_flow_max_loss_rate_list[i]

        pytest_assert(loss_rate <= max_loss_rate and loss_rate >= min_loss_rate,
                      'Loss rate of {} ({}) should be in [{}, {}]'.format(
                          data_flow_name_list[i], loss_rate, min_loss_rate, max_loss_rate))
