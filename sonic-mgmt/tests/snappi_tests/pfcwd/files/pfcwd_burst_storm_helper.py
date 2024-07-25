import time
from math import ceil
import logging

from tests.common.helpers.assertions import pytest_assert
from tests.common.snappi_tests.snappi_helpers import get_dut_port_id
from tests.common.snappi_tests.common_helpers import pfc_class_enable_vector,\
    get_pfcwd_poll_interval, get_pfcwd_detect_time, get_pfcwd_restore_time,\
    enable_packet_aging, start_pfcwd, sec_to_nanosec
from tests.common.snappi_tests.port import select_ports, select_tx_port
from tests.common.snappi_tests.snappi_helpers import wait_for_arp
from tests.snappi_tests.variables import pfcQueueGroupSize, pfcQueueValueDict

logger = logging.getLogger(__name__)

PAUSE_FLOW_PREFIX = "Pause Storm"
WARM_UP_TRAFFIC_NAME = "Warm Up Traffic"
DATA_FLOW_PREFIX = "Data Flow"
WARM_UP_TRAFFIC_DUR = 1
BURST_EVENTS = 15
DATA_PKT_SIZE = 1024
SNAPPI_POLL_DELAY_SEC = 2


def run_pfcwd_burst_storm_test(api,
                               testbed_config,
                               port_config_list,
                               conn_data,
                               fanout_data,
                               duthost,
                               dut_port,
                               prio_list,
                               prio_dscp_map):
    """
    Test PFC watchdog under bursty PFC storms

    Args:
        api (obj): SNAPPI session
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        conn_data (dict): the dictionary returned by conn_graph_fact.
        fanout_data (dict): the dictionary returned by fanout_graph_fact.
        duthost (Ansible host instance): device under test
        dut_port (str): DUT port to test
        prio_list (list): priorities to generate PFC storms and data traffic
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).

    Returns:
        N/A
    """
    pytest_assert(testbed_config is not None,
                  'Fail to get L2/3 testbed config')

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
    detect_time_sec = get_pfcwd_detect_time(
        host_ans=duthost, intf=dut_port) / 1000.0
    restore_time_sec = get_pfcwd_restore_time(
        host_ans=duthost, intf=dut_port) / 1000.0

    burst_cycle_sec = poll_interval_sec + detect_time_sec + restore_time_sec + 0.1
    data_flow_dur_sec = ceil(burst_cycle_sec * BURST_EVENTS)
    pause_flow_dur_sec = poll_interval_sec * 0.5
    pause_flow_gap_sec = burst_cycle_sec - pause_flow_dur_sec

    """ Warm up traffic is initially sent before any other traffic to prevent pfcwd
    fake alerts caused by idle links (non-incremented packet counters) during pfcwd detection periods """
    warm_up_traffic_dur_sec = WARM_UP_TRAFFIC_DUR
    warm_up_traffic_delay_sec = 0

    __gen_traffic(testbed_config=testbed_config,
                  port_config_list=port_config_list,
                  port_id=port_id,
                  pause_flow_prefix=PAUSE_FLOW_PREFIX,
                  pause_flow_dur_sec=pause_flow_dur_sec,
                  pause_flow_count=BURST_EVENTS,
                  pause_flow_gap_sec=pause_flow_gap_sec,
                  data_flow_prefix_list=[
                      WARM_UP_TRAFFIC_NAME, DATA_FLOW_PREFIX],
                  data_flow_delay_sec_list=[
                      warm_up_traffic_delay_sec, WARM_UP_TRAFFIC_DUR],
                  data_flow_dur_sec_list=[
                      warm_up_traffic_dur_sec, data_flow_dur_sec],
                  data_pkt_size=DATA_PKT_SIZE,
                  prio_list=prio_list,
                  prio_dscp_map=prio_dscp_map)

    flows = testbed_config.flows

    all_flow_names = [flow.name for flow in flows]
    exp_dur_sec = BURST_EVENTS * poll_interval_sec + 1

    flow_stats = __run_traffic(api=api,
                               config=testbed_config,
                               all_flow_names=all_flow_names,
                               exp_dur_sec=exp_dur_sec)

    __verify_results(rows=flow_stats,
                     data_flow_prefix=DATA_FLOW_PREFIX,
                     pause_flow_prefix=PAUSE_FLOW_PREFIX)


def __gen_traffic(testbed_config,
                  port_config_list,
                  port_id,
                  pause_flow_prefix,
                  pause_flow_count,
                  pause_flow_dur_sec,
                  pause_flow_gap_sec,
                  data_flow_prefix_list,
                  data_flow_delay_sec_list,
                  data_flow_dur_sec_list,
                  data_pkt_size,
                  prio_list,
                  prio_dscp_map):
    """
    Generate flow configurations

    Args:
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        port_id (int): ID of DUT port to test.
        pause_flow_prefix (str): prefix of names of PFC pause storms
        pause_flow_count (int): number of PFC pause storms
        pause_flow_dur_sec (float): duration of each PFC pause storm
        pause_flow_gap_sec (float): gap between PFC pause storms
        data_flow_prefix_list (list): list of prefixes of names of data flows
        data_flow_delay_sec_list (list): list of data flow start delays in second
        data_flow_dur_sec_list (list): list of durations of all the data flows
        data_pkt_size (int): data packet size in bytes
        prio_list (list): priorities to generate PFC storms and data traffic
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

    """ Generate long-lived data flows, one for each priority """
    data_flow_rate_percent = int(100 / len(prio_list))
    tx_port_name = testbed_config.ports[tx_port_id].name
    rx_port_name = testbed_config.ports[rx_port_id].name

    """ For each data flow """
    for i in range(len(data_flow_prefix_list)):

        """ For each priority """
        for prio in prio_list:
            data_flow = testbed_config.flows.flow(
                name='{} Prio {}'.format(data_flow_prefix_list[i], prio))[-1]

            data_flow.tx_rx.port.tx_name = tx_port_name
            data_flow.tx_rx.port.rx_name = rx_port_name

            eth, ipv4 = data_flow.packet.ethernet().ipv4()
            eth.src.value = tx_mac
            eth.dst.value = rx_mac
            if pfcQueueGroupSize == 8:
                eth.pfc_queue.value = prio
            else:
                eth.pfc_queue.value = pfcQueueValueDict[prio]

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

    """ Generate a series of PFC storms """
    speed_str = testbed_config.layer1[0].speed
    speed_gbps = int(speed_str.split('_')[1])
    pause_dur = 65535 * 64 * 8.0 / (speed_gbps * 1e9)
    pause_pps = int(2 / pause_dur)
    pause_pkt_cnt = pause_pps * pause_flow_dur_sec

    for id in range(pause_flow_count):
        pause_time = []
        for x in range(8):
            if x in prio_list:
                pause_time.append(int('ffff', 16))
            else:
                pause_time.append(int('0000', 16))

        vector = pfc_class_enable_vector(prio_list)

        pause_flow = testbed_config.flows.flow(
            name="{} {}".format(pause_flow_prefix, id))[-1]
        pause_flow.tx_rx.port.tx_name = testbed_config.ports[rx_port_id].name
        pause_flow.tx_rx.port.rx_name = testbed_config.ports[tx_port_id].name

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

        pause_flow_start_time = id * \
            (pause_flow_dur_sec + pause_flow_gap_sec) + WARM_UP_TRAFFIC_DUR

        pause_flow.rate.pps = pause_pps
        pause_flow.size.fixed = 64
        pause_flow.duration.fixed_packets.packets = int(pause_pkt_cnt)
        pause_flow.duration.fixed_packets.delay.nanoseconds = int(
            sec_to_nanosec(pause_flow_start_time))

        pause_flow.metrics.enable = True
        pause_flow.metrics.loss = True


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


def __verify_results(rows, data_flow_prefix, pause_flow_prefix):
    """
    Verify if we get expected experiment results

    Args:
        rows (list): per-flow statistics
        data_flow_prefix (str): prefix of names of data flows
        pause_flow_prefix (str): prefix of names of PFC pause storms

    Returns:
        N/A
    """
    for row in rows:
        flow_name = row.name
        tx_frames = row.frames_tx
        rx_frames = row.frames_rx

        if data_flow_prefix in flow_name:
            """ Data flow """
            pytest_assert(tx_frames > 0 and rx_frames == tx_frames,
                          "No data packet should be dropped")

        elif pause_flow_prefix in flow_name:
            """ PFC pause storm """
            pytest_assert(tx_frames > 0 and rx_frames == 0,
                          "All the PFC packets should be dropped")
