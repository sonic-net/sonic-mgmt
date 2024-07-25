import time
import logging

from tests.common.helpers.assertions import pytest_assert
from tests.common.snappi_tests.snappi_helpers import get_dut_port_id
from tests.common.snappi_tests.common_helpers import start_pfcwd, stop_pfcwd, sec_to_nanosec
from tests.common.snappi_tests.port import select_ports, select_tx_port
from tests.common.snappi_tests.snappi_helpers import wait_for_arp
from tests.snappi_tests.variables import pfcQueueGroupSize, pfcQueueValueDict

DATA_FLOW_NAME = "Data Flow"
WARM_UP_TRAFFIC_NAME = "Warm Up Traffic"
DATA_PKT_SIZE = 1024
DATA_FLOW_DURATION_SEC = 15
WARM_UP_TRAFFIC_DUR = 1
PFCWD_START_DELAY_SEC = 3 + WARM_UP_TRAFFIC_DUR
SNAPPI_POLL_DELAY_SEC = 2
TOLERANCE_THRESHOLD = 0.05

logger = logging.getLogger(__name__)


def run_pfcwd_runtime_traffic_test(api,
                                   testbed_config,
                                   port_config_list,
                                   conn_data,
                                   fanout_data,
                                   duthost,
                                   dut_port,
                                   prio_list,
                                   prio_dscp_map):
    """
    Test PFC watchdog's impact on runtime traffic

    Args:
        api (obj): SNAPPI session
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        conn_data (dict): the dictionary returned by conn_graph_fact.
        fanout_data (dict): the dictionary returned by fanout_graph_fact.
        duthost (Ansible host instance): device under test
        dut_port (str): DUT port to test
        prio_list (list): priorities of data flows
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).

    Returns:
        N/A
    """
    pytest_assert(testbed_config is not None,
                  'Fail to get L2/3 testbed config')

    stop_pfcwd(duthost)

    """ Get the ID of the port to test """
    port_id = get_dut_port_id(dut_hostname=duthost.hostname,
                              dut_port=dut_port,
                              conn_data=conn_data,
                              fanout_data=fanout_data)

    pytest_assert(port_id is not None,
                  'Fail to get ID for port {}'.format(dut_port))

    """ Warm up traffic is initially sent before any other traffic to prevent pfcwd
    fake alerts caused by idle links (non-incremented packet counters) during pfcwd detection periods """
    warm_up_traffic_dur_sec = WARM_UP_TRAFFIC_DUR
    warm_up_traffic_delay_sec = 0

    __gen_traffic(testbed_config=testbed_config,
                  port_config_list=port_config_list,
                  port_id=port_id,
                  data_flow_name_list=[WARM_UP_TRAFFIC_NAME, DATA_FLOW_NAME],
                  data_flow_delay_sec_list=[
                      warm_up_traffic_delay_sec, WARM_UP_TRAFFIC_DUR],
                  data_flow_dur_sec_list=[
                      warm_up_traffic_dur_sec, DATA_FLOW_DURATION_SEC],
                  data_pkt_size=DATA_PKT_SIZE,
                  prio_list=prio_list,
                  prio_dscp_map=prio_dscp_map)

    flows = testbed_config.flows

    all_flow_names = [flow.name for flow in flows]

    flow_stats = __run_traffic(api=api,
                               config=testbed_config,
                               duthost=duthost,
                               all_flow_names=all_flow_names,
                               pfcwd_start_delay_sec=PFCWD_START_DELAY_SEC,
                               exp_dur_sec=DATA_FLOW_DURATION_SEC)

    speed_str = testbed_config.layer1[0].speed
    speed_gbps = int(speed_str.split('_')[1])

    data_flows = [flow_stat for flow_stat in flow_stats if DATA_FLOW_NAME in flow_stat.name]

    __verify_results(rows=data_flows,
                     speed_gbps=speed_gbps,
                     data_flow_dur_sec=DATA_FLOW_DURATION_SEC,
                     data_pkt_size=DATA_PKT_SIZE,
                     tolerance=TOLERANCE_THRESHOLD)


def __gen_traffic(testbed_config,
                  port_config_list,
                  port_id,
                  data_flow_name_list,
                  data_flow_delay_sec_list,
                  data_flow_dur_sec_list,
                  data_pkt_size,
                  prio_list,
                  prio_dscp_map):
    """
    Generate configurations of flows

    Args:
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        port_id (int): ID of DUT port to test.
        data_flow_name_list (list): list of data flow names
        data_flow_delay_sec_list (list): list of data flow start delays in second
        data_flow_dur_sec_list (list): list of data flow durations in second
        data_pkt_size (int): size of data packets in byte
        prio_list (list): priorities of data flows
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


def __run_traffic(api, config, duthost, all_flow_names, pfcwd_start_delay_sec, exp_dur_sec):
    """
    Start traffic at time 0 and enable PFC watchdog at pfcwd_start_delay_sec

    Args:
        api (obj): SNAPPI session
        config (obj): experiment config (testbed config + flow config)
        duthost (Ansible host instance): device under test
        all_flow_names (list): list of names of all the flows
        pfcwd_start_delay_sec (int): PFC watchdog start delay in second
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

    time.sleep(pfcwd_start_delay_sec)
    start_pfcwd(duthost)
    time.sleep(exp_dur_sec - pfcwd_start_delay_sec)

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


def __verify_results(rows, speed_gbps, data_flow_dur_sec, data_pkt_size, tolerance):
    """
    Verify if we get expected experiment results

    Args:
        rows (list): per-flow statistics
        speed_gbps (int): link speed in Gbps
        data_flow_dur_sec (int): duration of data flows in second
        data_pkt_size (int): size of data packets in byte
        tolerance (float): maximum allowable deviation

    Returns:
        N/A
    """
    data_flow_rate_percent = int(100 / len(rows))

    for row in rows:
        flow_name = row.name
        tx_frames = row.frames_tx
        rx_frames = row.frames_rx

        pytest_assert(tx_frames == rx_frames, "{} packets of {} are dropped".
                      format(tx_frames-rx_frames, flow_name))

        exp_rx_pkts = data_flow_rate_percent / 100.0 * speed_gbps \
            * 1e9 * data_flow_dur_sec / 8.0 / data_pkt_size

        deviation = (rx_frames - exp_rx_pkts) / float(exp_rx_pkts)
        pytest_assert(abs(deviation) < tolerance,
                      "{} should receive {} packets (actual {})".
                      format(flow_name, exp_rx_pkts, rx_frames))
