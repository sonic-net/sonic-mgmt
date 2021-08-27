import time
import logging
from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts
from tests.common.snappi.snappi_helpers import get_dut_port_id
from tests.common.snappi.common_helpers import pfc_class_enable_vector,\
    get_egress_lossless_buffer_size, stop_pfcwd, disable_packet_aging
from tests.common.snappi.port import select_ports, select_tx_port

logger = logging.getLogger(__name__)

PAUSE_FLOW_NAME = 'Pause Storm'
TEST_FLOW_NAME = 'Test Flow'
TEST_FLOW_AGGR_RATE_PERCENT = 45
BG_FLOW_NAME = 'Background Flow'
BG_FLOW_AGGR_RATE_PERCENT = 45
DATA_PKT_SIZE = 1024
DATA_FLOW_DURATION_SEC = 2
DATA_FLOW_DELAY_SEC = 1
SNAPPI_POLL_DELAY_SEC = 2
TOLERANCE_THRESHOLD = 0.05


def run_pfc_test(api,
                 testbed_config,
                 port_config_list,
                 conn_data,
                 fanout_data,
                 duthost,
                 dut_port,
                 global_pause,
                 pause_prio_list,
                 test_prio_list,
                 bg_prio_list,
                 prio_dscp_map,
                 test_traffic_pause):
    """
    Run a PFC test
    Args:
        api (obj): snappi session
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        conn_data (dict): the dictionary returned by conn_graph_fact.
        fanout_data (dict): the dictionary returned by fanout_graph_fact.
        duthost (Ansible host instance): device under test
        dut_port (str): DUT port to test
        global_pause (bool): if pause frame is IEEE 802.3X pause
        pause_prio_list (list): priorities to pause for pause frames
        test_prio_list (list): priorities of test flows
        bg_prio_list (list): priorities of background flows
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).
        test_traffic_pause (bool): if test flows are expected to be paused
    Returns:
        N/A
    """

    pytest_assert(testbed_config is not None, 'Fail to get L2/3 testbed config')

    stop_pfcwd(duthost)
    disable_packet_aging(duthost)

    """ Get the ID of the port to test """
    port_id = get_dut_port_id(dut_hostname=duthost.hostname,
                              dut_port=dut_port,
                              conn_data=conn_data,
                              fanout_data=fanout_data)

    pytest_assert(port_id is not None,
                  'Fail to get ID for port {}'.format(dut_port))

    """ Rate percent must be an integer """
    test_flow_rate_percent = int(TEST_FLOW_AGGR_RATE_PERCENT / len(test_prio_list))
    bg_flow_rate_percent = int(BG_FLOW_AGGR_RATE_PERCENT / len(bg_prio_list))

    """ Generate traffic config """
    __gen_traffic(testbed_config=testbed_config,
                  port_config_list=port_config_list,
                  port_id=port_id,
                  pause_flow_name=PAUSE_FLOW_NAME,
                  global_pause=global_pause,
                  pause_prio_list=pause_prio_list,
                  test_flow_name=TEST_FLOW_NAME,
                  test_flow_prio_list=test_prio_list,
                  test_flow_rate_percent=test_flow_rate_percent,
                  bg_flow_name=BG_FLOW_NAME,
                  bg_flow_prio_list=bg_prio_list,
                  bg_flow_rate_percent=bg_flow_rate_percent,
                  data_flow_dur_sec=DATA_FLOW_DURATION_SEC,
                  data_flow_delay_sec=DATA_FLOW_DELAY_SEC,
                  data_pkt_size=DATA_PKT_SIZE,
                  prio_dscp_map=prio_dscp_map)

    flows = testbed_config.flows

    all_flow_names = [flow.name for flow in flows]
    data_flow_names = [flow.name for flow in flows if PAUSE_FLOW_NAME not in flow.name]

    """ Run traffic """
    flow_stats = __run_traffic(api=api,
                               config=testbed_config,
                               data_flow_names=data_flow_names,
                               all_flow_names=all_flow_names,
                               exp_dur_sec=DATA_FLOW_DURATION_SEC+DATA_FLOW_DELAY_SEC)

    speed_str = testbed_config.layer1[0].speed
    speed_gbps = int(speed_str.split('_')[1])

    """ Verify experiment results """
    __verify_results(rows=flow_stats,
                     duthost=duthost,
                     pause_flow_name=PAUSE_FLOW_NAME,
                     test_flow_name=TEST_FLOW_NAME,
                     bg_flow_name=BG_FLOW_NAME,
                     data_flow_dur_sec=DATA_FLOW_DURATION_SEC,
                     test_flow_rate_percent=test_flow_rate_percent,
                     bg_flow_rate_percent=bg_flow_rate_percent,
                     data_pkt_size=DATA_PKT_SIZE,
                     speed_gbps=speed_gbps,
                     test_flow_pause=test_traffic_pause,
                     tolerance=TOLERANCE_THRESHOLD)


sec_to_nanosec = lambda x: x * 1e9


def __gen_traffic(testbed_config,
                  port_config_list,
                  port_id,
                  pause_flow_name,
                  global_pause,
                  pause_prio_list,
                  test_flow_name,
                  test_flow_prio_list,
                  test_flow_rate_percent,
                  bg_flow_name,
                  bg_flow_prio_list,
                  bg_flow_rate_percent,
                  data_flow_dur_sec,
                  data_flow_delay_sec,
                  data_pkt_size,
                  prio_dscp_map):
    """
    Generate configurations of flows, including test flows, background flows and
    pause storm. Test flows and background flows are also known as data flows.
    Args:
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        port_id (int): ID of DUT port to test
        pause_flow_name (str): name of pause storm
        global_pause (bool): if pause frame is IEEE 802.3X pause
        pause_prio_list (list): priorities to pause for pause frames
        test_flow_name (str): name of test flows
        test_prio_list (list): priorities of test flows
        test_flow_rate_percent (int): rate percentage for each test flow
        bg_flow_name (str): name of background flows
        bg_prio_list (list): priorities of background flows
        bg_flow_rate_percent (int): rate percentage for each background flow
        data_flow_dur_sec (int): duration of data flows in second
        data_flow_delay_sec (int): start delay of data flows in second
        data_pkt_size (int): packet size of data flows in byte
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).
    Returns:
        flows configurations (list): the list should have configurations of
        len(test_flow_prio_list) test flow, len(bg_flow_prio_list) background
        flows and a pause storm.
    """

    rx_port_id = port_id
    tx_port_id_list, rx_port_id_list = select_ports(port_config_list=port_config_list,
                                                    pattern="many to one",
                                                    rx_port_id=rx_port_id)

    pytest_assert(len(tx_port_id_list) > 0, "Cannot find any TX ports")
    tx_port_id = select_tx_port(tx_port_id_list=tx_port_id_list,
                                rx_port_id=rx_port_id)
    pytest_assert(tx_port_id is not None, "Cannot find a suitable TX port")

    tx_port_config = next((x for x in port_config_list if x.id == tx_port_id), None)
    rx_port_config = next((x for x in port_config_list if x.id == rx_port_id), None)

    tx_mac = tx_port_config.mac
    if tx_port_config.gateway == rx_port_config.gateway and \
       tx_port_config.prefix_len == rx_port_config.prefix_len:
        """ If soruce and destination port are in the same subnet """
        rx_mac = rx_port_config.mac
    else:
        rx_mac = tx_port_config.gateway_mac

    tx_port_name = testbed_config.ports[tx_port_id].name
    rx_port_name = testbed_config.ports[rx_port_id].name
    data_flow_delay_nanosec = sec_to_nanosec(data_flow_delay_sec)

    """ Test flows """
    for prio in test_flow_prio_list:
        test_flow = testbed_config.flows.flow(
            name='{} Prio {}'.format(test_flow_name, prio))[-1]
        test_flow.tx_rx.port.tx_name = tx_port_name
        test_flow.tx_rx.port.rx_name = rx_port_name

        eth, ipv4 = test_flow.packet.ethernet().ipv4()
        eth.src.value = tx_mac
        eth.dst.value = rx_mac
        eth.pfc_queue.value = prio

        ipv4.src.value = tx_port_config.ip
        ipv4.dst.value = rx_port_config.ip
        ipv4.priority.choice = ipv4.priority.DSCP
        ipv4.priority.dscp.phb.values = prio_dscp_map[prio]
        ipv4.priority.dscp.ecn.value = (
            ipv4.priority.dscp.ecn.CAPABLE_TRANSPORT_1)

        test_flow.size.fixed = data_pkt_size
        test_flow.rate.percentage = test_flow_rate_percent
        test_flow.duration.fixed_seconds.seconds = data_flow_dur_sec
        test_flow.duration.fixed_seconds.delay.nanoseconds = int(data_flow_delay_nanosec)

        test_flow.metrics.enable = True
        test_flow.metrics.loss = True

    """ Background flows """
    for prio in bg_flow_prio_list:
        bg_flow = testbed_config.flows.flow(
            name='{} Prio {}'.format(bg_flow_name, prio))[-1]
        bg_flow.tx_rx.port.tx_name = tx_port_name
        bg_flow.tx_rx.port.rx_name = rx_port_name

        eth, ipv4 = bg_flow.packet.ethernet().ipv4()
        eth.src.value = tx_mac
        eth.dst.value = rx_mac
        eth.pfc_queue.value = prio

        ipv4.src.value = tx_port_config.ip
        ipv4.dst.value = rx_port_config.ip
        ipv4.priority.choice = ipv4.priority.DSCP
        ipv4.priority.dscp.phb.values = prio_dscp_map[prio]
        ipv4.priority.dscp.ecn.value = (
            ipv4.priority.dscp.ecn.CAPABLE_TRANSPORT_1)

        bg_flow.size.fixed = data_pkt_size
        bg_flow.rate.percentage = bg_flow_rate_percent
        bg_flow.duration.fixed_seconds.seconds = data_flow_dur_sec
        bg_flow.duration.fixed_seconds.delay.nanoseconds = int(data_flow_delay_nanosec)

        bg_flow.metrics.enable = True
        bg_flow.metrics.loss = True

    """ Pause storm """
    pause_flow = testbed_config.flows.flow(name=pause_flow_name)[-1]
    pause_flow.tx_rx.port.tx_name = testbed_config.ports[rx_port_id].name
    pause_flow.tx_rx.port.rx_name = testbed_config.ports[tx_port_id].name

    if global_pause:
        pause_pkt = pause_flow.packet.ethernetpause()[-1]
        pause_pkt.src.value = '00:00:fa:ce:fa:ce'
        pause_pkt.dst.value = '01:80:C2:00:00:01'

    else:
        pause_time = []
        for x in range(8):
            if x in pause_prio_list:
                pause_time.append(int('ffff', 16))
            else:
                pause_time.append(int('0000', 16))

        vector = pfc_class_enable_vector(pause_prio_list)
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

    """ Pause frames are sent from the RX port """

    speed_str = testbed_config.layer1[0].speed
    speed_gbps = int(speed_str.split('_')[1])
    pause_dur = 65535 * 64 * 8.0 / (speed_gbps * 1e9)
    pps = int(2 / pause_dur)

    pause_flow.rate.pps = pps
    pause_flow.size.fixed = 64
    pause_flow.duration.choice = pause_flow.duration.CONTINUOUS
    pause_flow.duration.continuous.delay.nanoseconds = 0

    pause_flow.metrics.enable = True
    pause_flow.metrics.loss = True


def __run_traffic(api,
                  config,
                  data_flow_names,
                  all_flow_names,
                  exp_dur_sec):

    """
    Run traffic and dump per-flow statistics
    Args:
        api (obj): snappi session
        config (obj): experiment config (testbed config + flow config)
        data_flow_names (list): list of names of data (test and background) flows
        all_flow_names (list): list of names of all the flows
        exp_dur_sec (int): experiment duration in second
    Returns:
        per-flow statistics (list)
    """

    api.set_config(config)
    logger.info('Starting transmit on all flows ...')
    ts = api.transmit_state()
    ts.state = ts.START
    api.set_transmit_state(ts)

    time.sleep(exp_dur_sec)

    attempts = 0
    max_attempts = 20

    while attempts < max_attempts:
        request = api.metrics_request()
        request.flow.flow_names = data_flow_names
        rows = api.get_metrics(request).flow_metrics

        """ If all the data flows have stopped """
        transmit_states = [row.transmit for row in rows]
        if len(rows) == len(data_flow_names) and\
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
                     duthost,
                     pause_flow_name,
                     test_flow_name,
                     bg_flow_name,
                     data_flow_dur_sec,
                     test_flow_rate_percent,
                     bg_flow_rate_percent,
                     data_pkt_size,
                     speed_gbps,
                     test_flow_pause,
                     tolerance):
    """
    Verify if we get expected experiment results
    Args:
        rows (list): per-flow statistics
        duthost (Ansible host instance): device under test
        pause_flow_name (str): name of pause storm
        test_flow_name (str): name of test flows
        bg_flow_name (str): name of background flows
        test_flow_rate_percent (int): rate percentage for each test flow
        bg_flow_rate_percent (int): rate percentage for each background flow
        data_pkt_size (int): packet size of data flows in byte
        speed_gbps (int): link speed in Gbps
        test_flow_pause (bool): if test flows are expected to be paused
        tolerance (float): maximum allowable deviation
    Returns:
        N/A
    """

    """ All the pause frames should be dropped """
    pause_flow_row = next(row for row in rows if row.name == pause_flow_name)
    tx_frames = pause_flow_row.frames_tx
    rx_frames = pause_flow_row.frames_rx
    pytest_assert(tx_frames > 0 and rx_frames == 0,
                  'All the pause frames should be dropped')

    """ Check background flows """
    for row in rows:
        if bg_flow_name not in row.name:
            continue

        tx_frames = row.frames_tx
        rx_frames = row.frames_rx

        pytest_assert(tx_frames == rx_frames,
                      '{} should not have any dropped packet'.format(row.name))

        exp_bg_flow_rx_pkts =  bg_flow_rate_percent / 100.0 * speed_gbps \
            * 1e9 * data_flow_dur_sec / 8.0 / data_pkt_size
        deviation = (rx_frames - exp_bg_flow_rx_pkts) / float(exp_bg_flow_rx_pkts)
        pytest_assert(abs(deviation) < tolerance,
                      '{} should receive {} packets (actual {})'.
                      format(row.name, exp_bg_flow_rx_pkts, rx_frames))

    """ Check test flows """
    for row in rows:
        if test_flow_name not in row.name:
            continue

        tx_frames = row.frames_tx
        rx_frames = row.frames_rx

        if test_flow_pause:
            pytest_assert(tx_frames > 0 and rx_frames == 0,
                          '{} should be paused'.format(row.name))
        else:
            pytest_assert(tx_frames == rx_frames,
                          '{} should not have any dropped packet'.format(row.name))

            exp_test_flow_rx_pkts = test_flow_rate_percent / 100.0 * speed_gbps \
                * 1e9 * data_flow_dur_sec / 8.0 / data_pkt_size
            deviation = (rx_frames - exp_test_flow_rx_pkts) / float(exp_test_flow_rx_pkts)
            pytest_assert(abs(deviation) < tolerance,
                          '{} should receive {} packets (actual {})'.
                          format(test_flow_name, exp_test_flow_rx_pkts, rx_frames))

    if test_flow_pause:
        """ In-flight TX bytes of test flows should be held by switch buffer """
        tx_frames_total = sum(row.frames_tx for row in rows if test_flow_name in row.name)
        tx_bytes_total = tx_frames_total * data_pkt_size
        dut_buffer_size = get_egress_lossless_buffer_size(host_ans=duthost)

        pytest_assert(tx_bytes_total < dut_buffer_size,
                      'Total TX bytes {} should be smaller than DUT buffer size {}'.\
                      format(tx_bytes_total, dut_buffer_size))