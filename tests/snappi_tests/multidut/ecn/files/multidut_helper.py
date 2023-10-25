import time
import dpkt
import logging
from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts             # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
     snappi_api                                                                                     # noqa: F401
from tests.common.snappi_tests.snappi_helpers import get_dut_port_id
from tests.common.snappi_tests.common_helpers import pfc_class_enable_vector, config_wred, \
    enable_ecn, config_ingress_lossless_buffer_alpha, stop_pfcwd, disable_packet_aging, \
    config_capture_pkt, packet_capture                                                              # noqa: F401
from tests.common.snappi_tests.port import select_ports, select_tx_port                             # noqa: F401
from tests.common.snappi_tests.snappi_helpers import wait_for_arp
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams

logger = logging.getLogger(__name__)

EXP_DURATION_SEC = 1
DATA_START_DELAY_SEC = 0.1
SNAPPI_POLL_DELAY_SEC = 2
PAUSE_FLOW_NAME = 'Pause Storm'
DATA_FLOW_NAME = 'Data Flow'

kmin = 500000
kmax = 510000
pmax = 100
pkt_size = 1024
pkt_cnt = 1000


def run_ecn_test(api,
                 testbed_config,
                 port_config_list,
                 conn_data,
                 fanout_data,
                 dut_port,
                 lossless_prio,
                 prio_dscp_map,
                 snappi_extra_params=None):
    """
    Run a ECN test

    Args:
        api (obj): SNAPPI session
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        conn_data (dict): the dictionary returned by conn_graph_fact.
        fanout_data (dict): the dictionary returned by fanout_graph_fact.
        dut_port (str): DUT port to test
        lossless_prio (int): lossless priority
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).

    Returns:
        Return captured IP packets (list of list)
    """

    if snappi_extra_params is None:
        snappi_extra_params = SnappiTestParams()

    duthost1 = snappi_extra_params.multi_dut_params.duthost1
    rx_port = snappi_extra_params.multi_dut_params.multi_dut_ports[0]
    rx_port_id = rx_port["port_id"]
    duthost2 = snappi_extra_params.multi_dut_params.duthost2
    tx_port = snappi_extra_params.multi_dut_params.multi_dut_ports[1]
    tx_port_id = tx_port["port_id"]
    iters = snappi_extra_params.test_iterations

    pytest_assert(testbed_config is not None, 'Failed to get L2/3 testbed config')

    stop_pfcwd(duthost1, rx_port['asic_value'])
    disable_packet_aging(duthost1)
    stop_pfcwd(duthost2, tx_port['asic_value'])
    disable_packet_aging(duthost2)

    """ Configure WRED/ECN thresholds """
    config_result = config_wred(host_ans=duthost1,
                                kmin=kmin,
                                kmax=kmax,
                                pmax=pmax,
                                asic_value=rx_port['asic_value'])
    pytest_assert(config_result is True, 'Failed to configure WRED/ECN at the DUT')

    """ Enable ECN marking """
    enable_ecn(host_ans=duthost1, prio=lossless_prio, asic_value=rx_port['asic_value'])

    """ Configure PFC threshold to 2 ^ 3 """
    config_result = config_ingress_lossless_buffer_alpha(host_ans=duthost1,
                                                         alpha_log2=3,
                                                         namespace=rx_port['asic_value'])

    pytest_assert(config_result is True, 'Failed to configure PFC threshold to 8')
    """ Get the ID of the port to test """
    port_id = get_dut_port_id(dut_hostname=duthost1.hostname,
                              dut_port=dut_port,
                              conn_data=conn_data,
                              fanout_data=fanout_data)

    pytest_assert(port_id is not None,
                  'Failed to get ID for port {}'.format(dut_port))

    """ Generate packet capture config """
    snappi_extra_params.packet_capture_type = packet_capture.IP_CAPTURE
    config_capture_pkt(testbed_config=testbed_config,
                       port_id=port_id,
                       capture_type=snappi_extra_params.packet_capture_type,
                       capture_name=snappi_extra_params.packet_capture_type.value + "_" + str(port_id))

    """ Generate traffic config """
    __gen_traffic(testbed_config=testbed_config,
                  port_config_list=port_config_list,
                  rx_port_id=rx_port_id,
                  tx_port_id=tx_port_id,
                  pause_flow_name=PAUSE_FLOW_NAME,
                  data_flow_name=DATA_FLOW_NAME,
                  prio=lossless_prio,
                  data_pkt_size=pkt_size,
                  data_pkt_cnt=pkt_cnt,
                  data_flow_delay_sec=DATA_START_DELAY_SEC,
                  exp_dur_sec=EXP_DURATION_SEC,
                  prio_dscp_map=prio_dscp_map)

    """ Run traffic and capture packets """
    capture_port_name = testbed_config.captures[0].port_names[0]
    result = []

    for i in range(iters):
        pcap_file_name = '{}-{}.pcap'.format(capture_port_name, i)

        __run_traffic(api=api,
                      config=testbed_config,
                      all_flow_names=[PAUSE_FLOW_NAME, DATA_FLOW_NAME],
                      exp_dur_sec=EXP_DURATION_SEC,
                      capture_port_name=capture_port_name,
                      pcap_file_name=pcap_file_name)

        result.append(__get_ip_pkts(pcap_file_name))

    return result


def sec_to_nanosec(x):
    return x * 1e9


def __gen_traffic(testbed_config,
                  port_config_list,
                  rx_port_id,
                  tx_port_id,
                  pause_flow_name,
                  data_flow_name,
                  prio,
                  data_pkt_size,
                  data_pkt_cnt,
                  data_flow_delay_sec,
                  exp_dur_sec,
                  prio_dscp_map):
    """
    Generate configurations of flows, including a data flow and a PFC pause storm.

    Args:
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        port_id (int): ID of DUT port to test
        pause_flow_name (str): name of the pause storm
        data_flow_name (str): name of the data flow
        prio (int): priority of the data flow and PFC pause storm
        data_pkt_size (int): packet size of the data flow in byte
        data_pkt_cnt (int): # of packets of the data flow
        data_flow_delay_sec (float): start delay of the data flow in second
        exp_dur_sec (float): experiment duration in second
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).

    Returns:
        N/A

    """
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

    data_flow = testbed_config.flows.flow(name=data_flow_name)[-1]
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
    data_flow.rate.percentage = 100
    data_flow.duration.fixed_packets.packets = data_pkt_cnt
    data_flow.duration.fixed_packets.delay.nanoseconds = int(data_flow_delay_nanosec)

    data_flow.metrics.enable = True
    data_flow.metrics.loss = True
    """ PFC Pause Storm """
    pause_time = []
    for x in range(8):
        if x == prio:
            pause_time.append(int('ffff', 16))
        else:
            pause_time.append(int('0000', 16))

    vector = pfc_class_enable_vector([prio])

    pause_flow = testbed_config.flows.flow(name=pause_flow_name)[-1]

    """ Pause frames are sent from the RX port """
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

    speed_str = testbed_config.layer1[0].speed
    speed_gbps = int(speed_str.split('_')[1])
    pause_dur = 65535 * 64 * 8.0 / (speed_gbps * 1e9)
    pps = int(2 / pause_dur)

    pause_flow.rate.pps = pps
    pause_flow.size.fixed = 64
    pause_flow.duration.fixed_seconds.seconds = exp_dur_sec
    pause_flow.duration.fixed_seconds.delay.nanoseconds = 0

    pause_flow.metrics.enable = True
    pause_flow.metrics.loss = True


def __run_traffic(api,
                  config,
                  all_flow_names,
                  exp_dur_sec,
                  capture_port_name,
                  pcap_file_name):
    """
    Run traffic and capture packets

    Args:
        api (obj): SNAPPI session
        config (obj): experiment config
        all_flow_names (list): names of all the flows
        capture_port_name (str): name of the port to capture packets
        pcap_file_name (str): name of the pcap file to store captured packets

    Returns:
        N/A
    """
    api.set_config(config)
    ixnetwork = api._ixnetwork
    filterPallette = ixnetwork.Vport.find().Capture.FilterPallette          # noqa: F841
    logger.info('Wait for Arp to Resolve ...')
    wait_for_arp(api, max_attempts=10, poll_interval_sec=2)

    cs = api.capture_state()
    cs.port_names = [capture_port_name]
    cs.state = cs.START
    api.set_capture_state(cs)

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
        # """ If all the flows have stopped """
        transmit_states = [row.transmit for row in rows]
        if len(rows) == len(all_flow_names) and \
                list(set(transmit_states)) == ['stopped']:
            time.sleep(SNAPPI_POLL_DELAY_SEC)
            break
        else:
            time.sleep(1)
            attempts += 1

    pytest_assert(attempts < max_attempts,
                  "Flows do not stop in {} seconds".format(max_attempts))

    """ Dump captured packets """
    request = api.capture_request()
    request.port_name = capture_port_name
    pcap_bytes = api.get_capture(request)
    with open(pcap_file_name, 'wb') as fid:
        fid.write(pcap_bytes.getvalue())

    """ Stop all the flows """
    logger.info('Stop transmit on all flows ...')
    ts = api.transmit_state()
    ts.state = ts.STOP
    api.set_transmit_state(ts)


def __get_ip_pkts(pcap_file_name):
    """
    Get IP packets from the pcap file

    Args:
        pcap_file_name (str): name of the pcap file to store captured packets

    Returns:
        Captured IP packets (list)
    """
    ip_pkts = []
    for ts, pkt in dpkt.pcap.Reader(open(pcap_file_name, 'rb')):
        eth = dpkt.ethernet.Ethernet(pkt)
        if isinstance(eth.data, dpkt.ip.IP):
            ip_pkts.append(eth.data)

    return ip_pkts


def is_ecn_marked(ip_pkt):
    """
    Determine if an IP packet is ECN marked

    Args:
        ip_pkt (obj): IP packet

    Returns:
        Return if the packet is ECN marked (bool)
    """

    return (ip_pkt.tos & 3) == 3
