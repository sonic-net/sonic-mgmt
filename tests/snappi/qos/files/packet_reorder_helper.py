import time
import logging

from tests.common.helpers.assertions import pytest_assert
from tests.common.snappi.snappi_helpers import get_dut_port_id
from tests.common.snappi.common_helpers import disable_packet_aging
from tests.common.snappi.port import select_ports, select_tx_port
from tests.common.snappi.snappi_helpers import wait_for_arp

logger = logging.getLogger(__name__)

FLOW_NAME = 'IP-IP Test Flow'
TX_PORT_NAME = None
RX_PORT_NAME = None
FLOW_AGGR_RATE_PERCENT = 70
LARGER_PKT_SIZE = 512
SMALLER_PKT_SIZE = 256
PKT_STEP_SIZE = LARGER_PKT_SIZE - SMALLER_PKT_SIZE
UDP_SRC_PORT = 63
UDP_DST_PORT = 63
UDP_PKT_LEN = 190
TOTAL_NUM_PKTS = 100000
EXP_FLOW_DUR_SEC = 3
SNAPPI_POLL_DELAY_SEC = 2
INNER_PKT_SRC_IP = "20.0.20.0"
INNER_PKT_DST_IP = "21.0.20.0"
SEQUENCE_CHECKING_THRESHOLD = 1


def run_ipip_packet_reorder_test(api,
                                 testbed_config,
                                 port_config_list,
                                 conn_data,
                                 fanout_data,
                                 duthost,
                                 dut_port,
                                 flow_prio_list,
                                 prio_dscp_map):
    """
    Run a IP-IP Packet Reorder Test
    Args:
        api (obj): snappi session
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        conn_data (dict): the dictionary returned by conn_graph_fact.
        fanout_data (dict): the dictionary returned by fanout_graph_fact.
        duthost (Ansible host instance): device under test
        dut_port (str): DUT port to test
        flow_prio_list (list): priorities of flows
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).

    Returns:
        N/A
    """

    pytest_assert(testbed_config is not None, 'Fail to get L2/3 testbed config')

    # Get the ID of the port to test
    port_id = get_dut_port_id(dut_hostname=duthost.hostname,
                              dut_port=dut_port,
                              conn_data=conn_data,
                              fanout_data=fanout_data)

    pytest_assert(port_id is not None,
                  'Fail to get ID for port {}'.format(dut_port))

    flow_rate_percent = int(FLOW_AGGR_RATE_PERCENT / len(flow_prio_list))

    # Generate traffic config
    __gen_traffic(testbed_config=testbed_config,
                  port_config_list=port_config_list,
                  port_id=port_id,
                  flow_name=FLOW_NAME,
                  flow_prio_list=flow_prio_list,
                  flow_rate_percent=flow_rate_percent,
                  total_tx_pkts=TOTAL_NUM_PKTS,
                  larger_pkt_size=LARGER_PKT_SIZE,
                  smaller_pkt_size=SMALLER_PKT_SIZE,
                  pkt_step_size=PKT_STEP_SIZE,
                  prio_dscp_map=prio_dscp_map)

    flows = testbed_config.flows
    all_flow_names = [flow.name for flow in flows]

    # Run traffic
    flow_metrics = __run_traffic(api=api,
                                 config=testbed_config,
                                 all_flow_names=all_flow_names,
                                 timeout=EXP_FLOW_DUR_SEC)

    # Verify results i.e. no out of order packets
    __verify_results(api=api,
                     flow_metrics=flow_metrics,
                     exp_rx_pkts=TOTAL_NUM_PKTS)


def __gen_traffic(testbed_config,
                  port_config_list,
                  port_id,
                  flow_name,
                  flow_prio_list,
                  flow_rate_percent,
                  total_tx_pkts,
                  larger_pkt_size,
                  smaller_pkt_size,
                  pkt_step_size,
                  prio_dscp_map):
    """
    Generate configurations of flows, and device configurations on both the DUT, and ixia device which
    emulates a neighbor.
    Args:
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        port_id (int): ID of DUT port to test
        flow_name (str): name of flow
        flow_prio_list (list): priorities of the flow
        flow_rate_percent (int): rate percentage for each flow
        total_tx_pkts (int): total number of packets to transmit
        larger_pkt_size (int): packet size of larger data flow in bytes
        smaller_pkt_size (int): packet size of smaller data flow in bytes
        pkt_step_size (int): packet size step of flow in bytes
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority).
    Returns:
        N/A
    """

    rx_port_id = port_id
    tx_port_id_list, _ = select_ports(port_config_list=port_config_list,
                                      pattern="many to one",
                                      rx_port_id=rx_port_id)

    pytest_assert(len(tx_port_id_list) > 0, "Cannot find any TX ports")
    tx_port_id = select_tx_port(tx_port_id_list=tx_port_id_list,
                                rx_port_id=rx_port_id)
    pytest_assert(tx_port_id is not None, "Cannot find a suitable TX port")

    tx_port_config = next((port_tx for port_tx in port_config_list if port_tx.id == tx_port_id), None)
    rx_port_config = next((port_rx for port_rx in port_config_list if port_rx.id == rx_port_id), None)

    # Set the correct MAC address for the switch
    tx_mac = tx_port_config.mac
    if tx_port_config.gateway == rx_port_config.gateway and \
       tx_port_config.prefix_len == rx_port_config.prefix_len:
        # If soruce and destination port are in the same subnet, use the rx port MAC, else use the switch MAC
        rx_mac = rx_port_config.mac
    else:
        rx_mac = tx_port_config.gateway_mac

    tx_port_name = testbed_config.ports[tx_port_id].name
    rx_port_name = testbed_config.ports[rx_port_id].name

    global TX_PORT_NAME, RX_PORT_NAME
    TX_PORT_NAME = tx_port_name
    RX_PORT_NAME = rx_port_name

    for prio in flow_prio_list:
        # Begin configuring flows
        ipip_flow = testbed_config.flows.flow(name="{} Packet_Prio_{}".format(flow_name, prio))[-1]
        ipip_flow.tx_rx.port.tx_name = tx_port_name
        ipip_flow.tx_rx.port.rx_name = rx_port_name
        eth, outer_ipv4, inner_ipv4, udp = ipip_flow.packet.ethernet().ipv4().ipv4().udp()

        # Configure ethernet header
        eth.src.value = tx_mac
        eth.dst.value = rx_mac

        # Configure outer IPv4 header
        outer_ipv4.src.value = tx_port_config.ip
        outer_ipv4.dst.value = rx_port_config.ip
        outer_ipv4.identification.choice = "increment"
        outer_ipv4.identification.increment.start = 1
        outer_ipv4.identification.increment.step = 1
        outer_ipv4.identification.increment.count = total_tx_pkts
        outer_ipv4.priority.choice = outer_ipv4.priority.DSCP
        outer_ipv4.priority.dscp.ecn.value = (
            outer_ipv4.priority.dscp.ecn.CAPABLE_TRANSPORT_1)

        # Configure inner IPv4 header
        inner_ipv4.src.value = INNER_PKT_SRC_IP
        inner_ipv4.dst.value = INNER_PKT_DST_IP
        inner_ipv4.priority.choice = inner_ipv4.priority.DSCP
        inner_ipv4.priority.dscp.ecn.value = (
            inner_ipv4.priority.dscp.ecn.CAPABLE_TRANSPORT_1)

        # Configure UDP header
        udp.src_port.value = UDP_SRC_PORT
        udp.dst_port.value = UDP_DST_PORT
        udp.length.value = UDP_PKT_LEN

        # Configure the appropriate priorities for each header
        eth.pfc_queue.value = prio
        outer_ipv4.priority.dscp.phb.values = prio_dscp_map[prio]
        inner_ipv4.priority.dscp.phb.values = prio_dscp_map[prio]

        # Configure packet size and other variables
        ipip_flow.size.increment.start = smaller_pkt_size
        ipip_flow.size.increment.end = larger_pkt_size
        ipip_flow.size.increment.step = pkt_step_size
        ipip_flow.rate.percentage = flow_rate_percent
        ipip_flow.duration.fixed_packets.packets = total_tx_pkts

        ipip_flow.metrics.enable = True
        ipip_flow.metrics.loss = True


def __run_traffic(api,
                  config,
                  all_flow_names,
                  timeout):

    """
    Run traffic and dump per-flow statistics
    Args:
        api (obj): snappi session
        config (obj): experiment config (testbed config + flow config)
        all_flow_names (list): list of names of all the flows
        timeout (int): time to wait in seconds before snappi begins recovering metrics
    Returns:
        flow_metrics (list): list of flow metrics
    """

    api.set_config(config)

    logger.info('Wait for Arp to Resolve ...')
    wait_for_arp(api, max_attempts=30, poll_interval_sec=2)

    logger.info("Setting up Ixia API session to capture advanced statistics ...")
    __configure_advanced_stats(api)

    logger.info('Starting transmit on all flows ...')
    ts = api.transmit_state()
    ts.state = ts.START
    api.set_transmit_state(ts)

    time.sleep(timeout)

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
    flow_metrics = api.get_metrics(request).flow_metrics
    logger.info('Stop transmit on all flows ...')
    ts = api.transmit_state()
    ts.state = ts.STOP
    api.set_transmit_state(ts)

    return flow_metrics


def __configure_advanced_stats(api):
    """
    Set up advanced statistics on the Ixia API session
    Args:
        api (obj): snappi session
    Returns:
        N/A
    """

    # Connect to restpy session
    restpy_session = api.assistant.Session
    ixnet = restpy_session.Ixnetwork
    statVarIxia = ixnet.Traffic.Statistics
    statVarIxia.AdvancedSequenceChecking.Enabled = True
    statVarIxia.AdvancedSequenceChecking.AdvancedSequenceThreshold = SEQUENCE_CHECKING_THRESHOLD


def __verify_results(api,
                     flow_metrics,
                     exp_rx_pkts):
    """
    Verify if we get expected experiment results
    Args:
        api (obj): snappi session
        flow_metrics (list): per-flow statistics
        exp_rx_pkts (int): total number of packets to receive
    Returns:
        N/A
    """

    # Calculate total frames sent and received across all configured ports
    total_tx = sum([flow_metric.frames_tx for flow_metric in flow_metrics])
    total_rx = sum([flow_metric.frames_rx for flow_metric in flow_metrics])

    pytest_assert(total_tx == total_rx, "Number of total Tx packets = {} and Rx packets = {} are not equal."
                  .format(total_tx, total_rx))
    pytest_assert(total_rx == exp_rx_pkts, "Number of total Rx packets = {} are not equal to expected packets = {}"
                  .format(total_rx, exp_rx_pkts))

    # Check for packet re-order
    flow_stat = api.assistant.StatViewAssistant("Flow Statistics")
    for stat in flow_stat.Rows:
        in_order_frames = int(stat["In Order Frames"])
        reordered_frames = int(stat["Reordered Frames"])
        error_msg = "Frames are out of order. Reordered frames = {}".format(reordered_frames)
        pytest_assert(in_order_frames == total_tx and reordered_frames == 0, error_msg)
