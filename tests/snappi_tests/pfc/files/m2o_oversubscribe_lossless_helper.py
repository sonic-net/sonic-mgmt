from math import ceil                                                                   # noqa: F401
import logging                                                                          # noqa: F401
import sys
from tests.common.helpers.assertions import pytest_assert, pytest_require               # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts  # noqa: F401
from tests.common.snappi_tests.snappi_helpers import get_dut_port_id, get_macsec_flow_loss             # noqa: F401
from tests.common.snappi_tests.common_helpers import pfc_class_enable_vector, \
    stop_pfcwd, disable_packet_aging, sec_to_nanosec, get_interface_stats                     # noqa: F401
from tests.common.snappi_tests.port import select_ports                                       # noqa: F401
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.common.snappi_tests.traffic_generation import setup_base_traffic_config, \
     run_traffic                                         # noqa: F401
from tests.common.snappi_tests.variables import pfcQueueGroupSize, pfcQueueValueDict
from tests.snappi_tests.files.helper import get_number_of_streams
from tests.common.snappi_tests.snappi_fixtures import gen_data_flow_dest_ip
logger = logging.getLogger(__name__)

PAUSE_FLOW_NAME = 'Pause Storm'
TEST_FLOW_NAME = 'Test Flow'
TEST_FLOW_AGGR_RATE_PERCENT = 35
BG_FLOW_NAME = 'Background Flow'
BG_FLOW_AGGR_RATE_PERCENT = 22.5
DATA_PKT_SIZE = 1024
DATA_FLOW_DURATION_SEC = 10
DATA_FLOW_DELAY_SEC = 5
SNAPPI_POLL_DELAY_SEC = 2
TOLERANCE_THRESHOLD = 0.05
UDP_PORT_START = 5000
# Number of non-MACsec devices created on the rx port per tx port (see __intf_config_macsec)
MACSEC_DEVICES_PER_TX_PORT = 7


def run_m2o_oversubscribe_lossless_test(api,
                                        testbed_config,
                                        port_config_list,
                                        conn_data,
                                        fanout_data,
                                        dut_port,
                                        pause_prio_list,
                                        test_prio_list,
                                        bg_prio_list,
                                        prio_dscp_map,
                                        snappi_extra_params=None):
    """
    Run PFC oversubsription lossless for many to one traffic pattern

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
        prio_dscp_map (dict): Priority vs. DSCP map (key = priority)
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    Returns:
        N/A
    """
    if snappi_extra_params is None:
        snappi_extra_params = SnappiTestParams()

    # initialize the (duthost, port) set.
    dut_asics_to_be_configured = set()

    rx_port = snappi_extra_params.multi_dut_params.multi_dut_ports[0]
    rx_port_id_list = [rx_port["port_id"]]
    egress_duthost = rx_port['duthost']
    dut_asics_to_be_configured.add((egress_duthost, rx_port['asic_value']))

    # Append the egress here for run_traffic to clear its counters
    snappi_extra_params.multi_dut_params.egress_duthosts.append(egress_duthost)

    tx_port = [snappi_extra_params.multi_dut_params.multi_dut_ports[1],
               snappi_extra_params.multi_dut_params.multi_dut_ports[2]]

    # Append the ingress here for run_traffic to clear its counters
    snappi_extra_params.multi_dut_params.ingress_duthosts.append(tx_port[0]['duthost'])
    snappi_extra_params.multi_dut_params.ingress_duthosts.append(tx_port[1]['duthost'])

    tx_port_id_list = [tx_port[0]["port_id"], tx_port[1]["port_id"]]
    # add ingress DUT into the set
    dut_asics_to_be_configured.add((tx_port[0]['duthost'], tx_port[0]['asic_value']))
    dut_asics_to_be_configured.add((tx_port[1]['duthost'], tx_port[1]['asic_value']))

    pytest_assert(testbed_config is not None, 'Fail to get L2/3 testbed config')

    # Disable PFC watchdog on the rx side and tx side of the DUT
    for duthost, asic in dut_asics_to_be_configured:
        stop_pfcwd(duthost, asic)
        disable_packet_aging(duthost)

    test_flow_rate_percent = int(TEST_FLOW_AGGR_RATE_PERCENT)
    bg_flow_rate_percent = int(BG_FLOW_AGGR_RATE_PERCENT)
    no_of_bg_streams = get_number_of_streams(egress_duthost, tx_port, rx_port)
    port_id = 0
    # Generate base traffic config
    snappi_extra_params.base_flow_config = setup_base_traffic_config(testbed_config=testbed_config,
                                                                     port_config_list=port_config_list,
                                                                     port_id=port_id)
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
                  prio_dscp_map=prio_dscp_map,
                  no_of_bg_streams=no_of_bg_streams,
                  snappi_extra_params=snappi_extra_params)

    flows = testbed_config.flows
    all_flow_names = [flow.name for flow in flows]
    data_flow_names = [flow.name for flow in flows if PAUSE_FLOW_NAME not in flow.name]

    """ Run traffic """
    flow_stats, switch_flow_stats, _ = run_traffic(duthost=egress_duthost,
                                                   api=api,
                                                   config=testbed_config,
                                                   data_flow_names=data_flow_names,
                                                   all_flow_names=all_flow_names,
                                                   exp_dur_sec=DATA_FLOW_DURATION_SEC + DATA_FLOW_DELAY_SEC,
                                                   snappi_extra_params=snappi_extra_params)

    ptype = "--snappi_macsec" in sys.argv
    if not ptype:
        dut_tx_port = rx_port['peer_port']
        ingress_dut1 = tx_port[0]['duthost']
        ingress_dut2 = tx_port[1]['duthost']
        ingress_port1 = tx_port[0]['peer_port']
        ingress_port2 = tx_port[1]['peer_port']
        # Fetch relevant statistics
        pkt_drop = get_interface_stats(egress_duthost, dut_tx_port)[egress_duthost.hostname][dut_tx_port]['tx_drp']
        rx_pkts_1 = get_interface_stats(ingress_dut1, ingress_port1)[ingress_dut1.hostname][ingress_port1]['rx_ok']
        rx_pkts_2 = get_interface_stats(ingress_dut2, ingress_port2)[ingress_dut2.hostname][ingress_port2]['rx_ok']
        # Calculate the total received packets
        total_rx_pkts = rx_pkts_1 + rx_pkts_2
        # Calculate the drop percentage
        drop_percentage = 100 * pkt_drop / total_rx_pkts
        pytest_assert(round(drop_percentage) == 0, 'FAIL: There should be no packet drops in ingress dut counters')

        """ Verify Results """
        verify_m2o_oversubscribe_lossless_result(flow_stats,
                                                 tx_port,
                                                 rx_port)
    else:
        """ Verify Results """
        verify_m2o_oversubscribe_lossless_result_for_macsec(flow_stats,
                                                            snappi_extra_params)


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
                  prio_dscp_map,
                  no_of_bg_streams,
                  snappi_extra_params):
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
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic

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
                     prio_dscp_map=prio_dscp_map,
                     snappi_extra_params=snappi_extra_params,
                     no_of_streams=1)

    __gen_data_flows(testbed_config=testbed_config,
                     port_config_list=port_config_list,
                     src_port_id_list=tx_port_id_list,
                     dst_port_id_list=rx_port_id_list,
                     flow_name_prefix=BG_FLOW_NAME,
                     flow_prio_list=bg_flow_prio_list,
                     flow_rate_percent=bg_flow_rate_percent,
                     flow_dur_sec=data_flow_dur_sec,
                     data_pkt_size=data_pkt_size,
                     prio_dscp_map=prio_dscp_map,
                     snappi_extra_params=snappi_extra_params,
                     no_of_streams=no_of_bg_streams)


def __gen_data_flows(testbed_config,
                     port_config_list,
                     src_port_id_list,
                     dst_port_id_list,
                     flow_name_prefix,
                     flow_prio_list,
                     flow_rate_percent,
                     flow_dur_sec,
                     data_pkt_size,
                     prio_dscp_map,
                     snappi_extra_params,
                     no_of_streams=1):
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
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic

    Returns:
        N/A
    """
    for src_index, src_port_id in enumerate(src_port_id_list):
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
                            prio_dscp_map=prio_dscp_map,
                            snappi_extra_params=snappi_extra_params,
                            src_index=src_index,
                            num_src_ports=len(src_port_id_list),
                            no_of_streams=no_of_streams)


def __gen_data_flow(testbed_config,
                    port_config_list,
                    src_port_id,
                    dst_port_id,
                    flow_name_prefix,
                    flow_prio,
                    flow_rate_percent,
                    flow_dur_sec,
                    data_pkt_size,
                    prio_dscp_map,
                    snappi_extra_params,
                    src_index,
                    num_src_ports,
                    no_of_streams):
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
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
        src_index (int): position of the source port in the source port list
        num_src_ports (int): number of source (MACsec) ports
        no_of_streams (int): number of UDP streams for the flow

    Returns:
        N/A
    """
    ptype = "--snappi_macsec" in sys.argv
    tx_port_config = next((x for x in port_config_list if x.id == src_port_id), None)
    rx_port_config = next((x for x in port_config_list if x.id == dst_port_id), None)
    tx_mac = tx_port_config.mac
    if tx_port_config.gateway == rx_port_config.gateway and tx_port_config.prefix_len == rx_port_config.prefix_len:
        rx_mac = rx_port_config.mac
    else:
        rx_mac = tx_port_config.gateway_mac

    flow = testbed_config.flows.flow(name='{} {} -> {}'.format(flow_name_prefix, src_port_id, dst_port_id))[-1]

    # Priority used by this flow: first priority for the flow from port 1, second for port 2
    if 'Flow 1 -> 0' in flow.name:
        prio = flow_prio[0]
    elif 'Flow 2 -> 0' in flow.name:
        prio = flow_prio[1]
    else:
        prio = flow_prio[src_index]

    if ptype:
        # MACsec devices of the tx ports are the last devices in the config; the rx port has
        # MACSEC_DEVICES_PER_TX_PORT non-MACsec devices per tx port, one per priority.
        tx_device = testbed_config.devices[len(testbed_config.devices) - num_src_ports + src_index]
        rx_device = testbed_config.devices[src_index * MACSEC_DEVICES_PER_TX_PORT + prio]
        flow.tx_rx.device.tx_names = [tx_device.ethernets[0].ipv4_addresses[0].name]
        flow.tx_rx.device.rx_names = [rx_device.ethernets[0].ipv4_addresses[0].name]
        flow.tx_rx.device.mode = flow.tx_rx.device.ONE_TO_ONE
        flow.packet.ethernet().ipv4()
        ipv4 = flow.packet[-1]
        eth = flow.packet[-2]
        eth.src.value = tx_mac
        eth.dst.value = rx_mac
        if pfcQueueGroupSize == 8:
            eth.pfc_queue.value = prio
        else:
            eth.pfc_queue.value = pfcQueueValueDict[prio]
        # MACsec flow statistics are tracked per PGID (priority), keep the mapping for verification
        PGID = src_index * MACSEC_DEVICES_PER_TX_PORT + prio
        snappi_extra_params.flow_name_stats_identity_map[flow.name] = (
            testbed_config.ports[src_port_id].name,
            testbed_config.ports[dst_port_id].name,
            PGID,
        )
    else:
        flow.tx_rx.port.tx_name = testbed_config.ports[src_port_id].name
        flow.tx_rx.port.rx_name = testbed_config.ports[dst_port_id].name
        eth, ipv4, udp = flow.packet.ethernet().ipv4().udp()

        eth.src.value = tx_mac
        eth.dst.value = rx_mac
        if pfcQueueGroupSize == 8:
            if 'Background Flow' in flow.name:
                eth.pfc_queue.value = 1
            elif 'Test Flow 1 -> 0' in flow.name:
                eth.pfc_queue.value = flow_prio[0]
            elif 'Test Flow 2 -> 0' in flow.name:
                eth.pfc_queue.value = flow_prio[1]
        else:
            # Adding queue values based on flow_priorities for both test and background flows.
            if 'Flow 1 -> 0' in flow.name:
                eth.pfc_queue.value = pfcQueueValueDict[flow_prio[0]]
            elif 'Flow 2 -> 0' in flow.name:
                eth.pfc_queue.value = pfcQueueValueDict[flow_prio[1]]

        global UDP_PORT_START
        src_port = UDP_PORT_START
        UDP_PORT_START += no_of_streams
        udp.src_port.increment.start = src_port
        udp.src_port.increment.step = 1
        udp.src_port.increment.count = no_of_streams

        ipv4.src.value = tx_port_config.ip
        ipv4.dst.value = gen_data_flow_dest_ip(rx_port_config.ip)

    flow.duration.fixed_seconds.delay.nanoseconds = int(sec_to_nanosec(DATA_FLOW_DELAY_SEC))
    ipv4.priority.choice = ipv4.priority.DSCP
    # Background flows have dynamic lossy priorities.
    ipv4.priority.dscp.phb.values = prio_dscp_map[prio]
    if ptype and len(ipv4.priority.dscp.phb.values) > 1:
        # Single DSCP value per MACsec flow so it maps to a single PGID
        ipv4.priority.dscp.phb.values = ipv4.priority.dscp.phb.values[:1]
    logger.info('{} prio {} queue {} dscp {}'.format(flow.name, prio, eth.pfc_queue.value,
                                                     ipv4.priority.dscp.phb.values))

    ipv4.priority.dscp.ecn.value = ipv4.priority.dscp.ecn.CAPABLE_TRANSPORT_1
    flow.size.fixed = data_pkt_size
    flow.rate.percentage = flow_rate_percent
    flow.duration.fixed_seconds.seconds = flow_dur_sec
    flow.metrics.enable = True
    flow.metrics.loss = True


def verify_m2o_oversubscribe_lossless_result(rows,
                                             tx_port,
                                             rx_port):
    """
    Verifies the required loss % from the Traffic Items Statistics

    Args:
        rows (list): Traffic Item Statistics from snappi config
        tx_port (list): Ingress Ports
        rx_port : Egress Port
    Returns:
        N/A
    """
    for row in rows:
        if TEST_FLOW_NAME in row.name or BG_FLOW_NAME in row.name:
            pytest_assert(int(row.loss) == 0, f"{row.name} must have 0% loss")


def verify_m2o_oversubscribe_lossless_result_for_macsec(rows,
                                                        snappi_extra_params):
    """
    Verifies the required loss % using the IxNetwork 'Flow Statistics' rows returned
    by run_traffic in MACsec mode. Each flow is matched to its rows through
    snappi_extra_params.flow_name_stats_identity_map, which holds
    (Tx Port, Rx Port, PGID) per flow name.

    Args:
        rows (list): IxNetwork Flow Statistics rows (keyed by column name)
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    Returns:
        N/A
    """
    for flow_name, identity in snappi_extra_params.flow_name_stats_identity_map.items():
        loss = get_macsec_flow_loss(rows, flow_name, *identity)
        pytest_assert(int(loss) == 0, f"{flow_name} must have 0% loss, observed {loss:.2f}%")
